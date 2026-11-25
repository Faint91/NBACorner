-- Ordinary bracket content only. Revisions live separately so the master row
-- shape and the established master creation/retirement RPCs remain unchanged.
BEGIN;

CREATE TABLE public.ordinary_bracket_revisions (
    bracket_id uuid PRIMARY KEY REFERENCES public.brackets(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0)
);
ALTER TABLE public.ordinary_bracket_revisions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.ordinary_bracket_revisions FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.ordinary_bracket_revisions TO service_role;

CREATE FUNCTION public.ordinary_bracket_plan(p_bracket uuid, p_actor uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT jsonb_build_object(
        'bracket', to_jsonb(b),
        'revision', coalesce(r.revision, 0)::text,
        'matches', CASE WHEN b.user_id = p_actor THEN coalesce(
            (SELECT jsonb_agg(to_jsonb(m) ORDER BY m.round, m.id) FROM public.matches m WHERE m.bracket_id = b.id),
            '[]'::jsonb) ELSE '[]'::jsonb END
    )
    FROM public.brackets b
    JOIN public.seasons s ON s.id = b.season_id
    LEFT JOIN public.ordinary_bracket_revisions r ON r.bracket_id = b.id
    WHERE b.id = p_bracket AND b.deleted_at IS NULL AND NOT b.is_master
        AND s.master_bracket_id IS DISTINCT FROM b.id;
$$;

CREATE FUNCTION public.ordinary_bracket_snapshot(p_bracket uuid, p_actor uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT jsonb_build_object(
        'bracket', to_jsonb(b) || jsonb_build_object(
            'owner', jsonb_build_object('id', u.id, 'username', u.username),
            'is_owner', true, 'is_historical', false, 'read_only', false,
            'is_master', false, 'isMaster', false
        ),
        'revision', coalesce(r.revision, 0)::text,
        'matches', coalesce((SELECT jsonb_object_agg(conference, rounds) FROM (
            SELECT conference, jsonb_object_agg(round, rows) AS rounds FROM (
                SELECT lower(m.conference) AS conference, m.round,
                    jsonb_agg(to_jsonb(m) ||
                        CASE WHEN a.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
                            'team_a_name',a.name,'team_a_code',a.code,'team_a_logo_url',a.logo_url,
                            'team_a_primary_color',a.primary_color,'team_a_secondary_color',a.secondary_color
                        ) END ||
                        CASE WHEN z.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
                            'team_b_name',z.name,'team_b_code',z.code,'team_b_logo_url',z.logo_url,
                            'team_b_primary_color',z.primary_color,'team_b_secondary_color',z.secondary_color
                        ) END ORDER BY m.slot,m.id) AS rows
                FROM public.matches m
                LEFT JOIN public.teams a ON a.id=m.team_a
                LEFT JOIN public.teams z ON z.id=m.team_b
                WHERE m.bracket_id=b.id GROUP BY lower(m.conference),m.round
            ) AS grouped_matches GROUP BY conference
        ) AS conferences), '{}'::jsonb)
    )
    FROM public.application_season c
    JOIN public.seasons s ON s.id=c.season_id
    JOIN public.brackets b ON b.season_id=s.id
    JOIN public.users u ON u.id=b.user_id
    LEFT JOIN public.ordinary_bracket_revisions r ON r.bracket_id=b.id
    WHERE c.singleton AND b.id=p_bracket AND b.user_id=p_actor AND NOT u.is_admin
        AND b.deleted_at IS NULL AND NOT b.is_master AND s.master_bracket_id IS DISTINCT FROM b.id;
$$;

CREATE FUNCTION public.write_ordinary_bracket(
    p_bracket uuid, p_season uuid, p_actor uuid, p_auth_version integer,
    p_revision bigint, p_action text, p_changes jsonb, p_name text, p_snapshot boolean
) RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog, public AS $$
DECLARE
    selected_season uuid;
    season public.seasons%ROWTYPE;
    bracket public.brackets%ROWTYPE;
    actor public.users%ROWTYPE;
    revision bigint;
    changed integer;
    write_time timestamptz;
BEGIN
    -- Lifecycle/scoring already lock the canonical pointer before bracket tables.
    SELECT season_id INTO STRICT selected_season FROM public.application_season WHERE singleton FOR SHARE;
    IF selected_season IS DISTINCT FROM p_season THEN
        RAISE SQLSTATE 'PT409' USING MESSAGE='The bracket season changed. Refresh and try again.';
    END IF;
    SELECT * INTO STRICT season FROM public.seasons WHERE id=selected_season FOR SHARE;
    SELECT * INTO actor FROM public.users WHERE id=p_actor FOR SHARE;
    IF NOT FOUND OR actor.auth_version IS DISTINCT FROM p_auth_version THEN
        RAISE SQLSTATE 'PT401' USING MESSAGE='Invalid or expired token';
    END IF;
    SELECT * INTO bracket FROM public.brackets WHERE id=p_bracket FOR UPDATE;
    IF NOT FOUND OR bracket.deleted_at IS NOT NULL THEN
        RAISE SQLSTATE 'PT404' USING MESSAGE='Bracket not found';
    END IF;
    IF bracket.season_id IS DISTINCT FROM p_season OR bracket.user_id IS DISTINCT FROM p_actor
       OR bracket.is_master OR season.master_bracket_id=p_bracket
       OR (actor.is_admin AND p_action<>'delete') THEN
        RAISE SQLSTATE 'PT403' USING MESSAGE='Unauthorized: You are not allowed to modify this bracket';
    END IF;
    SELECT coalesce((SELECT r.revision FROM public.ordinary_bracket_revisions r WHERE r.bracket_id=p_bracket),0)
        INTO revision;
    IF p_revision IS DISTINCT FROM revision THEN
        RAISE SQLSTATE 'PT409' USING MESSAGE='The bracket changed in another session. Refresh and try again.';
    END IF;
    write_time:=clock_timestamp();
    IF season.playoffs_start_utc IS NULL OR write_time>=season.playoffs_start_utc THEN
        IF p_action<>'delete' OR bracket.is_done IS TRUE THEN
            IF p_action='delete' THEN
                RAISE SQLSTATE 'PT403' USING MESSAGE='Submitted brackets cannot be deleted after the final deadline';
            END IF;
            RAISE SQLSTATE 'PT403' USING MESSAGE='Brackets are locked; you can no longer edit.';
        END IF;
    END IF;
    CASE p_action
    WHEN 'prediction' THEN
        IF jsonb_typeof(p_changes) IS DISTINCT FROM 'array' OR jsonb_array_length(p_changes)=0 THEN
            RAISE SQLSTATE 'PT400' USING MESSAGE='Invalid bracket changes';
        END IF;
        UPDATE public.matches m
        SET team_a=x.team_a,team_b=x.team_b,predicted_winner=x.predicted_winner,
            predicted_winner_games=x.predicted_winner_games,updated_at=write_time
        FROM jsonb_to_recordset(p_changes) AS x(id uuid,team_a text,team_b text,predicted_winner text,predicted_winner_games integer)
        WHERE m.id=x.id AND m.bracket_id=p_bracket;
        GET DIAGNOSTICS changed=ROW_COUNT;
        IF changed<>jsonb_array_length(p_changes) THEN
            RAISE SQLSTATE 'PT400' USING MESSAGE='Invalid or duplicate match changes';
        END IF;
        UPDATE public.brackets SET is_done=false,saved_at=NULL WHERE id=p_bracket;
    WHEN 'save' THEN
        IF p_name IS NULL OR btrim(p_name)='' THEN
            RAISE SQLSTATE 'PT400' USING MESSAGE='Bracket name is required';
        END IF;
        UPDATE public.brackets SET name=p_name,is_done=true,saved_at=write_time WHERE id=p_bracket;
    WHEN 'delete' THEN
        UPDATE public.brackets SET deleted_at=write_time,deleted_by_user_id=p_actor WHERE id=p_bracket;
        DELETE FROM public.bracket_scores WHERE bracket_id=p_bracket OR master_bracket_id=p_bracket;
    ELSE
        RAISE SQLSTATE 'PT400' USING MESSAGE='Invalid bracket action';
    END CASE;
    INSERT INTO public.ordinary_bracket_revisions(bracket_id,revision) VALUES (p_bracket,revision+1)
        ON CONFLICT (bracket_id) DO UPDATE SET revision=excluded.revision;
    IF p_snapshot AND p_action='prediction' THEN
        RETURN public.ordinary_bracket_snapshot(p_bracket,p_actor);
    END IF;
    RETURN jsonb_build_object('revision',(revision+1)::text,'name',p_name,'saved_at',write_time);
END;
$$;

CREATE FUNCTION public.create_ordinary_bracket(p_season uuid,p_actor uuid,p_auth_version integer,p_matches jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
DECLARE selected uuid; row public.brackets%ROWTYPE; season public.seasons%ROWTYPE; actor public.users%ROWTYPE; created timestamptz;
BEGIN
    SELECT season_id INTO STRICT selected FROM public.application_season WHERE singleton FOR SHARE;
    IF selected IS DISTINCT FROM p_season THEN
        RAISE SQLSTATE 'PT409' USING MESSAGE='The canonical season changed';
    END IF;
    SELECT * INTO STRICT season FROM public.seasons WHERE id=selected FOR SHARE;
    SELECT * INTO actor FROM public.users WHERE id=p_actor FOR SHARE;
    IF NOT FOUND OR actor.auth_version IS DISTINCT FROM p_auth_version THEN
        RAISE SQLSTATE 'PT401' USING MESSAGE='Invalid or expired token';
    END IF;
    created:=clock_timestamp();
    IF actor.is_admin OR season.playoffs_start_utc IS NULL OR season.regular_season_end_utc IS NULL
       OR created>=season.playoffs_start_utc OR created<season.regular_season_end_utc THEN
        RAISE SQLSTATE 'PT403' USING MESSAGE='Bracket creation is unavailable.';
    END IF;
    IF jsonb_typeof(p_matches) IS DISTINCT FROM 'array' OR jsonb_array_length(p_matches)<>21 THEN
        RAISE SQLSTATE 'PT400' USING MESSAGE='Invalid bracket graph';
    END IF;
    INSERT INTO public.brackets(user_id,season_id) VALUES(p_actor,p_season) RETURNING * INTO row;
    INSERT INTO public.matches(id,bracket_id,conference,round,slot,team_a,team_b,next_match_id,next_slot)
        SELECT m.id,row.id,m.conference,m.round,m.slot,m.team_a,m.team_b,m.next_match_id,m.next_slot
        FROM jsonb_to_recordset(p_matches) AS m(id uuid,conference text,round integer,slot integer,team_a text,team_b text,next_match_id uuid,next_slot text);
    RETURN to_jsonb(row);
END;
$$;

REVOKE ALL ON FUNCTION public.ordinary_bracket_plan(uuid,uuid), public.ordinary_bracket_snapshot(uuid,uuid),
    public.write_ordinary_bracket(uuid,uuid,uuid,integer,bigint,text,jsonb,text,boolean),
    public.create_ordinary_bracket(uuid,uuid,integer,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ordinary_bracket_plan(uuid,uuid), public.ordinary_bracket_snapshot(uuid,uuid),
    public.write_ordinary_bracket(uuid,uuid,uuid,integer,bigint,text,jsonb,text,boolean),
    public.create_ordinary_bracket(uuid,uuid,integer,jsonb) TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;
