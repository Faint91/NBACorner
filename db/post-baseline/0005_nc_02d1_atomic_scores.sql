-- Complete current score publication only; Python owns score formulas.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE FUNCTION public.publish_current_bracket_scores(p_season_id uuid,p_master_id uuid,p_source jsonb,p_rows jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE selected_id uuid; selected_master uuid; source_now jsonb; source_expected jsonb; old_scores jsonb; normalized_rows jsonb; row_count integer; BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_season_id THEN RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='40001'; END IF;
 SELECT master_bracket_id INTO STRICT selected_master FROM public.seasons WHERE id=selected_id FOR SHARE;
 IF selected_master IS NULL OR selected_master IS DISTINCT FROM p_master_id THEN RAISE EXCEPTION 'Canonical master changed' USING ERRCODE='40001'; END IF;
 -- Briefly freeze input tables to validate a complete observed input set, including inserts.
 LOCK TABLE public.brackets,public.matches IN SHARE MODE;
 IF NOT EXISTS(SELECT 1 FROM public.brackets WHERE id=selected_master AND season_id=selected_id AND is_master IS TRUE AND deleted_at IS NULL) THEN RAISE EXCEPTION 'Invalid canonical master'; END IF;
 IF jsonb_typeof(p_source) IS DISTINCT FROM 'object' OR jsonb_typeof(p_source->'brackets') IS DISTINCT FROM 'array' OR jsonb_typeof(p_source->'matches') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid score source'; END IF;
 SELECT jsonb_build_object(
 'brackets',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.id),'[]'::jsonb) FROM (SELECT id,user_id,season_id,is_master,is_done,deleted_at,saved_at FROM public.brackets WHERE season_id=selected_id) b),
 'matches',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]'::jsonb) FROM (SELECT id,bracket_id,season_id,conference,round,slot,team_a,team_b,predicted_winner,predicted_winner_games FROM public.matches WHERE season_id=selected_id) m)) INTO source_now;
 SELECT jsonb_build_object(
 'brackets',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.id),'[]'::jsonb) FROM jsonb_to_recordset(p_source->'brackets') AS b(id uuid,user_id uuid,season_id uuid,is_master boolean,is_done boolean,deleted_at timestamptz,saved_at timestamptz)),
 'matches',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]'::jsonb) FROM jsonb_to_recordset(p_source->'matches') AS m(id uuid,bracket_id uuid,season_id uuid,conference text,round integer,slot integer,team_a text,team_b text,predicted_winner text,predicted_winner_games integer))) INTO source_expected;
 IF source_now IS DISTINCT FROM source_expected THEN RAISE EXCEPTION 'Scoring inputs changed; recompute required' USING ERRCODE='40001'; END IF;
 IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Complete score array required'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r WHERE jsonb_typeof(r) IS DISTINCT FROM 'object'
 OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(r) k) IS DISTINCT FROM ARRAY['bonus_champion','bonus_finalists','bracket_id','full_hits','master_bracket_id','misses','partial_hits','points_by_match','points_by_round','season_id','total_points']::text[]
 OR jsonb_typeof(r->'points_by_match') IS DISTINCT FROM 'object' OR jsonb_typeof(r->'points_by_round') IS DISTINCT FROM 'object'
 OR (r->>'master_bracket_id')::uuid IS DISTINCT FROM selected_master OR (r->>'season_id')::uuid IS DISTINCT FROM selected_id) THEN RAISE EXCEPTION 'Invalid score row'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r CROSS JOIN LATERAL jsonb_each(r) f WHERE f.key IN ('total_points','full_hits','partial_hits','misses','bonus_finalists','bonus_champion') AND (jsonb_typeof(f.value) IS DISTINCT FROM 'number' OR (f.value::text)::numeric<0 OR (f.value::text)::numeric<>trunc((f.value::text)::numeric))) THEN RAISE EXCEPTION 'Invalid score components'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r WHERE (r->>'bonus_champion')::integer NOT IN (0,3) OR (r->>'bonus_finalists')::integer NOT IN (0,1)
 OR EXISTS(SELECT 1 FROM jsonb_each(r->'points_by_round') q WHERE jsonb_typeof(q.value) IS DISTINCT FROM 'number' OR (q.value::text)::numeric<0 OR (q.value::text)::numeric<>trunc((q.value::text)::numeric))
 OR (r->>'total_points')::numeric <> coalesce((SELECT sum((q.value::text)::numeric) FROM jsonb_each(r->'points_by_round') q),0)+(r->>'bonus_champion')::integer+(r->>'bonus_finalists')::integer) THEN RAISE EXCEPTION 'Score component total mismatch'; END IF;
 IF (SELECT coalesce(jsonb_agg(b.id ORDER BY b.id),'[]'::jsonb) FROM public.brackets b WHERE b.season_id=selected_id AND b.id<>selected_master AND b.is_done IS TRUE AND b.deleted_at IS NULL AND b.saved_at IS NOT NULL AND isfinite(b.saved_at))
 IS DISTINCT FROM (SELECT coalesce(jsonb_agg((r->>'bracket_id')::uuid ORDER BY (r->>'bracket_id')::uuid),'[]'::jsonb) FROM jsonb_array_elements(p_rows) r) THEN RAISE EXCEPTION 'Complete eligible score set required'; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(s)-'updated_at' ORDER BY s.bracket_id),'[]'::jsonb) INTO old_scores FROM public.bracket_scores s WHERE season_id=selected_id;
 SELECT coalesce(jsonb_agg(r ORDER BY (r->>'bracket_id')::uuid),'[]'::jsonb) INTO normalized_rows FROM jsonb_array_elements(p_rows) r;
 row_count:=jsonb_array_length(p_rows);
 IF old_scores=normalized_rows THEN RETURN jsonb_build_object('state','unchanged','master_bracket_id',selected_master,'season_id',selected_id,'updated_brackets',row_count,'written_rows',0); END IF;
 DELETE FROM public.bracket_scores WHERE season_id=selected_id;
 INSERT INTO public.bracket_scores(bracket_id,master_bracket_id,season_id,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,points_by_round,points_by_match)
 SELECT x.bracket_id,x.master_bracket_id,x.season_id,x.total_points,x.full_hits,x.partial_hits,x.misses,x.bonus_finalists,x.bonus_champion,x.points_by_round,x.points_by_match
 FROM jsonb_to_recordset(p_rows) AS x(bracket_id uuid,master_bracket_id uuid,season_id uuid,total_points integer,full_hits integer,partial_hits integer,misses integer,bonus_finalists integer,bonus_champion integer,points_by_round jsonb,points_by_match jsonb);
 RETURN jsonb_build_object('state','published','master_bracket_id',selected_master,'season_id',selected_id,'updated_brackets',row_count,'written_rows',row_count);
END;
$body$;
ALTER FUNCTION public.publish_current_bracket_scores(uuid,uuid,jsonb,jsonb) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.publish_current_bracket_scores(uuid,uuid,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.publish_current_bracket_scores(uuid,uuid,jsonb,jsonb) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
