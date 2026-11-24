-- QA-FIX-03K1: record the revision of the inputs that produced current scores.
BEGIN;
SET LOCAL lock_timeout='5s';
ALTER TABLE public.seasons ADD COLUMN published_score_revision text;

-- Include only inputs used by scoring. Unsubmitted drafts cannot invalidate live scores.
-- Epoch timestamps keep the digest independent of the caller's time zone.
CREATE FUNCTION public.score_input_revision(p_season_id uuid,p_master_id uuid)
RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $$
 WITH eligible AS (
   SELECT id, extract(epoch FROM saved_at) AS saved_at
   FROM public.brackets
   WHERE season_id=p_season_id AND id<>p_master_id AND is_done IS TRUE
     AND deleted_at IS NULL AND saved_at IS NOT NULL AND isfinite(saved_at)
 ), inputs AS (
   SELECT m.id,m.bracket_id,m.conference,m.round,m.slot,m.team_a,m.team_b,
          m.predicted_winner,m.predicted_winner_games
   FROM public.matches m
   WHERE m.season_id=p_season_id
     AND (m.bracket_id=p_master_id OR m.bracket_id IN (SELECT id FROM eligible))
 )
 SELECT encode(sha256(convert_to(jsonb_build_array(
   p_master_id,
   (SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY id),'[]'::jsonb) FROM eligible b),
   (SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM inputs m)
 )::text,'UTF8')),'hex');
$$;

CREATE FUNCTION public.retire_current_master(p_admin_id uuid,p_season_id uuid,p_expected_master_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
DECLARE selected_id uuid; master_id uuid;
BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_season_id THEN
   RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='PT409';
 END IF;
 PERFORM 1 FROM public.users WHERE id=p_admin_id AND is_admin IS TRUE FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Master operation requires an admin' USING ERRCODE='42501'; END IF;
 SELECT master_bracket_id INTO STRICT master_id FROM public.seasons WHERE id=selected_id FOR UPDATE;
 IF master_id IS NULL OR master_id IS DISTINCT FROM p_expected_master_id THEN
   RAISE EXCEPTION 'Canonical master changed' USING ERRCODE='PT409';
 END IF;
 UPDATE public.brackets SET deleted_at=now(),deleted_by_user_id=p_admin_id
 WHERE id=master_id AND season_id=selected_id AND is_master IS TRUE AND deleted_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Canonical master changed' USING ERRCODE='PT409'; END IF;
 UPDATE public.seasons SET master_bracket_id=NULL,published_score_revision=NULL WHERE id=selected_id;
 RETURN jsonb_build_object('master_bracket_id',master_id,'scoring_status','pending');
END;
$$;

-- Explicit maintenance starts pending even when it is recomputing the same inputs.
CREATE FUNCTION public.begin_current_score_recompute(p_season_id uuid,p_master_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
DECLARE selected_id uuid;
BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_season_id THEN
   RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='PT409';
 END IF;
 UPDATE public.seasons SET published_score_revision=NULL
 WHERE id=selected_id AND master_bracket_id=p_master_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Canonical master changed' USING ERRCODE='PT409'; END IF;
END;
$$;

-- One statement snapshot binds the readiness, scores and matchup labels together.
CREATE FUNCTION public.read_current_score_snapshot(p_season_id uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $$
 WITH state AS MATERIALIZED (
   SELECT s.id,b.id AS master_id, CASE
     WHEN b.id IS NOT NULL AND s.published_score_revision IS NOT NULL
     THEN s.published_score_revision=public.score_input_revision(s.id,b.id)
     ELSE false END AS ready
   FROM public.application_season a
   JOIN public.seasons s ON s.id=a.season_id
   LEFT JOIN public.brackets b ON b.id=s.master_bracket_id AND b.season_id=s.id
       AND b.is_master IS TRUE AND b.deleted_at IS NULL
   WHERE a.singleton AND s.id=p_season_id
 )
 SELECT jsonb_build_object(
   'scoring_status',CASE WHEN ready THEN 'ready' ELSE 'pending' END,
   'master_bracket_id',master_id,
   'scores',CASE WHEN ready THEN (
     SELECT coalesce(jsonb_agg(to_jsonb(sc) ORDER BY sc.bracket_id),'[]'::jsonb)
     FROM public.bracket_scores sc WHERE sc.season_id=state.id AND sc.master_bracket_id=state.master_id
   ) ELSE '[]'::jsonb END,
   'matches',CASE WHEN ready THEN (
     SELECT coalesce(jsonb_agg(jsonb_build_object('conference',m.conference,'round',m.round,
       'slot',m.slot,'team_a',m.team_a,'team_b',m.team_b) ORDER BY m.id),'[]'::jsonb)
     FROM public.matches m WHERE m.bracket_id=state.master_id AND m.season_id=state.id
   ) ELSE '[]'::jsonb END
 ) FROM state;
$$;

CREATE OR REPLACE FUNCTION public.create_master_bracket_atomic(p_user_id uuid, p_season_id uuid, p_replace boolean, p_matches jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE
  old_id uuid;
  new_row public.brackets%ROWTYPE;
  season_row public.seasons%ROWTYPE;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.users WHERE id=p_user_id AND is_admin IS TRUE) THEN
    RAISE EXCEPTION 'Master operation requires an admin' USING ERRCODE='42501';
  END IF;
  IF (SELECT season_id FROM public.application_season WHERE singleton FOR UPDATE) IS DISTINCT FROM p_season_id THEN
    RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='PT409';
  END IF;
  SELECT * INTO STRICT season_row FROM public.seasons WHERE id=p_season_id FOR UPDATE;
  SELECT id INTO old_id FROM public.brackets WHERE season_id=p_season_id AND deleted_at IS NULL
    AND (is_master IS TRUE OR id=season_row.master_bracket_id);
  IF old_id IS NOT NULL AND p_replace IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'Explicit master replacement confirmation required' USING ERRCODE='P0001';
  END IF;
  IF jsonb_typeof(p_matches) IS DISTINCT FROM 'array' OR jsonb_array_length(p_matches)<>21 THEN
    RAISE EXCEPTION 'Invalid master match graph';
  END IF;
  IF old_id IS NOT NULL THEN
    UPDATE public.brackets SET deleted_at=now(),deleted_by_user_id=p_user_id WHERE id=old_id;
  END IF;
  INSERT INTO public.brackets(user_id,season_id,is_master) VALUES(p_user_id,p_season_id,true) RETURNING * INTO new_row;
  INSERT INTO public.matches(id,bracket_id,conference,round,slot,team_a,team_b,next_match_id,next_slot)
    SELECT x.id,new_row.id,x.conference,x.round,x.slot,x.team_a,x.team_b,x.next_match_id,x.next_slot
    FROM jsonb_to_recordset(p_matches) AS x(id uuid,conference text,round integer,slot integer,team_a text,team_b text,next_match_id uuid,next_slot text);
  UPDATE public.seasons SET master_bracket_id=new_row.id, published_score_revision=NULL WHERE id=p_season_id;
  RETURN to_jsonb(new_row);
END;
$body$;

CREATE OR REPLACE FUNCTION public.publish_current_bracket_scores(p_season_id uuid,p_master_id uuid,p_source jsonb,p_rows jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE selected_id uuid; selected_master uuid; source_now jsonb; source_expected jsonb; old_scores jsonb; normalized_rows jsonb; revision text; row_count integer; BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_season_id THEN RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='40001'; END IF;
 SELECT master_bracket_id INTO STRICT selected_master FROM public.seasons WHERE id=selected_id FOR UPDATE;
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
 revision:=public.score_input_revision(selected_id,selected_master);
 -- This update and the complete scores publish (including unchanged rows) commit together.
 UPDATE public.seasons SET published_score_revision=revision
 WHERE id=selected_id AND published_score_revision IS DISTINCT FROM revision;
 IF old_scores=normalized_rows THEN RETURN jsonb_build_object('state','unchanged','master_bracket_id',selected_master,'season_id',selected_id,'updated_brackets',row_count,'written_rows',0); END IF;
 DELETE FROM public.bracket_scores WHERE season_id=selected_id;
 INSERT INTO public.bracket_scores(bracket_id,master_bracket_id,season_id,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,points_by_round,points_by_match)
 SELECT x.bracket_id,x.master_bracket_id,x.season_id,x.total_points,x.full_hits,x.partial_hits,x.misses,x.bonus_finalists,x.bonus_champion,x.points_by_round,x.points_by_match
 FROM jsonb_to_recordset(p_rows) AS x(bracket_id uuid,master_bracket_id uuid,season_id uuid,total_points integer,full_hits integer,partial_hits integer,misses integer,bonus_finalists integer,bonus_champion integer,points_by_round jsonb,points_by_match jsonb);
 RETURN jsonb_build_object('state','published','master_bracket_id',selected_master,'season_id',selected_id,'updated_brackets',row_count,'written_rows',row_count);
END;
$body$;

REVOKE ALL ON FUNCTION public.score_input_revision(uuid,uuid),
 public.retire_current_master(uuid,uuid,uuid),public.begin_current_score_recompute(uuid,uuid),
 public.read_current_score_snapshot(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.score_input_revision(uuid,uuid),
 public.retire_current_master(uuid,uuid,uuid),public.begin_current_score_recompute(uuid,uuid),
 public.read_current_score_snapshot(uuid) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
