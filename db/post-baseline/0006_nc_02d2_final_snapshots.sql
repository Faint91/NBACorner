-- Forward-only final snapshot publication. Existing historical values are untouched.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
ALTER TABLE public.leaderboard_history_snapshots
 ADD COLUMN expected_rows integer, ADD COLUMN is_final boolean, ADD COLUMN master_bracket_id uuid;
ALTER TABLE public.leaderboard_history_rows
 ADD COLUMN saved_at timestamptz, ADD COLUMN display_order integer,
 ADD COLUMN base_points integer, ADD COLUMN points_by_round jsonb;
CREATE UNIQUE INDEX nc_d2_one_final_snapshot ON public.leaderboard_history_snapshots(season_id) WHERE is_final IS TRUE;
CREATE UNIQUE INDEX nc_d2_snapshot_display_order ON public.leaderboard_history_rows(snapshot_id,display_order);

CREATE FUNCTION public.protect_final_leaderboard_history() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE frozen boolean; BEGIN
 IF TG_OP='TRUNCATE' THEN
  -- Owner-only administrative reset is not an application mutation capability.
  IF current_user<>'postgres' THEN RAISE EXCEPTION 'Historical snapshots are immutable'; END IF;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME='leaderboard_history_snapshots' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.is_final IS TRUE THEN RAISE EXCEPTION 'Final snapshots require atomic publication'; END IF;
   RETURN NEW;
  END IF;
  IF OLD.is_final IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'Historical snapshots are immutable'; END IF;
  IF TG_OP='UPDATE' AND NEW.is_final IS TRUE THEN
   IF NEW.expected_rows IS NULL OR NEW.expected_rows<0 OR NEW.master_bracket_id IS NULL
    OR (SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=NEW.id)<>NEW.expected_rows
    THEN RAISE EXCEPTION 'Incomplete structured snapshot'; END IF;
  END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN
   SELECT is_final INTO frozen FROM public.leaderboard_history_snapshots WHERE id=OLD.snapshot_id;
   IF frozen IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'Historical snapshots are immutable'; END IF;
  END IF;
  IF TG_OP<>'DELETE' THEN
   SELECT is_final INTO frozen FROM public.leaderboard_history_snapshots WHERE id=NEW.snapshot_id FOR SHARE;
   IF frozen IS TRUE THEN RAISE EXCEPTION 'Historical snapshots are immutable'; END IF;
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END;
$body$;
CREATE TRIGGER nc_d2_immutable_header BEFORE INSERT OR UPDATE OR DELETE ON public.leaderboard_history_snapshots FOR EACH ROW EXECUTE FUNCTION public.protect_final_leaderboard_history();
CREATE TRIGGER nc_d2_immutable_rows BEFORE INSERT OR UPDATE OR DELETE ON public.leaderboard_history_rows FOR EACH ROW EXECUTE FUNCTION public.protect_final_leaderboard_history();
CREATE TRIGGER nc_d2_no_app_truncate BEFORE TRUNCATE ON public.leaderboard_history_snapshots FOR EACH STATEMENT EXECUTE FUNCTION public.protect_final_leaderboard_history();
CREATE TRIGGER nc_d2_no_app_truncate BEFORE TRUNCATE ON public.leaderboard_history_rows FOR EACH STATEMENT EXECUTE FUNCTION public.protect_final_leaderboard_history();

CREATE FUNCTION public.publish_leaderboard_snapshot(p_season_id uuid,p_master_id uuid,p_source jsonb,p_scores jsonb,p_rows jsonb,p_columns jsonb,p_created_by uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE evaluation jsonb; header public.leaderboard_history_snapshots; row_count integer; actual_count integer; source_ids jsonb; payload_ids jsonb; BEGIN
 -- Reuse D1's complete eligibility/canonical/source validation and transaction locks.
 -- Any attempted repair here rolls back; only the successfully recomputed state is accepted.
 evaluation:=public.publish_current_bracket_scores(p_season_id,p_master_id,p_source,p_scores);
 IF (evaluation->>'written_rows')::integer<>0 THEN RAISE EXCEPTION 'Recomputed score state changed' USING ERRCODE='40001'; END IF;
 SELECT * INTO header FROM public.leaderboard_history_snapshots WHERE season_id=p_season_id AND is_final IS TRUE;
 IF FOUND THEN
  SELECT count(*) INTO actual_count FROM public.leaderboard_history_rows WHERE snapshot_id=header.id;
  IF header.expected_rows IS NULL OR actual_count<>header.expected_rows THEN RAISE EXCEPTION 'Existing final snapshot incomplete'; END IF;
  RETURN jsonb_build_object('state','existing','snapshot_id',header.id,'season_id',header.season_id,'season_code',header.season_code,'expected_rows',header.expected_rows,'actual_rows',actual_count,'is_final',true);
 END IF;
 IF EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots WHERE season_id=p_season_id) THEN RAISE EXCEPTION 'Existing unverified history requires review'; END IF;
 IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' OR jsonb_typeof(p_columns) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid structured snapshot payload'; END IF;
 row_count:=jsonb_array_length(p_scores);
 IF jsonb_array_length(p_rows)<>row_count THEN RAISE EXCEPTION 'Incomplete snapshot payload'; END IF;
 SELECT coalesce(jsonb_agg((r->>'bracket_id')::uuid ORDER BY (r->>'bracket_id')::uuid),'[]'::jsonb) INTO source_ids FROM jsonb_array_elements(p_scores) r;
 SELECT coalesce(jsonb_agg((r->>'bracket_id')::uuid ORDER BY (r->>'bracket_id')::uuid),'[]'::jsonb) INTO payload_ids FROM jsonb_array_elements(p_rows) r;
 IF source_ids IS DISTINCT FROM payload_ids THEN RAISE EXCEPTION 'Snapshot competitor mismatch'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) WITH ORDINALITY AS x(r,n) WHERE
  (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(r) k) IS DISTINCT FROM ARRAY['base_points','bonus_champion','bonus_finalists','bracket_id','display_name','display_order','full_hits','misses','partial_hits','per_match_points','points_by_round','rank','saved_at','total_points']::text[]
  OR jsonb_typeof(r->'display_name') IS DISTINCT FROM 'string' OR (r->>'display_order')::integer IS DISTINCT FROM n
  OR jsonb_typeof(r->'per_match_points') IS DISTINCT FROM 'object'
  OR EXISTS(SELECT 1 FROM jsonb_each(r->'per_match_points') q WHERE jsonb_typeof(q.value) IS DISTINCT FROM 'number')
 ) THEN RAISE EXCEPTION 'Invalid frozen row'; END IF;
 IF EXISTS(
  SELECT 1 FROM jsonb_to_recordset(p_rows) AS r(bracket_id uuid,rank integer,saved_at timestamptz,total_points integer,full_hits integer,partial_hits integer,misses integer,bonus_finalists integer,bonus_champion integer,points_by_round jsonb,base_points integer,per_match_points jsonb)
  JOIN public.brackets b ON b.id=r.bracket_id JOIN public.bracket_scores s ON s.bracket_id=r.bracket_id
  WHERE r.saved_at IS DISTINCT FROM b.saved_at OR r.total_points IS DISTINCT FROM s.total_points OR r.full_hits IS DISTINCT FROM s.full_hits
   OR r.partial_hits IS DISTINCT FROM s.partial_hits OR r.misses IS DISTINCT FROM s.misses OR r.bonus_finalists IS DISTINCT FROM s.bonus_finalists OR r.bonus_champion IS DISTINCT FROM s.bonus_champion
   OR r.points_by_round IS DISTINCT FROM s.points_by_round
   OR r.base_points IS DISTINCT FROM coalesce((SELECT sum((v.value::text)::integer) FROM jsonb_each(s.points_by_round) v),0)
   OR r.per_match_points IS DISTINCT FROM (SELECT coalesce(jsonb_object_agg(k.key,k.value->'points'),'{}'::jsonb) FROM jsonb_each(s.points_by_match) k)
 ) THEN RAISE EXCEPTION 'Snapshot score/source mismatch'; END IF;
 IF EXISTS(SELECT 1 FROM (
  SELECT r.*, rank() OVER(ORDER BY total_points DESC,full_hits DESC,saved_at ASC) AS required_rank
  FROM jsonb_to_recordset(p_rows) AS r(rank integer,total_points integer,full_hits integer,saved_at timestamptz,display_order integer)
 ) x WHERE rank IS DISTINCT FROM required_rank) OR EXISTS(
  SELECT 1 FROM (SELECT (r->>'rank')::integer AS rank,lag((r->>'rank')::integer) OVER(ORDER BY n) AS prior FROM jsonb_array_elements(p_rows) WITH ORDINALITY AS a(r,n)) x WHERE prior>rank
 ) THEN RAISE EXCEPTION 'Invalid competition rank/order'; END IF;
 INSERT INTO public.leaderboard_history_snapshots(season_id,season_code,columns,created_by,expected_rows,is_final,master_bracket_id)
 SELECT p_season_id,code,p_columns,p_created_by,row_count,false,p_master_id FROM public.seasons WHERE id=p_season_id RETURNING * INTO STRICT header;
 INSERT INTO public.leaderboard_history_rows(snapshot_id,rank,display_name,total_points,bonus_finalists,bonus_champion,full_hits,partial_hits,misses,per_match_points,saved_at,display_order,base_points,points_by_round)
 SELECT header.id,x.rank,x.display_name,x.total_points,x.bonus_finalists,x.bonus_champion,x.full_hits,x.partial_hits,x.misses,x.per_match_points,x.saved_at,x.display_order,x.base_points,x.points_by_round
 FROM jsonb_to_recordset(p_rows) AS x(rank integer,display_name text,total_points integer,bonus_finalists integer,bonus_champion integer,full_hits integer,partial_hits integer,misses integer,per_match_points jsonb,saved_at timestamptz,display_order integer,base_points integer,points_by_round jsonb);
 UPDATE public.leaderboard_history_snapshots SET is_final=true WHERE id=header.id;
 SELECT count(*) INTO actual_count FROM public.leaderboard_history_rows WHERE snapshot_id=header.id;
 IF actual_count<>row_count THEN RAISE EXCEPTION 'Snapshot row verification failed'; END IF;
 RETURN jsonb_build_object('state','created','snapshot_id',header.id,'season_id',header.season_id,'season_code',header.season_code,'expected_rows',row_count,'actual_rows',actual_count,'is_final',true);
END;
$body$;
ALTER FUNCTION public.protect_final_leaderboard_history() OWNER TO postgres;
ALTER FUNCTION public.publish_leaderboard_snapshot(uuid,uuid,jsonb,jsonb,jsonb,jsonb,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.protect_final_leaderboard_history(),public.publish_leaderboard_snapshot(uuid,uuid,jsonb,jsonb,jsonb,jsonb,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.protect_final_leaderboard_history(),public.publish_leaderboard_snapshot(uuid,uuid,jsonb,jsonb,jsonb,jsonb,uuid) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
