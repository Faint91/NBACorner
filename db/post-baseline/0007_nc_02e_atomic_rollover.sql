-- NC-02E: trusted explicit rollover. No scheduler or production target.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE TABLE public.season_rollover_audits (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 source_season_id uuid REFERENCES public.seasons(id), source_code text,
 target_season_id uuid REFERENCES public.seasons(id), target_code text NOT NULL,
 snapshot_id uuid REFERENCES public.leaderboard_history_snapshots(id),
 requested_by_user_id uuid NOT NULL REFERENCES public.users(id),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 status text NOT NULL CHECK(status IN ('STARTED','FAILED','COMPLETED')),
 failure_stage text, sanitized_message text, legacy_warning boolean NOT NULL DEFAULT false,
 CHECK ((status='STARTED' AND completed_at IS NULL) OR (status<>'STARTED' AND completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX nc_e_one_completed_transition ON public.season_rollover_audits(source_season_id,target_code) WHERE status='COMPLETED';
ALTER TABLE public.season_rollover_audits OWNER TO postgres;
ALTER TABLE public.season_rollover_audits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.season_rollover_audits FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.season_rollover_audits TO service_role;

CREATE FUNCTION public.require_completed_rollover_master(p_source uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE mid uuid; m public.matches; d public.matches; expected_slot integer; expected_side text; conf text;
BEGIN
 SELECT master_bracket_id INTO STRICT mid FROM public.seasons WHERE id=p_source FOR SHARE;
 IF mid IS NULL OR NOT EXISTS(SELECT 1 FROM public.brackets WHERE id=mid AND season_id=p_source AND is_master IS TRUE AND deleted_at IS NULL) THEN RAISE EXCEPTION 'Invalid canonical master'; END IF;
 IF (SELECT count(*) FROM public.matches WHERE bracket_id=mid)<>21 THEN RAISE EXCEPTION 'Master graph incomplete'; END IF;
 -- Exact topology is authoritative, not a saved flag or a guessed calendar date.
 FOR m IN SELECT * FROM public.matches WHERE bracket_id=mid LOOP
  IF m.season_id IS DISTINCT FROM p_source OR NOT (
    (m.conference IN ('east','west') AND ((m.round=0 AND m.slot IN (1,2,3)) OR (m.round=1 AND m.slot IN (4,5,6,7)) OR (m.round=2 AND m.slot IN (8,9)) OR (m.round=3 AND m.slot=10)))
    OR (m.conference='nba' AND m.round=4 AND m.slot=11))
   OR m.team_a IS NULL OR m.team_b IS NULL OR m.team_a=m.team_b
   OR m.predicted_winner IS NULL OR m.predicted_winner NOT IN (m.team_a,m.team_b)
   OR m.predicted_winner_games IS NULL
   OR (m.round=0 AND m.predicted_winner_games<>1)
   OR (m.round>0 AND m.predicted_winner_games NOT IN (4,5,6,7))
  THEN RAISE EXCEPTION 'Master results incomplete or invalid'; END IF;
  IF (SELECT count(*) FROM public.matches WHERE bracket_id=mid AND conference=m.conference AND round=m.round AND slot=m.slot)<>1 THEN RAISE EXCEPTION 'Duplicate master coordinate'; END IF;
  IF m.round=4 THEN
   IF m.next_match_id IS NOT NULL THEN RAISE EXCEPTION 'Invalid Finals edge'; END IF;
   CONTINUE;
  END IF;
  expected_slot:=CASE m.slot WHEN 1 THEN 3 WHEN 2 THEN 5 WHEN 3 THEN 4 WHEN 4 THEN 9 WHEN 5 THEN 8 WHEN 6 THEN 8 WHEN 7 THEN 9 WHEN 8 THEN 10 WHEN 9 THEN 10 WHEN 10 THEN 11 END;
  expected_side:=CASE m.slot WHEN 1 THEN 'a' WHEN 2 THEN 'b' WHEN 3 THEN 'b' WHEN 4 THEN 'a' WHEN 5 THEN 'b' WHEN 6 THEN 'a' WHEN 7 THEN 'b' WHEN 8 THEN 'b' WHEN 9 THEN 'a' WHEN 10 THEN CASE m.conference WHEN 'east' THEN 'a' ELSE 'b' END END;
  SELECT * INTO d FROM public.matches WHERE id=m.next_match_id AND bracket_id=mid;
  IF NOT FOUND OR d.slot IS DISTINCT FROM expected_slot OR m.next_slot IS DISTINCT FROM expected_side
   OR d.conference IS DISTINCT FROM (CASE WHEN m.round=3 THEN 'nba' ELSE m.conference END)
   OR (CASE expected_side WHEN 'a' THEN d.team_a ELSE d.team_b END) IS DISTINCT FROM m.predicted_winner
  THEN RAISE EXCEPTION 'Invalid master dependency'; END IF;
  IF m.slot=2 THEN
   IF NOT EXISTS(SELECT 1 FROM public.matches WHERE bracket_id=mid AND conference=m.conference AND slot=3 AND round=0 AND team_b=CASE WHEN m.predicted_winner=m.team_a THEN m.team_b ELSE m.team_a END) THEN RAISE EXCEPTION 'Invalid play-in loser feed'; END IF;
  END IF;
 END LOOP;
 RETURN mid;
END;
$body$;

-- Narrow post-snapshot transition; never publishes a snapshot.
CREATE FUNCTION public.execute_season_rollover_transition(p_audit uuid,p_source uuid,p_snapshot uuid,p_target text,p_opening timestamptz,p_lock timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE selected uuid; header public.leaderboard_history_snapshots; target_id uuid; saved_count integer; deleted_count integer; mid uuid; start_year integer;
BEGIN
 IF NOT pg_try_advisory_xact_lock(50405,2) THEN RAISE EXCEPTION 'Rollover busy' USING ERRCODE='55P03'; END IF;
 SELECT season_id INTO STRICT selected FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected IS DISTINCT FROM p_source THEN RAISE EXCEPTION 'Canonical source changed'; END IF;
 LOCK TABLE public.brackets,public.matches IN SHARE ROW EXCLUSIVE MODE;
 mid:=public.require_completed_rollover_master(p_source);
 SELECT * INTO STRICT header FROM public.leaderboard_history_snapshots WHERE id=p_snapshot AND season_id=p_source;
 IF header.is_final IS DISTINCT FROM true OR header.master_bracket_id IS DISTINCT FROM mid OR header.expected_rows IS NULL OR header.expected_rows<0 OR (SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=p_snapshot)<>header.expected_rows THEN RAISE EXCEPTION 'Unverified final snapshot'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.season_rollover_audits WHERE id=p_audit AND source_season_id=p_source AND snapshot_id=p_snapshot AND target_code=p_target AND status='STARTED') THEN RAISE EXCEPTION 'Invalid audit fence'; END IF;
 SELECT left(code,4)::integer INTO STRICT start_year FROM public.seasons WHERE id=p_source;
 IF p_target IS DISTINCT FROM (start_year+1)::text||'-'||lpad(((start_year+2)%100)::text,2,'0') OR p_opening IS NULL OR p_lock IS NULL OR NOT isfinite(p_opening) OR NOT isfinite(p_lock) OR p_opening>=p_lock THEN RAISE EXCEPTION 'Invalid next season'; END IF;
 -- A legitimate saved bracket remains nondeleted, with its original graph/time.
 -- Season relationship alone retires it from every canonical current consumer.
 SELECT count(*) INTO saved_count FROM public.brackets WHERE season_id=p_source AND is_done IS TRUE AND deleted_at IS NULL AND saved_at IS NOT NULL AND isfinite(saved_at);
 DELETE FROM public.bracket_scores WHERE season_id=p_source;
 -- Legacy has optional non-FK IDs: remove only references to physically deleted drafts.
 DELETE FROM public.leaderboard_history h USING public.brackets b WHERE h.bracket_id=b.id AND b.season_id=p_source AND NOT (b.is_done IS TRUE AND b.deleted_at IS NULL AND b.saved_at IS NOT NULL AND isfinite(b.saved_at));
 DELETE FROM public.brackets WHERE season_id=p_source AND NOT (is_done IS TRUE AND deleted_at IS NULL AND saved_at IS NOT NULL AND isfinite(saved_at));
 GET DIAGNOSTICS deleted_count=ROW_COUNT;
 -- Matches/scores cascade for drafts. Saved match graphs are deliberately retained.
 INSERT INTO public.seasons(code,regular_season_end_utc,playoffs_start_utc) VALUES(p_target,p_opening,p_lock) RETURNING id INTO target_id;
 PERFORM public.finalize_season_transition(p_source,target_id,p_target);
 UPDATE public.season_rollover_audits SET target_season_id=target_id,status='COMPLETED',completed_at=clock_timestamp(),failure_stage=NULL,sanitized_message='Atomic rollover completed' WHERE id=p_audit;
 RETURN jsonb_build_object('ok',true,'status',200,'state','completed','audit_id',p_audit,'saved_brackets',saved_count,'deleted_unsaved_brackets',deleted_count,'current_season',jsonb_build_object('id',p_source,'code',header.season_code),'new_season',jsonb_build_object('id',target_id,'code',p_target));
END;
$body$;

-- One critical lock. Nested rollback scopes keep failed preparation invisible and
-- keep the finalized snapshot/audit when destructive transition is rolled back.
CREATE FUNCTION public.run_season_rollover(p_target_code text,p_opening timestamptz,p_lock timestamptz,p_admin uuid,p_prepared jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE source_id uuid; source_code text; mid uuid; audit_id uuid; prior public.season_rollover_audits; final jsonb; result jsonb; stage text:='prerequisite'; start_year integer;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.users WHERE id=p_admin AND is_admin IS TRUE) THEN RETURN jsonb_build_object('ok',false,'state','failed','status',403,'stage','authorization','error','Forbidden'); END IF;
 IF NOT pg_try_advisory_xact_lock(50405,2) THEN RETURN jsonb_build_object('ok',false,'state','busy','status',409,'stage','lock','error','Rollover already in progress'); END IF;
 SELECT season_id INTO source_id FROM public.application_season WHERE singleton FOR UPDATE;
 SELECT * INTO prior FROM public.season_rollover_audits WHERE target_code=p_target_code AND status='COMPLETED';
 IF FOUND THEN
  IF prior.target_season_id=source_id THEN RETURN jsonb_build_object('ok',true,'state','already_completed','status',200,'audit_id',prior.id,'new_season',jsonb_build_object('id',prior.target_season_id,'code',prior.target_code)); END IF;
  RETURN jsonb_build_object('ok',false,'state','failed','status',409,'stage','conflict','audit_id',prior.id,'error','Transition already completed; current season differs');
 END IF;
 SELECT code INTO source_code FROM public.seasons WHERE id=source_id;
 INSERT INTO public.season_rollover_audits(source_season_id,source_code,target_code,requested_by_user_id,status) VALUES(source_id,source_code,coalesce(p_target_code,''),p_admin,'STARTED') RETURNING id INTO audit_id;
 BEGIN
  IF source_id IS NULL OR source_code !~ '^[0-9]{4}-[0-9]{2}$' OR right(source_code,2)::integer<>(left(source_code,4)::integer+1)%100 THEN RAISE EXCEPTION 'Invalid canonical season'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.seasons WHERE id=source_id AND regular_season_end_utc IS NOT NULL AND playoffs_start_utc IS NOT NULL AND isfinite(regular_season_end_utc) AND isfinite(playoffs_start_utc) AND regular_season_end_utc<=playoffs_start_utc) THEN RAISE EXCEPTION 'Invalid canonical timing'; END IF;
  start_year:=left(source_code,4)::integer;
  IF p_target_code IS DISTINCT FROM (start_year+1)::text||'-'||lpad(((start_year+2)%100)::text,2,'0') OR p_opening IS NULL OR p_lock IS NULL OR NOT isfinite(p_opening) OR NOT isfinite(p_lock) OR p_opening>=p_lock OR EXISTS(SELECT 1 FROM public.seasons WHERE code=p_target_code) THEN RAISE EXCEPTION 'Invalid immediate target or timing'; END IF;
  LOCK TABLE public.brackets,public.matches IN SHARE ROW EXCLUSIVE MODE;
  mid:=public.require_completed_rollover_master(source_id);
  stage:='recompute';
  IF p_prepared IS NULL OR (p_prepared->>'source_id')::uuid IS DISTINCT FROM source_id OR (p_prepared->>'master_id')::uuid IS DISTINCT FROM mid THEN RAISE EXCEPTION 'Successful canonical evaluation required'; END IF;
  PERFORM public.publish_current_bracket_scores(source_id,mid,p_prepared->'source',p_prepared->'scores');
  stage:='snapshot';
  final:=public.publish_leaderboard_snapshot(source_id,mid,p_prepared->'source',p_prepared->'scores',p_prepared->'rows',p_prepared->'columns',p_admin);
  IF (final->>'is_final')::boolean IS DISTINCT FROM true OR (final->>'expected_rows')::integer IS DISTINCT FROM (final->>'actual_rows')::integer THEN RAISE EXCEPTION 'Snapshot verification failed'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots WHERE id=(final->>'snapshot_id')::uuid AND season_id=source_id AND season_code=source_code AND master_bracket_id=mid AND is_final IS TRUE AND expected_rows>=0 AND expected_rows=(SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=(final->>'snapshot_id')::uuid)) THEN RAISE EXCEPTION 'Snapshot identity verification failed'; END IF;
 EXCEPTION WHEN OTHERS THEN
  UPDATE public.season_rollover_audits SET status='FAILED',completed_at=clock_timestamp(),failure_stage=stage,sanitized_message='Rollover preparation refused; current competition unchanged' WHERE id=audit_id;
  RETURN jsonb_build_object('ok',false,'state','failed','status',409,'stage',stage,'audit_id',audit_id,'error','Rollover preparation refused; current competition unchanged');
 END;
 UPDATE public.season_rollover_audits SET snapshot_id=(final->>'snapshot_id')::uuid WHERE id=audit_id;
 -- Optional compatibility only, after authoritative immutable preservation.
 BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.leaderboard_history WHERE season_id=source_id) THEN
   INSERT INTO public.leaderboard_history(season_id,season_code,rank,bracket_name,username,bracket_id,user_id,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,points_by_match)
   SELECT source_id,source_code,r.rank,b.name,u.username,b.id,b.user_id,r.total_points,r.full_hits,r.partial_hits,r.misses,r.bonus_finalists,r.bonus_champion,s.points_by_match
   FROM jsonb_to_recordset(p_prepared->'rows') AS r(bracket_id uuid,rank integer,total_points integer,full_hits integer,partial_hits integer,misses integer,bonus_finalists integer,bonus_champion integer)
   JOIN public.brackets b ON b.id=r.bracket_id JOIN public.users u ON u.id=b.user_id JOIN public.bracket_scores s ON s.bracket_id=b.id;
  END IF;
 EXCEPTION WHEN OTHERS THEN
  UPDATE public.season_rollover_audits SET legacy_warning=true WHERE id=audit_id;
 END;
 BEGIN
  result:=public.execute_season_rollover_transition(audit_id,source_id,(final->>'snapshot_id')::uuid,p_target_code,p_opening,p_lock);
 EXCEPTION WHEN OTHERS THEN
  UPDATE public.season_rollover_audits SET status='FAILED',completed_at=clock_timestamp(),failure_stage='transition',sanitized_message='Atomic transition rolled back; final snapshot preserved' WHERE id=audit_id;
  RETURN jsonb_build_object('ok',false,'state','failed','status',503,'stage','transition','audit_id',audit_id,'error','Atomic transition rolled back; final snapshot preserved');
 END;
 RETURN result||jsonb_build_object('snapshot_id',final->>'snapshot_id','legacy_warning',(SELECT legacy_warning FROM public.season_rollover_audits WHERE id=audit_id));
END;
$body$;
ALTER FUNCTION public.require_completed_rollover_master(uuid) OWNER TO postgres;
ALTER FUNCTION public.execute_season_rollover_transition(uuid,uuid,uuid,text,timestamptz,timestamptz) OWNER TO postgres;
ALTER FUNCTION public.run_season_rollover(text,timestamptz,timestamptz,uuid,jsonb) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.require_completed_rollover_master(uuid), public.execute_season_rollover_transition(uuid,uuid,uuid,text,timestamptz,timestamptz),public.run_season_rollover(text,timestamptz,timestamptz,uuid,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.require_completed_rollover_master(uuid), public.execute_season_rollover_transition(uuid,uuid,uuid,text,timestamptz,timestamptz),public.run_season_rollover(text,timestamptz,timestamptz,uuid,jsonb) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
