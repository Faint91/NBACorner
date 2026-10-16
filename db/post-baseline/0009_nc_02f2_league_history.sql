-- NC-02F2: new preservation only. No backfill or changes to stored global scores/ranks.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE TABLE public.leaderboard_history_competitors (
 snapshot_row_id uuid PRIMARY KEY REFERENCES public.leaderboard_history_rows(id) ON DELETE CASCADE,
 user_id uuid NOT NULL
);
-- A non-identifying all-league receipt also freezes a legitimate empty cutoff.
-- Counts describe the original atomic publication; approved whole-league deletion
-- can later remove league-specific records without rewriting this receipt.
CREATE TABLE public.league_history_cutoffs (
 global_snapshot_id uuid PRIMARY KEY REFERENCES public.leaderboard_history_snapshots(id),
 expected_leagues integer NOT NULL CHECK(expected_leagues>=0),
 expected_rows integer NOT NULL CHECK(expected_rows>=0),
 finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 is_final boolean NOT NULL DEFAULT false
);
CREATE TABLE public.league_history_seasons (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 league_id uuid NOT NULL REFERENCES public.leagues(id) ON DELETE CASCADE,
 season_id uuid NOT NULL REFERENCES public.seasons(id),
 global_snapshot_id uuid NOT NULL REFERENCES public.league_history_cutoffs(global_snapshot_id),
 expected_rows integer NOT NULL CHECK(expected_rows>0),
 finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 is_final boolean NOT NULL DEFAULT false,
 UNIQUE(league_id,season_id)
);
CREATE TABLE public.league_history_rows (
 history_season_id uuid NOT NULL REFERENCES public.league_history_seasons(id) ON DELETE CASCADE,
 global_snapshot_row_id uuid NOT NULL REFERENCES public.leaderboard_history_competitors(snapshot_row_id),
 rank integer NOT NULL CHECK(rank>0),
 display_order integer NOT NULL CHECK(display_order>0),
 PRIMARY KEY(history_season_id,global_snapshot_row_id),
 UNIQUE(history_season_id,display_order)
);

CREATE FUNCTION public.lock_league_history_membership() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
BEGIN
 -- F1 already locks the parent; this also fences trusted direct membership SQL.
 IF TG_OP='INSERT' THEN PERFORM id FROM public.leagues WHERE id=NEW.league_id FOR UPDATE;
 ELSIF TG_OP='DELETE' THEN PERFORM id FROM public.leagues WHERE id=OLD.league_id FOR UPDATE;
 ELSE PERFORM id FROM public.leagues WHERE id IN(OLD.league_id,NEW.league_id) ORDER BY id FOR UPDATE;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END;
$body$;
CREATE TRIGGER nc_f2_membership_cutoff BEFORE INSERT OR UPDATE OR DELETE ON public.league_members FOR EACH ROW EXECUTE FUNCTION public.lock_league_history_membership();

CREATE FUNCTION public.verify_league_history_cutoff(p_source uuid,p_snapshot uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE receipt public.league_history_cutoffs; h public.leaderboard_history_snapshots; s public.league_history_seasons;
BEGIN
 SELECT * INTO STRICT h FROM public.leaderboard_history_snapshots WHERE id=p_snapshot AND season_id=p_source;
 IF h.is_final IS DISTINCT FROM true OR h.expected_rows IS NULL OR h.expected_rows<0 OR h.expected_rows<>(SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=h.id) THEN RAISE EXCEPTION 'Unverified global source'; END IF;
 IF h.expected_rows<>(SELECT count(*) FROM public.leaderboard_history_competitors m JOIN public.leaderboard_history_rows g ON g.id=m.snapshot_row_id WHERE g.snapshot_id=h.id)
 OR h.expected_rows<>(SELECT count(DISTINCT m.user_id) FROM public.leaderboard_history_competitors m JOIN public.leaderboard_history_rows g ON g.id=m.snapshot_row_id WHERE g.snapshot_id=h.id) THEN RAISE EXCEPTION 'Internal final competitor mapping unavailable; review required'; END IF;
 SELECT * INTO STRICT receipt FROM public.league_history_cutoffs WHERE global_snapshot_id=h.id AND is_final IS TRUE;
 FOR s IN SELECT * FROM public.league_history_seasons WHERE global_snapshot_id=h.id LOOP
  IF s.is_final IS DISTINCT FROM true OR s.season_id<>h.season_id OR s.expected_rows<>(SELECT count(*) FROM public.league_history_rows WHERE history_season_id=s.id) THEN RAISE EXCEPTION 'Incomplete league history'; END IF;
  IF EXISTS(SELECT 1 FROM public.league_history_rows l JOIN public.leaderboard_history_rows g ON g.id=l.global_snapshot_row_id WHERE l.history_season_id=s.id AND g.snapshot_id<>h.id) THEN RAISE EXCEPTION 'Conflicting league history source'; END IF;
  IF EXISTS(SELECT 1 FROM (
   SELECT l.rank,l.display_order,rank() OVER(ORDER BY g.total_points DESC,g.full_hits DESC,g.saved_at ASC) AS required_rank,
    row_number() OVER(ORDER BY g.total_points DESC,g.full_hits DESC,g.saved_at ASC,g.display_name COLLATE "C",g.display_order,g.id) AS required_order
   FROM public.league_history_rows l JOIN public.leaderboard_history_rows g ON g.id=l.global_snapshot_row_id WHERE l.history_season_id=s.id
  ) q WHERE q.rank<>q.required_rank OR q.display_order<>q.required_order) THEN RAISE EXCEPTION 'Conflicting league rank/order'; END IF;
 END LOOP;
 -- No current membership comparison: approved later joins/leaves/deletion must
 -- not redefine the completed cutoff. Protected final receipt proves all-or-none.
 RETURN jsonb_build_object('state','verified','snapshot_id',h.id,'expected_leagues',receipt.expected_leagues,'expected_rows',receipt.expected_rows);
END;
$body$;

CREATE FUNCTION public.protect_league_history() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE h public.league_history_seasons; g public.leaderboard_history_rows; final_state boolean;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF current_user<>'postgres' THEN RAISE EXCEPTION 'League history is immutable'; END IF;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME='leaderboard_history_competitors' THEN
  IF TG_OP='DELETE' AND NOT EXISTS(SELECT 1 FROM public.leaderboard_history_rows WHERE id=OLD.snapshot_row_id) THEN RETURN OLD; END IF;
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Final competitor mapping is immutable'; END IF;
  SELECT * INTO STRICT g FROM public.leaderboard_history_rows WHERE id=NEW.snapshot_row_id;
  IF (SELECT is_final FROM public.leaderboard_history_snapshots WHERE id=g.snapshot_id) IS DISTINCT FROM false THEN RAISE EXCEPTION 'No mapping backfill into final global history'; END IF;
 ELSIF TG_TABLE_NAME='league_history_cutoffs' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.is_final OR NOT EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots WHERE id=NEW.global_snapshot_id AND is_final IS TRUE) THEN RAISE EXCEPTION 'Cutoff requires verified final source and atomic publication'; END IF;
  ELSIF TG_OP='UPDATE' THEN
   IF OLD.is_final OR NEW.is_final IS DISTINCT FROM true OR (to_jsonb(NEW)-'is_final') IS DISTINCT FROM (to_jsonb(OLD)-'is_final') THEN RAISE EXCEPTION 'League cutoff is immutable'; END IF;
   IF NEW.expected_leagues<>(SELECT count(*) FROM public.league_history_seasons WHERE global_snapshot_id=NEW.global_snapshot_id AND is_final IS TRUE)
    OR EXISTS(SELECT 1 FROM public.league_history_seasons WHERE global_snapshot_id=NEW.global_snapshot_id AND is_final IS NOT TRUE)
    OR NEW.expected_rows<>(SELECT count(*) FROM public.league_history_rows r JOIN public.league_history_seasons s ON s.id=r.history_season_id WHERE s.global_snapshot_id=NEW.global_snapshot_id) THEN RAISE EXCEPTION 'Incomplete all-league cutoff'; END IF;
  ELSE RAISE EXCEPTION 'League cutoff is immutable'; END IF;
 ELSIF TG_TABLE_NAME='league_history_seasons' THEN
  IF TG_OP='DELETE' THEN
   IF NOT EXISTS(SELECT 1 FROM public.leagues WHERE id=OLD.league_id) THEN RETURN OLD; END IF;
   RAISE EXCEPTION 'Only whole-league deletion may remove history';
  END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.is_final OR (SELECT is_final FROM public.league_history_cutoffs WHERE global_snapshot_id=NEW.global_snapshot_id) IS DISTINCT FROM false
    OR NOT EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots WHERE id=NEW.global_snapshot_id AND season_id=NEW.season_id AND is_final IS TRUE) THEN RAISE EXCEPTION 'Historical season requires open atomic cutoff'; END IF;
  ELSE
   IF OLD.is_final OR NEW.is_final IS DISTINCT FROM true OR (to_jsonb(NEW)-'is_final') IS DISTINCT FROM (to_jsonb(OLD)-'is_final') THEN RAISE EXCEPTION 'League history is immutable'; END IF;
   IF NEW.expected_rows<>(SELECT count(*) FROM public.league_history_rows WHERE history_season_id=NEW.id) THEN RAISE EXCEPTION 'Incomplete league season'; END IF;
  END IF;
 ELSE
  IF TG_OP='DELETE' AND NOT EXISTS(SELECT 1 FROM public.league_history_seasons WHERE id=OLD.history_season_id) THEN RETURN OLD; END IF;
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'League history rows are immutable'; END IF;
  SELECT * INTO STRICT h FROM public.league_history_seasons WHERE id=NEW.history_season_id;
  IF h.is_final OR NOT EXISTS(SELECT 1 FROM public.leaderboard_history_rows WHERE id=NEW.global_snapshot_row_id AND snapshot_id=h.global_snapshot_id) THEN RAISE EXCEPTION 'Invalid immutable league row/source'; END IF;
 END IF;
 RETURN NEW;
END;
$body$;

CREATE FUNCTION public.publish_league_history_cutoff(p_source uuid,p_snapshot uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE h public.leaderboard_history_snapshots; s public.league_history_seasons; league_entry record; n integer; expected_leagues integer; expected_rows integer; selected uuid;
BEGIN
 IF NOT pg_try_advisory_xact_lock(50405,2) THEN RAISE EXCEPTION 'Rollover busy' USING ERRCODE='55P03'; END IF;
 SELECT season_id INTO STRICT selected FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected IS DISTINCT FROM p_source THEN RAISE EXCEPTION 'Canonical source changed'; END IF;
 SELECT * INTO STRICT h FROM public.leaderboard_history_snapshots WHERE id=p_snapshot AND season_id=p_source AND is_final IS TRUE;
 IF EXISTS(SELECT 1 FROM public.league_history_cutoffs WHERE global_snapshot_id=h.id) THEN
  RETURN public.verify_league_history_cutoff(p_source,p_snapshot)||jsonb_build_object('state','existing');
 END IF;
 IF h.expected_rows IS NULL OR h.expected_rows<0 OR h.expected_rows<>(SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=h.id)
  OR h.expected_rows<>(SELECT count(*) FROM public.leaderboard_history_competitors m JOIN public.leaderboard_history_rows g ON g.id=m.snapshot_row_id WHERE g.snapshot_id=h.id)
  OR h.expected_rows<>(SELECT count(DISTINCT m.user_id) FROM public.leaderboard_history_competitors m JOIN public.leaderboard_history_rows g ON g.id=m.snapshot_row_id WHERE g.snapshot_id=h.id) THEN RAISE EXCEPTION 'Unverified global rows or internal mapping; review required'; END IF;
 -- Conflicts with the ROW SHARE lock obtained first by all F1 mutations.
 -- Includes raw membership SQL via nc_f2_membership_cutoff. No network IO here.
 -- Plain discovery/history reads continue. Held until enclosing RPC commits.
 LOCK TABLE public.leagues IN EXCLUSIVE MODE;
 SELECT count(*),coalesce(sum(row_count),0) INTO expected_leagues,expected_rows FROM (
  SELECT l.id,count(*) AS row_count FROM public.leagues l JOIN public.league_members m ON m.league_id=l.id
  JOIN public.leaderboard_history_competitors c ON c.user_id=m.user_id JOIN public.leaderboard_history_rows g ON g.id=c.snapshot_row_id AND g.snapshot_id=h.id GROUP BY l.id
 ) q;
 INSERT INTO public.league_history_cutoffs(global_snapshot_id,expected_leagues,expected_rows) VALUES(h.id,expected_leagues,expected_rows);
 FOR league_entry IN SELECT x.id,count(*) AS row_count FROM public.leagues x JOIN public.league_members m ON m.league_id=x.id
  JOIN public.leaderboard_history_competitors c ON c.user_id=m.user_id JOIN public.leaderboard_history_rows g ON g.id=c.snapshot_row_id AND g.snapshot_id=h.id GROUP BY x.id ORDER BY x.id LOOP
  INSERT INTO public.league_history_seasons(league_id,season_id,global_snapshot_id,expected_rows) VALUES(league_entry.id,p_source,h.id,league_entry.row_count) RETURNING * INTO s;
  INSERT INTO public.league_history_rows(history_season_id,global_snapshot_row_id,rank,display_order)
  SELECT s.id,g.id,rank() OVER(ORDER BY g.total_points DESC,g.full_hits DESC,g.saved_at ASC),
   row_number() OVER(ORDER BY g.total_points DESC,g.full_hits DESC,g.saved_at ASC,g.display_name COLLATE "C",g.display_order,g.id)
  FROM public.leaderboard_history_rows g JOIN public.leaderboard_history_competitors c ON c.snapshot_row_id=g.id
  JOIN public.league_members m ON m.user_id=c.user_id AND m.league_id=league_entry.id WHERE g.snapshot_id=h.id;
  UPDATE public.league_history_seasons SET is_final=true WHERE id=s.id;
 END LOOP;
 UPDATE public.league_history_cutoffs SET is_final=true WHERE global_snapshot_id=h.id;
 RETURN public.verify_league_history_cutoff(p_source,p_snapshot)||jsonb_build_object('state','created');
END;
$body$;

CREATE OR REPLACE FUNCTION public.publish_leaderboard_snapshot(p_season_id uuid,p_master_id uuid,p_source jsonb,p_scores jsonb,p_rows jsonb,p_columns jsonb,p_created_by uuid)
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
 INSERT INTO public.leaderboard_history_competitors(snapshot_row_id,user_id)
 SELECT g.id,b.user_id FROM jsonb_to_recordset(p_rows) AS x(bracket_id uuid,display_order integer)
 JOIN public.brackets b ON b.id=x.bracket_id JOIN public.leaderboard_history_rows g ON g.snapshot_id=header.id AND g.display_order=x.display_order;
 IF (SELECT count(*) FROM public.leaderboard_history_competitors c JOIN public.leaderboard_history_rows g ON g.id=c.snapshot_row_id WHERE g.snapshot_id=header.id)<>row_count THEN RAISE EXCEPTION 'Final competitor mapping incomplete'; END IF;
 UPDATE public.leaderboard_history_snapshots SET is_final=true WHERE id=header.id;
 SELECT count(*) INTO actual_count FROM public.leaderboard_history_rows WHERE snapshot_id=header.id;
 IF actual_count<>row_count THEN RAISE EXCEPTION 'Snapshot row verification failed'; END IF;
 RETURN jsonb_build_object('state','created','snapshot_id',header.id,'season_id',header.season_id,'season_code',header.season_code,'expected_rows',row_count,'actual_rows',actual_count,'is_final',true);
END;
$body$;
CREATE OR REPLACE FUNCTION public.execute_season_rollover_transition(p_audit uuid,p_source uuid,p_snapshot uuid,p_target text,p_opening timestamptz,p_lock timestamptz) RETURNS jsonb
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
 PERFORM public.verify_league_history_cutoff(p_source,p_snapshot);
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
CREATE OR REPLACE FUNCTION public.run_season_rollover(p_target_code text,p_opening timestamptz,p_lock timestamptz,p_admin uuid,p_prepared jsonb) RETURNS jsonb
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
 BEGIN
  PERFORM public.publish_league_history_cutoff(source_id,(final->>'snapshot_id')::uuid);
 EXCEPTION WHEN OTHERS THEN
  UPDATE public.season_rollover_audits SET status='FAILED',completed_at=clock_timestamp(),failure_stage='league_history',sanitized_message='League history preservation refused; global snapshot preserved' WHERE id=audit_id;
  RETURN jsonb_build_object('ok',false,'state','failed','status',409,'stage','league_history','audit_id',audit_id,'error','League history preservation refused; global snapshot preserved');
 END;
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
ALTER TABLE public.leaderboard_history_competitors OWNER TO postgres;
ALTER TABLE public.leaderboard_history_competitors ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.leaderboard_history_competitors FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON public.leaderboard_history_competitors TO service_role;
CREATE TRIGGER nc_f2_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.leaderboard_history_competitors FOR EACH ROW EXECUTE FUNCTION public.protect_league_history();
CREATE TRIGGER nc_f2_no_app_truncate BEFORE TRUNCATE ON public.leaderboard_history_competitors FOR EACH STATEMENT EXECUTE FUNCTION public.protect_league_history();
ALTER TABLE public.league_history_cutoffs OWNER TO postgres;
ALTER TABLE public.league_history_cutoffs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.league_history_cutoffs FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON public.league_history_cutoffs TO service_role;
CREATE TRIGGER nc_f2_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.league_history_cutoffs FOR EACH ROW EXECUTE FUNCTION public.protect_league_history();
CREATE TRIGGER nc_f2_no_app_truncate BEFORE TRUNCATE ON public.league_history_cutoffs FOR EACH STATEMENT EXECUTE FUNCTION public.protect_league_history();
ALTER TABLE public.league_history_seasons OWNER TO postgres;
ALTER TABLE public.league_history_seasons ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.league_history_seasons FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON public.league_history_seasons TO service_role;
CREATE TRIGGER nc_f2_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.league_history_seasons FOR EACH ROW EXECUTE FUNCTION public.protect_league_history();
CREATE TRIGGER nc_f2_no_app_truncate BEFORE TRUNCATE ON public.league_history_seasons FOR EACH STATEMENT EXECUTE FUNCTION public.protect_league_history();
ALTER TABLE public.league_history_rows OWNER TO postgres;
ALTER TABLE public.league_history_rows ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.league_history_rows FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON public.league_history_rows TO service_role;
CREATE TRIGGER nc_f2_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.league_history_rows FOR EACH ROW EXECUTE FUNCTION public.protect_league_history();
CREATE TRIGGER nc_f2_no_app_truncate BEFORE TRUNCATE ON public.league_history_rows FOR EACH STATEMENT EXECUTE FUNCTION public.protect_league_history();
GRANT UPDATE(is_final) ON public.league_history_cutoffs,public.league_history_seasons TO service_role;
ALTER FUNCTION public.lock_league_history_membership() OWNER TO postgres;
REVOKE ALL ON FUNCTION public.lock_league_history_membership() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.lock_league_history_membership() TO postgres,service_role;
ALTER FUNCTION public.protect_league_history() OWNER TO postgres;
REVOKE ALL ON FUNCTION public.protect_league_history() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.protect_league_history() TO postgres,service_role;
ALTER FUNCTION public.verify_league_history_cutoff(uuid,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.verify_league_history_cutoff(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.verify_league_history_cutoff(uuid,uuid) TO postgres,service_role;
ALTER FUNCTION public.publish_league_history_cutoff(uuid,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.publish_league_history_cutoff(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.publish_league_history_cutoff(uuid,uuid) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
