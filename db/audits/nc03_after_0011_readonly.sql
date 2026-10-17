-- NC-04 DESIGN ONLY. Final schema only; not executed against production in NC-03.
BEGIN READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT 'canonical_designations' AS check_name,count(*) AS actual_count FROM public.application_season;
SELECT 'invalid_auth_versions' AS check_name,count(*) AS finding_count FROM public.users WHERE auth_version IS NULL OR auth_version<0;
SELECT 'legacy_reset_fields_not_cleared' AS check_name,count(*) AS finding_count FROM public.users WHERE reset_token IS NOT NULL OR reset_token_expires IS NOT NULL;
SELECT 'incomplete_final_snapshots' AS check_name,count(*) AS finding_count FROM public.leaderboard_history_snapshots s WHERE s.is_final IS TRUE AND (s.expected_rows IS NULL OR s.expected_rows<0 OR s.master_bracket_id IS NULL OR s.expected_rows<>(SELECT count(*) FROM public.leaderboard_history_rows r WHERE r.snapshot_id=s.id));
SELECT 'legacy_structured_headers_require_compatibility_review' AS check_name,count(*) AS finding_count FROM public.leaderboard_history_snapshots WHERE is_final IS NULL;
SELECT 'unfinished_rollover_audits' AS check_name,count(*) AS finding_count FROM public.season_rollover_audits WHERE status='STARTED';
SELECT 'duplicate_completed_transition_groups' AS check_name,count(*) AS finding_count FROM (SELECT source_season_id,target_code FROM public.season_rollover_audits WHERE status='COMPLETED' GROUP BY source_season_id,target_code HAVING count(*)>1) duplicate;
SELECT 'invalid_league_final_headers' AS check_name,count(*) AS finding_count FROM public.league_history_seasons s WHERE NOT s.is_final OR s.expected_rows<>(SELECT count(*) FROM public.league_history_rows r WHERE r.history_season_id=s.id);
SELECT c.relname,c.relkind,c.relrowsecurity,c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','S');
SELECT p.oid::regprocedure AS signature,pg_get_userbyid(p.proowner) AS owner,p.prosecdef,p.proconfig,p.proacl FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e');
SELECT code,conference,seed,wins,losses,win_pct FROM public.standings ORDER BY conference,seed;
COMMIT;
