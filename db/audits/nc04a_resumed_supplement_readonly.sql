-- NC-04A resumed supplement: manual read-only catalog/aggregate inspection.
-- First verify NBA Corner / rpwesmvzmgoctrokrbhy / main PRODUCTION in dashboard.
-- Never run app mutation RPCs or the empty-database baseline against production.
-- Existing nc03_before_migrations_readonly.sql supplies identity/league/canonical checks.
BEGIN READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT clock_timestamp() AS observed_at,current_database(),current_user,
 current_setting('transaction_read_only') AS read_only;
SELECT c.relname,c.relkind,pg_get_userbyid(c.relowner) AS owner,c.relacl,
 c.relrowsecurity,c.relforcerowsecurity
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN('r','v','S') ORDER BY c.relname;
SELECT c.relname,a.attname,a.attacl FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL;
SELECT c.relname,r AS role,p AS privilege FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN unnest(ARRAY['anon','authenticated']) r
 CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
 WHERE n.nspname='public' AND c.relkind IN('r','v') AND has_table_privilege(r,c.oid,p);
SELECT c.relname,pg_get_userbyid(c.relowner) AS owner,c.relacl,r AS role,p AS privilege
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN unnest(ARRAY['anon','authenticated']) r
 CROSS JOIN unnest(ARRAY['SELECT','UPDATE','USAGE']) p
 WHERE n.nspname='public' AND c.relkind='S' AND has_sequence_privilege(r,c.oid,p);
SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS args,
 pg_get_userbyid(p.proowner) AS owner,p.prosecdef,p.proconfig,p.proacl,
 md5(btrim(regexp_replace(p.prosrc,'\s+',' ','g'))) AS body_md5
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.proowner='postgres'::regrole ORDER BY p.proname;
SELECT * FROM pg_policies WHERE schemaname='public';
SELECT pg_get_userbyid(d.defaclrole) AS owner,n.nspname,d.defaclobjtype,d.defaclacl
 FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname='public';
SELECT extname,extversion FROM pg_extension;
SELECT count(*) AS advisory_locks FROM pg_locks WHERE locktype='advisory';
SELECT count(*) AS active_rollover_queries FROM pg_stat_activity
 WHERE pid<>pg_backend_pid() AND state='active' AND query~*'(rollover|transition_season)' AND backend_type='client backend';
SELECT count(*) AS reset_total,count(*) FILTER(WHERE used IS NOT TRUE) AS unused,
 count(*) FILTER(WHERE used IS NOT TRUE AND expires_at>now()) AS unused_unexpired
 FROM public.password_resets;
SELECT count(*) AS duplicate_seed_groups FROM
 (SELECT conference,seed FROM public.standings GROUP BY 1,2 HAVING count(*)>1)d;
SELECT count(*) AS duplicate_history_payload_groups FROM
 (SELECT snapshot_id,to_jsonb(r)-'id'-'created_at' FROM public.leaderboard_history_rows r GROUP BY 1,2 HAVING count(*)>1)d;
-- Legacy structured rows do not retain user/bracket identity. Do not invent a
-- duplicate-user claim or backfill mappings from display names.
SELECT s.code,s.master_bracket_id,b.is_master,b.deleted_at IS NOT NULL AS deleted,
 u.is_admin,(SELECT count(*) FROM public.matches m WHERE m.bracket_id=b.id) AS match_count
 FROM public.seasons s LEFT JOIN public.brackets b ON b.id=s.master_bracket_id
 LEFT JOIN public.users u ON u.id=b.user_id WHERE s.master_bracket_id IS NOT NULL;
-- For complete topology proof, export only master match graph fields (no user data)
-- and run existing pure bracket_rules.dependency_edges/submission_error offline.
COMMIT;
