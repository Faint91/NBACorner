-- Read-only pre/post verification. Does NOT execute any target function.
-- Definition fingerprints and OIDs were captured from production catalog.
-- OID comparison is production-specific; isolated copies may have other OIDs.
WITH expected(signature, captured_oid, security_definer, definition_md5) AS (
  VALUES
    ('public.atomic_update_match(uuid,text,text,integer)', 19781::oid, true, 'e8adea287fb29d402010e219b50d0827'),
    ('public.set_master_bracket(uuid,uuid)', 31324::oid, true, '70bbfc39b0e19680b3ac38da1faa06f3'),
    ('public.set_winner_atomic(uuid,text,integer)', 19863::oid, false, '8fc1073c6b520e9ddd429bf1d5e552e9'),
    ('public.undo_prediction_atomic(uuid)', 19864::oid, false, '561bcc8ca8dcfbe2340fd93167c01f99')
), observed AS (
  SELECT e.signature, p.oid, p.oid IS NOT NULL AS function_exists,
    p.oid = e.captured_oid AS oid_unchanged,
    pg_get_userbyid(p.proowner) AS owner,
    pg_get_userbyid(p.proowner) = 'postgres' AS owner_unchanged,
    p.prosecdef AS security_definer,
    p.prosecdef = e.security_definer AS security_mode_unchanged,
    md5(pg_get_functiondef(p.oid)) AS definition_md5,
    md5(pg_get_functiondef(p.oid)) = e.definition_md5 AS definition_unchanged,
    p.proacl::text AS acl,
    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f',p.proowner))) a
            WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
    has_function_privilege('anon',p.oid,'EXECUTE') AS anon_execute,
    has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated_execute,
    has_function_privilege('service_role',p.oid,'EXECUTE') AS service_role_execute,
    has_function_privilege('postgres',p.oid,'EXECUTE') AS postgres_execute,
    statement_timestamp() AS observed_at
  FROM expected e LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
)
SELECT *, COALESCE(function_exists AND oid_unchanged AND owner_unchanged
  AND security_mode_unchanged AND definition_unchanged AND NOT public_execute
  AND NOT anon_execute AND NOT authenticated_execute AND service_role_execute
  AND postgres_execute, false) AS post_change_passed
FROM observed ORDER BY signature;
