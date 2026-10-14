-- Read-only verification of local fixture marker v2; no fixture rows created.
BEGIN READ ONLY;
SET LOCAL search_path = pg_catalog;
DO $verify_marker_v2$
DECLARE
 expression text;
 matrix_passed boolean;
BEGIN
 IF current_user <> 'postgres' OR current_database() <> 'postgres' THEN
   RAISE EXCEPTION 'Local marker verification role/database mismatch';
 END IF;
 IF (SELECT count(*) FROM nba_corner_test_control.test_environment_identity) <> 1
    OR NOT EXISTS (SELECT 1 FROM nba_corner_test_control.test_environment_identity
       WHERE singleton AND environment='test' AND project_ref='local:nba-corner-local-test'
       AND marker_id='nba-corner-local-test' AND marker_version='2'
       AND baseline_version='nc-env-02-current-secured-v1'
       AND baseline_checkpoint='da8c6695be0726ef3893ffefe605f6fa6e368f9c'
       AND baseline_commit='2e9d6752ce0a5f559673b99221d88c7f51c9d8ea') THEN
   RAISE EXCEPTION 'Local marker v2 identity mismatch';
 END IF;
 IF (SELECT count(*) FROM information_schema.columns
     WHERE table_schema='nba_corner_test_control' AND table_name='test_environment_identity'
       AND column_name IN ('fixture_version','fixture_checksum') AND data_type='text'
       AND is_nullable='YES' AND column_default IS NULL) <> 2 THEN
   RAISE EXCEPTION 'Local fixture metadata columns mismatch';
 END IF;
 IF (SELECT count(*) FROM pg_constraint
     WHERE conrelid='nba_corner_test_control.test_environment_identity'::regclass
       AND conname IN ('test_environment_identity_fixture_state_check',
                       'test_environment_identity_fixture_metadata_check')
       AND contype='c' AND convalidated) <> 2 THEN
   RAISE EXCEPTION 'Local fixture constraints missing/unvalidated';
 END IF;
 IF (SELECT pg_get_userbyid(relowner) FROM pg_class
     WHERE oid='nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM 'postgres'
    OR (SELECT relacl::text FROM pg_class
        WHERE oid='nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM
        '{postgres=arwdDxtm/postgres,service_role=r/postgres}'
    OR (SELECT nspacl::text FROM pg_namespace WHERE nspname='nba_corner_test_control') IS DISTINCT FROM
        '{postgres=UC/postgres,service_role=U/postgres}'
    OR has_schema_privilege('anon','nba_corner_test_control','USAGE')
    OR has_schema_privilege('authenticated','nba_corner_test_control','USAGE')
    OR has_table_privilege('anon','nba_corner_test_control.test_environment_identity','SELECT')
    OR has_table_privilege('authenticated','nba_corner_test_control.test_environment_identity','SELECT')
    OR NOT has_table_privilege('service_role','nba_corner_test_control.test_environment_identity','SELECT')
    OR has_table_privilege('service_role','nba_corner_test_control.test_environment_identity','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') THEN
   RAISE EXCEPTION 'Local marker owner/access mismatch';
 END IF;
 -- Evaluate the actual stored CHECK expressions against virtual states only.
 -- No UPDATE/temporary seeded state: authoritative row remains UNSEEDED.
 SELECT string_agg('(' || pg_get_expr(conbin,conrelid) || ')',' AND ' ORDER BY conname)
   INTO expression FROM pg_constraint
   WHERE conrelid='nba_corner_test_control.test_environment_identity'::regclass
     AND conname IN ('test_environment_identity_fixture_state_check',
                     'test_environment_identity_fixture_metadata_check');
 EXECUTE format($matrix$
   SELECT bool_and((%s) IS NOT DISTINCT FROM expected)
   FROM (VALUES
     ('UNSEEDED'::text,NULL::text,NULL::text,true),
     ('UNSEEDED','nc-fixtures-v1',NULL,false),
     ('UNSEEDED',NULL,repeat('a',64),false),
     ('UNSEEDED','nc-fixtures-v1',repeat('a',64),false),
     ('SEEDED',NULL,NULL,false),
     ('SEEDED',NULL,repeat('a',64),false),
     ('SEEDED','nc-fixtures-v1',NULL,false),
     ('SEEDED','nc-fixtures-v1',repeat('a',64),true),
     ('SEEDED','',repeat('a',64),false),
     ('SEEDED','nc-fixtures-v1','bad',false),
     ('OTHER',NULL,NULL,false)
   ) AS candidates(fixture_state,fixture_version,fixture_checksum,expected)
 $matrix$,expression) INTO matrix_passed;
 IF matrix_passed IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'Local fixture CHECK truth table mismatch';
 END IF;
END
$verify_marker_v2$;
SELECT 'Local marker v2 identity, ACL and CHECK verification passed';
COMMIT;
