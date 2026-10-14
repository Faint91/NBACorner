-- LOCAL TEST ONLY: deliberate v1 -> v2 marker evolution; no application DDL/data.
-- Run only after authenticated enrolled v1 identity and local container checks.
BEGIN;
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';
SET LOCAL search_path = pg_catalog;
DO $preflight$
BEGIN
 IF current_user <> 'postgres' OR current_database() <> 'postgres'
    OR current_setting('server_version_num')::integer / 10000 <> 17 THEN
   RAISE EXCEPTION 'Local marker execution identity mismatch';
 END IF;
 IF NOT pg_try_advisory_xact_lock(50405, 1) THEN
   RAISE EXCEPTION 'Local marker evolution lease unavailable';
 END IF;
END
$preflight$;
LOCK TABLE nba_corner_test_control.test_environment_identity IN ACCESS EXCLUSIVE MODE;
DO $marker_preflight$
BEGIN
 IF (SELECT count(*) FROM nba_corner_test_control.test_environment_identity) <> 1
    OR NOT EXISTS (SELECT 1 FROM nba_corner_test_control.test_environment_identity
       WHERE singleton AND environment = 'test'
       AND project_ref = 'local:nba-corner-local-test'
       AND marker_id = 'nba-corner-local-test' AND marker_version = '1'
       AND baseline_version = 'nc-env-02-current-secured-v1'
       AND baseline_checkpoint = 'da8c6695be0726ef3893ffefe605f6fa6e368f9c'
       AND baseline_commit = '2e9d6752ce0a5f559673b99221d88c7f51c9d8ea'
       AND fixture_state = 'UNSEEDED') THEN
   RAISE EXCEPTION 'Local v1 authoritative marker mismatch';
 END IF;
 IF (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
     WHERE attrelid = 'nba_corner_test_control.test_environment_identity'::regclass
       AND attnum > 0 AND NOT attisdropped) IS DISTINCT FROM
       ARRAY['singleton','environment','project_ref','marker_id','marker_version',
             'baseline_version','baseline_checkpoint','baseline_commit','fixture_state','created_at'] THEN
   RAISE EXCEPTION 'Local v1 marker column inventory mismatch';
 END IF;
 IF (SELECT pg_get_constraintdef(oid) FROM pg_constraint
     WHERE conrelid = 'nba_corner_test_control.test_environment_identity'::regclass
       AND conname = 'test_environment_identity_fixture_state_check') IS DISTINCT FROM
       'CHECK ((fixture_state = ''UNSEEDED''::text))' THEN
   RAISE EXCEPTION 'Local v1 fixture constraint mismatch';
 END IF;
 IF (SELECT pg_get_userbyid(relowner) FROM pg_class
     WHERE oid = 'nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM 'postgres'
    OR (SELECT relacl::text FROM pg_class
        WHERE oid = 'nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM
        '{postgres=arwdDxtm/postgres,service_role=r/postgres}'
    OR (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'nba_corner_test_control') IS DISTINCT FROM
        '{postgres=UC/postgres,service_role=U/postgres}' THEN
   RAISE EXCEPTION 'Local marker security mismatch';
 END IF;
END
$marker_preflight$;
ALTER TABLE nba_corner_test_control.test_environment_identity
 DROP CONSTRAINT test_environment_identity_fixture_state_check,
 ADD COLUMN fixture_version text,
 ADD COLUMN fixture_checksum text,
 ADD CONSTRAINT test_environment_identity_fixture_state_check
   CHECK (fixture_state IN ('UNSEEDED', 'SEEDED')),
 ADD CONSTRAINT test_environment_identity_fixture_metadata_check
   CHECK (
     (fixture_state = 'UNSEEDED' AND fixture_version IS NULL AND fixture_checksum IS NULL)
     OR
     (fixture_state = 'SEEDED' AND fixture_version IS NOT NULL AND fixture_checksum IS NOT NULL
      AND fixture_version ~ '^[a-z0-9][a-z0-9._-]{0,79}$'
      AND fixture_checksum ~ '^[a-f0-9]{64}$')
   );
UPDATE nba_corner_test_control.test_environment_identity
 SET marker_version = '2', fixture_version = NULL, fixture_checksum = NULL
 WHERE singleton;
DO $marker_postflight$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM nba_corner_test_control.test_environment_identity
       WHERE singleton AND marker_version = '2' AND fixture_state = 'UNSEEDED'
       AND fixture_version IS NULL AND fixture_checksum IS NULL)
    OR (SELECT pg_get_userbyid(relowner) FROM pg_class
        WHERE oid = 'nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM 'postgres'
    OR (SELECT relacl::text FROM pg_class
        WHERE oid = 'nba_corner_test_control.test_environment_identity'::regclass) IS DISTINCT FROM
        '{postgres=arwdDxtm/postgres,service_role=r/postgres}'
    OR (SELECT nspacl::text FROM pg_namespace WHERE nspname = 'nba_corner_test_control') IS DISTINCT FROM
        '{postgres=UC/postgres,service_role=U/postgres}' THEN
   RAISE EXCEPTION 'Local v2 marker postflight mismatch';
 END IF;
END
$marker_postflight$;
-- Refresh only the local PostgREST schema cache for the new marker columns.
NOTIFY pgrst, 'reload schema';
COMMIT;
