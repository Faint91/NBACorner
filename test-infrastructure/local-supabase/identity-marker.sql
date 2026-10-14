-- LOCAL TEST ONLY identity control; not application fixtures.
-- Apply only after baseline verification through the guarded local container path.
BEGIN;
CREATE SCHEMA nba_corner_test_control AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA nba_corner_test_control FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA nba_corner_test_control TO service_role;
CREATE TABLE nba_corner_test_control.test_environment_identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 environment text NOT NULL CHECK (environment = 'test'),
 project_ref text NOT NULL CHECK (project_ref = 'local:nba-corner-local-test'),
 marker_id text NOT NULL,
 marker_version text NOT NULL,
 baseline_version text NOT NULL,
 baseline_checkpoint text NOT NULL,
 baseline_commit text NOT NULL,
 fixture_state text NOT NULL CHECK (fixture_state = 'UNSEEDED'),
 created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE nba_corner_test_control.test_environment_identity FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE nba_corner_test_control.test_environment_identity TO service_role;
GRANT ALL ON TABLE nba_corner_test_control.test_environment_identity TO postgres;
INSERT INTO nba_corner_test_control.test_environment_identity
(singleton, environment, project_ref, marker_id, marker_version, baseline_version, baseline_checkpoint, baseline_commit, fixture_state)
VALUES (true, 'test', 'local:nba-corner-local-test', 'nba-corner-local-test', '1',
 'nc-env-02-current-secured-v1', 'da8c6695be0726ef3893ffefe605f6fa6e368f9c',
 '2e9d6752ce0a5f559673b99221d88c7f51c9d8ea', 'UNSEEDED');
DO $marker_security$
BEGIN
 IF EXISTS (SELECT 1 FROM aclexplode((SELECT relacl FROM pg_class
   WHERE oid='nba_corner_test_control.test_environment_identity'::regclass)) a
   WHERE a.grantee=0 OR a.grantee IN ('anon'::regrole,'authenticated'::regrole))
   OR has_table_privilege('anon','nba_corner_test_control.test_environment_identity','SELECT')
   OR has_table_privilege('authenticated','nba_corner_test_control.test_environment_identity','SELECT')
   OR NOT has_table_privilege('service_role','nba_corner_test_control.test_environment_identity','SELECT') THEN
   RAISE EXCEPTION 'Identity marker access mismatch';
 END IF;
END
$marker_security$;
COMMIT;
