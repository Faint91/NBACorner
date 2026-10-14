-- NC-SEC-01A: first new version-controlled change after the NC-00 snapshot.
-- Target: NBA Corner production rpwesmvzmgoctrokrbhy. Confirm target externally.
-- Only EXECUTE ACLs change. No RPC invocation or application data writes.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
DO $nc_sec_01a$
DECLARE
  target record;
  actual record;
  before_identity jsonb;
  after_identity jsonb;
BEGIN
  FOR target IN SELECT * FROM (VALUES
    ('public.atomic_update_match(uuid,text,text,integer)', 'e8adea287fb29d402010e219b50d0827', true),
    ('public.set_master_bracket(uuid,uuid)', '70bbfc39b0e19680b3ac38da1faa06f3', true),
    ('public.set_winner_atomic(uuid,text,integer)', '8fc1073c6b520e9ddd429bf1d5e552e9', false),
    ('public.undo_prediction_atomic(uuid)', '561bcc8ca8dcfbe2340fd93167c01f99', false)
  ) AS expected(signature, definition_md5, security_definer)
  LOOP
    SELECT p.oid, pg_get_userbyid(p.proowner) AS owner, p.prosecdef,
           md5(pg_get_functiondef(p.oid)) AS definition_md5
      INTO actual FROM pg_proc p WHERE p.oid = to_regprocedure(target.signature);
    IF NOT FOUND THEN RAISE EXCEPTION 'Missing NC-SEC-01A function: %', target.signature; END IF;
    IF actual.owner <> 'postgres' OR actual.prosecdef <> target.security_definer
       OR actual.definition_md5 <> target.definition_md5 THEN
      RAISE EXCEPTION 'NC-SEC-01A definition/owner/security drift: %', target.signature;
    END IF;
    IF NOT has_function_privilege('service_role', actual.oid, 'EXECUTE')
       OR NOT has_function_privilege('postgres', actual.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'Required server/owner EXECUTE missing: %', target.signature;
    END IF;
  END LOOP;

  SELECT jsonb_agg(jsonb_build_array(p.oid, p.proowner, p.prosecdef,
                    md5(pg_get_functiondef(p.oid))) ORDER BY p.oid)
    INTO before_identity FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),
      to_regprocedure('public.set_master_bracket(uuid,uuid)'),
      to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),
      to_regprocedure('public.undo_prediction_atomic(uuid)'));

  REVOKE EXECUTE ON FUNCTION
    public.atomic_update_match(uuid,text,text,integer),
    public.set_master_bracket(uuid,uuid),
    public.set_winner_atomic(uuid,text,integer),
    public.undo_prediction_atomic(uuid)
  FROM PUBLIC, anon, authenticated;

  FOR actual IN SELECT p.* FROM pg_proc p WHERE p.oid IN (
    to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),
    to_regprocedure('public.set_master_bracket(uuid,uuid)'),
    to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),
    to_regprocedure('public.undo_prediction_atomic(uuid)'))
  LOOP
    IF EXISTS (SELECT 1 FROM aclexplode(COALESCE(actual.proacl,
                  acldefault('f', actual.proowner))) a
               WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
       OR has_function_privilege('anon', actual.oid, 'EXECUTE')
       OR has_function_privilege('authenticated', actual.oid, 'EXECUTE')
       OR NOT has_function_privilege('service_role', actual.oid, 'EXECUTE')
       OR NOT has_function_privilege('postgres', actual.oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'NC-SEC-01A effective privilege verification failed: %', actual.oid;
    END IF;
  END LOOP;

  SELECT jsonb_agg(jsonb_build_array(p.oid, p.proowner, p.prosecdef,
                    md5(pg_get_functiondef(p.oid))) ORDER BY p.oid)
    INTO after_identity FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),
      to_regprocedure('public.set_master_bracket(uuid,uuid)'),
      to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),
      to_regprocedure('public.undo_prediction_atomic(uuid)'));
  IF before_identity IS DISTINCT FROM after_identity THEN
    RAISE EXCEPTION 'NC-SEC-01A changed function identity/definition';
  END IF;
END
$nc_sec_01a$;
COMMIT;
