-- NC-SEC-01B: privilege containment only; not a bracket visibility redesign.
-- Target: NBA Corner production rpwesmvzmgoctrokrbhy (confirm externally).
-- Preserve view SQL, owner, options, OID, underlying tables and all RPCs.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
DO $nc_sec_01b$
DECLARE
  view_oid oid := to_regclass('public.bracket_view');
  view_row record;
  before_identity jsonb;
  after_identity jsonb;
  before_rpc jsonb;
  after_rpc jsonb;
  role_name text;
  privilege_name text;
BEGIN
  SELECT c.*, pg_get_userbyid(c.relowner) AS owner_name INTO view_row
    FROM pg_class c WHERE c.oid=view_oid;
  IF NOT FOUND OR view_row.relkind <> 'v' OR view_row.owner_name <> 'postgres'
     OR md5(pg_get_viewdef(view_oid,true)) <> '91f509a8d70645f5d1f4d94bd93c9f09' THEN
    RAISE EXCEPTION 'NC-SEC-01B view identity/owner/definition drift';
  END IF;
  -- Preflight found no explicit column ACLs. Abort if that evidence changed;
  -- do not improvise column revocations or broaden this migration.
  IF EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=view_oid
             AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL) THEN
    RAISE EXCEPTION 'NC-SEC-01B unexpected column ACL; repeat preflight';
  END IF;
  FOREACH role_name IN ARRAY ARRAY['service_role','postgres'] LOOP
    FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE',
                                         'TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'] LOOP
      IF NOT has_table_privilege(role_name,view_oid,privilege_name) THEN
        RAISE EXCEPTION 'Required trusted privilege missing: % %',role_name,privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  SELECT jsonb_build_array(c.oid,c.relowner,pg_get_viewdef(c.oid,true),c.reloptions)
    INTO before_identity FROM pg_class c WHERE c.oid=view_oid;
  SELECT jsonb_agg(jsonb_build_array(p.oid,p.proacl,p.proowner,p.prosecdef,
                                   pg_get_functiondef(p.oid)) ORDER BY p.oid)
    INTO before_rpc FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),
      to_regprocedure('public.set_master_bracket(uuid,uuid)'),
      to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),
      to_regprocedure('public.undo_prediction_atomic(uuid)'));

  REVOKE ALL PRIVILEGES ON TABLE public.bracket_view FROM PUBLIC, anon, authenticated;

  FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF has_table_privilege(role_name,view_oid,
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
       OR has_any_column_privilege(role_name,view_oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION 'Ordinary-role access survived revocation: %',role_name;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_class c CROSS JOIN LATERAL
             aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
             WHERE c.oid=view_oid AND a.grantee=0) THEN
    RAISE EXCEPTION 'PUBLIC view access survived revocation';
  END IF;
  FOREACH role_name IN ARRAY ARRAY['service_role','postgres'] LOOP
    FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE',
                                         'TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'] LOOP
      IF NOT has_table_privilege(role_name,view_oid,privilege_name) THEN
        RAISE EXCEPTION 'Trusted access changed: % %',role_name,privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  SELECT jsonb_build_array(c.oid,c.relowner,pg_get_viewdef(c.oid,true),c.reloptions)
    INTO after_identity FROM pg_class c WHERE c.oid=to_regclass('public.bracket_view');
  SELECT jsonb_agg(jsonb_build_array(p.oid,p.proacl,p.proowner,p.prosecdef,
                                   pg_get_functiondef(p.oid)) ORDER BY p.oid)
    INTO after_rpc FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),
      to_regprocedure('public.set_master_bracket(uuid,uuid)'),
      to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),
      to_regprocedure('public.undo_prediction_atomic(uuid)'));
  IF before_identity IS DISTINCT FROM after_identity OR before_rpc IS DISTINCT FROM after_rpc THEN
    RAISE EXCEPTION 'NC-SEC-01B changed view identity or phase-01A RPC state';
  END IF;
END
$nc_sec_01b$;
SELECT clock_timestamp() AS acl_change_completed_at_utc;
COMMIT;
