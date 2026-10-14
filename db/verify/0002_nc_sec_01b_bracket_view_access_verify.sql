-- Read-only catalog verification; never selects actual bracket_view rows.
-- Captured production OID 19776; definition uses pg_get_viewdef(oid,true).
WITH v AS (
  SELECT c.*, pg_get_userbyid(c.relowner) AS owner_name,
         md5(pg_get_viewdef(c.oid,true)) AS definition_md5
    FROM pg_class c WHERE c.oid=to_regclass('public.bracket_view') AND c.relkind='v'
), roles(role_name) AS (VALUES ('anon'),('authenticated'),('service_role'),('postgres'))
SELECT r.role_name, v.oid, v.oid=19776 AS oid_unchanged,
       v.owner_name, v.owner_name='postgres' AS owner_unchanged,
       v.definition_md5, v.definition_md5='91f509a8d70645f5d1f4d94bd93c9f09' AS definition_unchanged,
       v.reloptions, v.relacl::text AS relation_acl,
       has_table_privilege(r.role_name,v.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS any_relation_privilege,
       has_any_column_privilege(r.role_name,v.oid,'SELECT,INSERT,UPDATE,REFERENCES') AS any_column_privilege,
       EXISTS (SELECT 1 FROM aclexplode(COALESCE(v.relacl,acldefault('r',v.relowner))) x
                WHERE x.grantee=0) AS public_relation_privilege,
       (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=v.oid AND a.attnum>0
          AND NOT a.attisdropped AND a.attacl IS NOT NULL) AS explicit_column_acl_count,
       (SELECT bool_and(has_table_privilege(r.role_name,v.oid,priv))
          FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE',
                           'REFERENCES','TRIGGER','MAINTAIN']) priv) AS all_eight_privileges,
       statement_timestamp() AS verified_at
  FROM roles r LEFT JOIN v ON true ORDER BY r.role_name;

-- NC-SEC-01A regression: expected false/false/false/true/true for each RPC.
WITH rpc(signature) AS (VALUES
  ('public.atomic_update_match(uuid,text,text,integer)'),
  ('public.set_master_bracket(uuid,uuid)'),
  ('public.set_winner_atomic(uuid,text,integer)'),
  ('public.undo_prediction_atomic(uuid)'))
SELECT rpc.signature, EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL
  aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid=to_regprocedure(rpc.signature) AND a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
  has_function_privilege('anon',rpc.signature,'EXECUTE') AS anon_execute,
  has_function_privilege('authenticated',rpc.signature,'EXECUTE') AS authenticated_execute,
  has_function_privilege('service_role',rpc.signature,'EXECUTE') AS service_role_execute,
  has_function_privilege('postgres',rpc.signature,'EXECUTE') AS postgres_execute
FROM rpc ORDER BY signature;
