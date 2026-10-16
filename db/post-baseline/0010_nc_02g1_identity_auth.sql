-- NC-02G1: new identity constraints only; no existing user/password rewrites.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE FUNCTION public.auth_identity_key(p_value text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT lower(btrim(p_value,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'));
$body$;
ALTER FUNCTION public.auth_identity_key(text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.auth_identity_key(text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.auth_identity_key(text) TO postgres,service_role;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.users WHERE username IS NULL OR email IS NULL OR public.auth_identity_key(username)='' OR public.auth_identity_key(email)='') THEN RAISE EXCEPTION 'Invalid existing identities require review'; END IF;
 IF EXISTS(SELECT 1 FROM public.users GROUP BY public.auth_identity_key(username) HAVING count(*)>1) OR EXISTS(SELECT 1 FROM public.users GROUP BY public.auth_identity_key(email) HAVING count(*)>1) THEN RAISE EXCEPTION 'Normalized identity collisions require review'; END IF;
END $$;
ALTER TABLE public.users ADD CONSTRAINT nc_g1_nonblank_identity CHECK(username IS NOT NULL AND email IS NOT NULL AND public.auth_identity_key(username)<>'' AND public.auth_identity_key(email)<>'');
CREATE UNIQUE INDEX nc_g1_username_key ON public.users(public.auth_identity_key(username));
CREATE UNIQUE INDEX nc_g1_email_key ON public.users(public.auth_identity_key(email));
CREATE FUNCTION public.find_auth_user(p_field text,p_identity text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT jsonb_build_object('id',u.id,'username',u.username,'email',u.email,'password',u.password,'is_admin',u.is_admin,'created_at',u.created_at)
 FROM public.users u WHERE (p_field='username' AND public.auth_identity_key(u.username)=public.auth_identity_key(p_identity)) OR (p_field='email' AND public.auth_identity_key(u.email)=public.auth_identity_key(p_identity));
$body$;
ALTER FUNCTION public.find_auth_user(text,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.find_auth_user(text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.find_auth_user(text,text) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
