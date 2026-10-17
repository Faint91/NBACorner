-- NC-02G2: deliberately invalidate every legacy reset link. LOCAL rollout first.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
ALTER TABLE public.users ADD COLUMN auth_version integer NOT NULL DEFAULT 0;
ALTER TABLE public.users ADD CONSTRAINT nc_g2_auth_version CHECK (auth_version>=0);
DELETE FROM public.password_resets;
UPDATE public.users SET reset_token=NULL,reset_token_expires=NULL WHERE reset_token IS NOT NULL OR reset_token_expires IS NOT NULL;
ALTER TABLE public.password_resets RENAME COLUMN token TO token_digest;
ALTER TABLE public.password_resets ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE public.password_resets ALTER COLUMN expires_at TYPE timestamptz USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE public.password_resets ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC';
ALTER TABLE public.password_resets ADD CONSTRAINT nc_g2_reset_digest CHECK(token_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE public.password_resets ADD CONSTRAINT nc_g2_reset_user UNIQUE(user_id);
CREATE OR REPLACE FUNCTION public.find_auth_user(p_field text,p_identity text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT jsonb_build_object('id',u.id,'username',u.username,'email',u.email,'password',u.password,'is_admin',u.is_admin,'created_at',u.created_at,'auth_version',u.auth_version)
 FROM public.users u WHERE (p_field='username' AND public.auth_identity_key(u.username)=public.auth_identity_key(p_identity)) OR (p_field='email' AND public.auth_identity_key(u.email)=public.auth_identity_key(p_identity));
$body$;
CREATE FUNCTION public.issue_password_reset(p_user_id uuid,p_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
BEGIN
 IF p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'Invalid reset verifier'; END IF;
 PERFORM 1 FROM public.users WHERE id=p_user_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 DELETE FROM public.password_resets WHERE user_id=p_user_id;
 INSERT INTO public.password_resets(user_id,token_digest,expires_at,created_at,used)
 VALUES(p_user_id,p_digest,clock_timestamp()+interval '60 minutes',clock_timestamp(),false);
 RETURN true;
END;
$body$;
CREATE FUNCTION public.cancel_password_reset(p_user_id uuid,p_digest text) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
BEGIN
 PERFORM 1 FROM public.users WHERE id=p_user_id FOR UPDATE;
 DELETE FROM public.password_resets WHERE user_id=p_user_id AND token_digest=p_digest;
END;
$body$;
CREATE FUNCTION public.complete_password_reset(p_digest text,p_password_hash text) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE subject uuid;
BEGIN
 IF p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$' OR p_password_hash IS NULL
 OR p_password_hash !~ '^nc-bcrypt-sha256-v1\$\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN RETURN false; END IF;
 SELECT user_id INTO subject FROM public.password_resets WHERE token_digest=p_digest;
 IF subject IS NULL THEN RETURN false; END IF;
 -- Same lock order as issuance/cancellation; re-read after acquiring the user lock.
 PERFORM 1 FROM public.users WHERE id=subject FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.password_resets WHERE user_id=subject AND token_digest=p_digest AND NOT used AND expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE public.users SET password=p_password_hash,auth_version=auth_version+1 WHERE id=subject;
 DELETE FROM public.password_resets WHERE user_id=subject;
 RETURN true;
END;
$body$;
ALTER FUNCTION public.issue_password_reset(uuid,text) OWNER TO postgres;
ALTER FUNCTION public.cancel_password_reset(uuid,text) OWNER TO postgres;
ALTER FUNCTION public.complete_password_reset(text,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.issue_password_reset(uuid,text),public.cancel_password_reset(uuid,text),public.complete_password_reset(text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.issue_password_reset(uuid,text),public.cancel_password_reset(uuid,text),public.complete_password_reset(text,text) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
