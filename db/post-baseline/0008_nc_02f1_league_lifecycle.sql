-- NC-02F1: live league lifecycle only; no history or season linkage.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user<>'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
LOCK TABLE public.leagues,public.league_members IN SHARE ROW EXCLUSIVE MODE;
CREATE FUNCTION public.normalize_league_name(p_name text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT btrim(p_name,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000');
$body$;
CREATE FUNCTION public.league_name_key(p_name text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT lower(public.normalize_league_name(p_name));
$body$;
DO $preflight$ BEGIN
 IF EXISTS(SELECT 1 FROM public.leagues GROUP BY public.league_name_key(name) HAVING count(*)>1) THEN RAISE EXCEPTION 'Normalized league name collisions require manual preflight review'; END IF;
 IF EXISTS(SELECT 1 FROM public.leagues WHERE name IS DISTINCT FROM public.normalize_league_name(name) OR char_length(name) NOT BETWEEN 1 AND 80) THEN RAISE EXCEPTION 'Existing league names require manual preflight review'; END IF;
 IF EXISTS(SELECT 1 FROM public.leagues l WHERE NOT EXISTS(SELECT 1 FROM public.league_members m WHERE m.league_id=l.id AND m.user_id=l.owner_user_id)) THEN RAISE EXCEPTION 'Owner membership inconsistencies require manual preflight review'; END IF;
END $preflight$;
ALTER TABLE public.leagues DROP CONSTRAINT leagues_name_unique;
CREATE UNIQUE INDEX nc_f1_league_name_unique ON public.leagues(public.league_name_key(name));
ALTER TABLE public.leagues ADD CONSTRAINT nc_f1_league_name_valid CHECK(name=public.normalize_league_name(name) AND char_length(name) BETWEEN 1 AND 80);
ALTER TABLE public.leagues ADD CONSTRAINT nc_f1_owner_membership FOREIGN KEY(id,owner_user_id) REFERENCES public.league_members(league_id,user_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION public.inspect_league_name(p_name text,p_except uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
 SELECT jsonb_build_object('name',public.normalize_league_name(p_name),'key',public.league_name_key(p_name),'available',NOT EXISTS(SELECT 1 FROM public.leagues WHERE public.league_name_key(name)=public.league_name_key(p_name) AND (p_except IS NULL OR id<>p_except)));
$body$;

CREATE FUNCTION public.create_league_with_owner(p_actor uuid,p_name text,p_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues; joined timestamptz;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.users WHERE id=p_actor) THEN RETURN jsonb_build_object('ok',false,'status',403,'error','Account unavailable'); END IF;
 INSERT INTO public.leagues(name,owner_user_id,password_hash,is_global) VALUES(public.normalize_league_name(p_name),p_actor,p_hash,false) RETURNING * INTO l;
 INSERT INTO public.league_members(league_id,user_id) VALUES(l.id,p_actor) RETURNING joined_at INTO joined;
 RETURN jsonb_build_object('ok',true,'status',201,'state','created','league',jsonb_build_object('id',l.id,'name',l.name,'owner_user_id',l.owner_user_id,'is_global',l.is_global,'created_at',l.created_at,'updated_at',l.updated_at,'requires_password',l.password_hash IS NOT NULL)||jsonb_build_object('is_member',true,'joined_at',joined));
 EXCEPTION WHEN unique_violation THEN RETURN jsonb_build_object('ok',false,'status',409,'error','League name is already in use');
END;
$body$;

CREATE FUNCTION public.join_league_member(p_actor uuid,p_league uuid,p_expected_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues; joined timestamptz;
BEGIN
 SELECT * INTO l FROM public.leagues WHERE id=p_league FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',404,'error','League not found'); END IF;
 IF l.is_global THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Global league cannot be changed through league management'); END IF;
 SELECT joined_at INTO joined FROM public.league_members WHERE league_id=l.id AND user_id=p_actor;
 IF FOUND THEN RETURN jsonb_build_object('ok',true,'status',200,'state','already_member','league',jsonb_build_object('id',l.id,'name',l.name,'owner_user_id',l.owner_user_id,'is_global',l.is_global,'created_at',l.created_at,'updated_at',l.updated_at,'requires_password',l.password_hash IS NOT NULL)||jsonb_build_object('is_member',true,'joined_at',joined)); END IF;
 IF l.password_hash IS DISTINCT FROM p_expected_hash THEN RETURN jsonb_build_object('ok',false,'status',409,'error','League privacy or password changed; retry joining'); END IF;
 INSERT INTO public.league_members(league_id,user_id) VALUES(l.id,p_actor) ON CONFLICT(league_id,user_id) DO NOTHING;
 SELECT joined_at INTO joined FROM public.league_members WHERE league_id=l.id AND user_id=p_actor;
 RETURN jsonb_build_object('ok',true,'status',201,'state','joined','league',jsonb_build_object('id',l.id,'name',l.name,'owner_user_id',l.owner_user_id,'is_global',l.is_global,'created_at',l.created_at,'updated_at',l.updated_at,'requires_password',l.password_hash IS NOT NULL)||jsonb_build_object('is_member',true,'joined_at',joined));
END;
$body$;

CREATE FUNCTION public.transfer_league_ownership(p_actor uuid,p_league uuid,p_target uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues;
BEGIN
 SELECT * INTO l FROM public.leagues WHERE id=p_league FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',404,'error','League not found'); END IF;
 IF l.is_global THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Global league cannot be changed through league management'); END IF;
 IF l.owner_user_id IS DISTINCT FROM p_actor THEN RETURN jsonb_build_object('ok',false,'status',403,'error','Only the current league owner may perform this action'); END IF;
 IF p_target IS NULL OR p_target=p_actor OR NOT EXISTS(SELECT 1 FROM public.league_members WHERE league_id=l.id AND user_id=p_target) THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Choose another active league member as owner'); END IF;
 UPDATE public.leagues SET owner_user_id=p_target,updated_at=clock_timestamp() WHERE id=l.id RETURNING * INTO l;
 RETURN jsonb_build_object('ok',true,'status',200,'state','transferred','league',jsonb_build_object('id',l.id,'name',l.name,'owner_user_id',l.owner_user_id,'is_global',l.is_global,'created_at',l.created_at,'updated_at',l.updated_at,'requires_password',l.password_hash IS NOT NULL));
END;
$body$;

CREATE FUNCTION public.remove_league_membership(p_actor uuid,p_league uuid,p_target uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues; target_id uuid;
BEGIN
 SELECT * INTO l FROM public.leagues WHERE id=p_league FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',404,'error','League not found'); END IF;
 IF l.is_global THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Global league cannot be changed through league management'); END IF;
 target_id:=coalesce(p_target,p_actor);
 IF p_target IS NOT NULL THEN
  IF l.owner_user_id IS DISTINCT FROM p_actor THEN RETURN jsonb_build_object('ok',false,'status',403,'error','Only the current league owner may perform this action'); END IF;
  IF p_target=p_actor THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Owner cannot remove themselves; transfer ownership or delete the league'); END IF;
 ELSIF l.owner_user_id=p_actor THEN RETURN jsonb_build_object('ok',false,'status',409,'error','Transfer ownership or delete the league before leaving'); END IF;
 DELETE FROM public.league_members WHERE league_id=l.id AND user_id=target_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',400,'error','User is not a league member'); END IF;
 RETURN jsonb_build_object('ok',true,'status',200,'state',CASE WHEN p_target IS NULL THEN 'left' ELSE 'removed' END,'league',jsonb_build_object('id',l.id,'name',l.name,'requires_password',l.password_hash IS NOT NULL,'is_member',p_target IS NOT NULL));
END;
$body$;

CREATE FUNCTION public.update_league_settings(p_actor uuid,p_league uuid,p_name text,p_private boolean,p_hash text,p_expected_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues;
BEGIN
 SELECT * INTO l FROM public.leagues WHERE id=p_league FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',404,'error','League not found'); END IF;
 IF l.is_global THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Global league cannot be changed through league management'); END IF;
 IF l.owner_user_id IS DISTINCT FROM p_actor THEN RETURN jsonb_build_object('ok',false,'status',403,'error','Only the current league owner may perform this action'); END IF;
 IF l.password_hash IS DISTINCT FROM p_expected_hash THEN RETURN jsonb_build_object('ok',false,'status',409,'error','League settings changed; reload before saving'); END IF;
 IF p_private IS TRUE AND (p_hash IS NULL OR p_hash='') THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Private league requires a new valid password'); END IF;
 UPDATE public.leagues SET name=coalesce(public.normalize_league_name(p_name),name),password_hash=CASE WHEN p_private IS NULL THEN password_hash WHEN p_private THEN p_hash ELSE NULL END,updated_at=clock_timestamp() WHERE id=l.id RETURNING * INTO l;
 RETURN jsonb_build_object('ok',true,'status',200,'state','updated','league',jsonb_build_object('id',l.id,'name',l.name,'owner_user_id',l.owner_user_id,'is_global',l.is_global,'created_at',l.created_at,'updated_at',l.updated_at,'requires_password',l.password_hash IS NOT NULL));
 EXCEPTION WHEN unique_violation THEN RETURN jsonb_build_object('ok',false,'status',409,'error','League name is already in use');
END;
$body$;

CREATE FUNCTION public.delete_league_confirmed(p_actor uuid,p_league uuid,p_confirm boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE l public.leagues;
BEGIN
 SELECT * INTO l FROM public.leagues WHERE id=p_league FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false,'status',404,'error','League not found'); END IF;
 IF l.is_global THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Global league cannot be changed through league management'); END IF;
 IF l.owner_user_id IS DISTINCT FROM p_actor THEN RETURN jsonb_build_object('ok',false,'status',403,'error','Only the current league owner may perform this action'); END IF;
 IF p_confirm IS DISTINCT FROM true THEN RETURN jsonb_build_object('ok',false,'status',400,'error','Explicit confirm_delete=true is required'); END IF;
 DELETE FROM public.leagues WHERE id=l.id;
 RETURN jsonb_build_object('ok',true,'status',200,'state','deleted','league',jsonb_build_object('id',l.id,'name',l.name,'is_member',false));
END;
$body$;
ALTER FUNCTION public.normalize_league_name(text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.normalize_league_name(text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.normalize_league_name(text) TO postgres,service_role;
ALTER FUNCTION public.league_name_key(text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.league_name_key(text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.league_name_key(text) TO postgres,service_role;
ALTER FUNCTION public.inspect_league_name(text,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.inspect_league_name(text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.inspect_league_name(text,uuid) TO postgres,service_role;
ALTER FUNCTION public.create_league_with_owner(uuid,text,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.create_league_with_owner(uuid,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.create_league_with_owner(uuid,text,text) TO postgres,service_role;
ALTER FUNCTION public.join_league_member(uuid,uuid,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.join_league_member(uuid,uuid,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.join_league_member(uuid,uuid,text) TO postgres,service_role;
ALTER FUNCTION public.transfer_league_ownership(uuid,uuid,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.transfer_league_ownership(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_league_ownership(uuid,uuid,uuid) TO postgres,service_role;
ALTER FUNCTION public.remove_league_membership(uuid,uuid,uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.remove_league_membership(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.remove_league_membership(uuid,uuid,uuid) TO postgres,service_role;
ALTER FUNCTION public.update_league_settings(uuid,uuid,text,boolean,text,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.update_league_settings(uuid,uuid,text,boolean,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.update_league_settings(uuid,uuid,text,boolean,text,text) TO postgres,service_role;
ALTER FUNCTION public.delete_league_confirmed(uuid,uuid,boolean) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.delete_league_confirmed(uuid,uuid,boolean) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.delete_league_confirmed(uuid,uuid,boolean) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
