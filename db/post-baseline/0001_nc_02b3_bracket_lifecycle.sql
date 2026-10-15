-- NC-02B3 portable forward migration. Apply after the secured NC-ENV baseline.
BEGIN;
SET LOCAL lock_timeout='5s';
LOCK TABLE public.brackets IN ACCESS EXCLUSIVE MODE;
DO $preflight$
BEGIN
  IF current_user <> 'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF;
  IF EXISTS (SELECT 1 FROM public.brackets WHERE deleted_at IS NULL GROUP BY user_id,season_id HAVING count(*)>1) THEN
    RAISE EXCEPTION 'Duplicate active user-season brackets; manual review required';
  END IF;
  IF EXISTS (SELECT 1 FROM public.brackets WHERE deleted_at IS NULL AND is_master IS TRUE GROUP BY season_id HAVING count(*)>1) THEN
    RAISE EXCEPTION 'Duplicate active masters; manual review required';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_index WHERE indexrelid='public.uniq_active_bracket_per_user_per_season'::regclass AND indisunique AND indisvalid AND indisready) THEN
    RAISE EXCEPTION 'Required per-season uniqueness missing';
  END IF;
END $preflight$;
DROP INDEX public.unique_active_bracket_per_user;
CREATE FUNCTION public.create_master_bracket_atomic(p_user_id uuid, p_season_id uuid, p_replace boolean, p_matches jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE
  old_id uuid;
  new_row public.brackets%ROWTYPE;
  season_row public.seasons%ROWTYPE;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.users WHERE id=p_user_id AND is_admin IS TRUE) THEN
    RAISE EXCEPTION 'Master operation requires an admin' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT season_row FROM public.seasons WHERE id=p_season_id FOR UPDATE;
  SELECT id INTO old_id FROM public.brackets WHERE season_id=p_season_id AND deleted_at IS NULL
    AND (is_master IS TRUE OR id=season_row.master_bracket_id);
  IF old_id IS NOT NULL AND p_replace IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'Explicit master replacement confirmation required' USING ERRCODE='P0001';
  END IF;
  IF jsonb_typeof(p_matches) IS DISTINCT FROM 'array' OR jsonb_array_length(p_matches)<>21 THEN
    RAISE EXCEPTION 'Invalid master match graph';
  END IF;
  IF old_id IS NOT NULL THEN
    UPDATE public.brackets SET deleted_at=now(),deleted_by_user_id=p_user_id WHERE id=old_id;
  END IF;
  INSERT INTO public.brackets(user_id,season_id,is_master) VALUES(p_user_id,p_season_id,true) RETURNING * INTO new_row;
  INSERT INTO public.matches(id,bracket_id,conference,round,slot,team_a,team_b,next_match_id,next_slot)
    SELECT x.id,new_row.id,x.conference,x.round,x.slot,x.team_a,x.team_b,x.next_match_id,x.next_slot
    FROM jsonb_to_recordset(p_matches) AS x(id uuid,conference text,round integer,slot integer,team_a text,team_b text,next_match_id uuid,next_slot text);
  UPDATE public.seasons SET master_bracket_id=new_row.id WHERE id=p_season_id;
  RETURN to_jsonb(new_row);
END;
$body$;
REVOKE ALL ON FUNCTION public.create_master_bracket_atomic(uuid,uuid,boolean,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.create_master_bracket_atomic(uuid,uuid,boolean,jsonb) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
