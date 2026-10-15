-- Narrow canonical finalization only. Earlier rollover steps remain separate.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user <> 'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE FUNCTION public.finalize_season_transition(p_source_season_id uuid,p_new_season_id uuid,p_new_season_code text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE selected_id uuid; target public.seasons%ROWTYPE; BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_source_season_id THEN RAISE EXCEPTION 'Canonical source season changed' USING ERRCODE='40001'; END IF;
 IF p_new_season_id IS NULL OR p_new_season_id=selected_id THEN RAISE EXCEPTION 'Distinct target season required'; END IF;
 SELECT * INTO STRICT target FROM public.seasons WHERE id=p_new_season_id FOR SHARE;
 IF target.code IS DISTINCT FROM p_new_season_code OR target.code !~ '^[0-9]{4}-[0-9]{2}$' THEN RAISE EXCEPTION 'Target season code mismatch'; END IF;
 IF right(target.code,2)::integer <> (left(target.code,4)::integer+1)%100 THEN RAISE EXCEPTION 'Invalid target season code'; END IF;
 IF target.regular_season_end_utc IS NULL OR target.playoffs_start_utc IS NULL
 OR NOT isfinite(target.regular_season_end_utc) OR NOT isfinite(target.playoffs_start_utc)
 OR target.regular_season_end_utc>target.playoffs_start_utc THEN RAISE EXCEPTION 'Target season timing is unconfigured or invalid'; END IF;
 -- Same canonical lock order as publish_current_standings; no stale refresh crosses activation.
 UPDATE public.application_season SET season_id=target.id WHERE singleton;
 DELETE FROM public.standings WHERE id IS NOT NULL;
 RETURN jsonb_build_object('state','transitioned','season_id',target.id,'season_code',target.code,'standings_count',0);
END;
$body$;
ALTER FUNCTION public.finalize_season_transition(uuid,uuid,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.finalize_season_transition(uuid,uuid,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.finalize_season_transition(uuid,uuid,text) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
