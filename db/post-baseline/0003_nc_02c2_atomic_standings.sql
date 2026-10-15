-- ESPN validated current-state publication. No season history or data rewrites.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user <> 'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE FUNCTION public.publish_current_standings(p_season_id uuid,p_rows jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $body$
DECLARE selected_id uuid; season_row public.seasons%ROWTYPE; stamp timestamp; BEGIN
 SELECT season_id INTO STRICT selected_id FROM public.application_season WHERE singleton FOR UPDATE;
 IF selected_id IS DISTINCT FROM p_season_id THEN RAISE EXCEPTION 'Canonical season changed' USING ERRCODE='40001'; END IF;
 SELECT * INTO STRICT season_row FROM public.seasons WHERE id=selected_id FOR SHARE;
 IF season_row.regular_season_end_utc IS NULL THEN RAISE EXCEPTION 'Canonical freeze is unconfigured'; END IF;
 IF clock_timestamp() >= season_row.regular_season_end_utc THEN
  RETURN jsonb_build_object('state','frozen','refreshed',false,'season_code',season_row.code,'team_count',0);
 END IF;
 IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' OR jsonb_array_length(p_rows)<>30 THEN RAISE EXCEPTION 'Expected 30 standings rows'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r WHERE jsonb_typeof(r) IS DISTINCT FROM 'object') THEN RAISE EXCEPTION 'Invalid standings row'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r WHERE
  (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(r) k) IS DISTINCT FROM ARRAY['code','conference','losses','name','seed','win_pct','wins']::text[]
  OR jsonb_typeof(r->'code') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'name') IS DISTINCT FROM 'string'
  OR jsonb_typeof(r->'conference') IS DISTINCT FROM 'string' OR length(btrim(r->>'name'))=0
  OR jsonb_typeof(r->'seed') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'wins') IS DISTINCT FROM 'number'
  OR jsonb_typeof(r->'losses') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'win_pct') IS DISTINCT FROM 'number') THEN RAISE EXCEPTION 'Invalid standings fields'; END IF;
 IF (SELECT count(DISTINCT r->>'code') FROM jsonb_array_elements(p_rows) r)<>30
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r LEFT JOIN public.teams t ON t.code=r->>'code' WHERE t.id IS NULL OR lower(t.conference) IS DISTINCT FROM r->>'conference'
 OR r->>'code' NOT IN ('ATL','BOS','BKN','CHA','CHI','CLE','DET','IND','MIA','MIL','NYK','ORL','PHI','TOR','WAS','DAL','DEN','GSW','HOU','LAC','LAL','MEM','MIN','NOP','OKC','PHX','POR','SAC','SAS','UTA')) THEN RAISE EXCEPTION 'Invalid or duplicate canonical team'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r WHERE
  (r->>'seed')::numeric NOT BETWEEN 1 AND 15 OR (r->>'seed')::numeric<>trunc((r->>'seed')::numeric)
  OR (r->>'wins')::numeric<0 OR (r->>'wins')::numeric<>trunc((r->>'wins')::numeric)
  OR (r->>'losses')::numeric<0 OR (r->>'losses')::numeric<>trunc((r->>'losses')::numeric)
  OR (r->>'win_pct')::numeric NOT BETWEEN 0 AND 1)
 OR (SELECT count(*) FROM jsonb_array_elements(p_rows) r WHERE r->>'conference'='east')<>15
 OR (SELECT count(*) FROM jsonb_array_elements(p_rows) r WHERE r->>'conference'='west')<>15
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_rows) r GROUP BY r->>'conference',(r->>'seed')::numeric HAVING count(*)<>1) THEN RAISE EXCEPTION 'Invalid standings ranks or results'; END IF;
 -- Defensive validation completed. DELETE and INSERT are one transaction.
 stamp := timezone('UTC',clock_timestamp());
 DELETE FROM public.standings WHERE id IS NOT NULL;
 INSERT INTO public.standings(code,name,conference,seed,wins,losses,win_pct,updated_at)
 SELECT x.code,x.name,x.conference,x.seed,x.wins,x.losses,x.win_pct,stamp
 FROM jsonb_to_recordset(p_rows) AS x(code text,name text,conference text,seed integer,wins integer,losses integer,win_pct double precision);
 RETURN jsonb_build_object('state','refreshed','refreshed',true,'season_code',season_row.code,'team_count',30,'updated_at',stamp);
END;
$body$;
REVOKE ALL ON FUNCTION public.publish_current_standings(uuid,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.publish_current_standings(uuid,jsonb) TO postgres,service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
