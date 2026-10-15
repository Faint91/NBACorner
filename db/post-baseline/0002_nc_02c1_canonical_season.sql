-- Durable canonical season designation; intentionally unconfigured after migration.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $$ BEGIN IF current_user <> 'postgres' THEN RAISE EXCEPTION 'Migration requires postgres'; END IF; END $$;
CREATE TABLE public.application_season (
  singleton boolean NOT NULL DEFAULT true,
  season_id uuid NOT NULL,
  CONSTRAINT application_season_pkey PRIMARY KEY(singleton),
  CONSTRAINT application_season_singleton_check CHECK(singleton),
  CONSTRAINT application_season_season_id_fkey FOREIGN KEY(season_id) REFERENCES public.seasons(id) ON DELETE RESTRICT
);
ALTER TABLE public.application_season OWNER TO postgres;
ALTER TABLE public.application_season ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.application_season FROM PUBLIC,anon,authenticated;
GRANT ALL ON public.application_season TO postgres,service_role;
-- No row inserted: a separately authorized designation must name a verified season.
NOTIFY pgrst,'reload schema';
COMMIT;
