-- Offline rollback design; never delete/merge rows to satisfy old uniqueness.
BEGIN;
LOCK TABLE public.brackets IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.brackets WHERE deleted_at IS NULL GROUP BY user_id HAVING count(*)>1) THEN
  RAISE EXCEPTION 'Rollback blocked: cross-season active rows require a reviewed plan';
 END IF;
END $$;
CREATE UNIQUE INDEX unique_active_bracket_per_user ON public.brackets(user_id) WHERE deleted_at IS NULL;
DROP FUNCTION public.create_master_bracket_atomic(uuid,uuid,boolean,jsonb);
NOTIFY pgrst,'reload schema';
COMMIT;
