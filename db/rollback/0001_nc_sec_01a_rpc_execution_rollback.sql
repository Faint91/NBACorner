-- EMERGENCY REVERSAL ONLY. Requires explicit approval; never run automatically.
-- Restores only captured PUBLIC/anon/authenticated EXECUTE on these signatures.
-- Pre-change ACL for each: {=X/postgres,postgres=X/postgres,anon=X/postgres,
-- authenticated=X/postgres,service_role=X/postgres}. No grant options added.
-- Server/owner grants and function definitions are not modified.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
GRANT EXECUTE ON FUNCTION
  public.atomic_update_match(uuid,text,text,integer),
  public.set_master_bracket(uuid,uuid),
  public.set_winner_atomic(uuid,text,integer),
  public.undo_prediction_atomic(uuid)
TO PUBLIC, anon, authenticated;
COMMIT;
