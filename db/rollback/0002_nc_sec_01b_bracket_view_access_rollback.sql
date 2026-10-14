-- EMERGENCY REVERSAL ONLY: separate explicit approval required.
-- Captured anon/authenticated ACL: arwdDxtm (eight privileges), no grant options.
-- PUBLIC had no relation/column grant: do NOT add one during rollback.
-- No explicit column ACLs existed. Trusted grants and view SQL remain unchanged.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN
ON TABLE public.bracket_view TO anon, authenticated;
COMMIT;
