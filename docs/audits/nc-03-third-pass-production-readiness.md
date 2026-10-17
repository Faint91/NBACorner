# NC-03 third-pass production-readiness plan

NC-03 third pass PASS; maximum readiness: READY FOR CONTROLLED PRODUCTION PREFLIGHT.
Final evidence is recorded in the accompanying third-pass compliance report. This document authorizes no production action.
No production preflight, deployment, credential rotation or real reset email was run.

## Configuration and read-only preflight

Complete names-only configuration registry: db/records/nc_03_pass3_configuration.json.
Backend requires explicit valid JWT_SECRET, correct trusted Supabase app/job keys,
provider email readiness, canonical DB authority and correct public frontend/API/CORS
pairing. No credential values are recorded. No automatic secret rotation is planned.

Read-only tooling added for later authorized NC-04:

- db/audits/nc03_before_migrations_readonly.sql: baseline catalog, exact Unicode
  normalized league/identity collision counts, invalid league names, owner/member
  integrity, duplicate memberships, legacy reset invalidation counts, bracket/user/
  season/master/history integrity counts. Returns no names, addresses, hashes/tokens.
- db/audits/nc03_after_0011_readonly.sql: final canonical designation/version state,
  immutable snapshot counts, league headers, unfinished rollover, relation/function
  catalog. These scripts never write, designate a season or call operational RPCs.
- db/baseline/validate_baseline.py is an offline source integrity check.
  db/post-baseline/verify_current_schema.sql verifies the reviewed final schema;
  do not substitute it for old-schema identification before migration.
- Provider/runtime/hosting/scheduler/backup state requires secure operator checks;
  SQL cannot verify an environment key, routing or that a backup is restorable.
  Those expected production checks remain unexecuted, not inferred successful.

Verify the migration creator is the reviewed postgres role. Current app relations
are closed; retained function defaults require explicit revokes. Platform-owned
supabase_admin default ACLs are not covered by postgres table/sequence hardening;
stop on an unexpected migration owner instead of assuming every creator is safe.

First fingerprint the authorized production schema/code/project and obtain backup
and restoration proof. If it differs from the reviewed baseline, STOP; do not apply
a consolidated bootstrap over an existing DB or guess which forward migration ran.
0008 requires resolving normalized names/owner/member anomalies through separately
approved data work.0010 requires explicit review of normalized identity collisions
and null/blank identities; never merge users automatically.0011 deliberately clears
all legacy reset links and initializes auth_version. Record only counts/decisions.

Timing preflight counts all seasons for review: historical nullable timing is not
automatically a blocker; the explicitly designated current season must be valid.
Legacy snapshot headers and outstanding-reset counts are informational/review
inputs, not permission to backfill or rewrite immutable history. Verify source
bracket uniqueness/master alignment, expected30-team mapping and snapshot integrity.
No accidental snapshot/rollover operation belongs in preflight or smoke.

## Safest eventual release order — design only

1. Obtain separate production authorization, fingerprint deployed versions/schema,
   take and verify a restorable backup; preserve current runtime keys securely.
2. Run authorized READ ONLY preflights and resolve blockers outside this audit.
3. Confirm required config and reset-link/frontend routing, CORS, provider sender
   and scheduler identities. If signing key is absent, unsafe or short, STOP for
   an explicit operational decision; do not silently rotate or reuse a fallback.
4. Enter coordinated maintenance: quiesce API mutations and externally pause the
   daily standings workflow/other callers. NBA_CORNER_JOBS_ENABLED is test-only
   and does not disable production jobs. Do not rely on it as a kill switch.
5. Apply only reviewed outstanding forward migrations0001–0011 in order. Do not
   re-bootstrap live production. A verified canonical source designation after
   migration0002 requires separate explicit data-write authorization; no automatic
   latest-season/calendar choice. Keep traffic paused through incompatibility.
6. Deploy matching backend, validate canonical state and runtime readiness, then
   deploy matching frontend. Verify email URL resolves to reset-completion UI.
7. Run only approved non-destructive/conditional smoke. Re-enable scheduled
   standings refresh only after canonical season/freeze/provider checks succeed.
8. Monitor sanitized errors,401/403/conflicts, reset delivery, safe health,
   canonical freshness and job results. Do not trigger rollover as validation.

## Compatibility matrix

Here “old” means pre-NC-02/G2 code; actual deployed versions are unknown and must be
fingerprinted during NC-04. Immediately previous frontend is unchanged by R1/R2.

| Pair/state | Assessment and evidence |
|---|---|
| Old frontend + new backend | Conditionally safe for unchanged login/basic reads only. Not a complete feature-compatible release: old UI can lack reset completion, canonical controls and authoritative ranks. Use coordinated maintenance and paired frontend. |
| New frontend + old backend | Unsafe for complete contracts: new reset completion, canonical season/league lifecycle/history paths and conflict semantics depend on new backend. |
| Old backend + migrated DB | Unsafe.0011 removes old raw-token column contract and new version-aware revocation must not be bypassed by old validators; earlier new RPC/constraints also change lifecycle assumptions. |
| New backend + pre-migration DB | Unsafe: canonical table, new RPCs and auth_version/token_digest are required. Missing reads fail closed rather than making this a safe mixed-version window. |
| Existing JWTs | Same valid configured signing key preserves signatures; missing-av means version0 only. Migrated users start0; successful reset increments version and revokes prior tokens. R1 never rotates keys. |
| Outstanding reset links | All pre-G2 links invalidated by0011; request a new link after compatible email/UI is live. No old-link resurrection or silent fallback. |
| Existing leagues/brackets/history | Forward migrations preserve intended data, but preflight collisions can block them.0009 does not backfill old league history;0006 preserves legacy global values. No actual rollover during deploy, so unsaved-draft deletion must not occur. |

## Rollback boundaries

Backend rollback to pre-G2 is not safe against0011 and could bypass revocation or
break reset storage. Prefer a reviewed forward correction; any rollback needs a
compatible schema/code pair and explicit recovery plan. Frontend rollback may
remove completion/rank/canonical features even if API reads still work. Do not
claim a UI rollback restores backend security or data.

Migration rollback is not data rollback: uniqueness changes need data review;
invalidated raw reset links do not recover automatically. Completed resets and
session-version increments survive code rollback. Hard-deleted rollover drafts,
confirmed league-specific history deletions and discarded old links require
explicit backup/recovery decisions. Never casually rewrite immutable finalized
global/league history. Restoring older auth data can alter revocation guarantees;
review recovery/session consequences rather than blindly restoring values.

## Safe production smoke plan — conditional, not executed

Read /season; there is no dedicated GET standings route. Use an explicitly approved
read-only standings SELECT (included in the post-migration SQL), safe public
league discovery/history with only an explicitly known public league, and health
using its configured access contract. Global history currently requires auth;
do not assume it is anonymous merely because its fields are public-safe.

Only with a designated approved test account, login and read /auth/test-me and a
safe existing product endpoint. Only with approved nonmember/member identities,
verify private denial. Reset request is conditional on an approved test mailbox;
completion revokes that account's sessions and requires separate explicit approval.
Do not invent credentials/mailboxes or reset any real account. No production
bracket mutation, deletion, snapshot, rollover, test-team helper or job invocation.

No production readiness claim beyond controlled preflight is possible until the
actual production checks and operator decisions above are separately authorized.
