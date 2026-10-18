# NC-04B deployment / rollback / smoke runbook — PLANNING ONLY

**NO-GO. NC-04A is BLOCKED. Do not execute this runbook.**
No deployment authorization was given. NC-03R3 repaired the reset-link defect locally
at a2a930291e32a6f73e03c2acf4dd0732eac70263. Resumed NC-04A verified effective
ACLs, master graph, lifecycle/history/reset state and www SPA deep links. Recovery,
canonical identity, protected configuration and operational release gates remain NO-GO.
This document does not start NC-04B or authorize any production write.

## Actual observed release gap

Production: Supabase NBA Corner/main/PRODUCTION `rpwesmvzmgoctrokrbhy`, PostgreSQL17.6,
secured baseline-equivalent; none of the release0001-0011 migrations are present.
Render `srv-d4239u6uk2gs73b8fts0`, live backend
`5bcb0b43ae0c232381ae857cd40c3fd7b1e23422`, starts `gunicorn app:app`.
Actual public frontend is https://www.nbacorner.com. Tokenless /reset-password
returns the same HTTP200 SPA HTML as /login; bundle contains the reset route and
HTTPS Render API origin. Cloudflare response headers do not establish hosting
provider. Hosting dashboard/build config and exact deployed frontend commit remain
unverified; remote repository main is not assumed to be deployed.
Frontend production version/configuration is not fully verified. Do not substitute
local Vite settings or infer frontend readiness from the backend service.

Only2025-26 has stored timing/master among nine seasons; no application_season table
or canonical designation exists. Selecting that row or another source requires an
explicit business/operator decision. Do not use the current date to choose a new
season or invoke rollover as deployment preparation.

## Gates before any execution

- Preserve the completed R3 local repair and validation. Obtain boolean-only actual
  runtime FRONTEND_ORIGIN validation: nonblank, valid HTTPS origin, actual www
  frontend and distinct from Render API. Required name presence is not a pass.
- Reuse resumed effective table/view/column/sequence/browser CREATE checks, all
  seven app function body hashes,16 policies and complete21-match admin master proof.
  Refresh critical data-sensitive checks immediately before release; no need to
  repeat already-valid expensive scans without drift evidence.
- Obtain boolean-only R1 validation of the existing runtime JWT secret. Name presence
  is insufficient. Do not reveal it or rotate it automatically. Render Free lacks
  Shell; choose a separately approved secure validation method rather than bypassing
  hidden fields or creating a new remote executor.
- Verify trusted Supabase credentials/provider-approved sender and email config,
  explicit environment classification,correct CORS/frontend/API pair and disabled
  test-admission/capture/fixture/rate-limit bypass settings. NBA_CORNER_ENV absence
  uses the code's legacy production behavior; explicit deployment policy still needs
  verification. NBA_CORNER_JOBS_ENABLED is TEST-ONLY, not a production pause switch.
- Prove a dated,restorable backup/PITR/equivalent for the exact project,with recovery
  point/retention/access owner and restoration steps. Current Free project has no
  scheduled backups/PITR. An external equivalent has not been verified. Creation,
  plan changes or restore testing need separate authorization; no cost commitment here.
- Reconfirm zero league/username/email normalized collisions,valid owner memberships,
  valid approved canonical season/master,baseline compatibility and no rollover lock.
- Approve a real maintenance/write-quiescence mechanism and verify external scheduler
  registrations. Render Free does not provide built-in maintenance mode. UI-only
  frontend hiding does not block direct API writes. No push/deploy/config change until
  automatic deployment behavior and API/workflow pause/resume semantics are verified.

Any failed or unknown gate is NO-GO. A migration guard failure means STOP; do not
rename users/leagues,drop constraints,merge identities or patch production ad hoc.

## Ordered future release sequence — requires separate authorization

1. Record approved repaired release commits,actual frontend version/runtime settings,
   production project and schema fingerprint. Confirm operator maintenance authority,
   backup/recovery owner and all GO gates. Use the repaired R3 backend and matching approved frontend commits, never the
   old incompatible production binary or an obsolete NC03 candidate.
2. Announce the controlled window; verify the restorable backup and retain exact
   deployed runtime keys securely outside documentation/Git.
3. Enter approved API write quiescence and pause actual external standings workflows
   and other mutation callers. Verify the old backend cannot serve mutation traffic
   throughout the incompatible schema window. Existing Render Suspend Web Service is the proposed mechanism, not yet executed.
   Prove deploy-while-suspended/resume behavior and capture Auto-Deploy state before
   authorization; no old binary may resume on0011. If this cannot be established,
   approve another supported quiescence mechanism before GO; do not briefly resume old code on0011.
4. Rerun critical READ ONLY preflights:identity/schema,no collisions,owner/member,
   canonical-source decision/timing/master,history shape,no locks/unfinished work.
   Recheck safe config booleans and backup recovery point. Abort if state drifted.
5. Under the reviewed postgres creator role,apply only the outstanding forward
   migrations below in exact order,each with its existing transaction/guards. Do not
   replay the consolidated empty-database baseline or the already-contained security
   migrations. Capture success/failure without credentials or user payloads.

   1. `db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql`
   2. `db/post-baseline/0002_nc_02c1_canonical_season.sql`
   3. `db/post-baseline/0003_nc_02c2_atomic_standings.sql`
   4. `db/post-baseline/0004_nc_02c3_season_transition.sql`
   5. `db/post-baseline/0005_nc_02d1_atomic_scores.sql`
   6. `db/post-baseline/0006_nc_02d2_final_snapshots.sql`
   7. `db/post-baseline/0007_nc_02e_atomic_rollover.sql`
   8. `db/post-baseline/0008_nc_02f1_league_lifecycle.sql`
   9. `db/post-baseline/0009_nc_02f2_league_history.sql`
   10. `db/post-baseline/0010_nc_02g1_identity_auth.sql`
   11. `db/post-baseline/0011_nc_02g2_password_reset_sessions.sql`

6. After0002 exists and before new backend startup,perform only the separately
   approved exact canonical designation for the confirmed source season. It is a
   production data write requiring explicit scope/identity; no implicit latest-season
   selection,season creation,refresh,snapshot or rollover. Reverify timing/master.
7. Validate final schema/security with approved READ ONLY verification;check row-count
   continuity and protected records,auth_version0 initialization,all13 legacy reset
   records intentionally invalidated,legacy global history preserved,league membership
   retained,new function ACLs closed. Verify actual creator and platform drift.
8. Deploy the repaired compatible backend with existing valid JWT key and verified
   settings while traffic remains controlled. Confirm startup/canonical resolution
   succeeds and reset links point to the intended frontend. No job trigger.
9. Deploy the matching frontend with verified public API origin and no backend keys.
   Ensure reset route and token bootstrap/URL cleanup work on that origin. Keep old
   cached frontend assumptions in mind; coordinate release/cache strategy explicitly.
10. Execute only separately authorized safe smoke below. Compare pre/post integrity
    counts while accounting for ordinary traffic only after maintenance ends.
11. Verify expected current-season freeze and standings read state. Re-enable only
    previously approved required schedules after all checks pass. The local workflow
    source runs09:00UTC; actual GitHub registration is manually DISABLED and must stay held unless
    separately approved. Render inventory contains3 Python web services, no cron
    service; pg_cron is absent. No automatic rollover was found in reviewed scope. Do not
    manually refresh or invoke rollover as a smoke test.
12. Monitor sanitized errors/auth/reset/league/history/standings/API/canonical results.
    Exit maintenance only after GO remains true. Preserve evidence and rollback owner.

No exact production connection string,credential,synthetic user or destructive command
is embedded here. Production-like dry-run strategy uses synthetic shapes only:
57 synthetic users,21complete bracket graphs,1league/1membership,7legacy headers and
140synthetic history rows,13synthetic legacy reset records and the observed null timing
pattern. Existing NC-03 full-chain proofs already cover functionality/concurrency;
a shape rehearsal has not been performed in NC-04A and must not copy real PII/hashes.

## Compatibility and session/link consequences

| Pair/state | Gate |
|---|---|
| Old frontend + new backend | Conditional basic login/reads only; actual old frontend unverified; not complete feature compatibility. |
| New frontend + live old backend | Unsafe for full canonical/G2/league/history contracts. |
| Live old backend + migrated DB | Unsafe:raw token column contract changes and old validation ignores revocation versions. |
| New backend + current DB | Unsafe:canonical table/auth_version/RPCs are absent. |
| Existing JWTs | Preserve same valid key; missing av means version0;successful reset increments version and revokes older JWTs. No deployment-time artificial reset/revocation. |
| Old reset emails |0011invalidates13legacy records;0unused/unexpired at observation. Users need a fresh link;low-support window guidance required. |
| Existing histories | Preserve7legacy structured headers/140rows;do not mark them newly final,backfill source mapping or fabricate historical league membership. |

## Safe post-release smoke — not performed

1. Use new code's safe read contracts for /season and /health;honor health token
   policy without logging it. Confirm canonical identity/timing/freeze.
2. Read standings through explicitly approved READ ONLY SQL because no dedicated
   GET standings endpoint exists. Confirm30known codes/15per conference;do not refresh.
3. Public league discovery/known public league history only;global history currently
   requires auth. Confirm legacy history remains readable through supported APIs.
4. If an existing designated safe test account is approved:login,protected read and
   private membership denial. No arbitrary real-user impersonation or account creation.
5. Only if separately approved mailbox/account exists:reset request/completion after
   link routing repair. Completion changes password/session version and is not part
   of unconditional read-only smoke. Never reset a real user's account for testing.
6. Inspect frontend error handling without synthetic analytics or product mutations.

Exclude rollover,snapshots,bracket edits/deletes,league deletion,standings refresh,
job invocations and unapproved mail. Unavailable credentials/mailbox =>conditional,
not fabricated or bypassed.

## Rollback / abort runbook — not executed

- Before migrations:abort;leave code/schema/data unchanged. Undo only separately
  approved maintenance/scheduler pauses according to captured original state.
- After migrations,before backend:keep incompatible old code quiescent. Do not resume
  pre-G2 code on0011. Prefer compatible forward release/fix;DB rollback or restoration
  needs explicit approval,verified backup and reviewed constraint/data consequences.
- After backend:rollback only to an audited schema-compatible and version-aware
  backend with the same valid explicit key. Old fallback-signing/old raw reset code
  is not an acceptable rollback. Do not infer credential rollback from code rollback.
- After frontend:frontend rollback does not restore reset UI/server ranks/canonical
  capabilities;choose only a compatible pair while holding maintenance if necessary.
- Data recovery:0011deleted links cannot be safely resurrected by code rollback.
  Completed resets/auth_version increments must preserve revocation semantics.
  New uniqueness constraints require collision review before schema reversal.
  Immutable history is not rewritten. Future rollover hard-deleted drafts or league
  history deletion would need explicit backup/PITR decisions;no such operation occurs
  during deployment. Restoring old auth data can reinstate compromised sessions and
  must be evaluated independently. No restore is automatically authorized.

## First-release monitoring — design only

Observe backend5xx and sanitized DB/RPC failures;auth401/403/login anomalies;reset
request/completion failures without verifiers;league/history/standings errors;frontend
API failures;canonical status and expected scheduled job results. Investigate new
systemic failures before exiting maintenance. Compare to an approved baseline and
assign operator ownership during the window. No alerts or monitoring settings were
created/changed here;never log passwords,JWTs,reset values,keys or connection strings.

**Current next step:resolve the resumed NC-04A GO gates under separate authorization.**
NC-04B remains unstarted and unauthorized.

## Resumed NC-04A addendum — 2026-10-18 (planning only)

- Production now has57 users (formerly53); other aggregate scale unchanged:
  21brackets/441matches/14scores/1league/1membership/7headers/140historyrows.
  This audit made no product writes. Do not use stale counts as release invariants.
- Recovery NO-GO:scheduled backups absent on Free; PITR not enabled; external
  equivalent unverified. Choose and separately authorize exact-project backup and
  credible restoration verification; document recovery point,retention,owner.
- Canonical NO-GO:2025-26 alone has timing/master evidence; business intent is not
  inferred from that fact.0002 intentionally creates no designation. Require exact
  approved source/timings and separate write authorization after0002,before backend.
- Config NO-GO:JWT_SECRET and FRONTEND_ORIGIN protected values never retrieved;
  provider/sender validity and FLASK_ENV/rate-limit/debug state remain unknown.
  Reuse pure R1/R3 validators in a separately approved secure operator/runtime
  context with boolean-only output; do not add an executor,load local dotenv as
  production evidence,reveal values,rotate keys or email users to prove config.
- Old frontend/new backend:basic contracts conditional,full deployed build contract
  unproved. New frontend/old backend unsafe; old backend/migratedDB unsafe; new
  backend/oldDB unsafe. R3+www UI route passes static structure,actual runtime origin
  remains unverified. Migrated backend+legacy emails invalidated by design.
- During any migration failure:retain quiescence; the failing migration transaction
  may roll back while earlier committed migrations remain. Inspect actual level;
  never blindly replay or resume old code. Prefer audited compatible forward repair;
  restore/down migration requires explicit review and recovery authorization.
- Tokenless frontend route load is the only unconditional reset smoke. Reset mail,
  password/version changes and designated account login require their own approved
  account/mailbox scope. No smoke is performed in NC-04A.
- Assign monitoring owner and baseline/abort thresholds for5xx,auth401/403,login,
  reset,DB/RPC,league/history,standings,canonical and browser API errors before GO.
- Full findings and57-item report: nc-04a-production-preflight-resumed.md.
