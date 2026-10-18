# NC-04B deployment runbook — PLANNING ONLY

**NO-GO: NC-04A remains BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED.**
Gate-closure pass:2026-10-18. No NC-04B execution authorized. No backup, suspension,
config change, migration, designation, deployment, mail or job invocation performed.
Earlier chronology remains in the NC-04A report and machine evidence.

## Approved canonical decision (resolved)

Canonical production season for this migration: **2025-26**.
Status: **APPROVED BUSINESS DECISION**, explicitly supplied by user in gate-closure prompt.
After successful0002, designate exactly existing season
994f58bc-bdbc-422e-9786-bb5c8559ea0f, code2025-26. Verify exactly one canonical row,
correct season pointer and stored timing/master identity before0003. Stop on mismatch.
This is future execution guidance, not an NC-04A DB write. Do not designate2026-27,
create a new season or run transition/rollover during this migration. A later2026-27
transition uses the validated lifecycle only after the migrated app is stable.

## Current release evidence and gates

- Backend live Render srv-d4239u6uk2gs73b8fts0 commit
  5bcb0b43ae0c232381ae857cd40c3fd7b1e23422, reconfirmed by dashboard.
- Proposed known repaired backend source:ce44ea59d0789f3f86a11ea6224bf0b5129357ff
  (includes R3; subsequent audit-only commit has identical application files).
  Pin the separately authorized deployment SHA; do not use moving branch latest.
- Target frontend:4fa0e9fc11d49354e3da137ee43e9d1ddbc87357. Existing public www UI
  fingerprint and route/API evidence are in the prior pass. Exact deployed source
  SHA/provider build record is unknown; remote GitHub main is not deployment proof.
- Recovery mechanism:PASS under the authorized 2026-10-18 private logical backup/restore
  proof. See nc-04a2-recovery-verification.md. Platform scheduled backups/PITR remain
  absent;this is the verified private equivalent. A fresh backup after write quiescence
  immediately before migrations is still mandatory. Schema/catalog-only archives are
  not substituted for the complete backup.
- Protected JWT/origin/email/flags:BLOCKED. Masked names cannot establish runtime
  validity. Use restricted procedure nc-04a-production-config-validation.md in a
  separately approved secure context; no generic executor/environment dump.
- Frontend revision:CONDITIONALLY ACCEPTABLE for complete known-source replacement
  only if independently enforced maintenance prevents mixed-version exposure and
  old tabs/cached assets are explicitly handled. Not a general existing-build
  compatibility PASS. If replacement/maintenance cannot be guaranteed, BLOCKED.
- Quiescence:BLOCKED pending proven pause/deploy/resume semantics and Auto-Deploy
  state. Render exposes Suspend Web Service and lacks Free maintenance mode.
- Schema/data:previous verified observations remain nonblocking; no new DB scan
  necessary for these gates. All critical checks repeat at deployment time.

## Recovery mechanism and freshness — hard gate

Before release authorization, identify an existing usable recovery mechanism for
this exact project, establish controlled storage/access/owner and a credible restore
procedure/proof. Missing or unknown mechanism is NO-GO.

Exact outstanding action:separately authorize an appropriate platform recovery
arrangement or a protected complete logical database backup plus recovery verification.
It must cover application rows, schema, functions/triggers, constraints, sequences,
ACL/RLS, required roles/extensions and dependencies; catalogue-only CSV/schema exports
are insufficient. Do not put production rows, credentials or backup contents in Git.
Use an approved secured recovery target; never import real accounts into the canonical
synthetic test fixture or restore into production during verification.

During NC-04B, after confirmed write quiescence and drained transactions, create a
fresh backup/snapshot immediately before migrations, verify completion and the exact
project/recovery point, manifest/checksums, access and restore method. Historical backup
existence alone does not waive freshness. If no valid fresh recovery point, abort
before0001. Backup creation and any restore require explicit separate authorization.

## Suspension and write-quiescence analysis

Official Render suspend/resume endpoints exist; troubleshooting documents503 for
suspended services. Suspension is distinct from idle Free spin-down, which wakes on
traffic. Never use idle spin-down as maintenance. No suspension/resume was tested here.

NBA Corner data is in separate Supabase. Pausing a Render web process is not a DB
restore/delete operation (architecture inference), but it does not fence independent
DB writers, existing transactions or other services. Hold the independently disabled
GitHub standings workflow. Existing inventory found no Render cron,pg_cron or automatic
rollover; recheck relevant callers and active writes before backup. Any unknown writer
blocks migrations. Cancel/finish existing writes under authorized procedure, not here.

The reviewed official docs do NOT establish deterministic deploy-while-suspended,
resume revision selection, failed-deploy fallback or absence of restart/auto-deploy
races for this service. Do not assert pause/resume is a verified release fence.
Before GO, obtain authoritative provider confirmation or separately approved isolated
proof of exact semantics. Capture Auto-Deploy behavior without changing it here.
The old binary must never become accessible against the migrated DB, even on failure.
If this cannot be guaranteed, approve a supported ingress/process maintenance fence
before deployment; no improvised flag/credential/network workaround is authorized.

Frontend recommendation:leave the static site available with announced short API
outage only if the backend fence remains effective through deployment and smoke.
Suspended responses fail rather than being accepted by the app. Target API client
uses direct fetch and has no app retry/offline mutation queue; no service-worker or
background-sync mechanism was found in reviewed target source. The exact old bundle
is unverified, so do not guarantee every old tab or upstream proxy has no pending
requests. Drain in-flight work and keep fencing until the matched release is ready;
request reload after reopening. Frontend-only hiding cannot block direct API writes.
A temporary maintenance-page deployment is higher-change and not approved here.
No claim that a frontend redeploy eliminates already-open cached tabs.

## Compatibility matrix

| Combination | Decision |
|---|---|
| Existing frontend + old backend/current DB | Current observed legacy service; not compliance approval of the old implementation. |
| Existing frontend + suspended backend | Conditional outage safety if complete process/ingress quiescence and no independent writer; users see failed API requests. |
| Existing frontend + new backend/migrated DB | Full compatibility unproved; do not deliberately reopen this mixed state. |
| Target frontend + new backend/migrated DB | Validated intended release, subject to runtime config/canonical/recovery gates. |
| Old backend + migrated DB | Unsafe; must stay inaccessible, including restart/fallback. |
| New backend + old DB | Unsafe; must never start against pre-migration schema. |

## Exact future execution order — DO NOT EXECUTE

1. Approve immutable backend/frontend SHAs, recovery/config evidence and supported
   maintenance fence. Assign operator, recovery owner and abort thresholds.
2. Announce maintenance. Keep GitHub standings workflow disabled; hold all other
   known DB writers and auto-deploy races under separately authorized controls.
3. Establish backend write quiescence using the verified mechanism. Confirm stopped
   write admission, drained requests/transactions and no active rollover.
4. Create fresh exact-project backup immediately before migrations; verify complete,
   restorable and controlled. Record recovery point without sensitive contents.
5. Rerun read-only schema identity, league/identity collision, owner/member, reset,
   canonical-source timing/master, history and active-operation preflights.
6. Obtain boolean-only runtime JWT/origin/email/production/debug/rate-limit checks.
   Recheck tokenless www reset route; abort on any UNKNOWN mandatory result.
7. Apply db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql.
8. Apply db/post-baseline/0002_nc_02c1_canonical_season.sql.
9. Under deployment write authorization only, designate existing2025-26 by approved
   identity. Verify exactly one canonical season, correct pointer/timings/master.
10. Apply db/post-baseline/0003_nc_02c2_atomic_standings.sql.
11. Apply db/post-baseline/0004_nc_02c3_season_transition.sql (no transition invocation).
12. Apply db/post-baseline/0005_nc_02d1_atomic_scores.sql.
13. Apply db/post-baseline/0006_nc_02d2_final_snapshots.sql (no synthetic backfill).
14. Apply db/post-baseline/0007_nc_02e_atomic_rollover.sql (no rollover invocation).
15. Apply db/post-baseline/0008_nc_02f1_league_lifecycle.sql.
16. Apply db/post-baseline/0009_nc_02f2_league_history.sql (no history reconstruction).
17. Apply db/post-baseline/0010_nc_02g1_identity_auth.sql.
18. Apply db/post-baseline/0011_nc_02g2_password_reset_sessions.sql.
19. Verify final schema/security/function ACLs and count continuity. Verify canonical
   identity, auth_version initialization, intentional legacy reset invalidation and
   preserved history/memberships. Never replay empty baseline/containment migrations.
20. Deploy/start the pinned compatible backend under the verified fence; no temporary
   old-binary resume. Validate startup/config without product-write probes.
21. Replace frontend fully from pinned target with correct API origin and SPA reset
   route. Keep public writes blocked until matching release and smoke are ready.
22. Approved non-destructive smoke:season/health, READ ONLY standings, supported
   history/league reads, frontend tokenless reset route; designated safe-account
   authentication/private denial only within explicit scope. Reset email/password
   mutation requires separately approved mailbox/account; otherwise skip and record.
23. Reconfirm version/reset semantics and monitoring readiness. Re-enable ONLY intended
   scheduler, if separately authorized, after migrated schema, canonical season,
   backend and frontend are verified. Recheck freeze behavior first. No manual job.
24. Open application writes only after all smoke/config/scheduler decisions pass,
   instruct stale clients to reload, observe monitored window and retain recovery owner.

The scheduler re-enable point is step23, never during migration. It may remain disabled
if not intended/authorized. No rollover/season2026-27 transition in this release.

## Migration failure and recovery boundaries

- Before0001:abort;DB unchanged. Undo only authorized maintenance controls safely.
- During0001-0002:each migration is transactional; inspect exact committed boundary.
  Failure of0002 does not undo committed0001. Keep all writers fenced. No invented
  reverse migration; prefer reviewed forward resolution or approved backup recovery.
- After designation:canonical singleton is a real data change and must be included in
  recovery reasoning. A complete pre-migration restore returns to absent canonical
  mechanism; selective deletion/downgrade is not automatically safe or authorized.
- During0003-0011:earlier migrations remain committed. New constraints/history/RPC
  contracts and0011 reset invalidation may make ad hoc downgrades unsafe. A verified
  pre-migration recovery point may be safer than improvised reverse SQL. Assess first.
- After schema,before backend:never resume old binary. Keep fence while correcting or
  recovering under authorization. Git/code rollback does not roll back the database.
- After backend/frontend:only audited schema/version-compatible rollback pair, same
  valid key, correct origin. Keep completed password resets/auth_version increments
  and immutable history semantics; restoration can reinstate obsolete credentials/
  sessions. Do not casually resurrect expired/reset links or rewrite snapshots.
- Recovery execution:stop deployment,retain backend and scheduler fence,identify failed
  boundary,have owner authorize exact restore/target. Verify recoverable backup and
  dependencies before restoration; verify schema/data/security/counts afterward.
  Resume only compatible code after fresh checks. No restore command authorized here.

## Smoke and monitoring prerequisites

No arbitrary real-user login/reset,synthetic analytics,votes or product writes. Obtain
an approved safe account/mailbox if their checks are requested; otherwise report the
coverage limit. No standings refresh,snapshot,rollover or destructive smoke.

Assign observation owner,baseline and abort thresholds for5xx,auth401/403/login,
registration/reset,DB/RPC,canonical,league/history,standings and frontend API failures.
Confirm sanitized diagnostics and provider deployment state. Hold quiescence on new
systemic failure; do not exit maintenance because a deploy merely reports live.

## Provider references and evidence limits

- https://render.com/docs/troubleshooting-deploys : suspended services can return503.
- https://api-docs.render.com/reference/suspend-service-1 : suspend operation exists.
- https://api-docs.render.com/reference/resume-service-1 : resume operation exists.
- https://render.com/docs/deploys : revision-specific deploy and automatic-deploy
  controls exist; this does not prove suspended rollout/fallback semantics.
- https://render.com/docs/free : idle wake-up differs from suspension; Free lacks Shell.

Reviewed2026-10-18; paraphrased applicability only. No provider API mutation called.
Remaining gates:the documented diagnostic-debug/rate-limit-bypass failures and deterministic release fence. Recovery mechanism now passes;deployment-day backup freshness remains mandatory. Frontend
old-SHA uncertainty is conditionally tolerable only with full known replacement and
that verified fence. NC-04B remains not ready and not authorized.


## Recovery proof update — 2026-10-18

Recovery mechanism gate is now PASS;the preceding unavailable-recovery statements are historical and superseded by nc-04a2-recovery-verification.md and db/records/nc_04a2_recovery_verification.json. A private logical backup was restored and verified,then its disposable restore removed. Backup remains private and available. NC04B MUST create a new backup after established write quiescence immediately before0001;this proof does not replace it.

Overall NC04A remains BLOCKED:diagnostic-debug check FAIL,rate-limit-bypass check FAIL,and deterministic write-fence/deploy/resume unresolved. No remediation or NC04B operation authorized/performed.
