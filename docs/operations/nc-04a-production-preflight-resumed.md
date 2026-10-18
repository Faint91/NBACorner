# NC-04A resumed production read-only preflight

**BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED**

Observed 2026-10-18T16:52:36.948733+00:00. This audit does not authorize deployment or remediation.
The first blocked pass and R3 repair chronology are preserved; no prior PASS record was rewritten.

1. **Local starting state.** Both main/clean. Backend a2a930291e32a6f73e03c2acf4dd0732eac70263; frontend 4fa0e9fc11d49354e3da137ee43e9d1ddbc87357.

2. **Production identity/read-only mode.** Fresh dashboard: NBA Corner, rpwesmvzmgoctrokrbhy, main/PRODUCTION. All executed SQL explicitly BEGIN READ ONLY; observed transaction_read_only=on. No app mutation admission or RPC invocation.

3. **NC04A-CODE-001 re-verification.** REPAIRED LOCALLY; production configuration compatibility remains BLOCKED. Do not misclassify masked variable presence as a validator pass.

4. **FRONTEND_ORIGIN readiness.** Name present, value protected. Nonblank/absolute/HTTPS/actual frontend/distinct API not validated from runtime. Actual public frontend confirmed by user: https://www.nbacorner.com. API is separate Render origin.

5. **Reset deep-link hosting readiness.** PASS for confirmed www origin: token-free static /login and /reset-password each HTTP200, identical SPA HTML; deployed first-party bundle contains /reset-password. No JavaScript executed, email sent or backend reset request.

6. **Backup/PITR/equivalent readiness.** BLOCKED. Free dashboard has no scheduled backups; PITR is an unavailable Pro add-on. External restore-capable equivalent UNKNOWN; no creation/upgrade/restore attempted.

7. **JWT_SECRET readiness.** Present by name; nonblank/final >=32 validator/unsafe fallback exclusion UNKNOWN. Render Free Shell unavailable per first-pass evidence. No value retrieved or exposed; safe operator validation is a deployment gate.

8. **Email/provider readiness.** BREVO_API_KEY, BREVO_SENDER_EMAIL and BREVO_SENDER_NAME names present. Actual provider authorization/sender/config validity unverified; no mail sent.

9. **Environment/guard readiness.** No NBA_CORNER_ENV or test-specific settings in observed names; final code treats absent identity as legacy production/real transport and retains test-production denylist. FLASK_ENV, rate-limit/debug values protected; no unsafe default assumed safe. Explicit production/no capture/no fixtures/no test admission must be verified before release.

10. **Current migration level.** Secured baseline-equivalent pre-0001; all 0001-0011 outstanding. Canonical/auth_version/new history/rollover objects absent. No migration execution.

11. **Schema drift result.** Reuse first structural comparison PASS. Fresh seven app-function body hashes and all16 policies match; relation inventory17 including3 sequences unchanged. No observed unknown drift; not a fresh full-column/index re-audit.

12. **Supplemental table ACL result.** PASS: all13 application tables plus bracket_view owned by postgres; grants only postgres/service_role. Effective anon/authenticated table privileges=0; column ACL grants absent; browser schema CREATE=false.

13. **Sequence privilege result.** PASS: leaderboard_history_id_seq/password_resets_id_seq/standings_id_seq owned by postgres with correct table-column ownership. Effective browser SELECT/UPDATE/USAGE=0; trusted roles only.

14. **Function/RPC privilege result.** PASS within baseline scope: seven app-owned functions unchanged; four mutation RPCs trusted-only with effective browser EXECUTE=0. Two legacy DEFINER helpers and legacy unpinned search paths retained as known baseline. Three trigger-only helpers retain baseline ordinary EXECUTE; no app mutation RPC called. Managed pg_trgm functions excluded from app-owned inventory. New migration functions individually close browser execution and pin search_path.

15. **RLS/policy result.** PASS:16 policies unchanged; RLS enabled users/brackets/matches/password_resets, not forced. Other relations remain ACL-contained. Broad legacy policies are not effective grants. Post-chain verifier must preserve containment; postgres function default ACL still requires explicit per-function revocation. Managed supabase_admin defaults are not app creator defaults.

16. **0001-0007 supplemental result.** PASS for observed structural/data prerequisites, conditional on separate canonical designation and maintenance. No collision/partial new object; master graph passes. Reused NC03 synthetic full-chain proof; no production dry-run or new full-suite rerun.

17. **0008 league collision result.** 0 normalized collision groups in first full Unicode trim observation; fresh lower/btrim collision count0. Existing one league unchanged by count. Recheck exact migration normalization immediately before deployment.

18. **0008 owner/member result.** 0 missing owner users, owner-not-member or duplicate membership groups. One league/one membership.

19. **0009 history result.** No conflicting new history/mapping objects; seven legacy structured headers/140 rows, no orphan/duplicate payload/header-season/code mismatch. 0009 adds empty mapping/cutoff/league history structures, no identity reconstruction or backfill.

20. **0010 username result.** Fresh exact Unicode-trim/lower normalized collision groups0 for57 users.

21. **0010 email result.** Fresh exact Unicode-trim/lower normalized collision groups0 for57 users.

22. **0010 blank/null result.** Fresh null/blank identities0; earlier full Unicode blank check0. No identities/hashes exported. Critical exact migration preflight must run at release.

23. **0011 reset state.** Fresh13 total,10 unused,0 unused+unexpired,0 orphan users,0 legacy user reset fields. Counts only; no tokens read.

24. **0011 auth_version readiness.** No pre-existing auth_version column/object collision;57 users compatible with deterministic default0. No version written.

25. **Canonical season evidence.** Nine seasons2017-18 through2025-26; only2025-26 has timing and active master. Opening/freeze2026-04-13T03:00Z, final lock2026-04-15T00:00Z; complete21-match admin master. Standings baseline has no season_id; seven old history headers. CURRENT_SEASON_CODE value remains masked. Chronology alone is not designation.

26. **Canonical season decision/readiness.** BLOCKED. 2025-26 is the sole evidenced stored timing/master candidate for preserving current state, not an approved canonical decision. User must confirm source season and timings. 0002 intentionally inserts no canonical row; do not auto-select latest/date or trigger rollover.

27. **Master validation.** PASS:one active valid pointer to admin-owned nondeleted master.21 matches, unique slots,22 derived winner/loser edges, no cycle/conflicting dependency or propagation/winner/game error under both existing master and complete-graph pure validators.

28. **Bracket lifecycle validation.** PASS observed:21 brackets/441 matches;0 duplicate active user-season/master, orphan user/season/match/score, done-without-saved, draft-with-saved, delete-actor-without-delete, bad graph count, season mismatch or duplicate slots. Soft-deleted saved brackets are valid history, not automatic repair targets.

29. **Standings validation.** 30 known teams,15 per conference from first observation; fresh30 rows and conference-seed duplicate groups0. Last timestamp2026-04-12T09:52:05.489838 WITHOUT time zone; no fabricated UTC conversion or season association. No refresh.

30. **Global history validation.** 7 headers/140 rows/0 legacy-only rows. Fresh0 duplicate payload/display-name groups, invalid rank, orphan/header-season/code mismatch. Legacy structured rows have no user/bracket/source identity, so duplicate-user proof cannot be fabricated. 0006 preserves legacy markers as NULL; not newly verified final snapshots. No backfill.

31. **League history validation.** PASS prerequisites: all four0009 table names absent, no partial structures; live membership valid. No historical league membership inferred from current membership or names.

32. **Scheduler/jobs result.** Actual GitHub Actions inventory shows only Daily NBA standings sync, manually DISABLED. Latest visible run successful Apr12. Source schedule09:00UTC; actual enablement remains disabled. Render all3 services are Python web services (NBA Corner and2 Telegram services), no cron service. pg_cron extension absent. No automatic rollover found in reviewed source/registrations; external systems outside inspected accounts not certified. No jobs triggered or enabled.

33. **Rollover safety result.** Fresh advisory locks0, other active rollover/transition queries0, no post-chain audit/transition tables yet. New code rollover is explicit admin action; no observed live transition. Recheck immediately before maintenance.

34. **Frontend deployment config.** User-confirmed www.nbacorner.com; Cloudflare response header is CDN evidence, not proof of hosting provider. Static bundle uses HTTPS Render API, no loopback API; no JWT_SECRET/SUPABASE_SERVICE_ROLE_KEY/BREVO_API_KEY names found. This limited scan does not prove absence of arbitrary embedded secret literals. Hosting dashboard/build env/commit unverified. GitHub frontend main ce54143 differs from local release; repository HEAD is not asserted as deployed commit.

35. **Backend deployment config.** Render service srv-d4239u6uk2gs73b8fts0 live commit5bcb0b43ae0c232381ae857cd40c3fd7b1e23422 unchanged. main, pip install -r requirements.txt, gunicorn app:app, Free. Auto-deploy selected value not exposed safely; no push/deploy performed. Existing old before_request can bootstrap writes, so no product API GET probes.

36. **Aggregate production scale.** Fresh57 users (previous53),21 brackets,441 matches,14 scores,1 league,1 membership,7 history headers/140 rows,0 legacy-only rows;30 standings. User-count drift is observed external activity, not attributed to this read-only audit.

37. **Mixed-version compatibility.** Old frontend/new backend only conditionally basic-compatible; current deployed frontend full G2/league/history contract not proved. New frontend/old backend unsafe; old backend/migrated DB unsafe; new backend/old DB unsafe. R3+current frontend route structurally compatible, runtime origin still unverified. Migrated backend rejects legacy reset links. Coordinated window required.

38. **Existing JWT effect.** Final code missing av=>0; same valid signing key preserves existing sessions until successful reset increments auth_version. Then old token version fails. Production key quality still gate; no rotation or arbitrary authentication.

39. **Reset-link migration effect.** 0011 intentionally invalidates all legacy reset rows and legacy user fields.0 currently usable links makes immediate disruption low, not zero forever. Recount just before migration; old emails require fresh links. No reset request/completion here.

40. **Migration-chain compatibility.** Conditional structural compatibility with secured baseline plus existing NC03 synthetic proof. Apply outstanding0001 through0011 in order only after gates; separately approved exact designation after0002. Never replay empty baseline or old containment migrations. No migration edits/execution or production-shape rehearsal claimed.

41. **Read-only preflight tooling completeness.** Existing nc03_before_migrations_readonly.sql plus new nc04a_resumed_supplement_readonly.sql cover counts/collisions/lifecycle/ACL/functions/reset/history/locks. New offline nc04a_verify_resumed_evidence.py verifies exports and existing pure master validator without IO to production. Provider/config/business gates cannot be replaced by SQL.24 offline evidence checks pass.

42. **Required remediation items.** Verified restorable recovery mechanism; explicit canonical source/timing decision; boolean-only JWT and actual FRONTEND_ORIGIN validation; email/env guard readiness; actual frontend hosting/build config/version; verified pause/deploy/resume and auto-deploy strategy. No remediation performed.

43. **Recovery/backup GO gate.** NO-GO until exact-project dated recovery point, retention/access/restore steps and credible restore proof are verified under separate authorization.

44. **Canonical-season GO gate.** NO-GO until explicit approved identity/timings and authorized designation plan;2025-26 candidate is not implicit approval.

45. **Configuration GO gate.** NO-GO. JWT/FRONTEND_ORIGIN/provider/env protected readiness unknown. API origin and www SPA deep-link contract pass; those do not waive protected-config checks.

46. **Exact deployment order.** Approve commits/gates/window; establish API write quiescence and keep disabled jobs held; verify recovery; fresh critical read-only checks; migrate0001->0011 with canonical designation after0002 under separate write authorization; final schema/ACL/count verification; start compatible backend; deploy matching frontend; approved safe smoke; verify reset routing and version behavior; resume only intended schedules; monitor; exit maintenance. Do not execute.

47. **Maintenance/write-quiescence recommendation.** Use existing Render Suspend Web Service control under separate deployment authorization, verify API quiescence, keep GitHub workflow disabled and block auto-deploy races. Platform deploy-while-suspended/resume procedure must be verified to ensure no old binary resumes against0011; if unavailable approve a supported alternative before GO. Frontend-only maintenance is insufficient. No suspend performed.

48. **Rollback runbook.** Before migrations abort cleanly. During failed migration keep quiescent, inspect transaction/earlier committed steps; no blind down migration. After migrations before backend never restart incompatible old code. After backend choose only schema/version-compatible rollback and same key. Frontend rollback must retain matching API/reset contract. Restore needs explicit approval; deleted links, completed resets/versions, immutable history and future hard deletes have distinct recovery consequences.

49. **Safe smoke plan.** Planning only: safe new /season and authorized /health; READ ONLY standings SQL; supported public league/history reads; designated account login/protected/private-denial checks only if authorized. Static tokenless frontend reset load; reset request/completion only with separately approved mailbox/account. No rollout/refresh/snapshot/destructive smoke or arbitrary user authentication.

50. **Monitoring plan.** Planning only:5xx,401/403 shifts,registration/login/reset failures,DB/RPC,league/history,standings and frontend API errors; canonical status and expected scheduler outcomes; redact credentials/verifiers. Assign owner/abort thresholds before release; no alerts/config edited.

51. **Production writes performed.** 0 DB/config/deploy/job/email/product mutations. SELECT/catalog/static first-party asset reads only; no browser app JS execution, mutation RPC, tokens or user payload exports. One SELECT failed due to baseline used_at naming; corrected to used before successful read; no data change.

52. **Application-code changes.** None. Frontend and C:/1on1ball untouched. Existing NC03/R3 PASS evidence unchanged; prior NC04A chronology retained.

53. **Files changed.** Audit report/progress record/runbook, sanitized resumed observations, SELECT-only supplement and offline verifier; exact Git diff recorded at completion.

54. **Git result.** Normal audit-only commit NC-04A complete resumed production preflight; no amendment/push/deployment. Commit hash supplied after commit.

55. **Final NC-04A status.** BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED.

56. **Readiness for NC-04B.** Not ready. No deployment authorization implied; NC04B not started.

57. **Recommended next step.** Resolve recovery, canonical decision and secure boolean config/hosting/maintenance evidence in explicitly authorized scopes, then recheck remaining GO gates. No further phase started.

## Evidence and limits

- Fresh DB observations:2026-10-18T16:43:32Z,16:44:53Z,16:47:24Z; explicit READ ONLY throughout.
- Existing structural source:2026-10-17 catalog/baseline comparison. Fresh policies/function hashes/effective privileges supplemented it.
- Sanitized evidence: `db/records/nc_04a_resumed_observations.json`; no master match payload or user identities retained.
- Offline verifier compares policy formatting with whitespace normalization and omits export-only schemaname; it does not erase semantic differences.
- First attempt to find frontend hosting on Vercel was an unverified provider assumption; no project found and no config changed. User confirmed www frontend; static reads succeeded there. Apex static reads failed; no apex compatibility asserted.
- No production read was refused by automatic approval review in this resumed pass; no denied-access workaround was used. Prior first-pass refusal remains preserved historically.

## Local artifact validation

24 fresh-export checks PASS;4 negative controls PASS (browser grant,policy semantic drift,missing READ ONLY proof,invalid master winner). Prior first-pass JSON preserved exactly as data;57 report items present;new Python compiles and Black passes. No completed application suite was rerun.
