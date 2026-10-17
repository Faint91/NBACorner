# NC-04A — Controlled production read-only preflight

**BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED.**

Mandatory stop: **NC04A-CODE-001** confirms a local release defect. The actual production reset-link helper selects the Render API hostname, which is configured as `gunicorn app:app`; its route map has no GET `/reset-password` UI or redirect. The UI exists in the separate frontend. No email or live application probe was sent. Required next repair checkpoint: **NC-03R3**, only after explicit authorization.

This evidence preserves NC-03 PASS and its chronology; it records new production-topology evidence that resolves an earlier routing advisory. No code repair or production change was made.

## Required47-item report

| # | Check | Result / evidence |
|---|---|---|
| 1 | Local starting state | Backend main bb73a7a4610ba742da4a9796663cdda7cf3348af and frontend main 4fa0e9fc11d49354e3da137ee43e9d1ddbc87357; both clean. |
| 2 | Production identity | Verified dashboard NBA Corner/main/PRODUCTION, Supabase rpwesmvzmgoctrokrbhy; postgres database/reader, PostgreSQL17.6. SQL returned transaction_read_only=on. Render service srv-d4239u6uk2gs73b8fts0 serves nbacorner.onrender.com; live commit5bcb0b43ae0c232381ae857cd40c3fd7b1e23422. |
| 3 | Schema/migration level | Secured baseline-equivalent, pre-release0001.13tables/1view/3sequences/7functions; no migration marker table. All release0001-0011 pending. Do not replay baseline/security containment migrations. |
| 4 | Schema drift | Offline comparison PASS:122columns/defaults,55constraints,38indexes,3triggers,16policies,view and7function bodies/modes/owners match baseline. Known deparser quote/schema/outer-parenthesis/whitespace variation only; no unknown structural difference in collected metadata. Supplemental relation ACL/sequence details uncollected after stop. |
| 5 | Backup/PITR | No scheduled backups on Free plan; PITR not enabled/available. Latest successful backup/retention unknown; external backup not verified. DEPLOYMENT PREREQUISITE, not a product-compliance failure. |
| 6 | JWT_SECRET | Name present/masked; nonempty,>=32/R1 validator and exact runtime delivery NOT VERIFIED. No reveal/copy/retrieval of secret. Free Render Shell unavailable. BLOCKED; do not rotate/generate. |
| 7 | Email/reset configuration | Brevo and sender names present; provider/sender values not exposed or tested. CONFIRMED NC04A-CODE-001: production helper builds API-origin reset URL; API has no GET reset UI/redirect, while frontend has route. Mandatory local-code stop; no mail sent. |
| 8 | Environment/guard | Supabase branch explicitly PRODUCTION. Render key list lacks NBA_CORNER_ENV; FLASK_ENV/FRONTEND_ORIGIN exist masked, DISABLE_RATE_LIMITS/ENABLE_DEBUG_LOGS booleans unknown. No test-specific NBA_CORNER_* keys observed. Unchanged local production denylist/test-admission guards remain; no test harness connected to production. Full runtime semantics remain unverified. |
| 9 | 0001-0007 prerequisites | No active user-season/master duplicates; no orphan bracket users; all active graphs have21matches; no cross-bracket next links,season mismatch,invalid counts,winner-outside-participants or submitted-without-time rows. Current season/master linkage valid. Recursive graph/scoring/ACL supplement not collected, so not a complete PASS. Canonical table absent; cannot start new backend as-is. |
| 10 | 0008 league names | Normalized collision groups0; invalid/untrimmed league names0. Unicode trimming matches actual migration, covering ordinary lower(trim(name)) collisions too. |
| 11 | 0008 owner/member | One league/one membership; missing owner-user0, owner-not-member0, duplicate membership groups0. Migration prerequisites collected here PASS. |
| 12 | 0009 history | New league-history/mapping/cutoff tables absent as expected. Seven legacy structured global headers/140rows predate final/source mapping. No backfill performed; future workflow must not reinterpret them as newly verified final snapshots or invent league membership. Final mapping/cutoff verification deferred. |
| 13 | 0010 username collisions | 0 normalized collision groups. |
| 14 | 0010 email collisions | 0 normalized collision groups; no email values exported. |
| 15 | 0010 blank/null identities | 0 null/blank-after-Unicode-trim username/email rows. Migration itself does not impose a new regex/length rewrite on historical usernames. |
| 16 | 0011 reset state | 13 legacy reset records;10unused,0unused/unexpired at observation;0legacy user reset-field rows;0orphan reset users. Counts only; no verifier read. |
| 17 | 0011 auth_version | Column not yet present; pending0011 adds NOT NULL/default0 and clears old links. Zero-initialization structurally compatible with observed53users; migration not executed. |
| 18 | Auth structural sanity | 53users,0missing-password values (presence only), no normalized identity collisions/blanks, reset FK integrity collected. Current backend is pre-auth_version; no real-user login/reset attempted. Post-migration/runtime proof remains gated. |
| 19 | Canonical season | BLOCKED: application_season absent and no confirmed source designation. Nine season rows;2025-26 only row with timing/master. Its timing is ordered but in the past. Do not infer current season from date/latest row; operator/business decision plus separately authorized designation after0002 required. |
| 20 | Master bracket | 2025-26 pointer080992c1-8d70-4c90-a4ce-31c314d89527 valid, exactly1active master/21matches. No duplicate active masters. Basic graph/count checks pass; recursive propagation/completeness supplement was not collected before stop. |
| 21 | Standings | 30rows/30distinct known team codes;15East/15West;0missing/unknown/duplicate codes,0bad seeds/negative records. Latest metadata2026-04-12T09:52:05.489838 (column has no timezone). Frozen/stale-looking existing data is not auto-refreshed or treated alone as a schema defect. No season_id column at baseline. |
| 22 | Global history | 7headers/140rows,0orphan rows,0duplicate season-header groups,0null ranks. Seasons2017-18,2018-19,2019-20,2020-21,2021-22,2022-23,2024-25 remain legacy structured data after0006; legacy-only leaderboard_history table has0rows. No final fields/order/source map asserted or rewritten. |
| 23 | League history | No league-history tables/rows yet; migration0009 pending. No historic membership inferred. No existing league-season receipt to validate; new integrity is gated by migration verification and remaining preflight. |
| 24 | Rollover safety | 0advisory locks at aggregate observation; no rollover-audit table yet. No job/rollover triggered. Full active-process/actual scheduler-state verification deferred; cannot mark fully safe from lock count alone. |
| 25 | Production scale | 53users;21brackets/441matches;1league;1membership;14scores;7global headers/140structured rows/0legacy-only rows;0league-history rows because tables absent;30standings. Small observed scale; no load benchmark. |
| 26 | Backend config compatibility | Required names exist but runtime validation incomplete. Current code is old5bcb0b4; local candidate has mandatory JWT config, canonical/RPC/auth_version dependencies and confirmed reset-routing defect. Deployment blocked. |
| 27 | Frontend config compatibility | Actual deployed frontend host/build/API configuration not verified before stop. Local Vite settings are not evidence of production. Frontend source contains reset UI; never expose backend secrets to VITE variables. |
| 28 | Mixed-version compatibility | Old frontend/new backend conditional for basic reads/login only; new frontend/old backend unsafe for complete contracts; old backend/migrated DB unsafe; new backend/current DB unsafe. Maintenance and a coordinated compatible pair required. |
| 29 | Existing JWTs | Preserve same valid configured signing key. Missing av maps to version0 after0011; before successful reset compatibility retained. Reset increments version and rejects old tokens. No sessions changed here; unknown key validity is a gate. |
| 30 | Outstanding reset-link effect | 0011 intentionally deletes13legacy records and invalidates all old reset emails;0currently unused/unexpired observed. Plan low-support window and fresh-link guidance; do not resurrect raw tokens. |
| 31 | Backup gate | NC-04B NO-GO until a dated,verified,restorable backup/PITR/equivalent for intended project is evidenced, with owner/retention/recovery point and restore procedure. No creation/restore test authorized here. |
| 32 | Deployment ordering | Planning only in nc-04b-deployment-runbook.md. First authorize/fix NC03R3 and revalidate, then finish NC04A; only after all GO gates and explicit NC04B authorization enter maintenance,backup/recheck,forward0001-0011 with explicit canonical designation,new backend,new frontend,smoke/jobs/monitoring. |
| 33 | GO gates | All collisions0; canonical designation/timing and master state approved; complete schema/security/graph checks pass; valid explicit JWT secret; DB/email/frontend settings verified; reset routing repaired; backup verified; no drift/rollover conflict; compatible release approved. |
| 34 | NO-GO gates | Any failed/unverified GO gate. Current NO-GO includes confirmed local reset-route defect,backup prerequisite,missing canonical designation,JWT/runtime validation and stopped/deferred preflight items. |
| 35 | Remediation items | See five identifiers/counts/severities/options/business decisions/downtime/scriptability entries in JSON and table below. No remediation performed. Deferred checks are not silently passed. |
| 36 | Maintenance | Recommended: incompatible old backend/reset schema and fail-closed new backend require a coordinated write-quiescent window. Render Free lacks built-in maintenance mode/zero-downtime guarantees; choose separately approved external traffic/write controls and pause actual schedulers. Do not use test-only job flag as production switch. |
| 37 | Safe smoke runbook | Planning only: canonical season/health/approved read-only standings SQL,public league discovery/history; approved test-account login/protected read/private denial only if credentials exist; reset only approved test mailbox/account after routing fix. Exclude real-user resets,rollover,bracket mutation,league delete,job triggers. |
| 38 | Rollback runbook | Before migrations abort unchanged. After migrations keep maintenance/new compatible code; old backend against0011 unsafe. Backend/frontend rollback require compatible pair. Restore/PITR for data recovery only under explicit authorization; old reset links,auth_version,uniqueness and immutable history have separate consequences. |
| 39 | Monitoring | Design only:5xx,auth401/403/login/reset errors,DB/RPC failures,league/history/standings/API errors,canonical status/job results and false test-mode activation. Sanitize logs/no secrets. No alerts created or logs containing private payloads exported. |
| 40 | PII/secrets | Persisted results contain schema metadata,aggregate counts and necessary season/master IDs only. No product emails,names,password hashes,reset values,JWT/provider/DB credentials copied into evidence. All hosting secret values remained masked; no environment export/reveal/copy used. |
| 41 | Production writes | 0product/config/schema writes;0deployments,0migrations,0job/refresh/rollover triggers,0emails. Only explicit READ ONLY SQL and dashboard reads. No saved SQL query action. |
| 42 | Application code changes | None. Frontend,baseline/migrations,earlier evidence and C:/1on1ball untouched. |
| 43 | Files changed | New offline schema comparator/reset-route proof,NC04A JSON records including already-collected metadata/aggregates,required preflight document and planning-only deployment runbook. Exact Git file list in commit. |
| 44 | Git result | Audit-only normal checkpoint to be returned with final hash; no amend,push or deployment. Frontend unchanged. Earlier NC03PASS history preserved. |
| 45 | Final NC-04A status | BLOCKED — PRODUCTION REMEDIATION/DECISION REQUIRED. Incomplete by mandatory section37 stop; not a new consolidated NC03 audit and not a deployment approval. |
| 46 | NC-04B readiness | NOT READY; do not begin. |
| 47 | Recommended next step | Explicitly authorize NC-03R3 reset-link routing repair; after repair/validation resume remaining NC04A checks and resolve prerequisites. No repair started. |

## Remediation/decision register — not executed

| ID | Scope / count | Severity | Required next action |
|---|---|---|
| NC04A-CODE-001 | Password-reset delivery/release; NC-03 regression guard section37 / 1 | HIGH / mandatory stop | Authorize NC-03R3 to route reset links to the explicitly approved frontend using trusted server configuration, validate origin and rerun relevant reset/contract tests. |
| NC04A-BACKUP-001 | All future production migrations / NC-04B backup gate / 0 | DEPLOYMENT PREREQUISITE | Separately authorize creation and verification of an equivalent restorable backup, or an approved platform backup/PITR arrangement. |
| NC04A-SEASON-001 | 0002 canonical designation / new backend startup / 0 | DEPLOYMENT BLOCKER / decision required | Confirm intended source season and timing, then separately authorize exact canonical designation after0002 during maintenance. |
| NC04A-CONFIG-001 | R1 / mandatory JWT_SECRET configuration / 1 | DEPLOYMENT BLOCKER / unverified | Obtain safe boolean-only R1 validation from an explicitly approved runtime/secure operator procedure; preserve the existing valid key. |
| NC04A-CONFIG-002 | Runtime guard/environment and email/frontend configuration / None | DEPLOYMENT PREREQUISITE / partially verified | After code repair, resume the remaining read-only configuration/deployment checks; verify production classification, intended origins, provider sender readiness, no synthetic/capture settings and no enabled test admission. |

## Read-only execution and privacy record

Before the first SQL product read, dashboard identity showed NBA Corner/main/PRODUCTION for `rpwesmvzmgoctrokrbhy`. Each fixed query used `BEGIN READ ONLY`, a bounded statement timeout, catalog/SELECT-only expressions and `COMMIT`; the first query returned `transaction_read_only=on`, as did captured catalog/aggregate results. No mutation RPC, DDL or job command was invoked. The approved script/connection mode was explicitly NC-04A READ-ONLY PREFLIGHT.

Initial identity read:2026-10-17T21:42:21.159015Z; catalog:21:43:55.787337Z; aggregates:21:46:07.331486Z. These are observations, not claims production stopped receiving ordinary user traffic. The schema-only CSV and count-only CSV were downloaded before the stop; only their safe contents enter Git. No real personal dataset was exported.

The supplemental ACL/sequence/recursive graph/source-check SELECT was started before the defect proof and a result-ready UI was seen. Its result was not collected before the stop and is not evidence of a pass. Automatic approval review rejected a post-stop attempt to export it, citing continued production access after the mandatory stop. No retry, alternate surface, clipboard workaround or additional production read followed.

The exact deployed backend source is available in local Git. Its old request bootstrap calls season initialization, so no live application GET/HEAD was used to test reset routing; a supposedly read-only HTTP method would not itself establish a no-write guarantee. The offline proof calls the real email helper with a non-issued synthetic marker and matches the current route rules using Werkzeug, without importing/starting app.py or connecting to DB/network.

## Evidence files

- `db/records/nc_04a_production_preflight.json`: full status,findings,config names,stop/safety/deferred checks.
- `db/records/nc_04a_production_catalog.json`: captured schema-only metadata.
- `db/records/nc_04a_schema_comparison.json`: offline baseline comparison and exact source CSV SHA256.
- `db/records/nc_04a_production_aggregates.json`: captured counts and safe season/master IDs.
- `db/records/nc_04a_reset_route_finding.json`: reproducible local-code finding.
- `scripts/nc04a_compare_catalog.py`: offline-only fixed-format metadata comparator, no production executor.
- `scripts/nc04a_reset_route_proof.py`: offline actual-helper/route-map proof.
- `docs/operations/nc-04b-deployment-runbook.md`: gated planning only; no authorization.

The collected schema matches the baseline structurally, but the uncollected supplement means direct relation ACL/sequence/recursive-graph checks are not newly certified. No previous phase result is substituted for an unperformed production check.
