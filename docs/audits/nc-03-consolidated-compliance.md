# NC-03 — Consolidated compliance audit: FAIL / stopped

Observation UTC: 2026-10-17T16:06:00.716979+00:00

## Confirmed finding NC03-SEC-001

**Foundational authentication FAIL; production readiness NOT READY.**
The ordinary production configuration path accepts a missing JWT_SECRET. The app
then uses a nonempty, publicly inspectable source literal as its signing key.
The signing value and all transient tokens are intentionally omitted here.

Current locations: app.py:49, app.py:527,
app.py:539, environment_safety.py:482.

With the variable absent in an explicitly production-classified isolated process,
the actual current auth helper, decorator and /auth/test-me route accepted a
source-fallback-signed token for an existing synthetic user (HTTP 200).
No token, wrong signing key and nonexistent user each returned HTTP 401.
The reproduction uses an in-memory user/version read double, not a real database;
it is not a full application startup proof. The actual environment loader receives
a no-op dotenv callback so it never reads local credentials. No network, DB client,
application module import, production contact or server listener is used.

This is conditional on missing configuration. It does **not** establish that the
current production deployment uses that key or that an account was compromised.
G1/G2 explicitly preserved the old signing configuration; this is not attributed
to a new G2 regression. Existing user/version checks remain effective controls but
cannot establish authenticity when the signing key is known from source.

Reproduce locally: `python -B scripts/audit_nc03_jwt_fallback.py`.
The script extracts current AST nodes rather than copying auth behavior.

## Mandatory-stop disposition

Your stop rule was applied after reproducing this security defect. No repair was
made and the remaining consolidated verification was not run. The 118-ID registry
retains every approved ID as BLOCKED/unverified; no individual product requirement
was reclassified as FAIL without its own evidence. This is a **partial audit**,
not a completed 118-rule proof. Detailed per-ID descriptions, source/test mappings,
function/catalog inventory and readiness checks remain unfinished.

## Required 50-item completion record

| # | Requested result | NC-03 evidence/disposition |
|---|---|---|
| 1 | Starting repositories | Backend main c5f24396f7387e250982bf2c124ba9753ad9550a; frontend main 4fa0e9fc11d49354e3da137ee43e9d1ddbc87357; both clean. |
| 2 | Migration inventory | Baseline and post-baseline 0001–0011 present; current hashes in JSON. Historical hash/semantic comparison not completed. |
| 3 | Database objects | BLOCKED; final catalog not queried. |
| 4 | Matrix totals | 118 retained IDs: 0 PASS, 0 FAIL, 118 BLOCKED, 0 NOT APPLICABLE; separate foundational FAIL. |
| 5 | Privacy P1–P10 | BLOCKED; 10 unverified. |
| 6 | Brackets B1–B16 | BLOCKED; 16 unverified. |
| 7 | Seasons S1–S14 | BLOCKED; 14 unverified. |
| 8 | Scoring SC1–SC17 | BLOCKED; 17 unverified. |
| 9 | Rollover RR1–RR16 | BLOCKED; 16 unverified. |
| 10 | Leagues L plus clarifications | BLOCKED; 25 unverified, L15 clarification counted once. |
| 11 | Auth A1–A20 | BLOCKED; 20 individual contracts not certified. Foundation defect does not imply all 20 fail. |
| 12 | Foundational architecture/security | FAIL: NC03-SEC-001 signing configuration. DB architecture not fully certified. |
| 13 | Function/grant audit | BLOCKED; inventory/grants after0011 not certified. |
| 14 | CROSS-01 | BLOCKED; no fresh bracket/auth integration. |
| 15 | CROSS-02 | BLOCKED; no fresh league/auth integration. |
| 16 | CROSS-03 | BLOCKED; no fresh privacy/history integration. |
| 17 | CROSS-04 | BLOCKED; no fresh bracket/scoring integration. |
| 18 | CROSS-05 | BLOCKED; no fresh scoring/history integration. |
| 19 | CROSS-06 | BLOCKED; no fresh league/scoring integration. |
| 20 | CROSS-07 | BLOCKED; no fresh league/rollover integration. |
| 21 | CROSS-08 | BLOCKED; no fresh global/league history integration. |
| 22 | CROSS-09 | BLOCKED; no fresh standings/rollover integration. |
| 23 | CROSS-10 | BLOCKED; no fresh auth/rollover-audit integration. |
| 24 | CROSS-11 | BLOCKED; offline auth reproduction is not the requested reset/product-endpoint transaction proof. |
| 25 | CROSS-12 | BLOCKED; no fresh privacy-switch/history integration. |
| 26 | Frontend/backend contracts | BLOCKED; no consolidated certification. |
| 27 | Error sanitization | Reproduction auth failures return401; broader contract audit BLOCKED. |
| 28 | Secret/privacy scan | Source signing fallback PRESENT; value omitted. Full other-secret scan not completed; absence not claimed. |
| 29 | Deprecated paths | Signing fallback persists. Other dead paths not exhaustively audited. |
| 30 | Fresh migration chain | BLOCKED; not run. |
| 31 | Backend suite | Not run; zero fresh full-suite cases certified. |
| 32 | Offline suite | Not run; focused reproduction: one accepting exploit case plus three rejecting controls. |
| 33 | Frontend suite/build | Not run; prior G2 reports not substituted for NC-03 validation. |
| 34 | Guarded integration | Not run; zero CROSS sequences certified. |
| 35 | Fixture cleanup | No fixtures/DB/mail/locks/jobs/server touched; checksum not freshly verified. |
| 36 | Coverage gaps | All fresh consolidated proofs pending; no claim that prior coverage is absent. |
| 37 | Configuration | JWT_SECRET must be required secret; current fallback violates safe missing-config behavior. Full registry pending. |
| 38 | Production preflights | Not executed; required checklist pending, see readiness document. |
| 39 | Release order | Provisional backup/preflight/migrations/backend/frontend/validation/guarded smoke/jobs/monitoring only; not an approved release plan. |
| 40 | Compatibility | G2 records describe missing-av→0 compatibility and invalidation of old reset links; NC-03 verification pending. |
| 41 | Rollback | Schema/data rollback differs from code rollback; destructive cleanup/reset revocation cannot be casually undone. |
| 42 | Smoke plan | Design only, conditional on approved test identities; see readiness document. |
| 43 | Performance | Not audited; no performance PASS or FAIL inferred. |
| 44 | Production contact | NONE. No deployment, production queries, emails, votes, jobs or provider actions. |
| 45 | Audit files | Two required Markdown reports, two required JSON records, one offline audit reproducer. |
| 46 | Git | Audit-only normal commit; final hash/status reported in completion response. No application changes. |
| 47 | NC-03 status | FAIL. |
| 48 | Production readiness | NOT READY. |
| 49 | Required repair | Separately authorize narrow production JWT-key validation/fallback removal and regression coverage. No repair performed. |
| 50 | Next checkpoint | Resume NC-03 after authorized repair; NC-04 not started. |

## Preservation

No application behavior, baseline/migration/verifier, frontend, prior NC evidence,
configuration, DB, production or C:/1on1ball files changed. Only NC-03 audit files
are included in this commit. Prior phase evidence remains intact.
