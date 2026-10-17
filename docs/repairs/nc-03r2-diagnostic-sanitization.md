# NC-03R2 — Diagnostic error-response sanitization

**NC03-SEC-002 = REPAIRED LOCALLY / pending NC-03 re-audit.**
No production contact, deployment, frontend/config/schema or shared auth changes.

## Starting state and route inventory

Backend main `613922d4522aefe319f187a067d6de2a2e22d87e` and frontend main
`4fa0e9fc11d49354e3da137ee43e9d1ddbc87357` were clean. The route was introduced
by `b1b96fa80b2b4d25367a10133de5e00e56b01bf8` (“added endpoint to test master
bracket”). No frontend, operational-script or public-product caller was found.
Historical NC-01 inventories identify it only as diagnostic. It reads a bracket's
season/master association and deleted state; it is an operational consistency check.

**Access decision: admin-only in every mode.** Internal linkage inspection and
absence of product callers support using the existing operational admin pattern:
valid current JWT, signed admin claim and current database admin status. This is an
explicit security posture decision, not an assertion that historical public access
was intentional. No environment-dependent availability or new flag is introduced.
The global canonical-season bootstrap is unchanged; it may perform its ordinary
canonical reads before authorization, but diagnostic bracket/season reads never run
for anonymous, ordinary or no-longer-admin callers.

Before repair there was no auth decorator or environment gate. Initial bracket
lookup was outside the local catch; season failures returned raw provider exceptions,
with one branch returning executable repair guidance. Success returned internal
bracket/season/master IDs. Original audit evidence and vulnerable reproducer function
are preserved without editing the historical FAIL.

## Repair and response contract

Only `app.py:debug_master_status` and its auth decorator changed. Authorization,
all diagnostic reads and malformed-state handling now fail safely. No shared error
helper or logging behavior changed. No raw SQL, exception, connection information,
provider payload, trace or internal IDs is returned, including to an authorized admin.
No exception text or new logging is emitted by this function.

| Caller / result | HTTP | Response |
|---|---|---|
| Anonymous/invalid JWT |401|Existing fixed require_auth error|
| Ordinary or no current DB admin role |403|`{"error":"Forbidden"}`|
| Admin, healthy |200|Only boolean `ok`, `bracket_deleted`, `is_master_computed`|
| Admin, missing/invalid input |400|`ok:false`, fixed `Invalid bracket id`|
| Admin, missing target |404|`ok:false`, fixed `Diagnostic target not found`|
| Admin, read failure/repair-needed/malformed stored state |503|`ok:false`, fixed `Diagnostic check failed.`|

A null master is a valid healthy state (`is_master_computed:false`). Provider error
fields and exceptions, missing state/columns and malformed identifiers are sanitized.
Operators can use trusted offline schema verification tooling; API repair SQL and
raw exception logs were not moved elsewhere. A provider's missing-row exception may
be reported generically503 rather than inferred as absence; explicit empty results
receive404. No raw error is used to distinguish those cases.

## Narrow related-route and regression audit

`/__debug/master-status` is the only debug-prefix route. `/health` returns fixed
text. `/admin/env-check` is admin-only with presence flags and generic DB failures.
`/season` retains its approved canonical status and fixed bootstrap failure.
Other reviewed `str(error)` paths handle controlled service stage/policy errors,
with unexpected exceptions sanitized; no second active diagnostic raw-exception/SQL
response was confirmed. Existing conditional logs elsewhere are unchanged and are
not claimed to have received the full NC-03 logging audit.

All other **85** application functions/classes and all imports are AST-identical,
including login, registration, reset, private membership, standings, rollover and
shared error handlers. Full offline safety provides representative identity/reset,
league, standings and rollover service regression coverage. No full NC-03 resumed.

## Verification

```text
python -B scripts/audit_nc03_debug_error.py
python -B scripts/audit_nc03_jwt_fallback.py
python -B -m unittest discover -s tests/offline -q
python -B scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
```

The original diagnostic CLI now invokes `scripts/verify_nc03r2_diagnostic.py`; the
original vulnerable `run` function remains unchanged. **46 scenarios pass** using
the actual current route, JWT decoder/decorator and canonical-season hook with
synthetic read doubles and networking blocked. This is an offline actual-code proof,
not a full deployed startup or production observation. In both production/test-mode
simulations, anonymous healthy/fault/repair-needed/malformed calls are401 without
diagnostic reads; ordinary and signed-admin-without-DB-role calls are403; current
admin healthy checks succeed and all provider/state failures are sanitized.
Captured output/logs are empty. Evidence contains status/boolean results only.

**350 offline tests pass**, including five new focused tests. The JWT R1 proof
passes seven unsafe-config cases and 14 route outcomes, including old-fallback
forgery401. Black on scoped route/new Python files, compile, unchanged-import review,
whitespace and scoped credential/reset/JWT static checks pass. No production secrets were inspected; credential values
were never printed or added to evidence. No schema/migration proof was needed for
this route-only repair; no frontend tests/build/deployment were required.

## Cleanup, release consequence and stop boundary

Read-only fixture verification confirms SEEDED/nc-fixtures-v1 with original checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`, four canonical
users/version0, canonical season and 30 standings, no temporary competition/league/
history/reset/audit state. No R2 database mutations, failure triggers, scratch DB,
listeners or real emails were created. Flask is stopped, jobs and unrestricted/
scoped mutation admission disabled. Failure messages existed only in synthetic test
memory; no raw exception/repair SQL payload was saved in new evidence.

Future rollout intentionally changes diagnostic access and reduces its payload.
No production configuration change is required. Existing production state is unknown;
no production request or deployment was performed.

Historical NC-03 FAIL and its 16 PASS/102 BLOCKED matrix remain unchanged. The local
repair does not mark NC-03 PASS. Commit backend only, without amending history:
`NC-03R2 sanitize diagnostic error responses`.

Recommended next step: **Resume NC-03 consolidated compliance audit from the repaired
backend HEAD**, only on explicit request. No automatic audit, NC-04 or other work.
