# NC-02C2 — ESPN standings authority, freeze and atomic refresh

## Scope/checkpoint

Approved S3–S9/S13 only. Backend main `6f05efbf13a77101d752666cc5193107d2edff7c`
and frontend main `947a785ed2abf38d0098f588d2edb0910169e6d7`, both initially clean.
No production reads/writes/deployment. No bracket/scoring/history/rollover repair.

## Pre-change complete path inventory

Recorded before implementation in `db/records/nc_02c2_standings_path_inventory.json`.

| Path | Original provider/source | Original freeze/validation/write | Auth/caller |
| --- | --- | --- | --- |
| Daily workflow -> scripts/update_standings.py | ESPN; C1 canonical ending year | No freeze; skips malformed/unknown rows, per-code update/insert, stale rows retained, partial failure possible | GitHub service-role secrets, 09:00 UTC daily including weekends; dispatch/manual CLI |
| Admin refresh -> fetch_and_sync_standings_from_nba | Balldontlie completed-game aggregation; C1 canonical start year | No freeze; delete all then independent insert, no atomic rollback | JWT + DB admin; operational guard |
| Cron refresh -> same helper | Same Balldontlie | Same | Existing header/query cron token; operational guard |
| Internal overwrite | Caller-supplied rows; canonical ID | Partial validation; expects nonexistent season_id, nontransactional write | Existing header/query token; operational guard |
| Admin insert_test_teams seed_standings | Synthetic 20-team data | Optional partial upsert and legacy column fallback | JWT + DB admin; operational guard |
| Provider seam | Fixed ESPN/Balldontlie fixtures | No live provider callbacks in test mode | Existing NC-ENV positive identity/provider/egress gates |
| Fixture reset | Original deterministic foundation | Transactional guarded reset, checksum restoration | Positive local identity and exclusive lease; never production |

No frontend standings-refresh action was found; frontend remains untouched.

## Consolidated service and provider

`standings_service.refresh_current_standings` is the single core for scheduled,
admin and cron callers. It resolves C1 canonical state, compares now against
bracket_creation_opens_at, derives ESPN ending year, fetches through the existing
provider_transport seam, parses/maps and validates the complete dataset, then
makes exactly one publish_current_standings RPC. No Balldontlie fallback. The old
Flask helper name remains only as a compatibility wrapper. Unrelated provider
transport and historical fixtures remain available.

The scheduled script is a small guarded wrapper; it does not parse or write
standings separately. Existing startup guard still precedes client construction.
Workflow keeps daily `0 9 * * *` and manual dispatch. Obsolete Balldontlie key,
backend URL and cron-token wiring are removed from this direct trusted DB script;
only existing Supabase URL/service-role secret references remain. No secrets read
or changed in GitHub/production and no season value added to the workflow.

## Freeze and canonical fencing

Before canonical opening, normal refresh may fetch/publish. At/after opening,
all three paths return successful structured `state=frozen, refreshed=false` and
skip provider fetch and standings write. Admin has no bypass; force input has no
effect. Freeze never depends on playoff lock; the interval after opening and before
playoff start freezes standings while ordinary bracket timing can remain editable.
No duplicate date parser or independent environment/calendar selector is introduced.

DB publication locks the singleton canonical pointer and selected season row,
checks supplied canonical ID, then compares clock_timestamp() against the native
regular-season-end timestamp again. This rejects stale canonical jobs and safely
returns frozen if fetch/validation crossed the boundary. Future C3 transition must
coordinate locking in pointer -> season order. No transition is implemented here.

## Mapping, normalized schema and validation

Normalized rows contain only code, canonical team name, conference, seed,
wins, losses and win_pct. Database owns IDs and one UTC publication timestamp.
No arbitrary provider payload is persisted. Fixed 30 NBA codes/conferences and
known ESPN aliases (NY/GS/SA/NO/WSH/UTAH) are centralized. Provider IDs, when supplied,
must match those NBA identities. Explicit wrong league/conference values fail.
All canonical teams must exist with expected conference; unrelated maintenance
teams cannot enter the NBA pool.

Complete validation requires exactly 30 distinct canonical teams, exactly 15
East/15 West, complete unique integer conference seeds 1–15, nonnegative integer
wins/losses and finite 0–1 win percentage consistent with wins/losses. Missing,
null, malformed, fractional, duplicate and unknown data fail, never get skipped.
Zero values remain zero; summary fallback applies only to absent/empty values.
Flat or list-of-group standings entries are combined completely, never first-group
selection. Missing/bad structure fails. Percentage is derived from wins/losses;
provider percentage, when supplied, must agree within rounding tolerance.

## Atomicity/schema/security

New portable migration `0003_nc_02c2_atomic_standings.sql` follows immutable baseline,
0001 B3, 0002 C1. Old migrations and table schema remain unchanged. No history or
season column added. New public.publish_current_standings(uuid,jsonb) returns jsonb,
owned by postgres, PL/pgSQL, SECURITY INVOKER, search_path pg_catalog,public. Same
transaction revokes PUBLIC/anon/authenticated execute and grants postgres/service_role
only. Existing table/sequence ACLs, RLS, policies, functions and triggers unchanged.
Browser path stays frontend -> Flask -> trusted server DB. No public arbitrary
standings input is accepted.

Function validates row count, shape/types, distinct canonical code/FK mappings,
conference counts/ranks and numeric ranges defensively before delete. Delete and
insert occur in one transaction/function call. An explicit non-null primary-key
predicate honors Supabase safe-update enforcement; no safety setting is disabled.
Successful publication contains exactly the new 30 rows, no stale or mixed state.
The evolved verifier retains all C1 assertions except adding the function inventory
entry, then checks body/settings/owner/ACL. C1 verifier is frozen separately.

Legacy caller-supplied overwrite is retired: existing authorization then HTTP 410
points callers to ESPN refresh. Optional seed_standings=true is refused with 409
before any team writes. Unrelated no-seed team-maintenance behavior remains unchanged.
These close identified write bypasses without granting emergency authority.

## Failures/API/logging

Provider/parsing/mapping/complete-validation failures occur before publication.
Database failure rolls back its entire transaction. All preserve last good published
rows. Admin/cron return success information or frozen at HTTP 200; sanitized refresh
errors return HTTP 502. Existing JWT/DB-admin and cron-token checks remain unchanged.
Logs allowlist only operational state, canonical season code and team count;
no provider bodies, raw exceptions, headers, tokens or environment dumps.
States distinguish refreshed/frozen/provider_failure/parsing_failure/mapping_failure/
validation_failure/publish_failure. CLI failure remains nonzero, frozen success zero.

## Test evidence and safety

New complete 30-team synthetic ESPN fixture is selected by the existing explicit
2026 fixture seam; the original two-team fixture remains historical data. Original
canonical application foundation/version/checksum remain unchanged. New focused
application cases exercise actual admin JWT/DB authorization, token cron and the
scheduled wrapper against the enrolled local fixture database. They converge on
equivalent 30-team semantic state, and prove exact/after freeze no-fetch, distinct
playoff timing, invalid-data/provider preservation, auth refusal and retired bypasses.
Pure tests cover missing/extra/duplicate/unknown identities, IDs/league/conference,
rank boundaries/duplicates/fraction/null, malformed result fields and real zero.

C2 test capability is selected-job-only, active owned local lease/positive identity,
fixture provider, nonce/route admission and scope protected. Jobs remain globally
disabled. Default and prior scopes still refuse jobs; score/snapshot/rollover are
never admitted. Scheduled test runs the actual script function with the verified
local client, not an uncontrolled subprocess. No production toggles or failure
injection are added to product functions.

Fresh disposable proof: schema-only verified local platform -> empty immutable
baseline -> 0001 -> 0002 -> 0003 -> semantic verifier -> synthetic seed -> trusted
service publish. A test-only temporary trigger raises during INSERT after DELETE;
catching that failure proves prior 30 rows, IDs and timestamps exactly preserved.
The trigger/function live only in the disposable transaction and are rolled back.
DB freeze, stale canonical ID and anon/authenticated refusal also pass. PostgreSQL
sequence increments are nontransactional; only the disposable fixture counter is
restored before canonical checksum verification. The disposable database is removed.

Early focused failure was the safe-update DELETE predicate requirement, corrected
without disabling protections; full focused rerun passed. A test-runner metadata
import was fixed before test execution. Historical observations are converted in
new phase evidence with previous metadata retained; historical reports unchanged.
No frontend changes, so conditional frontend test/build reruns are unnecessary.
Ruff/Pyflakes are unavailable and no backend lint runner is configured. No packages
were installed. Syntax/AST imported-name comparison, Black and whitespace checks
provide the recorded scoped lint comparison, with no new unused imports. This is
not represented as a full lint-engine run.

## Production readiness/rollback

Production untouched; migration and code are for review only. Later explicit
rollout requires verified secured C1 schema/backup, canonical designation and
opening/lock timing, complete expected canonical team codes/conferences, reviewed
current standings/FK state, server service-role permissions, and coordinated
migration/backend/scheduled-script release. Ensure HTTPS/DNS/TLS access to the
fixed ESPN endpoint and Supabase. GitHub requires existing secrets supabase_url and
supabase_key (trusted service role), no ESPN API key or season override. Flask cron
still requires its existing token independently.

First successful pre-freeze refresh replaces current state with exactly 30 validated
ESPN rows. Frozen first execution fetches/writes nothing; missing config or invalid
provider data fails closed and leaves the old state. No emergency correction path
is added. Rollback: pause refresh callers, retain last-good data, coordinate reviewed
code rollback/forward fix before removing the trusted function. Do not automatically
reenable legacy Balldontlie/nonatomic writers or clear/reconstruct standings. Schema
is otherwise unchanged; no destructive data rollback is required.

## Deferred/next

Canonical advancement, standings reset during rollover, broader rollover recovery,
legacy snapshot ambiguity, champion +3/finalist +1, snapshot tie order and league/auth
questions remain unchanged. Next recommended phase: NC-02C3 — Canonical season
transition and standings reset integration. Not started.


Final validation: 209/209 complete applicable backend regressions passed twice;
final run includes the narrowed seed-refusal guard and expanded real HTTP invalid
cases. Offline safety 263/263, C2 units9/9 and C1 units10/10 (included offline),
focused application5/5 (included full), source/in-memory70/70, fresh full migration
chain, actual mid-insert rollback, semantic verification, Black/whitespace and
secret/privacy audits passed. No full Python lint engine available; scoped AST
comparison found no new unused imports. Frontend unchanged and conditionally not
rebuilt. All71 historical artifacts remain byte-identical. Final cleanup confirms
original30-row foundation/checksum, unchanged canonical pointer, lease released,
Flask stopped, email capture empty, app import removed, jobs disabled and proof DB
absent. The C2 team-insert capability admits only the fixed seed=true refusal proof,
never ordinary maintenance. No production action or C3 work performed.
