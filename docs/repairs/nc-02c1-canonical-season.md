# NC-02C1 — Canonical season foundation

## Scope and starting state

S1/S2/S12/S14 only. Backend main `3546d175ef9c21ca160e8d0d64e7a3cec5f8f14b`;
frontend main `0ad01528808bfdd19f2778f74a0c0042f334f2e6`; both clean.
No production contact. No provider replacement, freeze enforcement, standings
atomicity/reset, rollover transition, scoring formula or bonus/tie changes.

## Complete pre-change season-source map

Recorded before implementation in `db/records/nc_02c1_season_source_inventory.json`.
Every affected application function and separate source appears below. Application
CURRENT_SEASON_ID/dates came from process-global resolution of the environment
CURRENT_SEASON_CODE, with environment date fallbacks and a 2099 default lock.
Standings is currently a singleton data table without a season_id column; that
schema mismatch and replacement behavior remain deferred.

| File/function | Original sources | Context/authority |
| --- | --- | --- |
| `app.py::<module>` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE`, `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::_resolve_season_globals` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE`, `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::playoffs_locked` | `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::current_master_bracket` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::bracket_creation_open` | `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::_fetch_matches_for_bracket` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::_compute_score_for_bracket` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::with_current_season` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::competitive_bracket_eligible` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::ensure_season_globals` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::active_current_master_exists` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::admin_snapshot_leaderboard` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::admin_season_rollover` | `CURRENT_SEASON_CODE`, `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::fetch_and_sync_standings_from_nba` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE` | production; authoritative |
| `app.py::internal_overwrite_standings` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE` | production; authoritative |
| `app.py::admin_insert_test_teams` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::recompute_scores` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::_snapshot_leaderboard_for_current_season` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE` | production; authoritative |
| `app.py::_rollover_current_season` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE`, `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::create_bracket_for_user` | `CURRENT_SEASON_ID`, `REGULAR_SEASON_END_UTC` | production; authoritative |
| `app.py::save_bracket` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::get_my_bracket` | `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::get_bracket_by_id` | `CURRENT_SEASON_ID`, `CURRENT_SEASON_CODE` | production; authoritative |
| `app.py::list_all_brackets` | `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC` | production; authoritative |
| `app.py::delete_bracket` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::update_match` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::set_match_games` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::leaderboard` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::champion_pick_stats` | `CURRENT_SEASON_ID` | production; authoritative |
| `app.py::add_conf` | `CURRENT_SEASON_ID` | production; authoritative |
| `scripts/update_standings.py::<module>` | `NBA_STANDINGS_SEASON` | production; authoritative |
| `scripts/update_standings.py::_current_nba_season_year` | `_current_nba_season_year` | production; authoritative |
| `scripts/update_standings.py::update_standings_from_json` | `NBA_STANDINGS_SEASON`, `_current_nba_season_year` | production; authoritative |
| `integration_harness.py::__init__` | `CURRENT_SEASON_CODE` | guarded-test-only; authoritative |
| `integration_harness.py::bracket_deadline_boundary` | `PLAYOFFS_START_UTC` | guarded-test-only; authoritative |
| `environment_safety.py::<module>` | `CURRENT_SEASON_CODE`, `REGULAR_SEASON_END_UTC`, `PLAYOFFS_START_UTC`, `NBA_STANDINGS_SEASON` | guarded-test-only; allowlist only |
| `.github/workflows/standings-cron.yml::standings job` | `NBA_SEASON_YEAR=2025` | production; unused legacy variable |
| `../frontend/src/pages/AdminPage.tsx::AdminPage` | `VITE_CURRENT_SEASON_CODE`, `VITE_CURRENT_SEASON` | production; confirmation/display |
| `../frontend/src/pages/PastSeasonsPage.tsx::PastSeasonsPage` | `VITE_CURRENT_SEASON_CODE`, `VITE_CURRENT_SEASON` | production; history exclusion filter |
| `../frontend/src/pages/PastSeasonsPage.tsx::canShowStatsLink` | `year >= 2025` | production; presentation only; retained |
| `tests/characterization/*::offline environments / fixed fixtures` | `synthetic current=2025-26`, `explicit test clock` | test-only; test fixtures only |

Historical snapshot codes, explicit historical season_code requests and requested
rollover target codes identify those records; they are not alternative current
season authorities. PastSeasons' `year >= 2025` stats-link threshold is a retained
historical presentation capability, not a current-season selector. Timing clocks
still determine status *within* the designated season. Test doubles contain fixed
synthetic identities only; no production helper reads their variables.

## Selected architecture and invariants

`public.application_season(singleton boolean PRIMARY KEY CHECK(singleton),
season_id uuid NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT)` stores one
backend-owned pointer. A configured environment has exactly one valid designation;
structural constraints prevent a second row, false singleton or nonexistent season.
The empty unconfigured state is deliberately allowed by schema but never by the
runtime. Missing/duplicate rows, invalid season codes, missing/naive/invalid timing,
reversed timings and provider/database failures cause a sanitized operational
error, never latest-row selection, environment fallback or calendar inference.

A singleton pointer avoids adding changing current flags/timing copies to every
season. It preserves existing season records and their checksum, avoids a parallel
configuration service and lets future controlled rollover update one FK atomically.
No unrestricted season-update API or mutation RPC was added.

## Migration, security and initialization

Migration order: immutable NC-ENV baseline ->
`0001_nc_02b3_bracket_lifecycle.sql` ->
`0002_nc_02c1_canonical_season.sql` -> full evolved semantic verifier.
The new migration deliberately inserts NO designation. It does not guess a season
and contains no production identifiers or temporary year. A future production
operator must separately verify and explicitly designate an existing valid season
with reviewed opening/lock timestamps before enabling the matching application.
Without that step, the backend returns 503 and the standings script refuses work.

The table is owned by postgres with RLS enabled and no client policies. PUBLIC,
anon and authenticated have no direct access; postgres/service_role retain trusted
server access (including PostgreSQL 17 MAINTAIN). Existing relation/column ACLs,
RLS/policies, functions, triggers, defaults, indexes and B3 RPC are unchanged.
No new privileged function exists. The full verifier preserves every B3 assertion,
changing only its relation inventory and adding strict canonical-table checks.
The B3 verifier is frozen separately as `verify_nc_02b3_schema.sql`; historical
NC-ENV and phase reports remain unchanged.

The guarded local reset explicitly designates `identity("current")` after seeding
existing synthetic seasons. It includes the pointer table in the fixed truncate
and inbound-FK allowlist, preserving identity/lease/egress/mail/job protections.
Original fixture rows, sequence state, version `nc-fixtures-v1` and checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`
remain unchanged. Canonical state has an independent mandatory readiness assertion;
it is not silently added to or excluded from an altered checksum definition.
Fresh bootstrap leaves the pointer empty until guarded synthetic seed or a future
explicit deployment designation. A C1-only test helper allows only current,
historical and missing synthetic states under the active owned local lease.

## Central backend authority and migrated consumers

`canonical_season.py:get_current_season(client)` returns immutable CurrentSeason
(id, code, bracket_creation_opens_at, playoff_lock_at). `app.py:current_season()`
pins one row per Flask request with g, avoiding cross-request globals and stale
worker state. Outside requests it resolves directly. Every former current-season
Name in bracket, current-master, scoring, leaderboard, statistics, snapshot, admin
and rollover consumers now obtains this same canonical context. Existing historical
queries keep explicit historical identity; score formulas and snapshot algorithms
are unchanged. Missing configuration returns sanitized HTTP 503 from the request
bootstrap before application work. Standalone provider scripts also fail before
provider fetch/write when canonical state is unavailable.

`CurrentSeason.status(now)` exposes distinct opening/freeze and final-lock states.
Before opening freeze=false; at opening freeze=true. Before playoff start lock=false;
at playoff start lock=true. The interval between them is bracket creation open.
S12 is timing metadata only: standings refresh does NOT enforce freeze yet.

`season_start_year("2025-26")=2025` supports the unchanged Balldontlie path;
`espn_season_year("2025-26")=2026` supports the existing ESPN script. Strict
adjacent-year validation includes century boundaries (1999-00 -> 2000).
NBA_STANDINGS_SEASON, NBA_SEASON_YEAR, CURRENT_SEASON_CODE and environment timing
values have no selection authority. The unused workflow NBA_SEASON_YEAR assignment
is retired; schedule, secrets references and provider/job mechanics remain intact.
NC-ENV config allowlists can still accept legacy test inputs, but product resolution
never reads them. No date inference helper remains in the production ESPN script.

## Backend endpoint and frontend

Public `GET /season` returns only season code, canonical opening/lock timestamps,
standings_freeze_reached, playoffs_locked and bracket_creation_open. Existing bracket
status envelopes keep their contracts and now derive from the same backend source.
AdminPage uses the validated backend status for season labels and confirmations;
failed configuration disables actions and shows an error. PastSeasons fetches the
canonical code before filtering current history; failure shows an error rather than
using a build-time guess. VITE_CURRENT_SEASON_CODE/VITE_CURRENT_SEASON are no longer
read. Dashboard/BracketPage deadline controls still use server flags. No UI redesign.

## Rollover preparation and exact deferred integration

The current side of rollover and snapshot now resolves canonical state. Requested
next season input and existing destructive ordering/recovery behavior are unchanged.
Rollover does NOT advance application_season. The existing env_next_actions response
keys are retained as compatibility target metadata, with a corrected message; they
are not instructions to choose season through environment values. Admin wording
explains activation is pending. NC-02C3 must update the singleton season_id only as
part of the reviewed successful controlled transition, after required history and
retirement/target initialization, coordinated atomically with that lifecycle. No
such update or standings reset was added here.

## Validation and provenance

Evidence files use nc_02c1_* names; earlier reports are not rewritten. New unit and
HTTP cases cover conflicting production legacy env values, missing/duplicate state,
explicit test pointer switching without restart, bracket/source consistency, safe
503 recovery, date independence, timing boundaries, multi-season ESPN conversion,
secure schema and strict verifier preservation. Frontend tests cover validated
backend data, fetch failure, missing/invalid fields, admin/history authority and
preserved deadline controls. Existing privacy/eligibility/B1/B2/B3 regressions are
rerun in the complete applicable suite. Original source observations remain in
previous_metadata when converted to S1/S2/S12/S14 acceptance.

Fresh disposable proof uses schema-only verified local platform definitions, then
empty immutable application baseline, B3 and C1, full semantic checks, synthetic
seed, singleton/FK/direct-access denial, canonical fixture equality and existing
master transaction rollback. It never fakes API enrollment. The disposable DB is
removed. Full HTTP acceptance runs separately on the positively enrolled local
Supabase with existing guards. Docker Desktop was initially stopped and was started
only for these local tests. The first new ACL assertion was corrected to include
PostgreSQL 17 MAINTAIN for trusted roles; no privilege weakening occurred.

## Production readiness, rollback and deferred requirements

Production was neither queried nor changed. Future rollout needs explicit approval,
verified target and backup, prior secured B3 schema verification, reviewed designation
and timings, migration, designation and coordinated backend/frontend/script release.
Avoid legacy season-writing operations during the controlled transition. Verify
endpoint, provider-year derivation and security before re-enabling jobs. A rollback
must retain/record the designated season, coordinate old application configuration
against that same reviewed identity and separately authorize any schema removal;
never guess from date/latest season or discard configuration implicitly.

S3-S11/S13 remain deferred: ESPN-only authority, refresh schedule/freeze enforcement,
30-team validation, atomic/stale-row-safe replacement, admin freeze, rollover
standings clear and canonical advancement, broader transition recovery. Champion
+3, finalist +1 and snapshot tie order are also unchanged. Recommended next phase:
NC-02C2 — ESPN standings authority, freeze and atomic refresh. Not started.


Final validation: complete corrected run 204/204, offline safety 254/254,
canonical unit 10/10 (included offline), focused HTTP 3/3 (included full),
frontend 19/19, production TypeScript/Vite build, strict semantic DB and fixture
verifiers all passed. Initial full run had one source-line-wrapping assertion
failure; assertion made whitespace-insensitive, all 70 source/in-memory cases
rechecked, then entire 204-case suite rerun successfully. No subset-only completion.
Twelve existing lint findings across the two affected pages remain; no new
findings. All 63 prior historical artifacts remain byte-identical. Final cleanup:
one canonical synthetic designation, original fixture checksum, lease released,
Flask stopped, email capture empty, app import removed, jobs disabled and disposable
DB absent. Production remains untouched.
