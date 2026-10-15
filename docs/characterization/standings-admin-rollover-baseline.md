# NC-01E — Standings / admin operations / season rollover baseline

Current behavior only; no fixes, provider changes, season-selection repair, workflow
changes or production contact. Frontend main `ce54143006f0409265937f5d548286d0b100d454`
and backend main `957ec94a3849c055c9088ff4bb04cde3addfa5da` were initially clean.

## Scope, approved requirements and evidence

Approved: ESPN authoritative; daily regular-season refresh; freeze at regular-season
end/bracket opening; canonical application season configuration for future selection;
match deletion permitted after successful history snapshot; no blanket playoff block
on unrelated actions; admin creation window bypass. No other operational policies
are inferred. Unreviewed: timing/manual automation, maintenance capabilities, season
creation, retries/idempotence, partial commits, overwrite and live-table retention.

25 cases passed: 2 LIVE guarded reads/refusals, 13 OFFLINE unchanged source-helper
executions, 10 STATIC inspections. 217 offline safety tests passed. Existing deterministic
ESPN and Balldontlie fixtures used through provider_transport fixture-only path; no
live provider call. Offline mutation functions use in-memory DB doubles and guard stubs
only; no real DB/network or disabled live guard bypass. LIVE jobs remain refused,
with explicit NC-01E scoped admission, identity/lease/egress checks and canonical reset.
No product code, job safety, provider transport, schema, fixture builder or frontend
changes. Scoring/snapshot helper dependencies reused; no scoring semantics repeated.

## Operational route/script/workflow inventory

| Method | Path | Authentication | Operational role |
| --- | --- | --- | --- |
| GET | /admin/env-check | JWT | admin_env_check |
| POST | /admin/leaderboard/snapshot | JWT | admin_snapshot_leaderboard |
| POST | /admin/season/rollover | JWT | admin_season_rollover |
| POST | /admin/standings/refresh | JWT | admin_refresh_standings |
| POST | /internal/standings/refresh | Token | internal_cron_refresh_standings |
| POST | /internal/standings/overwrite | Token | internal_overwrite_standings |
| POST | /admin/insert_test_teams | JWT | admin_insert_test_teams |
| GET/HEAD | /health | Optional health token | health |
| POST | /admin/score/master/<master_bracket_id>/recompute | JWT | recompute_scores |
| POST | /bracket/create | JWT | create_bracket_for_user |
| GET | /__debug/master-status | None | debug_master_status |

- admin standings refresh: JWT + DB admin, manual, Balldontlie, replaces standings,
  app season start year. Live job guard refuses before admin checks.
- internal refresh: cron token header/query, manual/external scheduled caller possible,
  same Balldontlie helper/season; no registered separate scheduler found in repository.
- internal overwrite: same token, caller-supplied rows, teams validation, standings
  season-filtered delete/insert; references absent standings.season_id. Live refusal.
- team insert: JWT + DB admin, manual, no provider, teams upserts/optional standings.
- recompute: JWT admin, bracket/match reads and score writes; NC-01D dependency,
  current season; live refusal preserved.
- snapshot: JWT + DB admin, current scores -> legacy/structured history; NC-01D
  dependency, live refusal preserved.
- rollover: JWT + DB admin, manual, no provider call, history/scores/matches/brackets/
  seasons; current ID + requested next code; live refusal preserved.
- bracket creation/master setup: own JWT, admin window bypass and automatic master
  promotion (NC-01B), teams/standings/matches/seasons; not rerun here.
- diagnostics: JWT + DB admin masked presence; health optional token/rate bucket;
  debug master status unauthenticated linkage read, inventoried not invoked.
- scripts/update_standings.py: direct DB writer using ESPN, own script job guard,
  manual or workflow schedule; no backend/token call on this path.
- .github/workflows/standings-cron.yml: daily 09:00 UTC, manual dispatch too; secret
  names only: BALLDONTLIE_API_KEY, BACKEND_BASE_URL, STANDINGS_CRON_TOKEN,
  supabase_url and supabase_key. Values not read. Several are unused by ESPN script.
  UTC daily includes weekends; 01:00 Vancouver PDT / 02:00 PST. No seasonal condition.

## Current season source map

| Subsystem | Actual source |
| --- | --- |
| Application | CURRENT_SEASON_CODE -> seasons.code -> CURRENT_SEASON_ID and dates |
| Brackets/scoring | App CURRENT_SEASON_ID; historical reads explicit stored code/ID |
| Flask standings | Starting 20xx year parsed from app code; calendar-year fallback |
| ESPN script | NBA_STANDINGS_SEASON override; otherwise UTC month/year inference of end year |
| Workflow | NBA_SEASON_YEAR=2025, not read by script |
| Rollover | Requested new_season_code; inserts row, leaves current globals/env unchanged |
| Frontend admin | VITE_CURRENT_SEASON_CODE or VITE_CURRENT_SEASON for confirmations |

No DB current-season flag. Date env values are fallbacks after DB lookup; absent end
skips early gate, absent playoff date defaults far future (NC-01B). Workflow mismatch
from NC-ENV-04B remains a confirmed independent season-source gap. UTC July 31 2026
infers ESPN end year 2026, August 1 infers 2027 regardless of canonical app season.
Production values/actual runs were not inspected; wrong target is a source-level risk,
not a claim that production fetched a particular year. Frontend env independence is
mapped without claiming its deployed value conflicts. Rollover outputs env-next-actions
and does not select the new season automatically.

## Standings/provider/refresh/freeze

standings columns: integer id, text name/code/conference, wins/losses, optional seed,
updated_at (timestamp without timezone), optional win_pct. PK id and FK code->teams.code;
no season_id and no unique standings.code constraint. Duplicate code rows possible.
Teams have required code/conference; script uses its static 30-code conference mapping.

ESPN request includes end-year season, public standings URL and JSON headers. Parser
accepts standings object or first entries-bearing object in a list. Abbreviation aliases
NY/GS/SA/NO/WSH/UTAH map to canonical codes. Stat type/name then value/summary feed wins,
losses, winpercent and playoffseed; numeric conversion falls back, pct derived if zero.
Unknown conference/missing name/code entries skipped. Fixed fixture parsed offline.
Duplicate entries update by code; existing duplicate DB codes would all update. Stale
absent teams retained. Malformed top shape returns without changes. Individual writes
can partially commit; DB/provider errors are printed/caught, not all-row transactional.
Failure test used a rejected insert; partial-prefix retention follows source write order,
not a separate live FK simulation. No FK semantics assumed from the in-memory double.

Active Flask refresh uses Balldontlie games, excludes postseason/unplayed/unknown teams,
aggregates wins/losses, sorts wins descending/losses/code, seeds each conference. Fixed
two-page fixture produced 30 rows for start year 2025. This active provider violates
ESPN authority; it is not a dormant reference. It deletes all standings then inserts,
without season field or transaction. Provider failure leaves old rows; insert failure
leaves empty table offline. Script updates win_pct; Flask replacement omits win_pct.

Daily schedule matches frequency, but no workflow/script/admin/cron/overwrite freeze
check exists at regular-season end/bracket opening. This is a confirmed approved-rule
gap; lack of seasonal scheduler condition does not turn frequency itself into a failure.
Operational playoff guards are not added. User contracts for manual overrides remain
unreviewed, but the approved freeze has no stated override exception.

## Admin/token/team operations

STATIC authorization beyond live job refusal: refresh/team/snapshot/rollover require
JWT admin + DB recheck; recompute uses JWT admin; internal refresh/overwrite use exact
STANDINGS_CRON_TOKEN equality via header or query. OFFLINE absent/wrong synthetic token
returns 403; correct token refresh returns 200; repeats retain 30 rows. No token values
recorded. LIVE anonymous JWT maintenance returns 401; ordinary/admin and token routes
reach unchanged job refusal 500, so those statuses are not claimed as live business-auth
proof. Diagnostics live anonymous401/ordinary403/admin200, masked values only.

Team maintenance attempts 20 upserts (19 synthetic IDs plus LAL), omitting required code
on initial payloads. Current schema can reject new rows before optional code fallback;
no successful live insertion/idempotence claimed. Optional standings detection/repair
is best effort; absence of standings code uniqueness can affect repeated upserts.
No approved team maintenance contract or new teams were introduced.

## Season lifecycle / rollover exact order

Seasons: unique code, ID, regular-season end, playoff start, created_at, nullable master
pointer. No current/historical flag. Admin rollover is the only discovered season
creation path; requires new nonempty/different/not-existing code, optional parseable
ISO dates. Helper accepts arbitrary nonempty code; exact naming policy unreviewed.
No completed-master/date or score-recompute precondition. Existing scores drive snapshot;
no scores abort. API job/auth guard and date parsing precede helper in normal production.

Actual helper order:
1. Validate current globals and new code; query existing next season.
2. Snapshot current stored leaderboard, or reuse exact legacy duplicate message.
3. Delete current-season bracket_scores.
4. Delete all current-season matches, including those attached to deleted brackets.
5. Soft-delete active current brackets; existing DB trigger demotes master/clears pointer
   (NC-01B, not emulated in offline transport).
6. Insert new season with optional dates; return env-next-actions.

No score recompute, provider request, standings/team cleanup, league cleanup, new bracket
or master initialization. Past-season matches retained in offline scenario. Ordinary
bracket rows remain soft-deleted; scores/matches hard-deleted. Each DB call separate;
no all-step transaction/rollback. Source pointer/trigger and FKs remain unchanged.

Successful legacy+structured snapshot writes precede match deletion. Snapshot error
aborts with no cleanup. Existing legacy-only history is accepted without checking
structured completeness. Structured snapshot failure is nonfatal in NC-01D helper,
so rollover can delete matches with legacy data but no Past Seasons snapshot. Classified
UNCLEAR: must checkpoint whether legacy-only persistence meets successfully-saved rule;
not falsely declared fully preserved or a proven no-history deletion. Original history
rank/saved-time issues cross-reference NC-01D without repeating scoring tests.

Failures in score delete/match delete/bracket soft-delete/season insert return errors
with earlier writes retained. Successful target repeated is rejected as existing; new
current season is not selected by helper. Same/empty target fails before snapshot.
Partial-state recovery/idempotence policy not inferred. No real rollover ran locally.

## Frontend and limitations

STATIC AdminPage uses cached admin flag, season-code confirmation, snapshot/rollover
modals, result/error/env-next-action display. Controls use independently configured
frontend season code. Master creation UI/backend behavior stays NC-01B. No frontend
changes/browser automation. No shared blanket playoff request guard affects operational
helpers; absence of per-operation lock is not approval of every admin capability.

No live job execution, account/league deletion, provider internet request, cron change,
production data read, deployment or season transition. Offline DB doubles do not prove
constraints/triggers/transaction behavior. No exhaustive fuzzing, real partial-provider
failure, every malformed stat variation or live date/job state. Those limits are explicit;
current source/fixed fixture and injected offline failures cover representative cases.

## Completion / requirement-gap matrix

Counts are finding rows, not independent issues. Two season-source rows refer to the
same NC-ENV-04B issue at runtime-helper/static-map levels. Evidence levels explicit;
known gaps use exact approved requirements. Passing tests record current behavior.

Classification totals: MATCHES REQUIREMENT=6; KNOWN GAP=4; REQUIREMENT NOT YET REVIEWED=14; UNCLEAR / NEEDS BUSINESS CHECKPOINT=1. Total=25.

### provider/source

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__active_provider | Active Flask admin/cron refresh aggregates Balldontlie regular-season fixture games rather than authoritative ESPN. | ESPN is the authoritative standings source. | KNOWN GAP | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | None required for classification |
| current_behavior__standings__espn | ESPN script parses existing 2026 fixture and updates/inserts codes, preserving absent stale rows; repeated refresh stable row count. | ESPN is the authoritative standings source. | MATCHES REQUIREMENT | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | None required for classification |

### season source

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__season_sources | App CURRENT_SEASON_CODE selects DB dates/id; script override/calendar independent; workflow NBA_SEASON_YEAR not consumed. NC-ENV-04B mismatch persists. | Future season selection must derive from canonical application season configuration, not conflicting independent environment variables. | KNOWN GAP | STATIC application/script/workflow/schema/frontend | None required for classification |
| current_behavior__standings__year | ESPN year follows independent NBA_STANDINGS_SEASON override or UTC August boundary; NBA_SEASON_YEAR workflow value ignored, not canonical CURRENT_SEASON_CODE. | Future season selection must derive from canonical application season configuration, not conflicting independent environment variables. | KNOWN GAP | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | None required for classification |

### standings refresh

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__espn_edges | Missing/unknown team skipped, malformed top shape leaves rows intact, duplicate team entries update existing code; changed wins written. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve parser/duplicates/stale and partial data semantics? |

### automation/schedule

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__schedule | Workflow schedules every day 09:00 UTC including weekends, invokes ESPN script and allows manual dispatch. No seasonal scheduler condition. | Standings refresh daily during the regular season. | MATCHES REQUIREMENT | STATIC application/script/workflow/schema/frontend | None required for classification |

### freeze

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__freeze | Scheduled script and active admin/cron refresh helper lack regular-season-end/bracket-opening freeze checks; overwrite also lacks freeze. | Standings freeze when the regular season ends / bracket-creation period opens. | KNOWN GAP | STATIC application/script/workflow/schema/frontend | None required for classification |

### admin operations

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__admin_ops__diagnostics | Health read works; env diagnostic anonymous401/ordinary403/admin200 with only masked presence metadata; season flags readable. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local refusal/read; reset per sequence | Operational job semantics require offline/static evidence while guard is preserved. |
| current_behavior__admin_ops__creation_bypass | Admin bracket creation bypasses ordinary early/locked window checks; prior NC-01B result retained, source gate unchanged. | Admin bracket creation may bypass the ordinary creation window. | MATCHES REQUIREMENT | STATIC application/script/workflow/schema/frontend | None required for classification |
| current_behavior__admin_ops__lock | No shared playoff guard blocks maintenance/rollover/snapshot/team helpers; ordinary creation gate has admin bypass (NC-01B). | Playoff start is not a universal block on unrelated actions. | MATCHES REQUIREMENT | STATIC application/script/workflow/schema/frontend | None required for classification |

### cron operations

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__admin_ops__cron | Internal refresh/overwrite share STANDINGS_CRON_TOKEN header/query equality; admin refresh uses JWT+DB admin; job guard runs first. Token values not inspected. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC application/script/workflow/schema/frontend | Approve cron replay/token transport/diagnostic contract? |
| current_behavior__admin_ops__token | Offline internal refresh rejects absent/wrong synthetic token; correct header calls same Balldontlie helper; repeat replaces same 30 rows. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve token transport/replay and admin/cron equivalence? |

### team maintenance

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__admin_ops__teams | Admin route attempts 20 team upserts (synthetic IDs plus LAL), omitting required code; optional standings fallback. STATIC only, live job guard unchanged. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC application/script/workflow/schema/frontend | Approve team maintenance/idempotence/schema prerequisite policy? |

### season lifecycle

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__rollover__season_model | Seasons have unique code/dates/master pointer, no current flag; rollover inserts next row without changing app globals/config, does not initialize standings/teams/master. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC application/script/workflow/schema/frontend | Approve creation/default/current-season transition policy? |
| current_behavior__rollover__preconditions | Empty/same/existing target season rejected; arbitrary nonempty new code accepted; dates optional; current globals stay old and env_next_actions asks manual config update. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve target code/date/current-selection policy? |

### rollover order

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__rollover__order | Rollover snapshots first, deletes current scores/matches, soft-deletes current brackets, inserts next season; standings/teams/past matches remain. | Season rollover may delete active match rows once the historical snapshot has been successfully saved. | MATCHES REQUIREMENT | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | None required for classification |

### snapshot preservation

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__rollover__partial_snapshot | Legacy-only existing snapshot is accepted; structured history failure is nonfatal and rollover still deletes matches. Snapshot-success definition needs checkpoint. | Season rollover may delete active match rows once the historical snapshot has been successfully saved. | UNCLEAR / NEEDS BUSINESS CHECKPOINT | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Does legacy-only persistence satisfy successfully saved snapshot when Past Seasons structured data is absent? |
| current_behavior__rollover__snapshot_failure | Snapshot error aborts before score/match deletion. | Season rollover may delete active match rows once the historical snapshot has been successfully saved. | MATCHES REQUIREMENT | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | None required for classification |

### cleanup

Coverage is mapped in the implementation/source sections and related matrix rows; no duplicate finding counted.

### failure/atomicity

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__rollover__failures | Failure deleting scores/matches, soft-deleting brackets or inserting season returns error with earlier writes retained; no all-step transaction. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve retry and partial commit recovery? |
| current_behavior__standings__refresh_failure | Flask refresh deletes all standings then inserts; insert failure leaves empty table; provider failure occurs before delete. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve replace/error/rollback policy? |
| current_behavior__standings__script_failure | ESPN DB failure is caught without rollback; per-code updates before failure can remain. Invalid override raises before request. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve error propagation and partial updates? |

### authorization

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__admin_ops__refusals | JWT routes reject anonymous 401; ordinary/admin operational jobs return existing job-guard 500 before operational authorization. No live maintenance write. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local refusal/read; reset per sequence | Operational job semantics require offline/static evidence while guard is preserved. |

### frontend

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__admin_ops__frontend | AdminPage cached admin gate, snapshot/rollover confirmation and error/result/env-next-action display; UI completeness gates can differ from helper preconditions. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC application/script/workflow/schema/frontend | Approve UI/backend operational preconditions? |

### edges

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__standings__overwrite | Internal overwrite expects standings.season_id though current table lacks it; delete+insert not atomic. No product/schema correction. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC application/script/workflow/schema/frontend | Approve overwrite schema and failure contract? |
| current_behavior__rollover__repeat | Repeat target rejected once created; existing legacy snapshot reuses without checking structured completeness; no master completion/date/recompute prerequisite in helper. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof | Approve rollover idempotence/preconditions? |

## Validation / cleanup / later checkpoint

```text
python -B scripts/run_operations_characterization.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
```

25 characterization cases and 217 safety cases passed. Fixed explicit classes only,
no arbitrary selectors/job bypass. Semantic schema and marker ACL verifiers passed;
independent final canonical readiness/checksum and localhost connection refusal passed.
Flask stopped, leases released, capture clear, jobs disabled, SEEDED nc-fixtures-v1:
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Counts restored: 4 users, 2 seasons, 30 teams, 30 fictional standings; other tables empty.
Formatting/syntax/JSON/matrix/secret/log/whitespace/exact-scope audits passed.

Later questions: canonical season propagation; manual provider/override policy; parser
partial/stale/duplicate semantics; operational auth/token transport; team maintenance;
season-code/default/transition policy; legacy-only snapshot success; rollover timing,
retry/partial commits and retention. Approved provider/freeze/configuration rules are
not reopened or repaired. No business behavior changed. Production contact/mutation/
secrets/deployment none. Next candidate: **NC-01F — Consolidated regression baseline /
requirement-gap matrix**. Not started; no remediation performed.
