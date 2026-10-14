# NC-ENV-04B: provider fixtures and operational job safety

This phase enables provider response characterization only. It does not enable
application startup, DB mutation, integration execution, seeds or reset/reseed.
Production callbacks, request arguments, parsers, authorization and workflow bytes
remain unchanged. No live provider was contacted and no operational writer ran.

## External provider inventory

| Path/function | Purpose and effects | Credential / caller | Test / production treatment |
| --- | --- | --- | --- |
| scripts/update_standings.py: update_standings_from_json | ESPN GET, parser, manual standings SELECT then UPDATE/INSERT by code | ESPN public, no provider key; Supabase service key; workflow or manual script | Exact local ESPN fixture; script blocked before clients; original GET in production |
| app.py: fetch_and_sync_standings_from_nba | Balldontlie paginated games GET; regular-season wins/losses and conference seeds; teams SELECT then whole standings DELETE/INSERT | BALLDONTLIE_API_KEY and Supabase key; admin refresh or cron-token refresh | Two local pages, no API key; job guard blocks writes; original production GET/header/pagination |
| app.py: NBA_STATS_STANDINGS_URL / NBA_STATS_SEASON_TYPE | Dormant constants only; no active request | None used; no caller | No invented NBA Stats fixture; unknown provider destination refused |
| app.py: create_client, all supabase.table(...).execute() | DB reads/writes across users, password resets, teams, standings, seasons, brackets, matches, scores, leagues and history | SUPABASE_KEY; Flask routes and internal helpers | Startup refuses before client creation; future target restricted to enrolled local identity; production unchanged |
| scripts/update_standings.py: create_client | Standings persistence | SUPABASE_SERVICE_ROLE_KEY; workflow/script | Guard precedes creation; production unchanged |
| environment_safety.py: verify_live_local_identity | Authenticated, bounded marker GET only, no redirects/proxy/DNS hostname | Native ignored local key; deliberate read-only helper | Numeric-loopback enrolled API only; never an execution permit |
| email_transport.py / app.py: _send_email_via_brevo_production | Brevo POST/email send; forgot-password also stores reset row, admin test-email send | BREVO_API_KEY / sender config; forgot-password or admin endpoint | Existing in-memory capture and reset-link origin gate preserved; original production Brevo body unchanged |
| frontend/src/lib/analytics.ts | Browser gtag events only; no backend Analytics HTTP path | Frontend VITE_GA_MEASUREMENT_ID | Frontend unchanged; no browser run or synthetic events |
| scripts/local_supabase_environment.py | CLI/Docker lifecycle, baseline/marker bootstrap, configure, verification | Native local stack credentials only | Existing safety paths preserved; only read-only readiness action used here |

No additional active backend external HTTP provider was found. models.py is empty.
The DB baseline has four service-only mutation RPCs and three existing trigger
functions; their ACLs and bodies are unchanged. They are not new scheduling paths.

## Job / operational writer inventory

| Path | Classification | Effects / production authorization |
| --- | --- | --- |
| .github/workflows/standings-cron.yml | Automatic schedule; workflow_dispatch | Daily 09:00 UTC, direct script; original secrets unchanged |
| scripts/update_standings.py | Script, direct DB writer | Standings manual upsert, original ESPN season override/fallback |
| /admin/standings/refresh | Manual admin endpoint | JWT admin flag + users.is_admin; Balldontlie helper |
| /internal/standings/refresh | Cron-token endpoint | X-Cron-Token or query token; same refresh helper |
| /internal/standings/overwrite | Cron-token endpoint, direct writer | Validates team codes; season-scoped standings delete/insert |
| /admin/insert_test_teams | Admin utility, direct writer | Teams upsert; optional standings seed/fallback; not executed |
| /admin/score/master/<id>/recompute; _compute_score_for_bracket | Admin/internal scoring operation | Current-season scores upsert; original scoring rules |
| /admin/leaderboard/snapshot; _snapshot_leaderboard_for_current_season | Admin/internal snapshot | Legacy and structured history inserts, existing partial-failure behavior |
| /admin/season/rollover; _rollover_current_season | Admin/internal maintenance | Snapshot/reuse, current-season score/match delete, bracket soft-delete, next season insert |
| scripts/local_supabase_environment.py bootstrap/configure/start/stop | Explicit local provisioning script | Existing empty-only bootstrap and local identity controls; not invoked here |
| scripts/run_test_environment.py | Controlled launcher | Backend/standings/integration child remains blocked before execution |
| Ordinary auth, bracket/match and league mutations in app.py | User request operations, not scheduled jobs | Existing authorization and SQL unchanged; all test startup remains blocked |

No in-process timer/background scheduler exists. threading is used for the rate
limit lock, not job execution. Season before_request bootstrap resolves globals;
it does not refresh standings, recompute, snapshot, rollover or insert teams.

## Fixture transport

provider_transport.provider_get forwards the original callback and identical
arguments in production. In test it validates explicit identity/enrollment and
NBA_CORNER_PROVIDER_MODE=fixtures, rejects provider/operational configuration and
credential headers, selects fixed local files, and never calls the callback.
Unexpected destinations, missing/unknown/live modes, seasons and cursors refuse.

Fixtures under tests/fixtures/providers are invented public team response examples,
not production captures or DB seeds. ESPN end-year 2026 has two entries covering
team-code normalization, type/name keys, summary fallback and real zero handling.
Balldontlie start-year 2025 has two cursor pages with completed games, playoffs,
unplayed games, ties and unknown teams. Production filtering/aggregation unchanged.
Fixture JSON is fresh per read; no response credentials or private/personal data.

## Credentials and application-level egress

Controlled child environments do not inherit provider secrets, cron/admin JWT or
health tokens, proxy variables, or arbitrary parent variables. Explicit test config
omits operational secrets; its only credential values are native local Supabase
server keys. Nonempty provider prefixes and operational secrets in config or ambient
environment refuse. No production .env is loaded for controlled test execution.

Known active provider requests have fixture-only transport with no live fallback.
Existing Brevo capture stays in place. Supabase client initialization remains blocked.
The existing live identity GET uses exact numeric loopback and rejects redirects;
validate_test_destination provides an enrolled-loopback allowlist for future local
services, not a new enabled client. There is no global requests/socket monkeypatch
or host firewall/container outbound isolation; future transports must use the guards.
No claim of OS/container egress isolation is made.

## Job contract and readiness

NBA_CORNER_JOBS_ENABLED is false by default in test. Readiness requires the explicit
literal false; missing or enabled job state cannot pass readiness. Production
behavior does not consult a new enable switch. Runtime test operational entrypoints
call guard_runtime_job and refuse without an explicit in-process invocation request.
There is no HTTP token, new shell entry or arbitrary callback executor bypass.

require_explicit_test_job checks a fixed known job name, matching requested_job,
explicit mutation opt-in, enrolled LOCAL target/production denylist, email capture,
fixture providers, jobs disabled, authenticated marker and current fixture state.
It then reaches the existing unconditional mutation/startup refusal. Even all these
checks passing is not permission to run a writer. Future seeded-state/reset/harness
proof must be implemented in later phases before any job executor is available.
The current authoritative marker must still say UNSEEDED; caller dictionaries are
not identity proof. Automatic HTTP/admin/script calls cannot set requested_job.

Read-only command (no Flask startup or job invocation):

```text
python -B scripts/local_supabase_environment.py provider-job-readiness --config C:/NBACorner/backend/.env.test.nba-local.local
```

Observed: local identity/marker PASS, email PASS, providers PASS, external credentials
absent PASS, jobs-disabled PASS. Fixture state UNSEEDED; fixture/reset and integration
harness UNMET; overall mutation_permitted=false. Ignored local config changed only
by adding NBA_CORNER_PROVIDER_MODE=fixtures; native credentials retained, not exposed.

## PRESERVED CURRENT BEHAVIOR / FUTURE BUSINESS REVIEW

- Workflow supplies NBA_SEASON_YEAR; script reads NBA_STANDINGS_SEASON. Unchanged.
- Script uses ESPN while Flask refresh uses Balldontlie; misleading NBA Stats comments
  and dormant constants are preserved.
- ESPN season fallback/end-year and zero/summary parsing remain unchanged.
- Balldontlie game filtering, 100-page cap, sorting and whole-table replace remain.
- Standings season/schema differences and admin utility fallback remain unchanged.
- No freeze, bracket gate, rollover, scoring or authorization fixes were attempted.
- Snapshot structured-history failure still retains legacy snapshot behavior.
- Production email/reset quirks from NC-ENV-04A remain unchanged.

## Verification

61 environment + 20 email + 28 provider/job tests passed (109 total). Suites prohibit
socket connections and never import Flask app or live integration modules. Extracted
parser/aggregation statements exercise fixtures without writer statements/clients.
Production GET arguments and job no-op behavior are mocked offline. Workflow hash
checked against exact pre-phase bytes. Syntax, JSON shape/size, scoped Black, Git
whitespace, production identifier and credential scans passed. After mechanically
removing only the approved transport/guard seams, ASTs match the starting app and
standings script exactly (65 and 4 top-level functions respectively).

```text
python -B -m unittest discover -s tests/offline -p test_environment_safety.py
python -B -m unittest discover -s tests/offline -p test_email_transport.py
python -B -m unittest discover -s tests/offline -p test_provider_job_safety.py
```

No provider call, email send, standings/job execution, DB mutation, integration test,
production contact, workflow run, deployment or frontend change occurred. Baseline
SQL and security containment remain unchanged. Next recommended phase is NC-ENV-05
(deterministic synthetic seed/reset tooling), requiring separate authorization.
