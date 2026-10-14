# NC-ENV-06 guarded local integration smoke

This phase proves isolated application persistence only. It is not broad
characterization or approval of bracket/scoring/league business behavior. Production,
frontend, application source and schema/baseline remain unchanged. No deployment.

## Exact approved invocation

Required services: the existing reviewed local Supabase PostgreSQL/API stack. Flask
must NOT already be listening at enrolled http://127.0.0.1:55410. The harness owns its
temporary local server and shutdown. No browser, hosted DB or external provider.

```text
python -B scripts/run_guarded_smoke.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B scripts/run_guarded_smoke.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations --simulate-failure
```

Without the explicit flag, invocation refuses. The ignored config's existing global
mutating-test opt-in stays 0. The explicit flag supplies scoped opt-in inside the
verified context; no ALLOW_MUTATIONS/global bypass was added. Use the maintained
GuardedHarness context only; never invoke app.py, raw helpers, old pytest integration,
standings mutator or administrative maintenance to bypass it.

## Gate inventory and orchestration

| Gate | Existing implementation / harness use |
| --- | --- |
| Identity, denylist, origin/registry | environment_safety.validate_test_target; explicit local enrollment, numeric loopback only |
| Marker/baseline/v2 metadata | validate_local_marker + authenticated verify_live_local_identity |
| Canonical fixture version/hash | verify_fixture_readiness + fixed expected nc-fixtures-v1 SHA256; complete rows and sequences verified |
| Mutation opt-in | CLI flag plus context settings; target validator still requires opt-in=1 inside context |
| Email/reset origin | validate_test_email_settings; in-memory capture, no Brevo; reset origin equals enrollment |
| Provider credentials/mode | validate_test_provider_settings; fixtures only; ambient/config provider and operational credentials denied |
| Disabled jobs | validate_test_job_settings; existing runtime job guards remain refusing |
| Reset/schema/ACL proof | existing run_reset and unchanged baseline/marker verifiers |
| Exclusive execution | LocalFixtureLease, same DB session advisory lease (50405,1) across reset/start/read/write/cleanup |
| Backend identity | actual SDK database origin checked; protected temporary identity route + marker evidence |

Existing validators are reused rather than rewritten. Pure marker validity is not
an execution permit. Repeated identity checks intentionally protect distinct
boundaries: preflight, immediately before reset, locked reset transaction, startup,
backend handshake and each admitted request. The reset tool remains a separately
approved fixed-foundation maintenance path, not a generic application test executor.

## Harness architecture and authorization

integration_harness.py defines the sole context. It validates settings and canonical
seeded state, acquires the DB session lease, performs approved reset/reseed, and
verifies the canonical rows/checksum again. Only then is an in-memory startup permit
active. environment_safety.prepare_runtime_environment accepts that permit only in
the owning thread during app import; environment flags or old startup helpers cannot
create it. The old unconditional require_live_identity and GuardedTestClient remain
refusing for direct/general execution. No capability is saved to disk or environment.

The context clears ambient environment to the existing controlled allowlist, fixes
CURRENT_SEASON_CODE to the fixture's 2025-26, and imports the unchanged Flask app only
after pre-initialization safety checks. No clock override or business patch. The
in-memory JWT signing key is generated for this temporary test backend after import;
no production JWT/cron key is inherited or configured. Only synthetic fixture users
can be logged in through the client; session tokens stay in memory and are cleared.

The temporary server binds only the enrolled numeric-loopback origin. Its first
before_request guard requires the live owning lease, a random in-memory context
capability, a small method/path allowlist and authenticated marker consistency.
Requests without capability get 403 before business/DB work. The identity response
exists only on this temporary test app at /__test__/identity, requires capability,
contains no secret and is never registered in production app.py. The handshake
compares project/marker/baseline/fixture identity, email capture, fixture providers,
jobs=false and backend origin; actual module/SDK Supabase origins are checked too.

The client rejects remote URLs, queries, encoded/unreviewed paths, unknown roles,
registration, maintenance/jobs and all unapproved writes. Approved writes are only
admin bracket creation and one admin play-in set_winner operation for the created
bracket/match. No general shell, arbitrary HTTP or synthetic-account registration.

In-process socket destinations are restricted to the enrolled loopback API/backend
ports; HTTPX/requests transports validate exact local origins and refuse redirects.
Unreviewed async/alternate socket connection paths refuse. Provider GETs continue to
use fixture seams, email uses capture, runtime job entrypoints remain blocked. These
are application/process guards, not OS/container egress firewall isolation claims.

## Actual smoke responses

Synthetic logins user-a/user-b/admin: POST /auth/login 200, shape message/token/user;
only field names appear in reports, never token/password values. Admin login is used
because existing admin bracket permissions permit the narrow operation after the
fixture's playoff date, avoiding test-clock or timing-rule changes.

Read responses, all 200:

| Endpoint | Shape |
| --- | --- |
| / | message object |
| /health | text |
| /auth/test-me | user object |
| /brackets/me | bracket + existing season/time flags |
| /brackets | list |
| /leagues, /leagues/me | leagues object |
| /leaderboard | rows/master metadata object |
| /leaderboard/history | seasons object |
| /bracket/<created-id> | bracket + grouped matches; read twice |

No dedicated team/season/standings read routes exist; existing bracket creation/
readback exercises their current DB-backed data path. No endpoint was invented to
expose product reference data. POST /bracket/create 200; existing admin creation also
sets its master state as current behavior. PATCH one east round-0 slot-1 prediction
200; GET confirmed that winner and games=1 persisted. These status/persistence checks
do not approve propagation/scoring semantics. League/password-reset/provider/job
writes were deferred as unnecessary. Missing-capability POST /bracket/create 403.

## Cleanup and failure proof

Cleanup runs on normal exit, request failure and startup failure: reject further
client/admitted work, stop and close Flask, reset through approved tooling under the
lease, independently verify canonical checksum, clear mailbox/tokens, restore env/
egress/log guards and release lease. If the lease session failed, it is closed before
recovering with the original standalone guarded reset; no unsafe SQL fallback.
Application import ownership is tracked, so an existing unapproved app import is
refused without treating it as this context's app. No existing server is adopted.

The runner verifies the server thread stopped, socket closed, localhost listener
absent, and a fresh verified lease can be acquired. Semantic application/marker ACL
verification runs after cleanup. Both normal and intentionally failing smoke runs
finished canonical SEEDED nc-fixtures-v1 with checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
All temporary brackets/matches/master pointer were removed by reset; foundation
counts remained 4 users, 2 seasons, 30 teams, 30 standings, others zero.

--simulate-failure raises a deliberate local error after successful prediction
persistence; the same cleanup restored all rows/sequences/marker. No external side
effect occurred. An initial lease-proof formatting refusal was fixed by restoring
canonical settings for its post-COMMIT read-only digest; no business code changed.
The smoke and failure paths both passed on final code.

## Logging and readiness

Raw stdout/stderr and Python app/SDK logging are suppressed during the context;
no raw log buffer is retained. Failure messages contain no payloads/headers/URLs.
Only method, normalized path, status, response field names and explicit cleanup
counts/version/checksum are retained. JWT, passwords, reset tokens, local server
keys, DB passwords and admission capability are never printed or committed.

Readiness report is availability, not authorization: all environment gates and
integration_harness PASS, state AVAILABLE_GUARDED, but outside a verified context
harness_scoped_mutation_permitted=false and mutation_permitted=false. Only during
an active leased/handshaken context can the allowlisted smoke writes run. The older
provider/job prerequisite helper still conservatively reports no harness permit;
canonical harness.readiness_report adds availability without changing that permit.

## Existing test disposition and NC-01 entry proof

The broad tests/test_bracket_fill_and_save.py remains unchanged and blocked by root
conftest/GuardedTestClient; it creates random users and performs broad bracket work,
so it was not enabled unchanged. It may be reviewed/adapted during NC-01, using this
verified context and an explicitly reviewed route/scenario scope. No NC-01 begun.

| NC-ENV-00 entry criterion | Proof |
| --- | --- |
| Separate non-production DB / isolated credentials | PASS; existing enrolled native local stack |
| Production denylist / positive allowlist | PASS; validators + 31 harness refusal/bypass checks |
| Fail-closed startup | PASS; in-memory startup permit, full pre-initialization proof |
| Deterministic reset/reseed | PASS; canonical checksum restored both runs |
| Email / providers neutralized | PASS; preserved capture/fixtures, no live calls |
| Jobs disabled | PASS; maintenance routes and runtime job paths refuse |
| Integration helpers cannot bypass | PASS; raw/legacy helpers and direct flags refuse |
| Baseline reproducible | PASS; prior baseline proof retained; bytes unchanged; verifier passes |
| Isolated application reads/writes | PASS; actual local Flask persistence/readback |

Validation: 198 offline tests (61 environment,20 email,28 provider/jobs,17 marker,
41 fixture/reset,31 harness), sockets prohibited. Final normal and failure smoke
runs passed, along with listener/lease release, canonical reset, schema/ACL checks,
formatting, syntax, whitespace and secret/log/scope review. No production contact,
production data/secrets/DB mutation, deployment or frontend/product change.
Next recommended phase: NC-01 Characterization / Regression Baseline; not started.
