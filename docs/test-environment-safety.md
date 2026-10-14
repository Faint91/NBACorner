# NC-ENV-01: fail-closed test entry guards

This phase adds safety infrastructure only. No test project is enrolled and no
live identity verifier or network transport is enabled. Mutating integration
execution is deliberately unavailable, even with opt-in or a synthetic target.

## Central enforcement

`environment_safety.py` is shared by Flask startup, standings startup, the
controlled launcher and all four integration-test HTTP helpers. Root conftest
refuses general pytest collection before test-module imports. Only an explicit
selection of tests/offline/test_environment_safety.py is exempt; broad offline
directory discovery is not an exemption. Ordinary startup
with no `NBA_CORNER_ENV`, or explicit `production`, preserves existing dotenv
loading. Explicit `test` requires controlled configuration and must refuse before
Supabase client creation. Unknown explicit identities refuse. A hidden test flag
in the ordinary `.env` also refuses before initialization.

Known production targets are denied: project `rpwesmvzmgoctrokrbhy`, its API and
`db.` hostnames, `nbacorner.onrender.com`, and `nbacorner.com` (including subdomains).
Case, default ports and trailing dots/slashes are normalized. Credential-bearing
URLs, encoded hosts, query strings, fragments and non-origin paths are rejected.
Remote origins require HTTPS. Redirects are refused, including same-origin ones.
A localhost API connected to production Supabase is still prohibited.

## Explicit configuration and enrollment

A future launcher requires `--config` pointing to an absolute, ignored
`.env.test.local` or `.env.test.<name>.local` file. It parses literal allowlisted
fields only, without interpolation, duplicate fields or ambient secret merging.
The existing production `.env` is not a test configuration. No real configuration
file or credentials were created in this phase.

Required identity fields: `NBA_CORNER_ENV=test`,
`NBA_CORNER_ALLOW_MUTATING_TESTS=1`, `NBA_CORNER_TEST_TARGET`,
`NBA_CORNER_EXPECTED_PROJECT_REF`, `SUPABASE_URL`, `NBACORNER_BASE_URL`.
Do not put credentials in either URL. Server keys and other future configuration
fields are enumerated in `CONFIG_FIELDS`; unknown fields refuse.

`test_environments.json` is version-controlled and intentionally contains zero
targets. Future reviewed enrollment must specify name, project_ref,
supabase_origin, backend_origin, marker_id and marker_version. It is not inferred
from a URL, config-file label or opt-in flag. Offline tests inject synthetic
identifiers directly into pure validation; none are enrolled for execution.

The future marker interface compares independent database/backend evidence,
project and marker identities, backend origin, captured email, fixture providers
and disabled jobs. Caller-provided evidence is NOT authentication proof.
`require_live_identity` currently always refuses. NC-ENV-03 must establish a real
separate project and authenticated marker verification; later safety phases must
establish actual email/provider/job safety before any execution is enabled.
Legacy JWT metadata is an extra consistency check, not signature verification;
opaque service keys still require live authenticated verification later.

The launcher constructs an allowlisted child environment, excluding production
secrets, Python-path injection and proxy variables. It can never launch a child
until the live identity gate passes; it cannot currently pass.

## Offline checks only

From the backend repository:

```text
python -B -m unittest discover -s tests/offline -p test_environment_safety.py -v
```

These tests prohibit socket connections, do not import/run the application or
integration module, and use only in-memory synthetic identities and temporary
non-secret configuration samples. Extracted startup/transport seams are tested
without executing business helpers or constructing Supabase clients.

Future controlled launcher shape (currently REFUSES):

```text
python scripts/run_test_environment.py --config <absolute-ignored-test-config> --entry backend
```

Entries are backend, standings and integration. Do not invoke the existing live
integration test or standings updater directly to verify this phase. No DB
baseline, marker table, seeds/reset, providers/email fixtures, endpoint, workflow,
frontend change or production deployment is implemented here.

## NC-ENV-03L local identity completion (mutation gates still closed)

One LOCAL TEST ONLY enrollment now exists with the original six-field registry
shape: local:nba-corner-local-test, numeric-loopback API 55421/backend 55410.
The original statements above describe the NC-ENV-01 checkpoint. The hosted live
verifier remains unavailable; the new verify_live_local_identity seam authenticates
only a loopback GET to the ACL-protected local test-control marker. Identity-only
validation may use mutation opt-in=0. Success is not an execution permit.
require_live_identity, guarded client transport and launcher/startup remain refusing
until later fixture/email/provider/job/reset requirements are proven. Production
startup and all denylist behavior remain unchanged. See the complete lifecycle and
execution proof in test-infrastructure/local-supabase/README.md. No production env
file, application data or secrets are copied into the local stack.

## NC-ENV-04A email gate

Test email now uses deterministic in-memory capture exclusively. Controlled test
config requires NBA_CORNER_EMAIL_MODE=capture and NBA_CORNER_RESET_LINK_ORIGIN
matching its enrolled backend origin. Live/ambient Brevo fields refuse test email;
production's existing Brevo transport and reset URL remain unchanged. The local
helper's email-readiness action verifies this gate plus authenticated DB identity,
without authorizing mutation. Capture inspection/clear and token-safe handling are
in docs/test-email-safety.md. Other provider/job/fixture/reset/harness gates remain
closed; no DB fixtures or integration mutations are enabled.


## NC-ENV-04B provider/job gate

ESPN and active Balldontlie GET paths now have deterministic provider response
fixtures and no test live fallback. Explicit fixtures mode, absent external/operational
credentials and jobs-disabled state are required. Runtime job entrypoints are guarded;
explicit in-process job requests still stop at the unconditional UNSEEDED/reset/harness
mutation block. No production workflow changes. Full inventory, preserved quirks,
local read-only readiness command and limitations: docs/test-provider-job-safety.md.


## NC-ENV-05A marker lifecycle contract

The enrolled local marker is now version 2. Read-only identity verification requires
v2 and the explicit fixture_version/fixture_checksum fields. UNSEEDED requires both
NULL; SEEDED requires a valid version and SHA-256 checksum. Metadata validity is not
fixture integrity proof or an execution permit. Mutation/startup/guarded transport
remain blocked. No application fixtures or reset occurred. Migration, security proof
and ownership rules: test-infrastructure/local-supabase/README.md (NC-ENV-05A section).


## NC-ENV-05 deterministic fixture/reset proof

Local marker v2 is now SEEDED with nc-fixtures-v1 and a verified full DB-state checksum.
Only the small synthetic foundation is installed; pure scenario builders are separate.
Two reset cycles, drift recovery, lease refusal and transactional rollback passed.
Read-only readiness independently verifies all rows/sequences and reports fixture/reset
PASS, harness UNMET, mutation_permitted=false. Startup/integration remain blocked.
Procedure, exact allowlist, checksum definition and schema limitations:
docs/test-fixtures-reset.md. NC-ENV-06 has not begun.


## NC-ENV-06 guarded smoke harness

Only an explicit verified GuardedHarness may temporarily start the local Flask API
and admit the reviewed smoke reads/writes. Context owns lease/reset/startup/backend
identity/HTTP admission/egress/session/cleanup. Global mutation remains false; old
raw/legacy helpers and jobs remain refusing. Normal and intentional-failure runs
restored nc-fixtures-v1 checksum, stopped Flask and released lease. Exact invocation,
gate map, response evidence, recovery and NC-01 entry proof:
docs/test-integration-harness.md. NC-01 has not begun.
