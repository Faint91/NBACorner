# NC-ENV-03L — LOCAL TEST ONLY Supabase

The isolated environment is `nba-corner-local-test`; registry identity is
`local:nba-corner-local-test` (a local namespace, not a hosted project reference).
API: http://127.0.0.1:55421. DB client destination: 127.0.0.1:55422.
Reserved future Flask origin: http://127.0.0.1:55410. Flask is not running.
No hosted project, production linkage, billing change or deployment is involved.

## Compatibility proof

Docker Desktop 4.95.0 / Engine 29.8.2 (WSL2 Linux) and the existing official cached
Supabase CLI 2.118.0 were used without installing/upgrading tooling. CLI image:
`public.ecr.aws/supabase/postgres:17.6.1.171`; actual PostgreSQL: **17.6**, matching
production's characterized major/minor. GoTrue v2.197.0, PostgREST v16.3 and Kong
2.8.1 run on `supabase_network_nba-corner-local-test` with dedicated local volumes.

Native postgres/anon/authenticated/service_role, public/auth/extensions, auth.uid(),
extensions.uuid_generate_v4(), RLS/default privileges and required extensions were
verified before bootstrap. plpgsql 1.0, uuid-ossp 1.1, pgcrypto 1.3,
pg_stat_statements 1.11 and supabase_vault 0.3.1 matched audited versions. pg_trgm
is absent and optional: application DDL does not depend on it. No platform
primitives were manually recreated. The fresh public application namespace was empty.

The unchanged NC-ENV-02 baseline committed, and its embedded plus standalone
semantic assertions passed: 13 tables, 122 columns, 3 sequences, 7 functions,
1 view, 3 triggers, 16 policies, 55 constraints, 38 indexes. The standalone verifier
also passed after marker installation. All application tables have zero rows.
This proves platform/schema/ACL compatibility, not application characterization;
no application function or mutation scenario was exercised.

First attempt fully rolled back: Windows text stdin changed LF to CRLF and the
function-body comparison refused. Retry used **binary UTF-8 bytes**, then passed.
This is a transport portability correction, not a baseline definition change.
`bootstrap-observation.json` retains the safe attempt evidence. Baseline SQL,
manifest, verifier, validator and provenance remain byte-identical to NC-ENV-02.
Its original deferred-execution documentation is historical; this record supplies
the subsequent local execution result.

## Security and identity

All baseline ordinary-role denials and trusted grants/defaults passed the semantic
verifier. Global/function defaults remain unchanged. The separate test-only schema
`nba_corner_test_control` keeps public baseline inventories unchanged. Its
`test_environment_identity` table has exactly one checked singleton row containing
non-secret environment/project/marker/baseline identities and fixture_state UNSEEDED.
Owner postgres controls the row; service_role has SELECT only; PUBLIC/anon/authenticated
have no grants and ordinary roles have no schema USAGE. No application fixtures
are created. Only this schema is additionally exposed in local PostgREST for an
ACL-protected authenticated server read.

The existing six-field registry schema is retained, extended to recognize explicit
`local:` identities bound to exact numeric loopback origins. Hosted matching and
all production denylist rules remain intact. Native local legacy credentials may
use issuer supabase-demo without a hosted ref; production refs still refuse, and
credential metadata alone never authenticates a target.

`verify_live_local_identity` is a separate read-only HTTP GET seam. It uses a literal
127.0.0.1 connection (no DNS/proxy/redirect transport), authenticated server headers,
exact marker/baseline/version matching, bounded response size and exactly one row.
Success always reports mutation_permitted=false. It does not start Flask, permit
integration collection or open the guarded client transport. Hosted live identity
remains unavailable. Local .env.test.nba-local.local is ignored and contains native
local credentials only, opt-in=0 and jobs=false. No ordinary production .env is read
or changed. No application JWT/Brevo/cron/health secrets were copied.

## Exact safe lifecycle

From `C:/NBACorner/backend`:

```text
python -B scripts/local_supabase_environment.py start
python -B scripts/local_supabase_environment.py verify
python -B scripts/local_supabase_environment.py configure
python -B scripts/local_supabase_environment.py identity --config C:/NBACorner/backend/.env.test.nba-local.local
python -B scripts/local_supabase_environment.py stop
```

The helper fixes the local workdir/project, checks safe configuration and absence
of a remote link/ambient .env, pins the reviewed CLI/image/network/DB port and
withholds credential-bearing CLI stdout. Stop preserves the local database volume.
The helper never installs/updates tooling, links, resets or launches the app.
Client destinations are loopback; Docker Desktop publishes the API/DB ports using
its native all-interface port mappings. This phase does not claim host-firewall
or container outbound-network isolation; later egress gates remain unmet.

For a **positively verified fresh empty local target only**:

```text
python -B scripts/local_supabase_environment.py start
python -B scripts/local_supabase_environment.py bootstrap
python -B scripts/local_supabase_environment.py configure
python -B scripts/local_supabase_environment.py verify
python -B scripts/local_supabase_environment.py identity --config C:/NBACorner/backend/.env.test.nba-local.local
```

Bootstrap applies baseline bytes, verifies semantics, then installs the marker. It
refuses existing application objects; do not rerun it on the current initialized
database. To rebuild later: stop the named project, positively verify only its
local volumes are disposable, use the separately reviewed NC-ENV-05 disposal/reset
procedure, then follow the fresh-target sequence above. No volume deletion/reset
helper is provided or executed here. Never use supabase link, remote db reset/push,
--linked, --all or inherited production configuration. Do not display raw supabase
status output; configure captures required local credential fields privately.

## Checks and remaining gates

61 offline tests passed (47 preserved safety tests plus 14 focused local identity
tests). They prohibit real sockets and cover production swaps, exact local origins,
marker/baseline/fixture mismatches, missing/duplicate markers, wrong credentials,
redirects/error responses and unconditional mutation refusal. Actual loopback marker
verification passed; wrong marker ID/version/project were refused; anonymous GET
was denied (HTTP 401). SQL independently verified service read/no write, ordinary
schema denial and a single marker row. Baseline/static validation, formatting,
source/credential/production-connection scans and Git whitespace checks passed.

Mutating characterization, backend/standings startup and integration transport
remain blocked even with opt-in. UNSEEDED fixtures, email capture, provider
fixtures/egress, full job neutralization and deterministic reset safety are unmet.
No users, teams, seasons, standings, brackets or leagues were added; no registration,
login, integration test, email, provider request, refresh or rollover was executed.
No production database/secrets/data, hosted project, billing or production behavior
changed. The local four-container stack is left running for read-only review.

References: Supabase CLI configuration
https://supabase.com/docs/guides/local-development/cli/config
