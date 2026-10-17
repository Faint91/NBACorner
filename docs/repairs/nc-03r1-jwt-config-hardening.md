# NC-03R1 — JWT signing configuration hardening

**NC03-SEC-001: REPAIRED LOCALLY / pending NC-03 re-audit.**
Verified UTC: 2026-10-17T16:19:36.995396+00:00. No production contact, deployment or real-key rotation.

## Starting state and vulnerable path

Backend main `a0587529e2d1443d846e46850b6884a6cab16f36` and frontend main
`4fa0e9fc11d49354e3da137ee43e9d1ddbc87357` started clean. Backend contains the
original NC-03 audit. Frontend remains unchanged.

`prepare_runtime_environment()` loads ordinary runtime/dotenv configuration for
production/legacy-unclassified startup. Previously app.py assigned JWT_SECRET using
a nonempty source fallback when the variable was absent, then created the Supabase
client and Flask app. Both generate_token and decode_token used that global key.
The existing user/auth_version check could not compensate for a known signing key.
There was no runtime quality check. Tracked-source scan found the old literal only
in that assignment, not in any tracked documentation/example. No value is repeated
here. Actual production configuration is unknown and was never inspected.

## Narrow repair and configuration contract

`jwt_configuration.py:runtime_jwt_secret` and `validate_jwt_secret` now initialize
the existing app global. An explicit backend JWT_SECRET is mandatory after runtime
loading. Missing, non-string, empty, whitespace-only or fewer-than-32-character
values raise a fixed JWTConfigurationError before Supabase client or Flask app
creation. The old source fallback and short known placeholder cases are rejected.
There is no key fallback, entropy estimate, automatic generation or rotation in the
application configuration path. Valid supplied values are retained exactly,
including meaningful whitespace; nothing trims or rewrites a configured key.

Supply the secret securely through backend runtime/deployment configuration.
The enforced minimum is **32 characters**. Do not commit it, include it in docs,
print it, or expose it to frontend/Vite configuration. No executable example key
is supplied. This phase does not modify real local or production credentials.

The algorithm expression, token claims, seven-day expiry, JWT storage, login
response, G1 hasher and all G2 version/reset behavior are unchanged. All **86**
existing application function/class ASTs are identical to the starting checkpoint;
app.py changes only one import and the JWT_SECRET assignment.

## Guarded local test injection

Existing test configuration deliberately prohibits ambient operational secrets.
That rule remains unchanged. The old harness generated an ephemeral synthetic
key after importing the app; it now supplies that explicit test fixture injection
before JWT initialization via startup_jwt_secret. Retrieval requires the active
exclusive verified lease, startup flag and owner thread. Unguarded/wrong-thread/
expired-lease access refuses. The ephemeral injection is cleared at cleanup.
No test-config file, production denylist, enrollment, job or mutation guard changes.
This is explicit test fixture injection, never an application default.

## Reproduction and regression evidence

Run the original command: `python -B scripts/audit_nc03_jwt_fallback.py`.
Its original vulnerable proof function and the NC-03 finding/report remain intact.
The CLI now runs the follow-up in scripts/verify_nc03r1_jwt_config.py, which obtains
the original fallback only from the original committed app source in memory.
It never prints that value or a generated JWT and makes no network connection.

Seven unsafe startup cases refuse: missing, empty, whitespace, short, original
fallback, and two known short placeholders. With valid explicit synthetic config,
actual current auth code accepts valid tokens, rejects the old-fallback forgery
with401, and retains the NC-03 negative controls. Fourteen route outcomes also
prove wrong-key/algorithm, missing/expired exp, malformed and nonexistent-user
rejection; legacy missing-av accepts version0, then fails after version increment;
a new version token succeeds. Reinitializing with the same explicit valid config
preserves existing signatures. The offline user read is a synthetic double;
actual app startup/login/protected requests and real reset commits are separately
covered by the guarded live suite.

Commands (isolated enrolled local target only):

```text
python -B scripts/audit_nc03_jwt_fallback.py
python -B -m unittest discover -s tests/offline -q
python -B scripts/run_jwt_config_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B scripts/local_supabase_environment.py verify
python -B scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
```

**345 offline tests passed. 25 guarded live tests passed**: existing G1 and G2
focused groups, selected existing auth regressions and explicit-key real startup/
login/forged-signature controls. Generic login, identity normalization, exact/long
passwords, reset supersession/expiry/replay and multi-device/legacy JWT revocation
all pass. Evidence is written separately; no previous validation JSON was replaced.
The historical static fallback assertion is superseded only in the current runner
through scripts/nc03r1_acceptance_metadata.py; original characterization is intact.

Black on affected modules and scoped changed app statements, in-memory compile,
import comparison, scoped credential/static scan and staged whitespace review pass.
No frontend signing configuration is present. No schema/migration changes; current
strict schema/fixture-marker verification passed, so no disposable migration proof
was needed. Full all-domain suite and the NC-03 audit were not resumed.

## Cleanup and production consequence

Canonical SEEDED/nc-fixtures-v1 restored; checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0` unchanged.
Four canonical users at auth_version0, canonical season,30 standings, no temporary
reset/history/league/rollover data, no advisory locks or disposable proof DB.
Flask stopped, capture mailbox empty, jobs disabled, unrestricted/scoped mutation
admission false. No credential/token artifacts were written.

Before any separately authorized production preflight/deployment, confirm an
explicit valid JWT_SECRET is supplied. If production relies on the removed fallback
or a key shorter than32 characters, this repaired backend intentionally refuses
startup until valid configuration exists. Do not infer whether it currently does.
Using the same already-valid configured key preserves sessions subject to expiry/
auth_version; no key was rotated here. Any necessary real configuration decision
belongs to controlled preflight/release planning.

## Final status and boundary

JR1–JR9 pass locally. Original NC-03 FAIL evidence and its118 unverified product
requirements remain unchanged. Do not mark NC-03 PASS. Backend-only normal commit:
`NC-03R1 require explicit JWT signing secret`. No amend, frontend changes, production
queries/emails/deployment or C:/1on1ball changes.

Recommended next step: **Resume NC-03 consolidated compliance audit from the repaired
backend HEAD**, only on explicit instruction. No NC-04 or other phase started.
