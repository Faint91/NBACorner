# NC-ENV-05: deterministic synthetic fixtures and guarded local reset

These fixtures describe raw test states only. They are not approved business
requirements, nor evidence that brackets, scoring, leagues, auth or history behave
correctly. NC-01 must distinguish observed behavior, approved requirements, gaps
and unreviewed requirements. No product logic or application schema was changed.

## Version and architecture

Fixture version: `nc-fixtures-v1`. Metadata is in tests/fixtures/application/manifest.json;
pure builders are in synthetic_fixtures.py. Any semantic fixture change requires a
version review/bump. Only the foundation is persisted after reset; all scenario
builders return complete independent in-memory bundles and have no DB/HTTP executor.
Later NC-ENV-06 can build a guarded scenario installer after review. This separation
avoids global active-bracket uniqueness collisions and keeps every reset small.

Foundation: 4 users, 2 seasons, 30 teams, 30 standings; all other application tables
empty. UUIDs are deterministic UUIDv5 from a test-only namespace and readable role/
scenario labels. All timestamps are fixed; no random/default UUID or now() is used.
Team IDs/codes are canonical reference codes, names are `Fixture <code>`; optional
logos/colors are NULL. East/West each have ranks 1–15 and fictional 82-game records,
including play-in positions. Standings has no season_id in the preserved schema;
it represents the current test season by fixture convention only.

Current/test season: 2025-26, regular-season end 2026-04-12 07:00 UTC, playoff start
2026-04-18 07:00 UTC. Historical: 2024-25, end 2025-04-12 07:00 UTC, playoff start
2025-04-19 07:00 UTC. Later explicit clock controls can exercise before/open/locked
states. Production time/window rules were not changed or inferred from these dates.

## Synthetic identities and credentials

Roles: user-a, user-b, admin, owner; usernames `fixture-<role>`; email addresses
`<role>@nba-corner.example`. Only admin has is_admin=true. No real names, addresses,
production hashes, identifiers or account records were copied.

Five bcrypt hashes were generated locally once with the application's cost 12,
then committed as explicitly synthetic fixtures in synthetic-bcrypt.json so resets
are binary deterministic. The test-only credential convention is a prefix
`NCFixture!2026-` followed by the role label (including private-league for that
scenario). It is public fixture data, never a production credential. No production
bcrypt behavior/cost was weakened. Hashes are not regenerated on reset, and reset
logs print only counts/version/checksum, never row contents or passwords/tokens.

## Pure scenario builders

- bracket_scenario(kind): independent draft, saved, master, deleted or historical
  bundle, 21 linked matches covering play-in, rounds 1/2, conference finals and NBA
  Finals. Saved/master/historical include a synthetic play-in winner, game count
  and downstream slot to support later propagation/undo characterization.
- league_scenario(): public/private leagues (private bcrypt hash), owner and user-a
  memberships; user-b is a non-member. is_global=false; no new global-league rules.
- score_history_scenario(): current master and two saved user brackets with equal
  raw stored scores and zero bonuses; historical soft-deleted brackets, one snapshot,
  two structured rows and two legacy history rows. These are raw values, not results
  of running scoring logic or desired tie/bonus corrections.
- reset_scenario(used=False): reserved synthetic token and fixed naive expiration/
  creation values as the schema requires. Default foundation has no reset rows or
  active reset fields. This pure helper never logs or persists a token.

validate_state checks exact table/column sets, deterministic identities, roles,
reserved domains, standings ranks, FK-like relationships, match DAG, master pointers,
league memberships, history and reset isolation. It does not certify business rules.

## PRESERVED CURRENT BEHAVIOR / FIXTURE LIMITATION

- Both per-season and global per-user active-bracket unique indexes exist. One user
  cannot have simultaneous active current and historical brackets; bundles are
  isolated, and historical score fixtures use soft-deleted rows.
- Both master uniqueness indexes remain, including one that covers deleted masters.
  Deleted fixture brackets are non-master. Master pointers form a circular FK;
  a future installer must insert seasons with NULL pointer, insert brackets, then
  assign the pointer. No schema/RPC fixes were made.
- Trigger-managed matches/bracket_scores season IDs must agree with bracket season.
- A single next_match_id cannot represent both winner and loser edges. The fixture
  graph reflects stored final links, including the overwritten play-in link from
  slot 2, rather than claiming the current propagation behavior is correct.
- Standings is unseasonized; history uses both legacy and structured representations.
  The structured row schema has no bracket/user FK; fixture display relationships
  are test metadata, not newly added product constraints.
- Duplicate email uniqueness constraints and nullable legacy fields are unchanged.
- No scenario bundle is installed by this phase; no scoring/job/API workflow ran.

## Fixed reset entrypoint and safety

```text
python -B scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-reset
python -B scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
python -B scripts/local_supabase_environment.py verify
python -B scripts/local_supabase_environment.py provider-job-readiness --config C:/NBACorner/backend/.env.test.nba-local.local
```

The writer requires explicit --allow-local-reset, separate from the global mutating
integration opt-in (still 0). It accepts no DB URL, table list, SQL file, remote target,
scenario name or arbitrary job. Controlled ignored config is parsed without production
.env fallback. Identity/production denylist/enrollment/email/provider/jobs gates run
before connection. Only the fixed reviewed local containers/ports/network are used;
child environment excludes provider credentials/proxies. No external provider/email.

Immediately before execution, authenticated v2 identity is re-read. The transaction
acquires advisory lease (50405,1), locks the marker, rechecks its exact fields against
the preflight evidence, and performs the unchanged NC-ENV-02 semantic verifier plus
marker ACL/CHECK verification. Unknown public objects, sequence/constraint/default
privilege drift and inbound dependencies from outside the 13-table set refuse.
TRUNCATE includes all 13 exact application tables simultaneously, RESTART IDENTITY
RESTRICT: circular/internal FKs are included together; no CASCADE/platform targets.
There is no generic arbitrary-table reset or wildcard schema destruction.

Within the same transaction, marker becomes UNSEEDED with NULL metadata, foundation
rows are inserted in users/seasons/teams/standings dependency order, and owned sequence
states become standings=(30,true), password_resets=(1,false), legacy_history=(1,false).
Every typed row and sequence must match the expected foundation before SHA-256 is
computed from actual DB state and marker is set SEEDED. Schema/ACL verification runs
again before COMMIT. Any failure rolls back rows, restarted sequences and marker.
The original baseline verifier bytes are SHA-256 pinned, never rewritten.

Current-process email capture is cleared after success. No Flask process is running,
so there is no separate live mailbox to clear. Provider fixtures stay unchanged and
jobs remain disabled. Infrastructure egress limitations from NC-ENV-04B still apply;
no host firewall/container isolation claim is made.

## Checksum and deterministic proof

Digest = SHA-256 of UTF-8 PostgreSQL jsonb::text for an object containing fixture_version,
all complete typed rows of all 13 tables, and all three sequence last_value/is_called.
Each table array is sorted by to_jsonb(row)::text COLLATE C. Session timezone is UTC,
DateStyle ISO/YMD and extra_float_digits=3. Expected rows are cast through each real
PostgreSQL record type before equality checks. All application columns participate,
including fixed timestamps and committed synthetic password hashes. Nothing from
application rows is excluded. Marker metadata/created_at are outside the fixture
object, avoiding a self-referential checksum. This hashes verified DB state, not
merely source bytes. A marker checksum alone is insufficient: readiness reads and
compares complete DB state with the typed foundation again, rejecting any drift.

Both live cycles produced checksum a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0 and identical counts/relationships/sequence
states. Between cycles a single fictional ATL wins value was incremented; read-only
proof detected drift and Cycle 2 removed it. Separate live local checks proved a held
advisory lease refuses before truncation, and an intentional failure immediately after
truncation rolls back the complete rows, sequences and marker to the prior checksum.
No schema alteration was used in those failure checks.

## State, rebuilding and remaining gate

Marker remains v2 with unchanged identity/baseline/created_at/security, now SEEDED,
fixture_version=nc-fixtures-v1 and the verified checksum. Anon/authenticated still
lack access; service_role is read-only; postgres owns it. Managed/auth schemas/data
are outside the reset list. Application baseline, tables, sequences, functions/view,
triggers, policies, constraints/indexes, RLS and default ACLs passed semantic checks
before/after each cycle. Only application data/sequence values and fixture metadata
changed. Native local credentials were retained, not copied from production.

For an existing verified local database, reset/reseed reconstructs application data
without touching schema. For a genuinely fresh empty reviewed local target, use the
existing guarded local start/bootstrap/configure/verify flow (baseline, marker v1→v2),
then the reset command above. Bootstrap refuses an existing application namespace.
No volume-disposal tool or remote reset/link/push is provided.

Readiness: identity/marker/email/providers/jobs/fixture-reset PASS; final guarded
integration harness UNMET; global mutation_permitted=false. Flask startup and all
runtime job/integration execution remain intentionally blocked. No local application
smoke/characterization was run. Next candidate is NC-ENV-06, not started.

Validation: 61 environment + 20 email + 28 provider/job + 17 marker + 41 reset/fixture
checks = 167 offline tests, all socket connections prohibited. Full local schema/
marker ACL verifiers passed each cycle. Formatting, syntax, whitespace, credential/
production-data scans and exact product/baseline byte-preservation review passed.
Production contact/data copying/secrets use/deployment: none. Frontend unchanged.
