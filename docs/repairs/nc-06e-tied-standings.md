# NC-06E: preserve ESPN ties and guard manual playoff seeding

## Scope and baseline

Backend main started clean at ff341dfa556a08ae396aacf33b74cb6c56a0ab71,
through migration 0011. Work is local on codex/nc06e-tied-standings.
No frontend, workflow YAML, cron, production DB, deployment or remote Git changes.
Master creation remains an explicit user/admin action; standings never creates it.

## Publication contract

The existing ESPN parser preserves playoffseed values as integer positions 1..15.
Duplicate positions and gaps are valid. It still requires all 30 distinct canonical
NBA identities, 15 teams in each correct conference, valid records/percentages and
required fields. It does not invent or renumber positions. Existing team-code
serialization order is unchanged and is not a competitive tiebreaker.

Runtime refresh passes the canonical ending year into parse_espn. The actual ESPN
top-level season.year is mandatory, integer and must match; supplied season display
names and group season metadata must agree. Missing or conflicting identity fails
before any publication RPC. Fixed local provider fixtures now identify 2026 and
2027 separately; production transport is unchanged.

0012_nc_06e_tied_standings.sql replaces only publish_current_standings. It removes
the duplicate-conference-position rejection and retains all other SQL validation,
row count, mappings, numeric ranges, 15/15 counts, canonical row locks, native freeze
boundary, trusted-only execution and single-transaction delete/insert. No table,
index, fake rank or data migration is introduced. The old 0011 verifier is frozen
byte-for-byte as verify_nc_02g2_schema.sql; current semantic verification and its
pinned reset checksum evolve for 0012. The old G2 proof uses its frozen verifier.
Local bootstrap includes 0012.

## Exact ambiguous-slot definition

The unchanged 21-match topology consumes seeds 1..10 in each conference: seeds
7..10 for Play-In, 1..6 for direct first-round assignments. Every consumed seed
must identify exactly one canonical team; all twenty selected team IDs must differ.
Missing or duplicate required seeds, a tie at seed 10 crossing qualification, bad
identities or invalid numeric seeds fail closed. Ties/gaps confined to 11..15 do
not affect the builder and are allowed. Slot lists are indexed by explicit seed;
there is no sort-based, retrieval-order or alphabetical tie resolution.

The shared manual bracket-create route checks before any bracket/match/RPC write.
Ambiguity returns HTTP 409 with the existing JSON error contract:
`Standings do not yet provide unambiguous playoff seeding.`
This protects admin master creation and ordinary bracket construction without
changing authentication, timing, master replacement, graph topology or propagation.

## Validation and reproduction

- Full offline suite: python -B -m unittest discover -s tests/offline -q
- Focused standings/source tests: tests/offline/test_tied_standings.py
- Actual isolated Flask route tests: tests/offline/test_playoff_seeding.py
- Real disposable PostgreSQL proof: python -B -m scripts.prove_tied_standings_migration
- Existing guarded characterization runner, separate new-phase evidence:
  python -B scripts/run_standings_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations --lifecycle-only --nc06e
- Black checks affected maintained Python files; compile all tracked/new Python
  sources without importing app.py; git diff --check.

The observed 2027 shape (East 1, thirteen 2s, 15; West fifteen 1s) is a synthetic
in-memory dry run: standings validation passes unchanged positions and manual
master seeding rejects. No live fetch, publication or production test is needed.
SQL proof clones only the verified LOCAL platform schema into a fixed disposable
DB, applies the fresh secured baseline and 0001..0012 chain, runs semantic and
atomic rollback/freeze tests, and removes the disposable DB. The guarded harness
restores the canonical synthetic fixture, stops Flask, clears capture email and
removes application imports after testing. No production credentials are used.

Existing duplicate-rank rejection cases are superseded by tied-success coverage.
Duplicate teams, wrong conferences/counts, invalid fields, malformed data, failure
preservation, auth, frozen refresh and canonical fencing remain regression cases.
Additional evidence lives in db/records/nc_06e_*; prior phase evidence is preserved.
No broad formatter/linter configuration exists; app.py retains its existing style.

## Separate release required

This commit must not be deployed or applied to production in NC-06E. A separately
authorized release must coordinate 0012 and backend/provider pipeline source.
The remote standings branch contains the later 17 9 * * * scheduling commit;
local implementation started at the pinned live backend revision. Integrate the
repair into current release source without reverting that schedule. Do not push
this local branch as a replacement for remote main. Do not initialize production
standings or create a master as part of this implementation phase.

## Final results

PASS: 383 full offline backend tests (17 focused standings + 5 focused master
cases included), 41 guarded live characterization cases, and 15 real disposable
PostgreSQL migration groups. All 157 Python sources compile. Black checks passed
for 11 affected maintained files; only create_bracket_for_user changed among
existing app functions. Secret/raw-file audit and whitespace review passed.
The original 370-test offline baseline and existing application style are retained;
no project-wide lint/type configuration was introduced. Production unchanged.
