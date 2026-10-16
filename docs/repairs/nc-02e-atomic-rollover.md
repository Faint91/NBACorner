# NC-02E — Atomic rollover recovery and operational safety

Local repair only. Production was not contacted. Starting clean main checkpoints:
backend `ef8488739bc7ef3f0bb9373c3774415515d03f31`, frontend
`66c9573ce4ad0878e69f72fddab2d40cf288d11f`.
Continuation preserved the uncommitted E implementation and completed its proof tooling.
Historical C3/D2 repair records and evidence remain historical; E supersedes only
rollover transaction, prerequisites, retention, retry and optional legacy semantics.

## Pre-change map

`POST /admin/season/rollover` requires authenticated admin JWT and an independent
`users.is_admin` database check. Jobs/test-entry guards apply. The helper resolved
canonical source, validated target/configuration, called the snapshot helper,
then separately deleted scores, deleted every source match, soft-deleted every
source bracket, inserted target, and called C3 finalization. Only canonical pointer
movement plus standings clear were one transaction. No whole-workflow lock, durable
audit or repeat-success fence existed. Cleanup errors could leave partial effects.
D2 recomputation and legacy-first snapshot publication were also separate calls.
Historical detail (`GET /history/bracket/<id>`) reads nondeleted `brackets`, their
`matches` graph (participants, winner/counts, edges), season relationship and safe
team metadata. A leaderboard snapshot cannot replace these rendering dependencies.

## RR1–RR16 implementation

| Rule | Implementation |
| --- | --- |
| RR1 | Existing explicit admin POST only; no schedule/date/cron trigger added. |
| RR2 | Pure completed-result validator plus locked SQL `require_completed_rollover_master`; exact 21 coordinates/topology, all winners/counts, valid play-in loser feeds and Finals champion; independent of master `is_done`. |
| RR3 | Existing D1 calculation/formulas and D2 atomic immutable publisher reused; typed source fence and successful full eligibility evaluation mandatory, including genuine zero. |
| RR4 | `execute_season_rollover_transition` contains every destructive change; no snapshot creation inside this function. |
| RR5 | Python preparation reads/calculates only. Recompute publication and structured snapshot share a rollback scope, so snapshot failure rolls score refresh back too. |
| RR6 | Destructive transition runs in a nested transaction scope; failure rolls back all transition writes, retaining the already-final snapshot and safe FAILED audit. |
| RR7 | Retry from beginning, revalidate and reuse same immutable snapshot; no partial resume or overwrite. |
| RR8 | Completed audit + canonical target fence returns `already_completed` without writes, including no extra audit or standings clear. Later differing canonical state returns conflict. |
| RR9 | `pg_try_advisory_xact_lock(50405,2)` covers locked DB prerequisites, preservation, compatibility and transition; busy loser makes no writes. Locks release at transaction end. |
| RR10 | Only immediate next `YYYY-YY` season, modulo-100 suffix, both finite timing values and opening strictly before lock; staged/existing target refused. |
| RR11 | Legitimately saved source brackets remain byte-equivalent with match graphs/save times; historical season identity retires them from canonical current consumers. Existing B15 public read-only path and mutation protections remain. |
| RR12 revised | Every other source bracket physically deleted inside transition, including stale-save edited drafts and already-deleted source rows; no private draft history survives and deleted data is never resurrected. |
| RR13 | All source `bracket_scores` cleared inside transition; immutable structured header/rows untouched. |
| RR14 | Rollover attempts optional legacy output only AFTER structured success; caught failure sets durable/result `legacy_warning=true` and does not block transition. Standalone D2 snapshot behavior is unchanged. |
| RR15 | New private `season_rollover_audits` stores source/target, snapshot, admin, start/end, outcome and fixed safe stage/message. Failed attempts retain audits. |
| RR16 | Distinct prerequisite/recompute/snapshot/transition/busy/repeat/database-unavailable outcomes; responses include audit ID where available. Exception text/provider payloads never persisted or returned. |

## Exact retention and dependencies

Saved predicate: source `season_id`, `is_done IS TRUE`, `deleted_at IS NULL`,
`saved_at IS NOT NULL AND isfinite(saved_at)`. Database timestamptz enforces typed
aware storage; Python D1 requires a valid aware save timestamp. Neither stale score
rows nor an old timestamp can rescue `is_done=false`. This extends the existing
active/saved A/B definition with its approved valid-save requirement.

Preserved brackets are not soft-deleted: B15 queries require `deleted_at IS NULL`.
Their old season makes them historical/noncompetitive/read-only. Their entire match
graph remains, including winner/count fields. An unsaved canonical master also
falls under the literal RR12 rule after its final results are frozen; snapshot
`master_bracket_id` intentionally has no live FK. Saved masters, if legitimately
submitted, meet the same retention predicate.

Draft `matches` and `bracket_scores` cascade through existing bracket FKs. Score
master references also cascade; source season master pointer uses ON DELETE SET
NULL. Optional non-FK legacy rows referring to deleted drafts are explicitly removed.
No user/league/membership/team rows are deleted. Existing schema contains no league
or statistics FK to bracket content. Immutable structured rows contain no live draft
FK and are never rewritten. Old seasons and historical leaderboard infrastructure
remain. Already-deleted source brackets are physically removed, never reactivated.

## Transaction and audit design

`rollover_service.run_rollover` prepares a complete D1 source/score/frozen-row payload
without publishing scores. A missing read/calculation returns no prepared payload,
never fabricated empty participation. Existing D1 source comparison rejects stale
input. SQL independently revalidates the completed master under table/row locks.

One trusted outer `run_season_rollover` RPC takes the transaction advisory lock and
canonical row lock, checks repeat fence and creates STARTED audit. Its preparation
subtransaction validates source/target/master, publishes fresh scores and creates
or reuses the D2 snapshot. Header ID/source/code/master/final/expected/actual counts
are verified. Any exception rolls the whole preparation back and records FAILED.

After preservation succeeds, the outer scope records the snapshot ID and attempts
legacy compatibility in a nonblocking exception scope. Then the narrow transition
RPC runs in another subtransaction. It fences source/audit/snapshot/target again,
locks source tables, removes source scores/drafts and dependent legacy references,
preserves saved graphs, inserts immediate target, invokes unchanged C3 canonical
finalization/standings clear, and marks audit COMPLETED. All of these transition
writes roll back together on any error. The outer RPC catches that failure, marks
FAILED/transition, returns a safe result, and commits preservation/failure evidence.

The snapshot is outside the destructive subtransaction, although both scopes run
inside one outer PostgreSQL transaction. This supplies one critical lock without a
session lease or stuck durable mutex. A normal returned transition failure commits
the immutable snapshot and audit. A catastrophic outer transaction/connection abort
may roll back the whole operation; clients must inspect audit/canonical state before
retrying an unknown transport outcome. No transition can partially commit.

`execute_season_rollover_transition` never publishes snapshots. All three new
functions are postgres-owned SECURITY INVOKER, pinned `pg_catalog,public`, and
executable only by postgres/service_role. Audit is postgres-owned, RLS enabled,
no browser policies/grants, trusted SELECT/INSERT/UPDATE/DELETE only. No browser
RPC mutation or new credentials are introduced.

## Verification and historical evidence

Machine results: `db/records/nc_02e_fresh_migration_proof.json`,
`nc_02e_lifecycle_validation.json`, `nc_02e_validation.json`, and
`nc_02e_atomic_rollover.json` (final consolidated completion).

Fresh proof builds immutable baseline and 0001–0007 in a fixed disposable local
schema-only platform clone, verifies frozen prior contracts, seeds synthetic data,
and exercises real SQL. Fault triggers exist only inside scratch test transactions,
never in migrations or application configuration. Faults after draft DELETE, score
DELETE, target INSERT, pointer UPDATE, standings DELETE and audit completion prove
whole-state rollback, retained final snapshot, FAILED audit and successful same-ID
snapshot retry. Additional cases cover invalid/missing master/graph/champion/counts,
recompute failure, snapshot row failure, unverified/mismatched snapshot, invalid
source/target/timing, zero participation, physical deletion, saved graph preservation,
legacy warning, exact no-write repeat, and untrusted RPC/audit denial. A second real
PostgreSQL session holds the rollover lock, verifies busy/no mutation, rolls back,
and proves lock release. A committed-failure scenario verifies retained snapshot/audit from a separate psql
session, then commits a same-snapshot retry and restores the exact scratch foundation.
Disposable database cleanup runs in `finally`.

Live E tests use the existing guarded D2 lease/route process, with only registered
historical GET admission added for B15. They verify actual Flask/PostgREST orchestration,
saved historical public/owner/other/admin access, safe serialization, refused historical
writes, new-season fixture refresh, no-write repeat, admin authorization, source failure
sanitization and SC17 snapshot reuse. Every scenario restores the canonical fixture.

The E regression runner preserves old characterization files/reports and explicitly
lists superseded C3 non-atomic rollover and D2 old-boundary fault doubles. Their
obsolete assertions are replaced by E real DB/live acceptance, not silently rewritten.
All other applicable A/B/C/D regressions run unchanged, including B15 and standalone
D2 immutability/privacy/ranking. The old D2 fresh proof now references its frozen D2
verifier and explicitly removes only the additive audit table from its disposable
schema clone before baseline replay; baseline and migrations 0001–0006 are byte-unchanged.

## Frontend and operational limits

Only admin rollover UX changes: immediate source/target, permanent draft deletion,
saved history, completed-master/final-snapshot requirement, ordered required timing,
explicit confirmation, audit/warning and already-completed outcome. Canonical state
is refetched after success. Standalone snapshot confirmation stays independent.
No automatic action is added. Frontend global lint has the pre-existing 83 errors/
1 warning; changed AdminPage has the same six diagnostics, with no new findings.
Build passes with existing stale browsers-data/chunk-size warnings. Backend Black
and compilation/import checks are scoped; no configured standalone backend linter
is present. Final machine evidence records exact checks/counts and limits.

## Fixture restore and production readiness

The supplemental audit table is explicitly included in reset/dependency inventory
and verified empty. It is excluded from the unchanged v1 foundation digest, preserving
`SEEDED`, `nc-fixtures-v1`, checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
The strict current schema verifier pin evolves; old verifiers/migrations remain frozen.
Final checks require canonical source, 30 standings, empty competition/history/audits,
Flask stopped, lease released, empty captured mail, jobs disabled, global mutation
disabled and no proof database.

No production query/migration/deploy/rollover occurred. Before any separately approved
rollout: obtain and verify database backup/restore, review exact pending migration
chain/current catalog, confirm active canonical season and fully resolved canonical
master/champion, inspect saved-versus-draft counts and dependent references, verify
structured snapshot completeness/immutability, approve immediate target code and both
explicit UTC timings, serialize admin operations, and run migration security preflight. Coordinate migration with the matching trusted
backend and admin frontend; applying SQL alone does not replace an older backend's
rollover helper. The new backend fails closed if its orchestration RPC is unavailable.
Unsaved source content will be irreversibly deleted after successful commit; transaction
rollback protects failures, not a completed business decision. Restoring completed
rollover data requires controlled backup recovery, not an automatic reverse rollover.
After activation, request the existing authorized ESPN refresh using target season
and observe freeze rules; old source standings never masquerade as target standings.
Do not run a production rollover as a migration smoke test.

NC-02E is the only phase in this change. Await a separately approved next-domain
checkpoint before starting league lifecycle or any other work.


## Local verification commands

- `python scripts/prove_rollover_migration.py`
- `python scripts/run_rollover_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations`
- Same command with `--lifecycle-only` for only the four E Flask scenarios.
- `python -m unittest discover -s tests/offline -q`
- Frontend: `node --test scripts/test-*.cjs` and `npm run build`.

During broad regression validation, five registration assertions exposed an accidental
adjacent route-decorator removal from helper replacement. The exact original decorator
and CSRF documentation were restored. AST comparison proves every application
definition except the two rollover functions remains identical to the starting
checkpoint; an offline fingerprint now protects the full pre-E route inventory.
Affected registration/auth scenarios are rechecked before completion. This was a
local development defect; no production state or deployment was involved.


## Final validation result

- 217 applicable backend cases executed; 211 passed initially. Five registration
  cases exposed the restored adjacent decorator, and one static call-shape assertion
  needed its E-only delegation adaptation. All six passed corrective recheck.
- 10 corrective cases passed: the six findings plus all four final E route cases,
  including explicit timezone rejection. Initial run preserved unchanged in
  `nc_02e_initial_validation.json`; final aggregate in `nc_02e_validation.json`.
- 300 offline tests passed; 36 frontend tests passed; frontend TypeScript/build passed.
- 21 fresh-database proof groups passed, including six actual transition fault
  points, same-snapshot retries, real two-session contention, and committed failure
  evidence verified from a later session.
- Strict semantic/security and marker verification passed; baseline/0001–0006
  unchanged; frozen D2 assertions retained. Compilation, import comparison, scoped
  Black, whitespace and credential/privacy review passed, with the stated existing
  frontend lint baseline and no configured standalone backend linter.
- Independent cleanup proof: SEEDED/v1 checksum unchanged, 30 standings, zero
  brackets/matches/scores/history/audits, Flask stopped, no fixture/rollover locks,
  no scratch databases, no captured mail, jobs and global/scoped mutations disabled.

No production contact, query, migration, deployment or rollover occurred. No next
phase began. Final Git commit identifiers are reported by the completing chat;
this evidence is included in the normal completion commit without amendments.
