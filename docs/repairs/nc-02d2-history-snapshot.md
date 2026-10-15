# NC-02D2 — historical snapshot integrity, ordering and rollover snapshot gate

Scope: SC5 and SC10–SC16, plus explicitly approved SC17 zero-competitor final
snapshots. No production connection, query, migration or deployment. Implementation and final
local validation are complete.

## Starting checkpoint and previous architecture

Backend main 4f61f0964a8e534b0b5ab9fe5cbcbdd6293c182e and frontend main
1a23c571439068e2747e723c6756f6a1331858c8 were clean. Pre-change path/input/season/
master/ranking/write/privacy/immutability inventory is recorded in
 db/records/nc_02d2_snapshot_path_inventory.json.

The old builder read stored scores and current saved brackets/usernames without
fresh canonical recompute or saved_at ranking metadata. Snapshot ranked points,
full hits, then username and assigned sequential ranks. Legacy rows, structured
header and structured rows used separate transactions. Structured failure was
nonfatal after legacy success. Rollover also accepted the legacy duplicate error
as preservation success. Historical endpoints required JWT and ordered points/hits;
frontend could fabricate rank from index. Existing schema allowed multiple headers
per season and had no complete/final marker or immutable write guard.

## Canonical workflow and source freshness

history_service.create_final_leaderboard_snapshot is the sole production final
snapshot orchestrator, reached by the existing admin route and rollover wrapper.
It resolves the canonical current season/active master through D1, then successfully
recomputes the entire eligible score set. D1's optional internal snapshot_context
returns exactly the validated inputs/computed rows for that successful evaluation.
Normal D1 responses and formulas are unchanged, and clients cannot request or supply
this internal context through the admin API.

The orchestrator reads only bracket display/save information and safe usernames,
uses scoring_engine.rank_live_rows, constructs frozen rows and columns, then calls
one atomic publisher. There is no stale-score fallback or caller-selected master.
A failed/missing/query/unknown source is an error, never zero participation.

The publisher reuses the unchanged D1 score publisher inside its transaction to
revalidate canonical authority, complete eligibility, complete input snapshot and
computed score state under D1's locks. That recheck must be an unchanged/no-write
result: if repair would be needed, the transaction raises and rolls it back. This
fences source changes between successful recompute and snapshot publication without
introducing a second scoring formula. Python owns score/rank construction; SQL
validates complete IDs, values, saved timestamps, component sums and rank/order.

The old private builder remains only as a read-only compatibility helper; it is
not the new snapshot source and cannot publish historical state.

## Frozen competition model and ranking

New rows freeze display identity, total, full/partial hits, misses, separate +3/+1
bonuses, saved_at, base_points, points_by_round, numeric per-match points, competitive
rank and stable display_order. There is no live bracket/user FK in structured rows
and historical ordering does not consult mutable current data.

SC5 reuses D1 ordering: total DESC, full_hits DESC, saved_at UTC ASC. Exact equality
shares competition rank (1,2,2,4); username/user/bracket IDs stabilize display only.
Header stores expected_rows, is_final and the evaluated master identity. Internal
master/creator identifiers are not public historical payloads. Existing records
receive no data rewrite, rank correction or automatic final-status backfill.

## Atomic publication and immutability

0006_nc_02d2_final_snapshots.sql follows unchanged baseline/0001–0005. It adds only
nullable history metadata columns, final-season/display-order unique indexes, a
snapshot publisher and immutable write triggers. Prior table ACLs/RLS and functions
remain unchanged. Both new functions are postgres-owned, SECURITY INVOKER with
search_path=pg_catalog,public; EXECUTE only postgres/service_role, explicitly revoked
from PUBLIC/anon/authenticated. No direct browser writes or generic mutation API.

publish_leaderboard_snapshot creates an internal nonfinal header, inserts all rows,
then marks the header final within one transaction. Publication failure leaves no
new header or partial rows. Header finalization checks expected/actual row count.
The returned confirmation includes snapshot/season identity, complete/final flag,
expected count and actual count; the service validates it before declaring success.
A partial/inconsistent result cannot open rollover cleanup.

Completed new headers and rows cannot be changed, deleted or appended to. Unique
final season identity prevents duplicate final snapshots. Repeated valid requests
return the same verified stored record without rewriting it, even when current
computed values differ. Recompute still validates current canonical authority;
missing authority is not bypassed because an old final exists. Existing final
expected count remains the frozen count, not a mutable current competitor count.

Existing untagged structured records stay readable; updates/deletes of their
existing values are also guarded. Their prior trusted insertion compatibility is
retained, but no normal application path appends or rewrites them. The new publisher
refuses to treat an unverified existing structured header as final success, rather
than guessing completeness or silently replacing historical results.

Application-role TRUNCATE is blocked. The database owner retains administrative
TRUNCATE capability for the existing identity/lease-verified local fixture reset;
this introduces no application flag, runtime bypass or unrestricted mutation mode.
Owner administration is not claimed to be protected against the database owner.

## Legacy relationship and rollover gate

Keep the existing legacy-first dependency: when no structured header/legacy record
exists and participants exist, write the safe legacy compatibility rows first.
Existing legacy rows are not rewritten. Legacy write/read failure blocks this
attempt as before. Legacy success alone never counts as preservation. If the later
structured publisher fails, legacy rows may remain but no rollover cleanup begins.
A repeated attempt may complete structured publication without duplicating legacy.
Zero participants need no fabricated legacy row; the structured header is sufficient.

Rollover still validates source/target/timing first. It then invokes the canonical
workflow and requires structured_complete, final flag, matching season, confirmed
snapshot identity and equal expected/actual counts before cleanup. D1 recompute can
legitimately refresh current scores/remove stale ineligible rows; this is distinct
from destructive rollover cleanup, which remains blocked on snapshot failure.

After the gate, existing score/match deletion, bracket retirement, target creation
and C3 finalization are AST-identical. C3 still atomically activates the new season
and clears standings. These later steps remain separate transactions. If later
cleanup fails, the immutable snapshot remains; no automatic rollback/deletion,
retry, resume or broader recovery policy is introduced.

## SC17 — genuine zero participation

The user explicitly resolved the section-19 checkpoint: a successful canonical
season/master evaluation and recompute that establishes zero eligible competitors
must create one complete immutable zero-row structured snapshot. Publisher and
service verify expected_rows=0, actual_rows=0, intended season, existing identity
and final=true. This verified record satisfies the same cleanup gate as a nonempty
snapshot. Repeated requests preserve the same zero header and create no duplicates.

Scoring failure, eligibility/query failure, invalid/missing season/master, unknown
source state or partial publication never becomes zero success and cannot reach
cleanup. No speculative result is inferred from empty/failed responses.

## Public history and frontend

Existing structured-history GET endpoints now intentionally permit anonymous safe
reads. Nonfinal new headers are excluded. Responses use stored rank ascending,
stable display_order and row ID; no current score/name rerank. Safe allowlists
exclude email/password/reset/auth fields, live user/bracket identifiers, drafts and
private league payloads. Nested numeric point maps and column metadata are filtered.
Old structured snapshots remain readable and retain original stored ranks, including
historical username-derived ranks. No silent historical competition correction.

PastSeasonsPage renders stored ranks, including true ties. Missing legacy rank
renders an unknown mark rather than a fabricated index rank. Existing historical
UI, authentication elsewhere, live leaderboard and bracket rules are unchanged.

## Acceptance evidence and limits

Focused guarded HTTP/DB scenarios cover stale live scores before snapshot, true
stored ties/public privacy, exact repeated final identity, zero final plus cleanup,
failed evaluation/query/source refusal, legacy-only success with structured failure,
source change fencing, later cleanup failure preserving history, immutable history
through current score/recompute/bracket/canonical changes, and admin-only writes.
Offline matrix covers points, full hits, save-time order, true ties, unknown read
results, sanitized errors, public nested serialization and job admission refusal.

The disposable fresh proof covers baseline through 0006, exact semantic/security
verification, synthetic seed, actual failure on the second row after header insert,
no orphan/partial snapshot, preservation of an older completed record, repeat
idempotence, immutable history/application TRUNCATE refusal, zero final/repeat and
ordinary-role denial. Fixed scratch DB is removed after proof. Actual rollover gate
and C3 activation are exercised through the guarded HTTP suite on the verified local
full-chain database. No production failure toggle is added.

Prior characterization evidence is retained. Approved historical assertions are
updated with previous metadata; old offline cleanup doubles explicitly mock the
snapshot boundary rather than pretending to prove a PostgreSQL transaction. Real
HTTP/SQL acceptance provides that proof. Full validation totals and cleanup are
recorded in db/records/nc_02d2_history_snapshot.json.

## Fixture identity and production readiness

Canonical foundation has empty history/score/bracket tables; new nullable columns
therefore do not alter nc-fixtures-v1 or checksum
 a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0.
The existing owner-only guarded TRUNCATE reset restores immutable synthetic history
without changing fixture identity. Final cleanup verifies designated canonical
season, 30 standings, empty canonical scores/history, released lease, stopped Flask,
empty capture, disabled jobs, no global permission and no scratch DB.

No production history was queried. Later separately approved rollout needs secured
schema/0001–0005 preflight, canonical master/graph/save-metadata checks, backup of
all structured/legacy history and current competition state, inventory/review of
any already-existing unverified current-season headers, and coordinated backend/
frontend/0006 release. Old historical values need no data migration/reranking;
nullable schema additions preserve them. Future rollover now requires fresh scoring
and complete immutable structured preservation; legacy-only success cannot proceed.

Rollback must preserve completed records and their metadata. Pause snapshot/rollover
callers, inspect committed state, keep backups and prefer a reviewed forward fix.
Reverting code/migration does not undo previous cleanup or restore earlier live
state; removing metadata/guards could lose preservation guarantees. No rollback or
production operation was performed.

Broader rollover transactionality, partial cleanup recovery, retry/resume, exact
trigger timing, master-completion business prerequisites, broader retention, league
lifecycle and unrelated auth remain deferred. No next domain has started.

## Final results

231/231 complete applicable backend regressions passed, including D1 scoring and
A/B/C protections. Final input validation rejects null display_order and non-integer
zero-count/identity confirmations. The final fresh-chain proof, 293/293 offline
tests and 8/8 focused live tests passed after that tightening; the focused pass also
confirms history survives a subsequent real D1 recompute. 33 affected offline/source
characterization checks passed. Frontend 31/31 tests and TypeScript/Vite build passed.

Black/scoped app formatting, whitespace, syntax/JSON/size/secret/privacy scans and
import comparison passed; zero new unused imports. Python full lint tooling is not
configured/installed. Frontend ESLint retains baseline 83 errors/1 warning; the
changed history page has the same 6 errors/0 warnings and zero new diagnostics.
Existing browser-metadata and chunk-size build warnings remain outside this phase.

All 100 protected files, including the live scoring engine, bracket rules,
canonical season and standings implementation remain unchanged. The post-gate
rollover AST is identical. Independent cleanup confirmed original fixture checksum,
canonical designation, 30 standings, empty canonical score/structured/legacy history,
released lease, stopped Flask, empty capture, disabled jobs, no global permission and
no proof DB. Production is unchanged. NC-02D1/D2 plus SC17 are complete locally;
broader rollover recovery remains deferred and no next domain has started.
