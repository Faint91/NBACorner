# NC-02F2 — Historical league membership and season leaderboards

## Scope and starting state

Backend main started clean at b6b8830b82678c4809bb935fc3fa54a4291759b0;
frontend main started clean at 2887277f67e8666ac1da3df2526042585793dfb8.
The continuation preserved all saved implementation and the successful 218-case
applicable backend run. Only missing concurrency/authorization assertions,
documentation, final safety checks and independent commits were finished.
No production query, migration, deployment or backfill was performed.

Before F2, league tables supported current membership/live competition only.
Global D2 snapshots already stored immutable score/display truth, but had no
stable competitor identity with which to freeze league membership safely.

## Approved behavior: L20, L21, L22, L20A, L20B, L21A

League history freezes only cutoff members found in the successfully evaluated,
finalized global eligible competitor set. Draft/no-bracket/deleted-ineligible
members never receive placeholder rows. An eligible competitor whose real score
is zero still competes. A league with zero eligible competitors has no competitive
season header or UI entry. This differs from the complete zero-row global SC17
snapshot, which remains supported. A zero-league all-league receipt is valid.

Leave before cutoff excludes; join before includes if globally eligible. Leave,
join, kick, rename and ownership transfer after cutoff cannot rewrite standings.
Current ownership/member controls are hidden while the past table is selected.
Current league name/privacy remain current; historical competitor names/results
remain the frozen global source.

## Data model and internal mapping

Forward migration `db/post-baseline/0009_nc_02f2_league_history.sql` adds:

- `leaderboard_history_competitors`: global snapshot row primary key -> stable
  internal user UUID. No public serialization, email, credentials or browser ACL.
  No user-account FK: account deletion must not erase global result retention.
- `league_history_cutoffs`: one immutable final receipt per global snapshot,
  original expected nonempty league/row totals and finalization timestamp. It has
  no league name/ID/member list and also records genuine zero-league decisions.
- `league_history_seasons`: unique league/season, reference to source receipt,
  positive expected competitor count, final timestamp/seal.
- `league_history_rows`: reference to immutable global row, stored league rank and
  display order. Scores and display identity are not unnecessarily duplicated.

The global snapshot publisher captures the mapping before its existing final
seal; source bracket IDs never enter public history. Existing D2 result/ranking
semantics remain unchanged. No old final snapshot is rewritten or backfilled.
A nonempty pre-F2 finalized global snapshot without a complete mapping blocks
league preservation for explicit review; it is never guessed from current names
or memberships. A verified global zero snapshot requires no mapping rows.

## Ranking

League rank is computed from its own frozen subset: total_points descending,
full_hits descending, saved_at ascending. Exact equality shares competition rank
(1,2,2,4). Display name with C collation, existing global order and row ID stabilize
display only after those competitive fields; they cannot break competitive ties.
The API/UI use stored league rank, never global rank or array index.

## Cutoff, concurrency and transaction boundaries

`publish_league_history_cutoff` shares E's transaction advisory lock (50405,2)
and canonical pointer row lock. It validates the finalized global source and
complete unique internal mapping. A short EXCLUSIVE lock on `leagues` conflicts
with the ROW SHARE lock acquired first by F1 lifecycle RPCs. A membership trigger
also locks parent league rows for trusted raw membership mutations. New league
creation, joins, leaves and owner removal therefore settle before or after one
unambiguous cutoff. Plain reads continue. The lock lasts until the enclosing
short database RPC commits, including its transition work; no network/rendering
work happens inside it. Deadlock/error aborts block cleanup, never partially
sample. Six real two-session races observe lock waits for join/leave/owner removal
in both orderings and check exact frozen/live membership outcomes.

All expected nonempty leagues/rows and final receipt publish within a single
preservation subtransaction. Failure on a second league rolls all new league
history back. The global snapshot was sealed in the preceding preservation
scope and remains available. No destructive transition starts on that failure.
After league success, E's separate atomic destructive transition runs. A later
transition failure rolls that transition back while retaining global plus league
history for retry. This is deliberately not one all-or-nothing rollback of all
preservation. The transition verifies the cutoff again before cleanup.

A finalized receipt is verified and reused, without querying today's membership
for composition. Late joins, originally empty leagues and new leagues cannot be
silently added on retry. Partial/unfinalized/conflicting state blocks for review.
Unique keys refuse duplicate league/season headers. Final headers/rows/maps and
receipt refuse normal updates/appends/partial deletes/source swaps/truncation.

## Current authorization, safe reads and frontend

`league_history_service.py` reads finalized league headers and immutable global
rows only, not current scores/memberships for composition. Current authorization
uses the existing private-league helper. Optional JWT allows anonymous public
history; a supplied invalid JWT is refused. Current private members/owner can
read; former/historical members, former owner and admin nonmembers cannot.
Privacy switches affect both endpoints immediately without changing history:

- `GET /leagues/<league_id>/history`: finalized league season list, newest first.
- `GET /leagues/<league_id>/history/<season_code>`: stored rank/order and safe
  frozen score/display fields; absent history 404, inconsistent/read failure 503.

Explicit allowlists exclude user/bracket/global row IDs, internal mapping,
security fields and email. League UUID is the existing public resource identity.
Global public serialization remains unchanged. The minimal LeagueHistoryPanel
adds a current/past selector, safe table and empty/error states. It clears old
rows before refetch and on authority changes; stale responses are cancelled.
Focus refetch rechecks privacy/membership. No persistent history cache is added.

## L22 deletion and retry

Confirmed F1 whole-league deletion cascades league-specific headers/rows and
memberships. Final-history triggers permit only this parent-deletion exception.
Global snapshots/rows/internal mapping, users, brackets and global competition
remain unchanged. Deleted league endpoints return 404; F1 normalized name reuse
still applies. The nonidentifying receipt keeps original aggregate counts; its
immutable completion proof is not rewritten by legal league deletion. Verification
checks remaining histories without resampling current membership. No identifying
league tombstone survives in that receipt.

## Migration/security and fixture safety

Baseline and migrations 0001-0008 remain byte-identical. The F1 verifier is frozen
as `verify_nc_02f1_schema.sql`; current verifier extends exact catalog assertions
for F2 columns/FKs/indexes/triggers/ACL/owners/RLS and approved RPC body extensions.
New tables are postgres-owned, RLS enabled with no policies. PUBLIC/anon/
authenticated have no access. Service role has SELECT/INSERT and only is_final
column UPDATE on receipt/header, no DELETE/generic UPDATE/TRUNCATE. New functions
are postgres-owned INVOKER, pinned pg_catalog,public, execute postgres/service_role
only. Flask remains the authentication boundary, not browser direct DB access.

Reset explicitly includes four new tables and checks them empty independently.
They are intentionally outside unchanged v1 checksum inputs. Canonical fixtures
remain four users, 30 standings, no leagues/members/competition/history/audits,
SEEDED/nc-fixtures-v1, checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
The standalone legacy harness=UNMET field means no active lease; outer readiness
must remain PASS/AVAILABLE_GUARDED with no mutation admission.

## Validation and repeatability

From backend, enrolled isolated local settings only:

```
python scripts/run_league_history_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -m unittest discover -s tests/offline -q
python scripts/prove_league_history_migration.py
python scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
```

The saved full applicable suite passed 218/218, including F1 and E regressions.
The continuation additionally rechecks seven F2 API cases with explicit public,
member and owner access assertions for both endpoints. Offline safety: 317 tests.
Frontend: 48 tests and TypeScript/Vite local production-mode build passed.
Existing global frontend lint debt remains 83 errors/one warning, zero new
diagnostics; no standalone backend linter exists. Scoped Black, whitespace,
compilation, import/preservation and credential/file audits are recorded separately.
No browser/E2E run is claimed; frontend verification uses the existing Node
interaction suite and TypeScript/Vite build.

Fresh disposable baseline -> 0001-0009 runs exact semantic/security checks,
17 F2 proof groups (including six real membership races), nine F1 groups and
21 E SQL groups after F2. Failure injections cover all-league rollback, immutable
source mismatch, transition fault/retry, genuine zero and failure-not-zero.
The disposable database is removed. Final totals/state are in
`db/records/nc_02f2_league_history.json` and linked validation records.

## Production prerequisites — not performed

A separately authorized rollout needs backup, 0009 review, global mapping/active
final-snapshot preflight, actual league/member integrity review, FK/cascade review,
and coordinated backend/frontend rollout. Review any pre-F2 current-season final
snapshot without mapping before rollover; the gate intentionally fails closed.
No automatic historical backfill: pre-F2 completed seasons do not gain league
history. Their immutable global history remains available globally.

NC-02F2 completes the approved league domain locally; do not begin another domain
without the user's next approved checkpoint.
