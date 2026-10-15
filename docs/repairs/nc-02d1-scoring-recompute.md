# NC-02D1 â€” scoring correctness, canonical master and atomic recomputation

Scope: SC1, SC2, SC3, SC4, SC6, SC7, SC8, SC9 only. No production contact,
migration, score query or deployment. Implementation and final local verification
are complete. SC5 and SC10-SC16 remain for NC-02D2.

## Starting state and pre-change inventory

Backend main 410507ad6948ec14e67dc68b0cea9838e714588d and frontend main
53dd1d71eb59494596360a2c3955e1f651176ae0 were clean. Full pre-change caller/input,
master/season/eligibility/write/transaction map is recorded in
 db/records/nc_02d1_scoring_path_inventory.json.

The former _compute_score_for_bracket accepted a caller's master dictionary/ID
and upserted one competitor at a time; recompute selected a URL master without
checking the canonical pointer/is_master. Bonuses stayed zero. Result edits did
not recompute. Live backend sorted points/full_hits/save time without competitive
ranks; frontend sorted again and rendered array positions. Frontend maintenance
selected the admin's own bracket as master. Snapshot/rollover behavior was mapped
and remains unchanged.

## Approved scoring clarification and pure engine

The user clarified that a correct winner with the wrong opponent is worth 1;
3 requires both teams, winner and games correct. scoring_engine.score_bracket is
pure and deterministic, with no IO or authority selection. Play-in winner hits
are 1, misses 0, no series-length bonus. A play-in full hit retains the existing
participant-match requirement; a winner hit with another opponent is partial 1.
Best-of-seven correct winner is 1; matching both teams and exact winning game count
adds 2, totaling 3. Missing/incorrect legacy user counts earn only the winner point.
Wrong winner never receives exact-game points. Existing full_hits counts full
series/play-in outcomes, never bonuses. Participant pairs retain unordered identity
semantics, including the Finals pair.

The engine exposes base_points, full_hits, partial_hits, misses, bonus_finalists,
bonus_champion, total_points and base-only points_by_round/points_by_match. Existing
DB names are preserved; no base_points column is added. A completed canonical
Finals result establishes champion +3. Both established Finals participants matched
add +1 independently of champion. No established champion means zero champion
bonus; unknown finalists mean zero finalist bonus. Known finalists can earn +1
while the Finals winner remains unresolved. Earlier completed rounds score normally
while later results are pending. Total = base + finalists + champion, no double count.

## Canonical orchestration, eligibility and persistence

scoring_service.get_current_scoring_master resolves canonical season, then its
master pointer, then validates exact referenced bracket identity, season, active
state and is_master=True. No fallback to scores, user ownership or arbitrary IDs.
Missing/invalid authority fails closed. The legacy URL parameter is a constraint
against canonical truth and is rejected on mismatch; the preferred route is
POST /admin/score/recompute. Both JWT admin and users.is_admin are checked.
The former per-row writer is removed; test fixtures invoke only the pure engine.

Recompute fetches the complete current bracket/match input state, validates the
21-coordinate master representation, calculates every eligible competitor, checks
component totals and types, and makes one publish RPC. Only saved/current/active
competitors with valid aware saved_at are included; master itself is excluded as
before. SC21 defensive invalid save metadata is treated as ineligible for live
ranking/publication, never fabricated as earliest. The shared historical eligibility
helper remains unchanged so D2 historical policy is not silently altered.

Chosen persistence: successful publication replaces the current-season score set
with exactly current eligible competitors, removing stale current draft/deleted
rows. Older-season/legacy-null rows are not rewritten. Ordinary edits still only
invalidate submission and hide stale scores, retaining stored rows until successful
recompute. This preserves A2 visibility behavior. No historical score/snapshot
recalculation is performed.

## Atomic publisher and security

Portable 0005_nc_02d1_atomic_scores.sql follows immutable baseline and 0001-0004.
New public.publish_current_bracket_scores(uuid,uuid,jsonb,jsonb) is postgres-owned
PL/pgSQL SECURITY INVOKER, search_path=pg_catalog,public. PUBLIC/anon/authenticated
EXECUTE is revoked in the migration transaction; postgres/service_role only.
Existing table grants, RLS, policies, indexes and prior functions are unchanged.
No arbitrary table/SQL selector exists. Frontend -> Flask -> trusted DB remains.

Publisher locks canonical pointer FOR UPDATE then the selected season FOR SHARE,
matching prior publication/transition ordering. It validates the canonical master.
Brief SHARE locks on bracket/match input tables prevent concurrent insert/update
while comparing the complete typed source snapshot and publishing. Reads remain
available; no entire-rollover transaction is introduced. Source comparison covers
all current eligibility and scoring fields. Changes during calculation fail closed
rather than publishing a mixture. Table locks are limited to this short publication
transaction; there is no network/provider fetch or Python calculation inside it.

The DB checks complete eligible ID set (including duplicate/missing rejection),
master/season IDs, required fields/types, numeric components, bonus bounds and
base-round/total consistency, while Python owns winner/bonus semantics. DELETE and
INSERT are one transaction with existing FK integrity. Empty eligible set is valid.
When the entire computed set already equals stored values, the RPC writes nothing,
so repeat requests preserve even updated_at exactly. Otherwise one complete new
current set becomes visible, without independent upserts or mixed users.

The previous C3 verifier is frozen byte-identically as verify_nc_02c3_schema.sql.
The full verifier preserves previous assertions except required function inventory
addition and adds exact body/owner/language/settings/grants assertions. Reset pin
and local bootstrap chain include 0005. The old C3 proof uses its frozen verifier.
No old migrations, baseline, historical report or canonical fixture was rewritten.

## Automatic/manual recompute and failures

Successful canonical master winner/update, undo, game-count change, and canonical
master establishment/replacement synchronously invoke the same orchestration.
Failed operations and ordinary user edits do not recompute; reads/save operations
do not invoke publication. The existing B3 creation/replacement transaction and
B1/B2 authorization/propagation rules are retained; only scoring is integrated
after successful establishment. No background/eventually-consistent queue is added.

Scores alone are atomic. A master result or master replacement may commit before
recompute fails. API then returns sanitized SCORE_RECOMPUTATION_FAILED with
master_mutation_committed=true and explicit inspect/manual-recompute guidance.
No cross-operation rollback is claimed. Controlled SQL failure retains exact old
scores; a transport failure may leave old or fully new scores, never a partial
published set, so confirmation is not falsely claimed. Canonical manual recompute
recovers idempotently. After replacement, rows referring to the retired master are
hidden until new canonical scores publish; score rows cannot choose live master
metadata. No automatic retry/rollback policy is invented.

## Live ordering and frontend

rank_live_rows sorts total DESC, full_hits DESC, saved_at UTC instant ASC. Equal
competitive keys share competition ranks (1,2,2,4); username/user/bracket IDs only
stabilize tied display order. Invalid save times are omitted. Canonical master
metadata is resolved from season authority rather than frequency among score rows.
Private/public league scope filtering remains in the existing authorized server
path, with rank calculated after scope filtering.

LeaderboardPage consumes server order/rank, fetches the selected league scope,
and ignores stale overlapping responses. It never re-sorts or assigns index ranks.
Manual recompute no longer fetches the admin's own bracket or supplies authority.
Original mount-only analytics scope is preserved using its initial ref; no new
analytics event is introduced. Existing leaderboard UI and historical pages remain.

## Acceptance and reproducibility

Pure matrix tests cover base hit/partial/miss, wrong opponent clarification,
champion/finalist combinations, pair order, incomplete truth, bonus separation,
full-hit independence, true ties/save-time ordering, invalid save times and no input
mutation. Canonical resolver tests cover missing/wrong/deleted/non-master pointers,
caller mismatch, source season mismatch and sanitized errors. A calculation failure
on a later competitor is proved to call no publisher at all.

Guarded real HTTP/DB cases cover complete eligible replacement, exact manual
idempotence, admin-only/manual refusal, winner/undo/count auto flow, no ordinary or
failed-operation recompute, spoof/invalid pointer refusal, source changes during
calculation, committed master + last-good score failure/manual recovery, live ranks
and stored bonuses, and canonical replacement/recovery. Existing A/B/C regressions
are retained. Explicit local admission requires enrolled identity, canonical fixture,
active lease, ready context, nonce, registered mutation route or selected D1 manual
request. Global jobs remain disabled; manual maintenance in prior scopes stays
refused. Automatic admission follows only already-authorized master mutations.

The disposable local proof recreates baseline -> 0001 -> 0002 -> 0003 -> 0004 ->
0005 -> exact semantic/security verification -> synthetic seed. Trusted publication,
unchanged exact idempotence, spoof/source-change fencing, incomplete-set rejection
and ordinary-role refusal pass. A scratch-only trigger fails on the second INSERT
after DELETE, proving every old score value/ID/timestamp survives rollback. The
transaction removes the temporary trigger, and the newly owned scratch DB is
removed. There is no production failure toggle or persistent test mutation bypass.

## Fixture identity and production readiness

Canonical foundation has empty brackets/matches/bracket_scores; temporary scenario
scores are deliberately fixture states, not precomputed canonical engine output.
The checksum covers those empty canonical score rows. Formula changes therefore do
not change nc-fixtures-v1 or a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0.
Cleanup must restore original standings, empty canonical scores, designated current
season, lease released, Flask stopped, capture empty, jobs disabled and no global
mutation permission. No canonical identity/version is silently rewritten.

No production state was queried. Later separately approved rollout requires secured
0001-0004 schema and canonical source/master validation, graph/eligibility/save-time
preflight, backup of score/competition/history state, trusted server grants and a
coordinated DB/backend/frontend release. First current recompute is required to
apply +3/+1 and rebuild current eligible scores; users with established matching
truth may gain up to +4 separately from ordinary series base points. The clarified
wrong-opponent play-in winner now earns 1 rather than the former 0; full-hit
participant matching remains unchanged. Live rank/order may change accordingly. Historic snapshots
are not retroactively changed in D1. Review missing save metadata rather than
inventing timestamps. No new provider key or season configuration is required.

Rollback: pause mutation/recompute callers, inspect committed master and scores,
preserve backup/history, and prefer a reviewed forward fix. Code/function rollback
does not undo master results or reconstruct earlier scores. Do not restore only
one side blindly or enable legacy arbitrary-master/per-row scoring as a workaround.

## Deferred and next

SC5 and SC10-SC16 remain unresolved: historical tie ordering, pre-snapshot recompute,
structured success definition, atomic snapshot header/rows, rollover snapshot gate,
immutability/privacy/order integrity. Rollover body and destructive gate remain
unchanged. Existing historical data and reads are preserved. Next only upon explicit
request: NC-02D2 â€” Historical snapshot integrity, ordering and rollover snapshot gate.

## Final validation and cleanup

223/223 complete applicable backend regressions and 7/7 focused live scoring cases
passed. Offline safety/pure scoring: 285/285; frontend: 28/28; TypeScript/Vite build:
PASS. Fresh immutable baseline through 0005, actual second-insert failure rollback,
semantic/security verifier, source/master fencing and untrusted-role refusal passed.
The final run includes all repaired A/B/C protections and the master replacement
hook. Existing characterization evidence was retained; repaired source assertions
and acceptance metadata now describe the approved current live behavior.

Black passed for 20 changed modules plus scoped changed app functions; whitespace,
compilation, JSON parsing, size/secret/privacy audit passed. All 86 protected
historical artifacts remain byte-identical, as do unrelated app functions including
snapshot/rollover functions. Zero new unused Python imports. Full Python lint tooling
is unavailable. Frontend ESLint retains existing 83 errors/1 warning; the changed
page retains 11 existing errors and has zero warnings, with no new diagnostics.
Existing browser-metadata/chunk-size build warnings remain outside this phase.

Independent cleanup confirmed SEEDED/nc-fixtures-v1 and its original checksum,
canonical designation, 30 standings, zero canonical score rows, released lease,
stopped Flask, empty capture, disabled jobs, no global mutation permission and
removed scratch DB. The standalone readiness harness is intentionally UNMET until
an explicit guarded invocation; no global bypass was enabled. Full machine-readable
results, file inventory and frontend checkpoint are in
 db/records/nc_02d1_scoring_recompute.json. Production was not contacted. D2 has not
started.
