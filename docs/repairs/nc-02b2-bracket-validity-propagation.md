# NC-02B2 — Bracket validity and propagation

## Approved scope and starting state

B6–B9 only. Backend main `652d4096097fe2cb6660b9b16d1048cd2d4cb843`;
frontend main `d62dd948b864086d0240f27bfbdefa2e9f46acc6`; both clean at start.
No production contact/deployment, migrations, baseline changes, scoring changes or
standings/season changes. B10–B15 remain explicitly deferred.

## Existing match/graph model and before behavior

`matches` contains `conference`, integer `round`, `slot`, participant A/B, prediction,
predicted count and one explicit winner edge (`next_match_id`, `next_slot`).
The existing creation routine builds, per east/west conference, three round-0
play-ins, four round-1 series, two round-2 semifinals and one round-3 conference
final; one nba round-4 Finals joins the conferences. This is 21 required matches.
Round 0 identifies play-in semantics; no new type column or fixed match IDs.

The 9/10 winner feeds the deciding play-in; the 7/8 winner feeds a first-round
series, while its loser feeds the other input of the deciding play-in. The
7/8 source stores only its winner edge: the existing code previously handled its
loser with hardcoded slot-2/slot-3 logic. The new helper derives that missing loser
edge from the conference's existing round-0-to-round-0 dependency, using the
unoccupied destination slot. It does not change stored links or creation.

Previously normal counts accepted zero/negative/arbitrary values, and play-in
selection silently overwrote invalid supplied counts with 1. One-sided predictions
could succeed. Save skipped unresolved matches and checked neither the required
graph nor count domain. Winner/undo cleanup followed the old team into later rows,
which missed downstream predictions whose selected winner came from the other
branch but whose opponent had changed. Frontend optimistic propagation handled
only immediate outputs and could keep deeper stale picks/counts visible.

## Shared rules and routes

`bracket_rules.py` is pure: no Flask, DB, clock, credentials or authorization.

| Rule | Implementation |
| --- | --- |
| Counts | `game_count_error`: strict Python integers, excluding bool/float/string; normal series exactly 4/5/6/7; nullable only during unfinished editing/incremental master persistence |
| Play-in | Round 0 count exactly integer 1; direct count editing always refused; omitted count on valid winner selection becomes 1; explicitly invalid/null count refused |
| Dependencies | `dependency_edges`: stored winner edges plus topology-derived play-in loser edge; rejects missing targets, invalid slots, duplicate IDs and cycles |
| Propagation | `apply_prediction`: copy rows; replace changed dependent input; clear that match's winner/count; enqueue its now-empty outputs recursively; only touched rows are returned |
| Submission | `submission_error`: required semantic round/conference shape, unique match coordinates, edges/round relations, unique incoming slots, required feeders, upstream participant consistency, both distinct participants, valid winner and counts |

The ordinary validator verifies the graph rather than counting non-null winners.
A missing/extra/duplicate match, broken/cyclic edge, impossible round transition,
missing required feed, stale propagated participant or invalid prediction refuses
submission. The 21-match shape comes from the existing creation model, grouped by
round/conference; propagation itself never assumes fixed slot numbers.

`app.py` integrates the rules only into:

- PATCH /bracket/<id>/match/<match_id>: existing auth/active/current-season/B1
  content guard first; both participants required; winner must be one of them;
  count checked; pure graph change computed before DB writes; only changed rows
  persisted; existing submission invalidation called.
- PATCH /bracket/match/<match_id>/games: same B1 guard; shared count validator;
  play-in edits refused; existing invalidation preserved.
- PATCH /bracket/<id>/save: same B1 guard; canonical ordinary/master validity
  before any submission update; explicit save alone writes is_done/saved_at.

`current_master_bracket` extracts the identical B1 current-master flag OR season
pointer check, so authorization and the master-save exception share identity.
This does not change master promotion/replacement/deletion or admin privileges.
Create, delete, final-lock predicate/error, competition eligibility, invalidation,
scoring, history, account, leagues, standings and season functions remain unchanged.
Existing individual DB writes remain; no new transaction/RPC/schema architecture.

## Ordinary submission versus incremental master persistence

Ordinary drafts may progress naturally and may have missing counts for unfinished
series. Both-participant validation applies when selecting a winner; full graph
completion is enforced only at explicit save. No auto-fill or auto-submit occurs.

The authenticated admin on the current active master can save an empty/partial
result state without requiring every match/prediction/count. Existing stored
predictions must still have both participants and a valid winner; any stored
count must satisfy B7, and stored propagated inputs must match upstream outputs.
A missing normal-series count may remain unfinished; a recorded play-in winner
has count 1. Master editing still requires B1 authorization, B7/B8, and the same
B9 propagation. No ordinary/admin bypass is introduced.

## Change/undo/count semantics

A changed source winner replaces its direct winner output and its play-in loser
output where applicable. Every changed downstream input invalidates that match's
prediction/count even if its previously selected winner came from its unaffected
opponent branch. Its previous advanced winner is then removed from the next
match, continuing to Finals as necessary. Undo uses exactly the same traversal
with empty source outputs. Unchanged inputs stop traversal; unrelated conference,
round branches, selected winners/counts and timestamps are untouched.

Changing a normal-series winner with a new valid count stores the new pair.
Without a supplied count, the new prediction has NULL count rather than inheriting
the old one. Submission remains unavailable until a valid count is supplied.
A same-winner count edit leaves downstream participants/picks intact but still
invalidates submission. Undo clears the current winner/count, including play-in.

## Frontend

`src/lib/bracketValidity.ts` checks obvious ordinary submission readiness: actual
round/conference shape, identity uniqueness, populated distinct participants,
winner membership, canonical counts and stored winner-edge consistency. Backend
validation remains authoritative for the full dependency graph. Master-admin
save readiness explicitly permits incomplete results.

`BracketPage.tsx` retains existing discrete 4/5/6/7 controls and the round>0 guard;
play-in counts remain noneditable. One-sided winner buttons retain the existing
`hasTeams` disable/handler guard and TBD conventions. Handler validation also
rejects invalid series values. Successful winner/count/undo edits reload server
state, including complete recursive clearing, metadata and submission flags.
Two immediate-only optimistic propagation helpers were removed. Pending counts
are removed only for the edited match or changed participant pairs; unrelated
pending branches remain intact. All B1 ownership/master/lock/undo rules remain.

## Acceptance and NC-01 provenance

Converted existing NC-01B source findings, with previous metadata retained in
`scripts/nc02b2_acceptance_metadata.py`:
`prediction_validation`, `game_count_values`, `winner_change_graph`, `undo_graph`,
`partial_graph_save`, `save_completeness_static`. These were source observations
and unreviewed validity contracts, not separately numbered canonical gaps in the
19-gap consolidated catalog. No historical classification/report is rewritten.
Existing test helpers now supply canonical play-in counts; this does not change
canonical fixture data/checksum or historical evidence.

Ten new guarded live B2 cases cover strict counts through both routes, play-in
immutability and automatic 1, omitted replacement count, ordinary/master one-sided
refusal and natural progression, nine corrupt-submission fixtures and valid save,
opponent-dependent recursive winner/undo clearing, Finals, dual play-in feeds,
unrelated branches and incremental post-lock master saves.

The new fixed local fault context permits only reviewed faults on the synthetic
draft Finals, inside the enrolled NC-02B2 lease, and restores the changed fields
on exit. It never accepts arbitrary SQL, record IDs or production targets.
Missing/duplicate/extra graph rows and malformed stored count values are also
covered by pure tests; PostgreSQL integer columns cannot store malformed text.

Twelve pure rule tests cover strict types, absent/invalid counts/winners, missing
participants, missing/duplicate/extra/broken/cyclic graph state, partial masters,
normal/Finals change/undo, dual play-in propagation and input immutability.
Three new offline tests prove the fault/scope controls refuse bypasses. Seven
frontend Node tests include the four unchanged B1 access tests and three new
readiness/control/server-refresh cases, using the same synthetic complete graph.

## Gap status and deferrals

| Validity finding/theme | NC-02B2 result |
| --- | --- |
| Invalid game counts (NC-01B game_count_values) | FIXED; strict shared validator |
| One-sided prediction (NC-01B prediction_validation) | FIXED for ordinary and admin/master |
| Incomplete/inconsistent submission (NC-01B save_completeness_static/partial_graph_save) | FIXED under approved B6; no separate historical canonical gap ID |
| Downstream dependency integrity (NC-01B winner_change_graph/undo_graph) | FIXED for recursive opponent dependencies; existing unaffected-branch behavior CONFIRMED |
| B1 backend/frontend lock, owner Undo and arbitrary-admin content restriction | PRESERVED |
| GAP-RESAVE-001 / B4 | PRESERVED / ALREADY FIXED NC-02A2 |

B10/B11 deletion, B12 season uniqueness, B13/B14 explicit master lifecycle, and
B15 historical access are deferred. Champion +3, finalist +1, snapshot tie ordering,
standings provider/freeze, canonical season source and league lifecycle unchanged.
No schema changes or NC-ENV baseline edits. No production contact or deployment.

## Validation, evidence and cleanup

The fixed runner is `python -B scripts/run_bracket_validity_acceptance.py --config
<absolute ignored local test config> --allow-local-mutations`. `--validity-only`
selects ten new live cases. `--static-only` selects ten read-only source checks
without importing the app or accessing the DB. It writes separate NC-02B2 evidence
and does not overwrite any NC-01/NC-02A1/NC-02A2/NC-02B1 report.

Focused live 10/10, offline 238/238, frontend 7/7, TypeScript and Vite build passed.
Lint comparison: edited page 28 baseline errors -> 16, no new findings; new frontend
files zero errors/warnings. There is no unrelated lint cleanup. Existing Vite
browser-data-age and bundle-size warnings remain.

Final validation is recorded in `db/records/nc_02b2_bracket_validity_propagation.json`.
The full run executed 189 cases: 188 passed and one source-only assertion failed
because it expected a single-line call that Black had wrapped. The full process
had loaded the old assertion before its correction. The corrected complete
10-case static class passed in a separate read-only rerun. No application code
changed for this correction and no runtime/application regression failed. Current
required coverage is fully verified, with no remaining failures. The raw full-run
result (including its one failure) is retained unchanged in `nc_02b2_validation.json`;
`nc_02b2_static_validation.json` and the summary document its resolution. No claim
is made that the first full run was an uninterrupted 189/189 pass.

All B1 lock, A1 privacy, A2 edit/resubmit and domain regressions passed. Semantic
schema and fixture-marker-v2 verification passed. Syntax, formatting, whitespace,
secret/privacy scans and consolidated historical baseline validation passed.
All 41 previous schema/baseline/characterization/repair evidence files remain
byte-for-byte unchanged. Final canonical state is SEEDED / nc-fixtures-v1 with
checksum `a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Flask is stopped, pg_locks confirms the fixture lease released, captured email is
empty, app import is removed and jobs remain disabled. Production was not contacted.

Next phase recommended only: **NC-02B3 — Bracket lifecycle, season uniqueness,
master management and historical access**. Not started.
