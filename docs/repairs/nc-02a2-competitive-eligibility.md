# NC-02A2 — Draft/saved competitive visibility and eligibility

## Approved scope and starting checkpoint

Backend main `c2543b8aa97ee63b683a2a86f0ff047020cc5a29`; frontend main
`ce54143006f0409265937f5d548286d0b100d454`; both clean at start. P4/P5/P9
explicitly approved by the user. No production contact, deployment, schema/baseline,
frontend, score-formula, final-lock authorization, arbitrary-admin mutation policy,
standings/season or league lifecycle changes.

Historical sources remain immutable: NC-01 consolidated baseline/report and domain
reports/records, plus NC-02A1 repair reports/records. Current repair evidence is
separate. NC-02A1 serialization and private membership protections remain in force.

## Competitive-surface inventory

| Surface | Source / prior filtering | Canonical expected rule / change | Baseline finding |
| --- | --- | --- | --- |
| GET /leaderboard, global | Stored current bracket_scores + nondeleted current brackets; no submitted-state check | Validate current bracket eligibility before entries, order and score-derived master metadata; global anonymous contract unchanged | NC-01D current_behavior__scoring__draft; GAP-DRAFT-SCORES-001 |
| GET /leaderboard?league_id=public | Before NC-02A2 query ignored; global rows were downloaded and client-filtered | Authenticate explicit league scope, restrict rows to member owners, and require current saved state | NC-01C leaderboard_private_surface/frontend_leaderboard; NC-01D league_surface; GAP-PRIVATE-SCORES-001 |
| GET /leaderboard?league_id=private | NC-02A1 membership gate and member-owner filtering, but persisted draft scores remained eligible | Preserve membership gate; apply the same current saved predicate before competitive serialization | NC-01C draft_scored_leaderboard; GAP-DRAFT-SCORES-001 and GAP-PRIVATE-SCORES-001 |
| GET /stats/champion-picks (global/current) | Saved/nondeleted current brackets already filtered before picks and point aggregates | Reuse canonical predicate; same eligible set, denominator and math | NC-01C stats_membership, draft_saved_visibility; NC-01D scoring architecture |
| GET /stats/champion-picks?league_id=... | Saved member brackets; private membership gate, existing public member/owner/admin authorization | Preserve access and aggregate math; canonical predicate before both champion and least/most-point calculations | NC-01C stats_membership, historical; NC-02A1 private access acceptance |
| Explicit season_code champion stats | Reads live bracket records in explicitly selected season, not snapshot history | Require saved/nondeleted in that explicit season; do not force current season | NC-01C historical |
| GET /brackets, optional league_id | Saved/current/nondeleted; master excluded; private gate | Same existing set, now canonically verified; private gate and safe display retained | NC-01B visibility_boundary; NC-01C private_bracket_bypass/draft_saved_visibility |
| GET /bracket/<id> | Active/current row; owner can read own draft; other users require saved state | Reuse predicate for other-user visibility; own draft management remains allowed; no admin draft-read bypass | NC-01A cross_user_draft_boundary; NC-01B visibility_boundary |
| GET /leagues/<id>/members | Current saved/nondeleted member bracket links, safe has_bracket indicator | Reuse predicate before linking IDs; draft member remains visible only as has_bracket=false / bracket_id=null | NC-01C draft_saved_visibility |
| GET /brackets/me | Own-account draft/saved management metadata, no competitive score/rank | Unchanged; own draft access is legitimate | NC-01B current own-bracket lifecycle |
| _build_leaderboard_rows_for_current_season | Current score-to-bracket join used to create NEW historical snapshots; no submission check | Filter current eligible competitors before freezing a new snapshot; preserve snapshot scoring/order semantics | NC-01D snapshot_source/snapshot_tie; GAP-DRAFT-SCORES-001 |
| GET /leaderboard/history and /leaderboard/history/<season> | Stored structured finalized snapshot data | Unchanged: no live bracket join/current eligibility filter, including after live edits/deletions | NC-01D history reads/deleted; NC-01E rollover characterization |
| POST admin score recomputation | Existing entry selects is_done=true, nondeleted current brackets; internal scorer does not independently enforce submission | Inspected, unchanged; stale persisted scores may remain; runtime job remains refused in local harness | NC-01D recompute_source/upsert/job_refusal |

There is no independent league score/rank or participant-pick API. Existing competition
UI uses leaderboard rows, member links and champion-pick statistics. Operational
master results are distinct from ordinary competitor eligibility; scoring math and
master-result handling are not redesigned.

## Canonical predicate and submission model

`app.py:competitive_bracket_eligible` is the canonical serialization-boundary rule:

```text
is_done is True
AND deleted_at IS NULL
AND season_id equals the requested competition season (current by default)
```

The actual schema has no separate active flag. `is_done` is the existing authoritative
submission flag; `saved_at` is save/tie metadata, not an independent eligibility flag.
A retained timestamp cannot make is_done=false eligible. A legacy saved flag is not
newly rejected merely because its timestamp is absent. Normal explicit save writes
both is_done=true and saved_at; every accepted content-edit path clears both.
Existing query-side saved/deleted/season filters remain useful reductions, but all
live competitive serialization boundaries use the one predicate. Explicit past-season
live statistics pass their selected season. Historical snapshot reads never call it.

`invalidate_bracket_submission` extracts the exact existing winner/undo update:
`is_done=false`, `saved_at=null`. The two winner branches (including same-winner count
edits) and undo reuse it without changing graph operations, authorization or ordering.
The dedicated PATCH /bracket/match/<id>/games route now calls it after its existing
successful update. Invalid requests and all current ownership/season/error rules
are unchanged. No new game-count validation, deadline check or admin exception.

## Visibility, scores, ranks and resubmission

A stored score is not proof of current eligibility. The leaderboard validates the
associated live bracket first, filters stale draft/deleted/wrong-season entries,
and derives its score-based master selection only from eligible score rows. It does
not return a draft bracket ID, score, rank, per-match points or entry. Remaining
rows use the unchanged points/full_hits/saved_at comparator, with no new rank format.

Explicit public league leaderboard reads now require authentication and are scoped
to league member owners on the server. Private reads additionally retain mandatory
current membership, including owner/admin nonmembers. The global saved leaderboard
and general saved-bracket route remain legitimate global competition surfaces; they
do not enumerate private league relationships. Existing public member/stat endpoint
authorization is retained rather than broadening league member-list access.

Champion picks and least/most predicted matchup aggregates first restrict to eligible
bracket IDs. Their existing denominator is unchanged: only recorded Finals predictions
count toward total_brackets; no new score formula, denominator or pick math is added.
A draft member may still have an innocuous not-submitted indication but no draft link,
pick or competitive score. The NC-02A1 public-user serializer and privacy gates are reused.

Recomputation entry already skips drafts; it does not delete their previous score.
The internal scorer can calculate a draft if directly called internally, but is behind
the existing runtime job guard; it is not a user-facing score API. No score persistence
or job timing is changed. Edits do not delete stored scores, and explicit resave restores
eligibility. Existing stored values may be visible again until the existing admin-triggered recomputation
updates them, exactly as the prior winner-edit/resave workflow did. No claim of an
immediate automatic recomputation is made. Fixed stored scores in tests establish
visibility/state transitions, not newly calculated point correctness.

## Guarded acceptance and regression provenance

`scripts/nc02a2_acceptance_metadata.py` records eight explicit NC-01 transitions with
source finding IDs, canonical gaps and approved requirements. The games-only saved
bypass, mixed numeric-count submission aspect, draft score cases, existing winner
resave/undo behavior and league-scope findings are linked deliberately. Mixed numeric
range acceptance and deferred mutation/lock/scoring behavior are retained. NC-02A1's
public/global deferral assertion is explicitly adapted to now-approved P4/P5/P9 while
retaining its serialization/access checks. No historical report/JSON is overwritten.

The local harness adds only an explicit NC-02A2 scope: fixed fixture identities,
registered bracket/match/league IDs, required reads, login and content/save PATCHes.
It does not permit arbitrary routes, league lifecycle mutations or runtime jobs.
Three offline refusal tests protect these limits. Existing marker, enrollment,
checksum, startup, capability, thread, lease, egress, capture and job gates are intact.
A fixed scenario combines the existing synthetic graph/score/history generators;
no production data or new canonical fixture version is introduced.

Six live acceptance sequences verify winner, dedicated games-only and undo lifecycles
across global/public/private scopes; physically retained draft scores; post-lock
permissiveness with consistent invalidation and resave denial; and unchanged admin
mutation authorization with shared invalidation and no draft-read bypass. They check
all affected lists/details/stats/member links, retained score rows, unchanged histories
and league membership. Private anonymous/nonmember/admin requests remain denied.
Three offline acceptance cases cover predicate boundaries, saved-only NEW snapshot
construction with old history retained, and recompute selection/stale-row retention.

## Gap disposition and deliberate deferrals

| Canonical gap | NC-02A2 status | Evidence / boundary |
| --- | --- | --- |
| GAP-RESAVE-001 | FIXED | Dedicated game-count route now clears both submission fields; winner/undo model shared |
| GAP-DRAFT-SCORES-001 | FIXED | Global/public/private current competitive entries and score aggregates exclude unsaved brackets, even with stored scores |
| GAP-PRIVATE-SCORES-001 | FIXED within approved scope | NC-02A1 membership plus current saved eligibility and server-side league scoping; global generic saved competition remains allowed |
| GAP-PRIVATE-DETAIL-001 | DEFERRED / retained scope boundary | Prior prompt explicitly preserved separate general saved-detail visibility; no private relationship is exposed by that route |

No invented separate canonical gap ID for public/global drafts: those are surfaces
of the existing cataloged draft-score/private-score gaps. Prior NC-02A1 email,
admin-draft-read, private-list/member/stat and password-state fixes remain intact.
Unrelated known gaps remain: post-deadline edits, frontend/backend final lock, arbitrary
admin user-bracket mutation, ordinary-owner undo UI, champion/finalist bonuses,
snapshot tie ordering, standings provider/freeze, season-source mismatch and league
lifecycle/delete policy. For still-permitted post-lock edits the same invalidation
applies; ordinary resave after lock remains forbidden by the existing save route.

## Validation, cleanup and scope proof

The full fixed runner includes all NC-01 domain regressions, seven NC-02A1 privacy
acceptance cases and nine new NC-02A2 cases. Scoring and operations offline fixtures
now explicitly represent submitted competitors; no historical finding/assertion is
erased to make a test pass. Operations regressions are included because the new
snapshot builder depends on current eligibility. Full offline safety coverage also
includes three new scope-refusal tests. Results live only in NC-02A2 records.

```text
python -B scripts/run_competitive_eligibility_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations --competition-only
python -B scripts/run_competitive_eligibility_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
python -B scripts/validate_consolidated_baseline.py
```

AST preservation verifies unchanged score math/recompute entry, save/deadline logic,
historical reads/snapshot writer, rollover, private authorization, safe-user serializer,
auth and league lifecycle. Expanding the three shared invalidation calls produces
exactly the prior winner/undo AST; removing the new games-only invalidation call
produces exactly the prior games route AST. The only intentional existing function
changes are the nine inventoried eligibility/read/invalidation functions.

Canonical cleanup must restore SEEDED nc-fixtures-v1,
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`, stopped Flask,
released lease, cleared capture and disabled jobs, with semantic schema/marker proof.
Final results and timestamp are recorded in db/records/nc_02a2_competitive_eligibility.json.
Python syntax/Black/CRLF-aware whitespace and added-artifact secret/privacy scans
are required. No configured Python static type checker exists; frontend is unchanged.

Next candidate: **NC-02B — Bracket integrity business-requirements checkpoint**.
Not started. STOP after NC-02A2 review.

Final validation: all **171** full-suite tests passed (155 NC-01 domain regressions,
7 prior privacy acceptance cases and 9 new eligibility cases), with zero failures/errors.
The 9 new cases also passed in their initial focused run. The final strengthened undo
regression was rerun separately and passed after adding explicit save-before-undo and
both-field invalidation assertions; all prior graph assertions remain. Full offline
safety: **220 passed**, including 3 new scope refusal cases.

Final semantic schema/marker v2, canonical checksum, SEEDED nc-fixtures-v1, stopped
Flask, released advisory lease, cleared same-process capture and disabled jobs passed.
Historical NC-01 and NC-02A1 records/reports are byte-for-byte unchanged. Syntax,
scoped Black, CRLF-aware whitespace, credential/hash/privacy and AST scope checks passed.
Production contact/deployment/schema changes: none. Frontend remains unchanged.
