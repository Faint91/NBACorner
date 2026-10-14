# NC-01B — Bracket characterization / regression baseline

No application behavior was changed. This is a record of current behavior, not
remediation. Only explicitly approved requirements are used for classification.
A passing characterization test can document a KNOWN GAP.

## Scope, checkpoints and evidence

Frontend main `ce54143006f0409265937f5d548286d0b100d454`; backend main
`771a1bea72db85a7241fd703d87f55b899b5ef15`; both initially clean.
27 live local sequences + 10 static checks passed; 206 offline safety tests passed.
All live work used the existing GuardedHarness with explicit NC-01B scope, enrolled
local PostgreSQL/Supabase identity, marker v2, reserved synthetic users, safe capture
and provider fixtures, disabled jobs, production denylist, startup/admission/egress
checks and an exclusive lease. No production contact or browser automation.
Every live sequence reset before/after; original application, frontend, schema,
fixture builders, environment safety and earlier evidence remain unchanged.

## Approved requirements

1. Other users may see another user's bracket only if saved.
2. Emails must never be exposed in bracket responses.
3. Saved/submitted brackets may be edited before final lock.
4. Editing a saved bracket before lock requires saving/submitting again.
5. Ordinary owners may undo predictions before lock.
6. Playoff start blocks ordinary winner changes, undo, series counts and saving/resubmitting.
7. Playoff start must not be a universal block on unrelated actions.
8. Admins edit only the master, not arbitrary user brackets.
9. Admin creation may bypass the ordinary creation window.
10. Past-season bracket/history information may be public (permission, not a mandate).

## Bracket and related-route inventory

There is one creation route; admin creation auto-promotes it to master. There is no
separate master-creation, master-read, archive or anonymous bracket-display route.
Undo is an action on the prediction PATCH route, not a separate endpoint. Related
snapshot/rollover/scoring maintenance routes are inventoried statically only and
were not invoked. Their domain calculations remain deferred.

| Method | Path | Auth | Owner/admin enforcement | Read/write | Tables/functions | Frontend caller |
| --- | --- | --- | --- | --- | --- | --- |
| POST | /admin/leaderboard/snapshot | JWT | JWT admin plus DB admin; STATIC inventory only, not invoked | Write | users, leaderboard_history_snapshots, leaderboard_history_rows, bracket_scores (via snapshot helper) | AdminPage |
| POST | /admin/season/rollover | JWT | JWT admin plus DB admin; STATIC inventory only, not invoked | Write | users, seasons, brackets, standings; snapshot/history helpers (deferred) | AdminPage |
| POST | /admin/score/master/<master_bracket_id>/recompute | JWT | JWT admin; current master-ID lookup; STATIC inventory only, not invoked | Write | brackets, matches, bracket_scores (via score helpers; deferred) | No caller found |
| POST | /bracket/create | JWT | JWT subject; JWT admin bypasses date window | Write | brackets, matches, seasons, standings, teams | DashboardPage |
| PATCH | /bracket/<bracket_id>/save | JWT | Owner or DB admin; current/nondeleted; ordinary playoff lock | Write | brackets, matches, users | BracketPage |
| GET | /brackets/me | JWT | Own current/nondeleted | Read | brackets, users | DashboardPage; BracketPage; AccountPage |
| GET | /bracket/<bracket_id> | JWT | Own or DB admin or saved; current/nondeleted | Read | brackets, matches, seasons, teams, users | BracketPage |
| GET | /brackets | JWT | Authenticated; saved/current/nondeleted/nonmaster; optional league filter (deferred) | Read | brackets, league_members, leagues, users | DashboardPage |
| DELETE | /bracket/<bracket_id> | JWT | Owner or DB admin; current/nondeleted; no date lock | Write | bracket_scores, brackets, users | DashboardPage |
| PATCH | /bracket/<bracket_id>/match/<match_id> | JWT | Owner or JWT admin; current/nondeleted; no date lock | Write | brackets, matches | BracketPage (set_winner/undo) |
| PATCH | /bracket/match/<match_id>/games | JWT | Owner only; current/nondeleted; no date lock | Write | brackets, matches | No caller found; BracketPage counts use set_winner |
| GET | /leaderboard/history | JWT | JWT; snapshot read | Read | leaderboard_history_snapshots | PastSeasonsPage |
| GET | /leaderboard/history/<season_code> | JWT | JWT; snapshot read | Read | leaderboard_history_rows, leaderboard_history_snapshots | PastSeasonsPage |

## Implementation and represented state

Creation inserts a current-season bracket then 21 matches from canonical team
conferences/current standings seeds. Graph linking and promotion are separate
PostgREST writes, not an atomic Flask transaction. The per-season Flask duplicate
lookup is backed by both per-season and global active-user unique indexes.

There is no lifecycle enum. Incomplete/draft is represented by `is_done=false` and
normally `saved_at=NULL`; submitted is `is_done=true` with saved_at/name. Editing
through set_winner/undo resets those two submission fields. Games-only does not.
The synthetic saved scenario is a deliberately partial stored-state fixture; genuine
full-submit sequences fill all 21 matches through the API before saving.
`is_master` and/or `seasons.master_bracket_id` derive master display status.
Deletion uses deleted_at/deleted_by_user_id; it retains matches and hides the row
from current reads. Historical means season differs from current; locked is a
comparison against current season timing, not a stored bracket state.

Predictions/counts live on matches. Round 0 has three play-ins per conference;
round 1 four series; round 2 two; round 3 one; round 4 the single NBA Finals.
Edges per conference: 1->3a, 2->5b, 3->4b, 4->9a, 5->8b, 6->8a,
7->9b, 8->10b, 9->10a; east/west 10->Finals a/b. The creation code's
2->3 link is overwritten by 2->5; special action logic feeds its loser to 3b.
Existing graph nodes are updated, not created by prediction changes.
Changing winner clears immediate child prediction/count and cleans propagated old
teams deeper only if a later-round prediction exists. Undo uses similar cleanup,
including the 7–8 loser branch. Same winner with new count changes count and still
unsaves. Play-in counts are forced to one. Team locked flags are stored but are not
an authorization/readiness check in the mutation handler.

## Enforcement, schema and timing

Flask JWT/owner/admin checks enforce API boundaries. Reads/save/delete recheck DB
admin status; prediction PATCH trusts the JWT admin claim. Games-only requires
ownership and provides no admin bypass. Frontend edit checks are separate and do
not replace server enforcement. No test helper supplies product authorization or
propagation: helpers only install existing synthetic scenarios and season dates.

The match-season trigger copies bracket season on insert/bracket-ID change. Master
soft-delete trigger demotes is_master and clears the season pointer. Season->master
and bracket->season foreign keys are cyclic. Both master unique indexes exist;
one excludes deleted rows and one does not. The ordinary soft-delete trigger avoids
that conflict by demoting the master. Matches have team/bracket/next-match/season
foreign keys and next-slot a/b check, but no game-count range check.
Dormant `atomic_update_match`, `set_winner_atomic`, `undo_prediction_atomic` and
`set_master_bracket` SQL helpers include transactional/row-locking behavior; current
Flask bracket routes do not invoke them. Existing contained RPC privileges unchanged.

DB season dates resolve startup UTC globals with environment fallback; missing
regular-season end skips the early-side check, missing playoff start defaults 2099.
Current-season ID gates reads/writes. Final lock compares now>=playoff start;
creation uses regular-season end<=now<playoff start. Exact equality/default behavior
is STATIC; live early/open/locked dates are installed in the local DB then resolved
through the existing helper. No application clock or production refactor.
Only ordinary create/save are date-gated; prediction, undo, games-only, deletion and
reads are not. No shared before-request playoff guard exists; an unrelated identity
read still succeeds after lock. No league operations were invoked to extend this check.
Deletion's content-versus-unrelated classification is not approved and remains open.

## Visibility, history and frontend

Current details permit owner/admin drafts and other users' saved brackets. List
returns only saved/current/nondeleted/nonmaster rows. Owner email appears in both
saved detail and list responses: **Previously established in NC-01A1**; listing is
additional coverage of the same no-email-exposure issue. The email finding is one
matrix row, not separate new issues for each endpoint. Detail owner object contains
id/username/email; no password/reset/admin fields. The bracket payload carries DB
IDs/season/saved/deleted fields and derived ownership/master flags; matches carry
DB graph/lock fields and team display metadata. No raw values are recorded here.
Own bracket summary uses id/username without email.

Historical saved details return 404 even for owner/admin due to current-season
filter. Historical draft exclusion follows the same guard (STATIC, not a separate
live draft fixture). PastSeasonsPage uses snapshot/history rows, not historical raw
bracket display. Anonymous history calls require JWT. Public past history is allowed
by the approved rule but not mandated, so this is not automatically a gap. Scores,
snapshot calculations and rollover execution are out of scope.

STATIC frontend: /bracket/:bracketId loads details; Dashboard creates/deletes and
lists own/saved brackets; PastSeasonsPage reads history snapshots. Owners or
admin+master can edit; undo handler and rendered undo controls require admin+master,
blocking the approved ordinary-owner undo feature. Winner/game controls lack final
lock gating while save uses savingLockedForUser. UI limits series options to 4–7,
forces play-in one, stores pending counts locally before a winner, optimistically
updates then reloads backend state. Admin creation's actual expression bypasses
window restrictions despite a stale comment. No browser claims or frontend changes.

## Completion / gap matrix

Counts are matrix-row counts, not distinct requirement counts. Backend and frontend
lock manifestations have separate coverage; the previously established email issue
is cross-referenced. Every KNOWN GAP below names its approved requirement.

Classification totals: MATCHES REQUIREMENT=7; KNOWN GAP=7; REQUIREMENT NOT YET REVIEWED=23; UNCLEAR / NEEDS BUSINESS CHECKPOINT=0. Total=37.

### creation

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| creation_payload | Create ignores request fields/non-object body; authenticated open-window request still creates draft. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve ignored creation payload behavior? |
| creation_windows | Ordinary creation rejected before regular-season end and after playoff start; unauthenticated creation rejected. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve normal creation window and missing-date policies? |
| ordinary_creation | Open-window ordinary creation produces 21 current-season matches, draft state and active-user duplicate rejection. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve initial graph and duplicate response contract? |

### state/lifecycle

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| state_model | is_done/saved_at encode submission; deleted_at/deleted_by encode soft deletion; is_master plus season pointer derive master. Historical/locked are contextual, not enum states. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve formal state transitions and derived-master precedence? |

### predictions

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| prediction_validation | Valid winner advances to existing child; play-in games forced to one; unsupported actions/invalid winner fail; one-sided not-ready match can accept its populated team. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve readiness, action and winner-input contract? |

### undo

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| owner_undo | Owner undo succeeds before lock; repeated/no-prior undo succeeds and clears prediction/count. | Ordinary bracket owners may undo predictions before lock. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |

### game counts

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| game_count_values | Games-only accepts negative/zero/large counts, requires field, leaves saved state unchanged; absent set-winner count persists NULL outside play-in. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve range/required count and games-only unsave semantics? |

### save/resubmit

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| games_only_saved_edit | Games-only edits to a saved bracket do not clear is_done/saved_at, bypassing required resubmission state. | A saved/submitted bracket may be edited before final lock; editing requires saving/submitting again. | KNOWN GAP | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| partial_graph_save | Partial graph with ready but unpredicted pairs is rejected at save; missing-pair skip is separately static evidence. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve what completion means for unpopulated downstream matches? |
| save_edit_resubmit | Complete bracket saves repeatedly; pre-lock winner/count edits through set_winner clear is_done/saved_at and require explicit resave. | A saved/submitted bracket may be edited before final lock; editing requires saving/submitting again. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| save_completeness_static | Save requires name and predictions/counts only for matches with both teams; empty or missing-pair matches skipped. No exact 21-match completion requirement. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve completion validation for absent/unpopulated matches? |

### visibility/privacy

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| admin_draft_visibility | Admin can read another ordinary user's unsaved draft. | Other users may see another user's bracket only if it is saved. | KNOWN GAP | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| email_serialization | Saved bracket detail/list expose owner email; same issue previously established in NC-01A1, now confirmed for listing too. Previously established in NC-01A1. | Emails must never be exposed in bracket responses. | KNOWN GAP | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| visibility_boundary | Ordinary other-user draft detail is denied; saved detail is readable; anonymous detail/list denied; owners can read draft/saved. | Other users may see another user's bracket only if it is saved. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |

### cross-user authorization

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| nonowner_mutations | Other ordinary user cannot predict, undo, change games, save or delete an owner's current bracket. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve non-owner mutation policy for all routes? |

### admin/master behavior

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| admin_arbitrary_mutations | Admin predicts, undoes, saves and deletes another ordinary user's bracket; games-only route still requires owner. | Admins should edit only the master bracket, not arbitrary user brackets. | KNOWN GAP | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| admin_creation_bypass | Admin creation bypasses early/locked windows and promotes new bracket with season master linkage. | Admin bracket creation may bypass the normal creation window. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| master_mutations | Admin-owned master supports prediction, undo, games-only and save after playoff start. | Admins should edit only the master bracket, not arbitrary user brackets. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| master_replacement | New admin creation demotes existing other-owner master, updates pointer; ordinary payload cannot request master status. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve automatic master replacement policy? |

### playoff lock

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| postlock_content | Ordinary predictions, undo and both series-count paths still mutate after playoff lock. | At playoff start ordinary users may not select/change winners, undo, change series counts or save/resubmit. | KNOWN GAP | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |
| postlock_save | Ordinary save/resubmit rejected after playoff start even when complete. | At playoff start ordinary users may not select/change winners, undo, change series counts or save/resubmit. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset before/after sequence | None required for classification |

### deletion

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| delete_recreate | Owner can soft-delete draft/saved after lock; matches retained, detail hidden and same-season recreation possible in open window. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Is deletion content-changing or unrelated? Approve deletion/recreation/history retention policy? |
| master_delete | Master soft-delete demotes flag and clears season pointer; admin can recreate master afterward. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve master deletion/replacement lifecycle? |

### match propagation

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| undo_graph | Undo with downstream selections clears advanced slots/predictions/counts; 7-8 play-in winner/loser feeds two branches. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve play-in loser branches and deep undo clearing semantics? |
| winner_change_graph | Full graph progresses through 21 matches to Finals; changing earlier winner clears propagated old team and downstream picks/counts. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve exact downstream clearing rules? |

### historical brackets

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| historical_boundaries | Historical saved/draft detail returns 404 even to owner/admin due current-season filter; historical writes rejected; history routes require auth and read snapshots. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Should public historical visibility be implemented? Requirement permits public history but does not mandate anonymous routes. |
| history_source | No archive/public bracket-display endpoint; current bracket routes filter current season; PastSeasonsPage reads leaderboard snapshot routes, not raw historical brackets. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve public history and historical bracket access scope? |

### frontend behavior

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| frontend_controls | Frontend allows owner editing and admin-master editing; game options are 4–7, play-in one; pending games local until winner; edits reload backend state. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve UI count range, optimistic state and admin-owner overlap? |
| frontend_creation | Dashboard uses brackets/me and saved list, creates/deletes via backend; actual createDisabled lets admins bypass creation timing despite stale comment. | Admin bracket creation may bypass the normal creation window. | MATCHES REQUIREMENT | STATIC source inspection; no browser/runtime claim | None required for classification |
| frontend_lock | Winner and game controls check ownership/admin-master and readiness, but not playoff lock; save alone checks savingLockedForUser. | At playoff start ordinary users may not select/change winners, undo, change series counts or save/resubmit. | KNOWN GAP | STATIC source inspection; no browser/runtime claim | None required for classification |
| frontend_undo | Ordinary owner undo is suppressed by admin+master-only UI handler, although backend accepts pre-lock owner undo. | Ordinary bracket owners may undo predictions before lock. | KNOWN GAP | STATIC source inspection; no browser/runtime claim | None required for classification |

### schema/timing quirks

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| historical_creation_constraint | Historical active bracket blocks new current-season creation through global user uniqueness despite per-season Flask lookup. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve cross-season active-bracket policy? PRESERVED CURRENT BEHAVIOR / CHARACTERIZATION LIMITATION. |
| schema_constraints | Two active-user unique indexes include a global user predicate; two master indexes differ on deleted_at; season/master foreign keys form cyclic linkage. No fixes. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve cross-season uniqueness and soft-deleted master constraints? |
| timing | DB season timestamps resolve UTC globals at startup; env fallbacks, missing lock defaults 2099; lock is now>=start, creation requires end<=now<start. No shared blanket request lock. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve date defaults, refresh and timezone contract? |
| triggers_rpc | Match season IDs copied from bracket by trigger; soft-delete trigger demotes master and clears pointer. Flask graph updates are individual requests, not atomic RPC calls. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source inspection; no browser/runtime claim | Approve partial-write/transaction contract and trigger behavior? |

### edge/errors

| Scenario/test | Current observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| edge_errors | Invalid IDs/actions/fields return 400, missing IDs 404, non-object save/prediction/game payloads 500, missing auth 401. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve edge-error status and payload contract? |
| wrong_bracket_deleted | Match from another bracket returns 400; deleted bracket predictions/games denied; drafts omitted from saved listing. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset before/after sequence | Approve error precedence and deleted-record visibility? |

## Limitations and later checkpoint questions

Global active-user uniqueness prevents a same-owner current+historical active pair:
**PRESERVED CURRENT BEHAVIOR / CHARACTERIZATION LIMITATION**. Fixture/schema constraints
were not relaxed. Live historical coverage uses the existing saved historical builder;
draft season rejection is static. Master omission from list is static. API representative
bad inputs include non-object JSON, missing fields and invalid IDs/actions/teams;
raw malformed JSON syntax, exhaustive fuzzing/rate loads and failure injection were
not run. Partial-save acceptance with missing graph rows is static, not proven live;
ready-but-unpredicted pairs were live rejected. Score cleanup on delete is static.

Later questions: completion with missing/unpopulated matches; exact series count
range and requirement; creation window/missing-date policy; cross-season uniqueness;
master replacement/deletion and derived flags; delete-after-lock semantics; graph
clearing/readiness/partial writes; historical/anonymous display scope; error status
contract and optimistic UI state. Known-gap requirements are already approved and
are not reopened for inference or repaired in this phase.

## Running, safety and canonical cleanup

```text
python -B scripts/run_bracket_characterization.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
```

The fixed runner loads only the NC-01B live/static classes. No arbitrary selector or
global mutation bypass. Default and NC-01A scopes stay narrow; NC-01B denies auth
registration/reset, league writes, jobs, maintenance and arbitrary/query paths.
Scenario helpers require active lease, ready context, owner thread and explicit scope.
Only existing fixture builders and enrolled synthetic subjects are used.
Logs/evidence contain route/status/shape and safe facts, no raw bodies, emails,
passwords, tokens, secrets or provider values. Exceptions are sanitized.

27 live sequences, 10 static checks and 206 offline safety checks passed. Schema
semantic and marker ACL verifiers passed. Every context shut down Flask, cleared
capture, released lease and reset canonical nc-fixtures-v1 checksum:
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Independent final readiness/checksum passed and localhost connection was refused.
Final state: SEEDED, 4 users, 2 seasons, 30 teams, 30 fictional standings, all other
application tables empty; jobs disabled and unscoped mutation permission false.
An initial independent probe used an invalid relative config and was refused;
its corrected absolute-path check passed. Windows needed a longer refusal timeout.
Neither probe made a mutation or contacted production.

No business behavior changed. No production contact, production mutation, production
secret use, deployment or browser test. Next candidate: **NC-01C — League
characterization baseline**. Not started; no remediation performed.
