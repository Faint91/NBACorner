# NC-02B1 — Bracket final-lock and authorization integrity

## Scope, checkpoints and source evidence

Approved B1/B2/B3/B4 preservation/B5/B16 only. Starting backend `main`
`17e5a20a66d5de5e2f6511f512ccdc987ab202a9`; frontend `main`
`ce54143006f0409265937f5d548286d0b100d454`; both initially clean.
No production contact or deployment. No schema or NC-ENV baseline changes.
NC-01 consolidated/domain evidence and NC-02A1/NC-02A2 records remain immutable.

NC-01B provenance is retained in the existing test names. Separate
`scripts/nc02b1_acceptance_metadata.py` records the old metadata and approved
transition. Two NC-02A2 tests formerly preserved deferred post-lock/admin gaps;
those now assert denied writes while preserving submitted state and scores.
The other NC-02A2 edit/resubmit lifecycles remain unchanged.

## Mutation inventory and behavior

All routes retain authentication, active-record and current-season checks.

| Entry point | Before | NC-02B1 behavior | Submission handling |
| --- | --- | --- | --- |
| POST /bracket/create (`create_bracket_for_user`, conference graph builder) | Ordinary creation after regular end and before playoff start; admin bypass with automatic master promotion/replacement | Hard final lock checked before opening rule; existing admin master creation bypass and graph/lifecycle preserved | Creates draft; no automatic submission |
| PATCH /bracket/<id>/match/<match_id>, action=set_winner (`update_match`) | Owner or arbitrary admin; no deadline guard | Shared owner/master content guard before any writes, including same-winner/count branch | Accepted edit still clears is_done and saved_at |
| Same combined route, action=undo | Owner or arbitrary admin; no deadline guard | Same shared guard; owner allowed before deadline; admin limited to master | Existing downstream clearing unchanged; accepted undo clears submission |
| PATCH /bracket/match/<match_id>/games (`set_match_games`) | Owner only; no deadline guard | Same shared guard; ordinary owner before lock, admin master after lock even if differently owned | NC-02A2 invalidation preserved |
| PATCH /bracket/<id>/save (`save_bracket`) | Owner or arbitrary admin; admins bypass lock | Same shared guard; admin only on master | Existing completeness validation and explicit is_done=true/saved_at persistence preserved |
| DELETE /bracket/<id> | Owner or admin, including post-lock ordinary deletion | Unchanged; intentionally does not use content guard | Existing soft deletion/score cleanup preserved; B10/B11 deferred |
| Admin master creation/replacement | Existing creation endpoint promotes new master and silently demotes/repoints old one | Unchanged; no new mutation endpoint | B13/B14 deferred |
| Admin score/snapshot/rollover operations | Existing operation-specific authorization and job guards | Unchanged; no global playoff guard | Not prediction mutation entry points; no execution added |

`update_match` keeps its existing match cache, `get_match`,
`cleanup_future_matches`, `flush_touched_matches`, winner/loser propagation and
individual-write behavior. `invalidate_bracket_submission` is reused unchanged.
There is no additional admin prediction API. Database RPC permissions/bodies are
unchanged and the Flask routes do not switch to RPC implementations.

## Central policy and error contract

`app.py:bracket_content_mutation_error` checks the authenticated account's current
DB admin role. For ordinary content, only a nonadmin owner of a non-master bracket
may write, and only before `playoffs_locked()` becomes true. An admin cannot edit
an ordinary bracket even if they own it. Nonadmins cannot edit a master they own.

Master identity reuses existing current-season `is_master` OR the current season's
`master_bracket_id` pointer semantics. Every caller first checks active/current
parent bracket. Admin master content remains editable after deadline, including
when the master is owned by a different account. Master lifecycle is not redesigned.

`playoffs_locked()` remains `now_utc() >= PLAYOFFS_START_UTC`, populated by the
existing season configuration resolver. No environment variable, independent date
source or global middleware was introduced. Creation retains the existing
regular-season opening check and checks the hard lock first.

Locked ordinary requests with valid route/payload return consistently:
HTTP 403, `{"error":"Bracket content is locked once the playoffs start."}`.
Unauthorized content returns HTTP 403 with the existing descriptive unauthorized
error shape. Existing malformed-input, missing-record and wrong-season checks
retain their precedence; no unrelated error-contract redesign.

## Frontend alignment

`frontend/src/lib/bracketAccess.ts` shares owner/admin/master rules between the
controls and handlers. Ordinary controls fail closed until server flags load.
`useBracketDeadline` observes the existing server `playoffs_deadline_utc`, so an
open tab locks when it crosses that deadline; the backend remains authoritative.
It uses a local 250ms subscription with cleanup and no new HTTP endpoint.

`BracketPage.tsx` gates winner selection, games, name/save and undo with the shared
policy. Ordinary owners now see Undo for existing picks before deadline. All three
bracket sections use that rule, and master-admin undo remains available. After
lock the owner sees a locked save control and a frozen-submission/draft message.
An unsaved draft is explicitly described as frozen and competitively ineligible.

`DashboardPage.tsx` uses the same deadline for ordinary creation, refuses handler
entry when disabled, preserves the admin master creation window bypass, and
prioritizes final-lock messaging over the opening-window message. Delete controls,
league/account/navigation/analytics behavior and all other frontend pages remain
unchanged.

## Drafts and B4 preservation

A draft at deadline is not submitted or deleted. Owner reads continue to work;
prediction, undo, count and save are denied without writes, leaving it ineligible.
A submitted bracket denied a post-lock edit stays submitted: refusals must not
invalidate it. Existing stored score/history/membership rows are preserved.

Before lock the three unchanged NC-02A2 winner/count/undo acceptance lifecycles
prove saved -> edit -> unsaved/ineligible on all competitive surfaces -> explicit
resave when complete -> eligible. Graph/count/completeness rules are not tightened.

## Acceptance and provenance

Eight new guarded live cases in `tests/characterization/bracket_lock.py` cover:

- ordinary winner/undo/count/save one microsecond before the configured deadline;
- a picked but incomplete draft at and one microsecond after deadline;
- a saved bracket at deadline, preserving its saved flag/timestamp and contents;
- hard creation lock even with a simulated opening predicate returning true;
- nonowner and admin rejection on ordinary brackets;
- admin rejection on an admin-owned ordinary bracket;
- nonadmin master-owner rejection and a differently owned master's admin
  winner/undo/count/save after deadline.

Boundary controls patch only `now_utc` in the existing guarded test context,
using the configured fixture season deadline. They require the existing local
lease and explicit NC-02B1 scope and unwind on exit. Production clock architecture
is unchanged. Existing creation-window/admin-bypass/master-lifecycle/deletion and
B4 tests remain in the fixed regression suite.

Converted NC-01B cases: `admin_arbitrary_mutations`, `postlock_content`,
`frontend_undo`, `frontend_lock`, `frontend_controls`, `frontend_creation`, `timing`.
Test metadata links the original NC-01B finding IDs; original reports are retained.
Static checks continue to preserve deferred schema, count, graph and historical
contracts. Four Node policy tests exercise all role/lock/readiness combinations,
exact deadline equality, creation lock/window and existing/pending bracket behavior.
Three offline cases verify the new harness route allowlist and boundary refusals.

## Gap status

| Canonical gap | Result |
| --- | --- |
| GAP-LOCK-BACKEND-001 | FIXED for ordinary bracket content and creation |
| GAP-LOCK-FRONTEND-001 | FIXED; frontend supplements server enforcement |
| GAP-UNDO-FRONTEND-001 | FIXED; ordinary pre-lock owner undo enabled |
| GAP-ADMIN-MUTATE-001 | FIXED for bracket-content mutation; deletion aspect deferred |
| GAP-RESAVE-001 | PRESERVED / ALREADY FIXED by NC-02A2 |

## Explicit deferrals and impact

B6 completeness, B7 series count/play-in validation, B8 both-participant validation,
B9 exact downstream clearing, B10/B11 deletion, B12 uniqueness, B13/B14 master
replacement/deletion and B15 historical access remain deferred. Existing master
replacement/deletion and ordinary post-lock deletion behavior is not claimed fixed.
Scoring bonuses, standings, historical policies, league lifecycle and account
behavior are not changed. There is no schema migration.

Only intentional product changes are final content/creation lock, ordinary-admin
content denial, preserved admin master maintenance, pre-lock owner Undo in the UI,
and frozen unsaved drafts. Production was not contacted or modified.

## Validation and canonical cleanup

See `db/records/nc_02b1_lock_validation.json`, `nc_02b1_validation.json` and
`nc_02b1_bracket_lock_authorization.json` for results and final cleanup proof.
The fixed runner is `python -B scripts/run_bracket_lock_acceptance.py --config
<absolute ignored local test config> --allow-local-mutations` (add `--lock-only`
for the eight focused cases). It retains enrollment/identity/lease/capability,
loopback egress, reset-before/after and disabled-job guards.

The initial relative-config attempt was refused before any live test mutation;
rerunning with the required absolute ignored config passed focused acceptance.
Full frontend lint retains pre-existing errors; in-memory comparison with the
starting commit found no added lint findings. No unrelated lint cleanup is included.
The existing Vite build emits browser-data-age and bundle-size warnings.

Final results: **179/179** full relevant backend tests passed (including eight new
live cases, all seven NC-02A1 privacy tests, six NC-02A2 live lifecycles and three
NC-02A2 offline checks); **223/223** offline safety tests; **4/4** frontend Node
policy tests. The focused eight-case suite also passed independently. TypeScript
and the Vite production build passed. Syntax, Black for touched Python test/tooling
and new helpers, Git whitespace, secret/privacy scans, and the immutable historical
baseline validator passed. Full lint retains 95 existing errors and three warnings;
changed pages introduce none, and both new frontend files lint cleanly.

Semantic schema and fixture-marker-v2 verifiers passed. Final fixture state is
SEEDED / nc-fixtures-v1, checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
An explicit read-only pg_locks check confirmed fixture lease release. Flask is
stopped, capture is empty, guarded app import is removed and jobs remain disabled.
No production contact, code deployment or schema changes occurred.
Recommended single next phase: **NC-02B2 — Bracket validity and propagation**.
It has not been started.
