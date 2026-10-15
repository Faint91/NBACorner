# NC-01 — Consolidated characterization / regression baseline

## Executive summary and completion meaning

**NC-01 CHARACTERIZATION / REGRESSION BASELINE COMPLETE**

155 findings retained with original phase/identifier, observed behavior, source report,
JSON pointer, original/effective classification, evidence level and real test reference.
This means characterization is complete; product requirement compliance is not complete.
No fixes, refactoring, new business requirements, broad live exploration or production
contact. Backend started clean on main at 64fd5b778295514df626bc4a3c0d66987eb0a854;
frontend main ce54143006f0409265937f5d548286d0b100d454 remains unchanged.
Machine-readable authority: [nc_01_consolidated.json](../../db/records/nc_01_consolidated.json).

## Source manifest

Checkpoint totals below are immutable committed phase totals; audited totals include
four explicit NC-01F corrections. Manifest JSON also records source digests, fixed
runners, test paths and LIVE/OFFLINE/STATIC counts. NC-01A1 is the final auth classification
checkpoint; original NC-01A implementation commit a0d5d35239f87bfef47510ae4194ba7c3d84fb53.

| Phase | Report | Evidence | Checkpoint commit | Audited M/G/U/X |
| --- | --- | --- | --- | --- |
| NC-01A/A1 | docs/characterization/auth-access-baseline.md | db/records/nc_01a_auth_access.json | 771a1bea72db85a7241fd703d87f55b899b5ef15 | 0/3/30/0 |
| NC-01B | docs/characterization/bracket-baseline.md | db/records/nc_01b_bracket.json | d7041e76416387bf14e9960532e75e0d8fc599ce | 7/8/22/0 |
| NC-01C | docs/characterization/league-baseline.md | db/records/nc_01c_league.json | d2ec3cba6601a4dafaf56c8be6db4c44b1964a54 | 2/8/25/0 |
| NC-01D | docs/characterization/scoring-leaderboard-history-baseline.md | db/records/nc_01d_scoring_history.json | 957ec94a3849c055c9088ff4bb04cde3addfa5da | 2/5/18/0 |
| NC-01E | docs/characterization/standings-admin-rollover-baseline.md | db/records/nc_01e_operations.json | 64fd5b778295514df626bc4a3c0d66987eb0a854 | 6/4/14/1 |

## Raw totals and explicit classification audit

Original corrected phase checkpoints: **17 MATCHES, 24 GAPS, 113 UNREVIEWED, 1 UNCLEAR**.
After NC-01F audit: **17 MATCHES, 28 GAPS, 109 UNREVIEWED, 1 UNCLEAR**. Total **155**.
Raw 28 gap findings map to **19 canonical underlying gaps**, not 28 unique defects.
Observed behavior, HTTP/fact evidence and prior test results are unchanged.

Every matching/gap row has an explicit approved rule. Every unreviewed row has an audit
disposition; mixed findings retain unapproved parts, with partial approved aspects
linked separately. No inference that missing functionality or awkward code is a defect.
Four corrections, each from REQUIREMENT NOT YET REVIEWED to KNOWN GAP:

- **NC-01A:current_behavior__auth__cross_user_draft_boundary**: Ordinary draft denial matches the rule, but admin access to another user draft violates it. Confirmed by the existing NC-01A live case and NC-01B admin_draft_visibility; no admin exception was approved.
- **NC-01A:current_behavior__auth__display_fields_static**: Static serialization finding is now corroborated by existing NC-01B email_serialization and NC-01C member_email. Runtime league exposure is no longer pending; other non-email fields remain unreviewed.
- **NC-01B:current_behavior__bracket__game_count_values**: Numeric range/NULL policy remains unreviewed, but leaving saved state unchanged after games-only edit violates resubmission. Same issue as games_only_saved_edit.
- **NC-01C:current_behavior__league__frontend_leaderboard**: Client-side filtering follows an unrestricted global download; existing leaderboard_private_surface and NC-01D league_surface confirm private data exposure. Other score/rank presentation details remain unreviewed.

Source JSON and source report matrix/counts were corrected together. Earlier audit
history remains clearly chronological. Test decorators can predate curated classification
corrections: consolidated regression metadata supplies the authoritative requirement/gap
relationship; rerunning a raw domain evidence generator must not erase accepted audits.
No behavior needed retesting to resolve these existing cross-referenced observations.

## Approved requirement catalog and coverage matrix

19 stable normalized IDs. The email rule is shared across auth/bracket/league surfaces;
lock includes winner/prediction, undo, series-count and save/resubmit restrictions.
Permission for public past history does not mandate anonymous access. Scope/limits and
all matching/gap/partial source IDs are retained in JSON, not reduced to one passing test.

| Requirement | Approved rule | Current observed assessment |
| --- | --- | --- |
| REQ-PRIVACY-EMAIL-001 | Email addresses must never be exposed. | PARTIAL / HAS KNOWN GAPS |
| REQ-BRACKET-SAVED-001 | Other users may see another user's bracket only if saved. | PARTIAL / HAS KNOWN GAPS |
| REQ-BRACKET-EDIT-001 | Saved/submitted brackets may be edited before final lock. | FULLY MATCHES OBSERVED |
| REQ-BRACKET-RESAVE-001 | Editing a previously saved bracket before lock requires saving/submitting again. | PARTIAL / HAS KNOWN GAPS |
| REQ-BRACKET-UNDO-001 | Ordinary bracket owners may undo before lock. | PARTIAL / HAS KNOWN GAPS |
| REQ-BRACKET-LOCK-001 | At playoff start ordinary users may not change winners/predictions, undo, series counts or save/resubmit. | PARTIAL / HAS KNOWN GAPS |
| REQ-OPERATIONS-LOCK-001 | Playoff start is not a universal block on unrelated actions. | FULLY MATCHES OBSERVED |
| REQ-BRACKET-ADMIN-001 | Admins should edit only the master bracket, not arbitrary user brackets. | PARTIAL / HAS KNOWN GAPS |
| REQ-BRACKET-CREATE-001 | Admin bracket creation may bypass the ordinary creation window. | FULLY MATCHES OBSERVED |
| REQ-HISTORY-PUBLIC-001 | Past-season history may be public. | INSUFFICIENT CHARACTERIZATION |
| REQ-LEAGUE-PRIVATE-001 | Private-league bracket information requires membership. | PARTIAL / HAS KNOWN GAPS |
| REQ-SCORING-CHAMPION-001 | Correct NBA champion bonus is +3 points. | NO MATCH / KNOWN GAP |
| REQ-SCORING-FINALISTS-001 | Correctly predicting both NBA Finals participants awards +1 point. | NO MATCH / KNOWN GAP |
| REQ-LEADERBOARD-TIE-001 | Exact leaderboard ties use earlier bracket saved_at. | PARTIAL / HAS KNOWN GAPS |
| REQ-STANDINGS-SOURCE-001 | ESPN is the authoritative standings source. | PARTIAL / HAS KNOWN GAPS |
| REQ-STANDINGS-DAILY-001 | Standings refresh daily during the regular season. | FULLY MATCHES OBSERVED |
| REQ-STANDINGS-FREEZE-001 | Standings freeze when regular season ends / bracket creation opens. | NO MATCH / KNOWN GAP |
| REQ-SEASON-SOURCE-001 | Future season selection derives from canonical application season configuration, not conflicting independent environment variables. | NO MATCH / KNOWN GAP |
| REQ-ROLLOVER-SNAPSHOT-001 | Active match rows may be deleted after the historical snapshot has been successfully saved. | INSUFFICIENT CHARACTERIZATION |

Coverage summary: **4 FULLY MATCHES OBSERVED**, **9 PARTIAL / HAS KNOWN GAPS**,
**4 NO MATCH / KNOWN GAP**, **2 INSUFFICIENT CHARACTERIZATION**. “Fully” is confined
to the observed coverage, not all possible surfaces or production execution. Public
history permission and legacy-only snapshot success remain insufficiently resolved.
Static UI is not browser evidence; offline jobs are not successful live maintenance.

## Canonical known-gap registry

| Gap ID | Title | Requirement | Primary owner | Impact / severity |
| --- | --- | --- | --- | --- |
| GAP-EMAIL-001 | Email serialization leaks | REQ-PRIVACY-EMAIL-001 | CROSS-CUTTING PRIVACY / SERIALIZATION | PRIVACY / AUTHORIZATION / High |
| GAP-ADMIN-DRAFT-001 | Admin reads other-user drafts | REQ-BRACKET-SAVED-001 | BRACKET | PRIVACY / AUTHORIZATION / High |
| GAP-ADMIN-MUTATE-001 | Admin mutates arbitrary user brackets | REQ-BRACKET-ADMIN-001 | BRACKET | COMPETITION INTEGRITY / High |
| GAP-RESAVE-001 | Games-only edit retains submission | REQ-BRACKET-RESAVE-001 | BRACKET | COMPETITION INTEGRITY / High |
| GAP-LOCK-BACKEND-001 | Backend permits post-lock content edits | REQ-BRACKET-LOCK-001 | BRACKET | COMPETITION INTEGRITY / High |
| GAP-LOCK-FRONTEND-001 | Frontend lacks content lock gates | REQ-BRACKET-LOCK-001 | BRACKET | UX / FRONTEND ENFORCEMENT / Medium |
| GAP-UNDO-FRONTEND-001 | Ordinary owner undo unavailable in UI | REQ-BRACKET-UNDO-001 | BRACKET | UX / FRONTEND ENFORCEMENT / Medium |
| GAP-PRIVATE-LIST-001 | Private league bracket-list gate absent | REQ-LEAGUE-PRIVATE-001 | LEAGUE | PRIVACY / AUTHORIZATION / High |
| GAP-PRIVATE-DETAIL-001 | Private member saved-detail gate absent | REQ-LEAGUE-PRIVATE-001 | LEAGUE | PRIVACY / AUTHORIZATION / High |
| GAP-PRIVATE-MEMBERS-001 | Nonmember owner/admin member-data exceptions | REQ-LEAGUE-PRIVATE-001 | LEAGUE | PRIVACY / AUTHORIZATION / High |
| GAP-PRIVATE-STATS-001 | Nonmember admin reads private stats | REQ-LEAGUE-PRIVATE-001 | LEAGUE | PRIVACY / AUTHORIZATION / High |
| GAP-PRIVATE-SCORES-001 | Unrestricted global score download | REQ-LEAGUE-PRIVATE-001 | SCORING / HISTORY | PRIVACY / AUTHORIZATION / High |
| GAP-DRAFT-SCORES-001 | Leaderboard exposes stored draft scores | REQ-BRACKET-SAVED-001 | SCORING / HISTORY | PRIVACY / AUTHORIZATION / High |
| GAP-CHAMPION-001 | Champion bonus missing | REQ-SCORING-CHAMPION-001 | SCORING / HISTORY | DATA CORRECTNESS / Medium |
| GAP-FINALISTS-001 | Both-finalists bonus missing | REQ-SCORING-FINALISTS-001 | SCORING / HISTORY | DATA CORRECTNESS / Medium |
| GAP-SNAPSHOT-TIE-001 | Snapshot ignores saved-time ties | REQ-LEADERBOARD-TIE-001 | SCORING / HISTORY | COMPETITION INTEGRITY / Medium |
| GAP-STANDINGS-PROVIDER-001 | Active refresh provider mismatch | REQ-STANDINGS-SOURCE-001 | STANDINGS / SEASON / ROLLOVER | DATA CORRECTNESS / High |
| GAP-STANDINGS-FREEZE-001 | Refresh lacks freeze enforcement | REQ-STANDINGS-FREEZE-001 | STANDINGS / SEASON / ROLLOVER | COMPETITION INTEGRITY / High |
| GAP-SEASON-SOURCES-001 | Conflicting season selection sources | REQ-SEASON-SOURCE-001 | STANDINGS / SEASON / ROLLOVER | OPERATIONAL / SEASON MANAGEMENT / High |

14 High and 5 Medium engineering-priority entries. Severity is based on disclosed data,
competition integrity, wrong scoring/ranking or operational consequences; not effort.
Each JSON registry entry includes affected surfaces, exact source finding IDs/evidence,
regression and future acceptance candidates, dependent owners and consequence rationale.

### Deduplication and boundaries

- **GAP-EMAIL-001** (4 finding reference(s)): Multiple serializers disclose contact data; consolidate the approved rule, retain each surface.
- **GAP-ADMIN-DRAFT-001** (2 finding reference(s)): Same bracket detail admin exception, encountered in auth and bracket baselines.
- **GAP-ADMIN-MUTATE-001** (1 finding reference(s)): Prediction/undo/save/delete admin bypass affects competitors entries.
- **GAP-RESAVE-001** (2 finding reference(s)): Same games-only saved-state path; range policy remains unreviewed.
- **GAP-LOCK-BACKEND-001** (1 finding reference(s)): Users can change predictions after outcomes become known.
- **GAP-LOCK-FRONTEND-001** (1 finding reference(s)): Separate frontend repair from server enforcement; UI exposes prohibited controls.
- **GAP-UNDO-FRONTEND-001** (1 finding reference(s)): Server permits approved pre-lock action but UI suppresses it.
- **GAP-PRIVATE-LIST-001** (1 finding reference(s)): List handler lacks league membership validation; separate from detail handler.
- **GAP-PRIVATE-DETAIL-001** (1 finding reference(s)): Detail handler has no league context; shared raw finding proves a separately implemented surface.
- **GAP-PRIVATE-MEMBERS-001** (2 finding reference(s)): Same member endpoint OR owner/admin predicate; merge role variants.
- **GAP-PRIVATE-STATS-001** (1 finding reference(s)): Champion-picks implements its own bypass; keep distinct from member endpoint.
- **GAP-PRIVATE-SCORES-001** (3 finding reference(s)): Same global endpoint/client-filter pipeline repeated across C/D; one canonical gap.
- **GAP-DRAFT-SCORES-001** (2 finding reference(s)): Same missing saved-state filter, not two defects.
- **GAP-CHAMPION-001** (1 finding reference(s)): Approved +3 component remains zero.
- **GAP-FINALISTS-001** (1 finding reference(s)): Approved +1 component remains zero; separate scoring component.
- **GAP-SNAPSHOT-TIE-001** (1 finding reference(s)): Historical ranks can reverse earlier-saved ordering.
- **GAP-STANDINGS-PROVIDER-001** (1 finding reference(s)): Active admin/cron path derives standings from a nonauthoritative provider.
- **GAP-STANDINGS-FREEZE-001** (1 finding reference(s)): Standings may change after bracket creation opens.
- **GAP-SEASON-SOURCES-001** (2 finding reference(s)): Same workflow/script override/calendar mismatch; NC-ENV-04B cross-reference retained.

One private-bracket raw finding maps to two canonical gaps because list and detail are
independently implemented authorization surfaces. Owner/admin member variants share one
endpoint/predicate; champion stats has its own implementation and remains separate.
Global private-score exposure repeated in C/D is one pipeline; draft-score exposure is
its own missing saved-state filter. Email serialization and membership authorization are
not merged. Backend and frontend deadline gaps remain separate repairs. Repeated source
rows remain in the raw dataset even when they reference one canonical issue.

## Unreviewed business-question registry

109 unreviewed findings grouped into **53 domain/subdomain topics**. Four corrected
mixed rows additionally retain their non-email presentation/count/ranking questions
in mixed_row_unreviewed_aspects; their approved violations are not reopened. Duplicate question
text removed within each topic; all source references/current behaviors retained. These
are questions, not new requirements. Topics are indexed below; full question variants,
reasons and source finding IDs are in the companion JSON.

| Topic ID | Domain | Topic | Source findings |
| --- | --- | --- | --- |
| QUESTION-001 | Auth/account | Admin authorization | 2 |
| QUESTION-002 | Auth/account | Frontend auth behavior | 4 |
| QUESTION-003 | Auth/account | Login/session | 8 |
| QUESTION-004 | Auth/account | Password reset | 7 |
| QUESTION-005 | Auth/account | Registration | 6 |
| QUESTION-006 | Auth/account | Sensitive-field exposure | 1 |
| QUESTION-007 | Auth/account | User/profile access | 2 |
| QUESTION-008 | Brackets | admin/master behavior | 1 |
| QUESTION-009 | Brackets | creation | 3 |
| QUESTION-010 | Brackets | cross-user authorization | 1 |
| QUESTION-011 | Brackets | deletion | 2 |
| QUESTION-012 | Brackets | edge/errors | 2 |
| QUESTION-013 | Brackets | frontend behavior | 1 |
| QUESTION-014 | Brackets | historical brackets | 2 |
| QUESTION-015 | Brackets | match propagation | 2 |
| QUESTION-016 | Brackets | predictions | 1 |
| QUESTION-017 | Brackets | save/resubmit | 2 |
| QUESTION-018 | Brackets | schema/timing quirks | 4 |
| QUESTION-019 | Brackets | state/lifecycle | 1 |
| QUESTION-020 | Leagues | admin powers | 1 |
| QUESTION-021 | Leagues | creation | 3 |
| QUESTION-022 | Leagues | delete | 1 |
| QUESTION-023 | Leagues | discovery | 1 |
| QUESTION-024 | Leagues | frontend | 2 |
| QUESTION-025 | Leagues | historical/cross-season behavior | 2 |
| QUESTION-026 | Leagues | join | 1 |
| QUESTION-027 | Leagues | league leaderboard | 1 |
| QUESTION-028 | Leagues | leave | 2 |
| QUESTION-029 | Leagues | membership | 2 |
| QUESTION-030 | Leagues | owner powers | 1 |
| QUESTION-031 | Leagues | password behavior | 3 |
| QUESTION-032 | Leagues | schema/edge behavior | 5 |
| QUESTION-033 | Scoring/leaderboard/history | base points | 1 |
| QUESTION-034 | Scoring/leaderboard/history | edge behavior | 3 |
| QUESTION-035 | Scoring/leaderboard/history | eligibility | 1 |
| QUESTION-036 | Scoring/leaderboard/history | frontend | 1 |
| QUESTION-037 | Scoring/leaderboard/history | game-count scoring | 1 |
| QUESTION-038 | Scoring/leaderboard/history | global leaderboard | 1 |
| QUESTION-039 | Scoring/leaderboard/history | historical reads | 1 |
| QUESTION-040 | Scoring/leaderboard/history | privacy | 1 |
| QUESTION-041 | Scoring/leaderboard/history | ranking/sorting | 1 |
| QUESTION-042 | Scoring/leaderboard/history | recomputation | 3 |
| QUESTION-043 | Scoring/leaderboard/history | scoring architecture | 1 |
| QUESTION-044 | Scoring/leaderboard/history | snapshot creation | 3 |
| QUESTION-045 | Standings/admin/rollover | admin operations | 1 |
| QUESTION-046 | Standings/admin/rollover | authorization | 1 |
| QUESTION-047 | Standings/admin/rollover | cron operations | 2 |
| QUESTION-048 | Standings/admin/rollover | edges | 2 |
| QUESTION-049 | Standings/admin/rollover | failure/atomicity | 3 |
| QUESTION-050 | Standings/admin/rollover | frontend | 1 |
| QUESTION-051 | Standings/admin/rollover | season lifecycle | 2 |
| QUESTION-052 | Standings/admin/rollover | standings refresh | 1 |
| QUESTION-053 | Standings/admin/rollover | team maintenance | 1 |

Important unresolved examples: username/account resolution; password whitespace/session
revocation; league hash-valued response and membership/owner lifecycle; bracket completion,
count ranges and deletion; full-hit/equal-time tie definitions; snapshot/retention policy;
master identity; rollover partial failures and future season propagation. They cannot be
silently converted into fixes without an approved business checkpoint.

## Unclear finding

**NC-01E:current_behavior__rollover__partial_snapshot** remains UNCLEAR / NEEDS BUSINESS
CHECKPOINT. Legacy-only existing history is accepted and structured history failure can
be nonfatal, allowing match cleanup. The user must decide whether legacy-only persistence
satisfies “historical snapshot successfully saved” when Past Seasons structured rows are
missing. No resolution inferred; observed behavior unchanged. This is not added to the
canonical known-gap count.

## Regression inventory and gap/test relationship

155 test references across **12 source test files**: **88 LIVE**, **22 OFFLINE**, **45 STATIC**
finding references. All paths/names are verified against AST definitions; historical
completed test outcomes are retained, not represented as new NC-01F executions.
17 APPROVED REQUIREMENT relationships, 28 KNOWN-GAP REGRESSION relationships, 110
CURRENT-BEHAVIOR REGRESSION ONLY relationships (109 unreviewed + 1 unclear).

A known-gap regression stays valid until intentionally repaired. After user approval,
update its expectation deliberately and add missing endpoint/role/deadline/privacy
acceptance cases. Do not silently delete a failing regression or assume a static/offline
case proves live/browser behavior. Each canonical gap maps current proving tests to
future acceptance candidates and identifies additional coverage needs. The original
mixed behaviors must retain separate assertions for still-unapproved portions.

## Cross-domain dependencies and ownership

- Privacy serialization → Auth/bracket/league response acceptance.
- Bracket saved/lock/admin semantics → Draft-score visibility and score eligibility.
- League membership policy → Bracket list/detail, global score and aggregate presentation.
- Canonical season configuration → ESPN season mapping, freeze and future rollover.
- Master identity business checkpoint → Score/recompute/rollover preconditions (unreviewed, not an invented gap).
- Snapshot tie policy → Persisted historical rank and history UI.

Owner assignment is organizational, not permission to modify a feature. Master identity
remains a business question, not an invented approved-requirement gap. Privacy response
changes need shared auth/bracket/league regression coverage. Saved-state and membership
contracts must precede dependent score visibility fixes.

## Proposed future repair order — no phase started

### Proposed NC-02 — Cross-cutting privacy

Owned gaps: GAP-EMAIL-001.

Minimize contact-data disclosure across serializers before dependent feature changes. Protect with: tests/characterization/auth_access.py, tests/characterization/auth_static.py, tests/characterization/bracket_access.py, tests/characterization/league_access.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.

### Proposed NC-03 — Bracket integrity and authorization

Owned gaps: GAP-ADMIN-DRAFT-001, GAP-ADMIN-MUTATE-001, GAP-RESAVE-001, GAP-LOCK-BACKEND-001.

Protect competition deadlines, submission state and ownership before dependent scoring/UI. Protect with: tests/characterization/auth_access.py, tests/characterization/bracket_access.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.

### Proposed NC-04 — League and score visibility

Owned gaps: GAP-PRIVATE-LIST-001, GAP-PRIVATE-DETAIL-001, GAP-PRIVATE-MEMBERS-001, GAP-PRIVATE-STATS-001, GAP-PRIVATE-SCORES-001, GAP-DRAFT-SCORES-001.

Coordinate membership and saved-state policy across independently implemented surfaces. Protect with: tests/characterization/league_access.py, tests/characterization/league_static.py, tests/characterization/scoring_live.py, tests/characterization/scoring_static.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.

### Proposed NC-05 — Canonical seasons and standings

Owned gaps: GAP-SEASON-SOURCES-001, GAP-STANDINGS-PROVIDER-001, GAP-STANDINGS-FREEZE-001.

Resolve season foundation before provider/freeze behavior and future rollover work. Protect with: tests/characterization/operations_offline.py, tests/characterization/operations_static.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.

### Proposed NC-06 — Scoring and historical ranking

Owned gaps: GAP-CHAMPION-001, GAP-FINALISTS-001, GAP-SNAPSHOT-TIE-001.

Repair approved numeric/ranking components after visibility/submission foundations. Protect with: tests/characterization/scoring_offline.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.

### Proposed NC-07 — Bracket UI alignment

Owned gaps: GAP-LOCK-FRONTEND-001, GAP-UNDO-FRONTEND-001.

Align controls after server boundary contract and acceptance coverage are settled. Protect with: tests/characterization/bracket_static.py.

Prerequisite: Present current behavior, approved requirements, unresolved questions and a recommendation for each; implementation only after explicit user approval.


**Standing rule:** Before modifying/refactoring a feature/domain, perform a short explicit
business-requirements checkpoint with the user. Present current behavior, already-approved
requirements, unresolved questions and ChatGPT recommendation for each question.
**Implementation begins only after user approval.** Current code is not the requirement.
The list above is a proposal only; no checkpoint or NC-02 work has begun.

## Completion criteria and canonical environment

- Auth/access characterized: **PASS**.
- Brackets characterized: **PASS**.
- Leagues characterized: **PASS**.
- Scoring/leaderboard/history characterized: **PASS**.
- Standings/admin/rollover characterized: **PASS**.
- Approved requirements mapped: **PASS**.
- Known gaps mapped: **PASS**.
- Unreviewed questions preserved: **PASS**.
- Regression tests linked: **PASS**.
- Production untouched: **PASS**.
- Canonical environment restored: **PASS**.

Read-only canonical verification: SEEDED nc-fixtures-v1, marker v2, jobs disabled,
checksum `a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Fixture readiness and local socket refusal passed. Read-only pg_locks check confirms
no granted fixture lease. Prior capture cleanup/readiness remains valid; NC-01F issued
no email or mutation and acquired no lease. No broad live suites rerun.

Validation command: `python -B scripts/validate_consolidated_baseline.py`.
It verifies source totals/digests, observations, allowed corrections, IDs/links, actual
tests/files, question and gap coverage, coverage assessments and secret-safe output.
Product code, frontend, schema, workflow, guard/provider configuration and DB records
are unchanged. Only consolidated artifacts and explicitly corrected source docs/evidence
are committed. No production contact/mutation/secrets/deployment; no behavior changes.

**NC-01 CHARACTERIZATION / REGRESSION BASELINE COMPLETE**.
Product requirement compliance remains incomplete. Recommended next action, only when
requested: the proposed NC-02 cross-cutting privacy/access business-requirements checkpoint.
STOP; no repair or next-phase checkpoint performed.
