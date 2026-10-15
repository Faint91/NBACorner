# NC-01D — Scoring / leaderboard / history characterization baseline

Current behavior only; no scoring fixes, sorting changes, history-model changes or
production contact. Frontend main `ce54143006f0409265937f5d548286d0b100d454` and backend
main `d2ec3cba6601a4dafaf56c8be6db4c44b1964a54` were initially clean.

## Approved requirements and evidence limits

Approved: champion bonus +3; both correct Finals participants bonus +1; exact leaderboard
ties use earlier saved_at; past history may be public; other-user bracket visible only
if saved; no email exposure; private-league bracket information requires membership.
Base/partial/count points, rank style, pagination, retention, snapshot frequency,
recalculation timing and deletion/history policies remain unapproved.

25 cases passed: 8 LIVE guarded local fixture reads/job refusal, 9 OFFLINE unchanged
source-helper executions, 8 STATIC source/schema/frontend checks. 214 offline safety
tests passed. Every live case used enrolled local Supabase, marker v2, canonical
nc-fixtures-v1, safe capture/providers, jobs disabled, denylist/admission/egress/lease
checks and canonical reset before/after. No application code or fixture builder changed.

**PRESERVED CURRENT BEHAVIOR / CHARACTERIZATION LIMITATION:** existing job_safety
requires an explicit job and refuses seeded test job execution. Recompute/snapshot
HTTP attempts return 500 from that guard even for the seeded admin. No guard was
patched, disabled, replaced or relaxed; no live recompute or snapshot succeeded.
Calculations and snapshot writes were observed by compiling only the unchanged named
source functions with an in-memory DB transport double. The offline guard stub records
job names and never reaches any DB/network; this is not live job or transaction proof.
No production-code change was necessary to observe these isolated helper results.

## Route / script / helper inventory

| Method | Path | Auth | Read/write | Evidence |
| --- | --- | --- | --- | --- |
| POST | /admin/leaderboard/snapshot | JWT | Write/job | Live read/refusal |
| POST | /admin/season/rollover | JWT | Write/job | Static inventory only |
| POST | /admin/score/master/<master_bracket_id>/recompute | JWT | Write/job | Live read/refusal |
| GET | /leaderboard | None | Read | Live read/refusal |
| GET | /stats/champion-picks | JWT | Read | Static inventory only |
| GET | /leaderboard/history | JWT | Read | Live read/refusal |
| GET | /leaderboard/history/<season_code> | JWT | Read | Live read/refusal |
| GET | /__debug/master-status | None | Read | Static inventory only |

Global leaderboard reads bracket_scores/brackets/users/matches/teams for current season.
No dedicated league leaderboard endpoint: LeagueInfoPage navigates to LeaderboardPage,
which filters global results by member IDs (NC-01C). Champion-picks reads saved brackets,
Finals predictions and score metadata; its distributions were not recalculated here.
Recompute JWT-admin route reads brackets/matches and upserts bracket_scores; runtime
job guard remains in force. Snapshot requires token + DB admin and writes all three
history tables. AdminPage calls snapshot; LeaderboardPage calls recompute.
History index/detail require JWT, read structured snapshots/rows, and are used by
PastSeasonsPage. Debug master-status is unauthenticated, reads bracket/season linkage,
and was inventoried only, not called. Rollover invokes snapshot as a dependency; its
route/body and effects were not exercised. No standalone scoring script/internal cron
was found; existing standings schedule is unrelated and untouched.

Named helpers: _fetch_matches_for_bracket; _compute_score_for_bracket;
_build_leaderboard_rows_for_current_season; _snapshot_leaderboard_for_current_season.
No SQL scoring engine or DB recalculation trigger found in current secured baseline.
Scores are stored values; reads do not recompute them. All job/provider safety remains.

## Scoring architecture and components

Master predicted_winner/predicted_winner_games are treated as actual results, keyed
by conference-round-slot; user predictions and participants are compared by same key.
Caller master ID is not checked against season master pointer/is_master flag. Both
brackets must be active/current. Helper requires two distinct bracket rows, so scoring
the master against itself returns None. No independent real-results feed is read.
Master selection for leaderboard display derives from frequency of stored score
master IDs, not the season pointer. Replacing/deleting master does not itself calculate
new scores. Soft-deleted/historical master/user helpers skip; active new result inputs
produce overwriting recalculation. Missing actual winner/count is pending.

OFFLINE actual values: play-in correct winner+participant set=1, otherwise zero;
rounds 1–4 correct winner+participants+count=3; correct winner with wrong participants
or count=1; wrong winner=0. No escalating per-round multiplier. Missing user match
and no-pick are misses; pending actual result carries zero pending status. Count
comparison is equality. NULL/zero/negative/large user counts yield partial one against
normal actual count. Play-in ignores count; API forcing one is prior NC-01B behavior.

**Champion gap:** correct Finals full hit base=3, explicit bonus_champion=0, approved
additional champion bonus=3. Base Finals points are not counted as that bonus.
**Finalist gap:** bonus_finalists=0 for both/one/neither/reversed participants and a
correct champion with different finalist set. Both-finalists approved +1 is absent;
no per-finalist bonus or champion coupling exists. Base participant comparison uses
sets, so reversed sides still compare equal. These are offline source calculations,
not successful live scoring-job runs. Unapproved base/count semantics remain unreviewed.

## Eligibility and recomputation

Admin recompute statically selects saved/current/nondeleted brackets. The lower helper
itself does not check is_done and will score a draft offline. Missing user matches
skip persistence. Each upsert overwrites bracket-keyed score, not increments; repeated
inputs have same numeric score but updated timestamp, separate PostgREST writes and
no atomic all-bracket transaction. Prediction/save routes do not automatically score.
Unsaving can leave a stale score row. Live persisted draft score is still public on
leaderboard (existing NC-01C gap); deleted bracket is omitted despite retained score.
No cleanup/rollover or destructive account deletion was performed.

## Leaderboard and ties

Anonymous current leaderboard returns stored score rows, IDs/names/points/components/
per-match JSON/saved timestamps/master matchup map, no backend rank/pagination. Missing
scores produce empty rows. It filters current/nondeleted brackets, not saved status.
No email/password/JWT/config values in observed rows; history privacy is separately
asserted. Malformed unrelated query parameters are ignored; league_id handling remains
NC-01C's same existing privacy gap and was not broadly retested.

Global backend and frontend sort total points descending, full hits descending, then
earlier saved_at (missing timestamps last). Live identical point/full-hit tie ranks
earlier timestamp first. Frontend uses sequential idx+1 rank, not dense/shared ranks.
Equal points with unequal full hits prioritizes hits; exact-tie definition/full-hit
priority remains a later checkpoint question, not implicitly declared compliant.
Equal score/components/time has no explicit further server tiebreak.

**Snapshot tie gap:** builder drops saved_at, snapshot sorts equal points/hits by
lowercase username. Controlled Alpha saved later ranks 1 while Zulu saved earlier
ranks 2, violating the approved exact-tie rule. Historical reads also sort points/hits
without explicit rank/date order; stored sequential rank can differ from row order.

## Historical model / creation / reads / retention

Legacy leaderboard_history persists season/rank/bracket name/username/score counters/
per-match JSON plus nullable user/bracket references; these references are not FKs to
those objects. Structured leaderboard_history_snapshots persists season/time/columns/
optional creator; leaderboard_history_rows persists snapshot/rank/display_name and
numeric score components/per-match values, without live user/bracket IDs. Current
PastSeasons API uses structured tables, not legacy rows. Names denormalized; no emails.

OFFLINE snapshot writes legacy rows first, then structured snapshot and rows, flattens
per-match points, builds ordered matchup/bonus columns, assigns sequential ranks.
Duplicate protection checks legacy rows for current season; repeat returns 400.
Structured-only existing snapshot does not trigger that guard. No score rows yields
400. Structured failure is caught as nonfatal after legacy success (STATIC, not fault
injected), so these are not atomic writes. Rollover dependency is inventory only.

LIVE history index/detail require JWT; authenticated synthetic historical snapshot
returns fields/ranks/numeric points without user/bracket/email/security payloads.
Invalid/no-snapshot season=404. Latest snapshot per season selected; public historical
access is permitted, not required, so auth itself is not a gap. History UI displays
stored snapshot rows/columns and rank or index fallback, not archived bracket links;
current raw historical bracket detail remains rejected (NC-01B).

Existing synthetic historical brackets are soft-deleted while their independent
snapshot rows remain readable. This is stored-state coverage, not a before/after
live deletion test. Structured row FK cascades from snapshot and snapshot from
season; created_by FK can restrict creator deletion. Legacy season FK remains; no
account deletion route invoked. Retention and season cleanup semantics remain unreviewed.
No history cleanup/model changes. Frontend score/bonus indicators display stored fields,
season selector sorts by start year; no browser or UI modifications.

## Completion / gap matrix

Rows are characterization findings, not unique issue counts. Draft/global league gaps
cross-reference NC-01C rather than being declared new issues. All known gaps name an
approved requirement. OFFLINE, LIVE and STATIC evidence are explicitly separated.

Classification totals: MATCHES REQUIREMENT=2; KNOWN GAP=5; REQUIREMENT NOT YET REVIEWED=18; UNCLEAR / NEEDS BUSINESS CHECKPOINT=0. Total=25.

### scoring architecture

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__master_source | Master predicted_winner/games keyed conference-round-slot are actual results; caller-supplied master ID need not match season pointer or is_master. Same master/user ID skips score. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve ground-truth identity and missing/replaced master policy? |

### base points

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__base_points | Play-in full hit awards 1; rounds 1–4 full winner/participants/count hit awards 3 each; wrong winner zero; no round escalation. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve round base values? |

### champion bonus

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__champion_bonus | Correct Finals champion earns base Finals 3 only; explicit bonus_champion remains 0 rather than approved +3. | Correct NBA champion bonus: +3 points. | KNOWN GAP | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | None required for classification |

### finalist bonus

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__finalist_bonus | Both/one/neither/swapped finalists and champion-correct different set all have bonus_finalists=0; approved both-finalists +1 absent. | Correctly predicting both NBA Finals participants: +1 point. | KNOWN GAP | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | None required for classification |

### game-count scoring

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__counts | Rounds 1–4 exact count earns full 3 with matching participants; incorrect/null/zero/negative/large user count yields partial 1. Play-in count ignored; NULL actual count is pending. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve partial/count and historical availability rules? |

### eligibility

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__deleted | Soft-deleted current bracket omitted despite retained stored score; historical snapshot rows remain readable. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local fixture reads/job refusal; canonical reset per case | Approve deleted-object retention/visibility? |
| current_behavior__scoring__draft | Stored unsaved score row appears in anonymous leaderboard; same draft-score surface established in NC-01C. | Another user's bracket may be visible only if saved. | KNOWN GAP | LIVE guarded local fixture reads/job refusal; canonical reset per case | None required for classification |

### recomputation

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__job_refusal | Existing test job guard refuses recompute/snapshot HTTP execution (500) even admin; score/history records remain unchanged. Preserved characterization limitation. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local fixture reads/job refusal; canonical reset per case | A separately approved scoped-job extension would be needed for live maintenance execution. |
| current_behavior__scoring__recompute_source | Admin trigger selects saved/current/nondeleted brackets, upserts each separately; no automatic scoring on prediction/save; no independent scoring cron/script found. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve recalculation timing and transaction/failure behavior? |
| current_behavior__scoring__upsert | Per-bracket upsert overwrites score rather than increments; same inputs repeat same numeric result, updated_at changes. Helper does not check submission flag; source job entry remains blocked live. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve recalculation timing/eligibility/atomicity? |

### global leaderboard

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__global | Anonymous leaderboard reads stored current score rows; no rank field/pagination; malformed unrelated query ignored. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local fixture reads/job refusal; canonical reset per case | Approve accessibility/pagination and score presentation? |

### tie ordering

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__tie | Exact equal score/full-hit tie ranks earlier saved_at first on global backend. | Exact leaderboard ties are ranked by earlier bracket saved_at. | MATCHES REQUIREMENT | LIVE guarded local fixture reads/job refusal; canonical reset per case | None required for classification |
| current_behavior__history__snapshot_tie | Snapshot exact score/hit ties sort username instead of earlier saved_at; builder omits saved_at. Later-saved Alpha ranks ahead of earlier-saved Zulu. | Exact leaderboard ties are ranked by earlier bracket saved_at. | KNOWN GAP | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | None required for classification |

### league leaderboard

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__league_surface | No backend league filter; frontend filters global rows using member IDs. Existing NC-01C private-score exposure, not a newly counted surface. | Private-league bracket information requires membership. | KNOWN GAP | STATIC source/schema/frontend; no browser or live job claim | None required for classification |

### snapshot creation

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__history__snapshot_source | Legacy write precedes structured snapshot; structured failure is nonfatal; duplicate guard only checks legacy rows. Rollover calls snapshot but is not executed here. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve atomicity/recovery/snapshot scheduling? |
| current_behavior__history__snapshot_empty | Missing score rows refuses snapshot; existing structured snapshot alone does not trigger duplicate legacy guard. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve cross-model duplicate/failure policy? |
| current_behavior__history__snapshot_repeat | Snapshot writes legacy rows plus structured snapshot/rows; repeat rejected by legacy season row; sequential ranks and numeric per-match flattening persisted, not one transaction. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve snapshot frequency/atomicity/rank format? |

### historical reads

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__history__reads | History index/detail require JWT; read structured snapshots/rows, retain ranks/display/numeric points, omit email/security/bracket-user IDs. | Email addresses must never be exposed. | MATCHES REQUIREMENT | LIVE guarded local fixture reads/job refusal; canonical reset per case | None required for classification |
| current_behavior__history__storage | Three history tables: legacy denormalized internal bracket/user references; structured season snapshots and snapshot rows power current API. Reads latest snapshot per season, no live user join. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve history retention/legacy purpose and duplicate selection? |

### privacy

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__history__retention | Structured history rows have no live user FK; legacy user/bracket references and schema deletion behavior differ; no account deletion performed. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve deleted-user/bracket retention? |

### ranking/sorting

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__hits_priority | Equal points with unequal full_hits rank more full hits ahead of saved time; full equality has no explicit further tiebreak. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local fixture reads/job refusal; canonical reset per case | Approve full-hit priority and equal-time tie policy? |

### frontend

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__history__frontend | Global frontend sorts points/full hits/earlier saved time, ranks displayed by array position; history uses stored rank or index fallback, dynamic numeric points and snapshot columns; no archived bracket links. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve rank style, snapshot display and historical navigation? |

### edge behavior

| Scenario/test | Current behavior | Approved requirement | Classification | Evidence | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| current_behavior__scoring__empty | No stored scores returns empty rows/master map; historical missing snapshots return 404 authenticated. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local fixture reads/job refusal; canonical reset per case | Approve empty/missing response contract? |
| current_behavior__history__sorting | History read sorts total_points/full_hits without explicit rank or saved-time order; saved_at not stored. Equal score/time secondary order and historical retention remain unreviewed. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser or live job claim | Approve rank/order consistency and retention? |
| current_behavior__scoring__edges | Missing user match/no pick are misses; incomplete actual winner/count is pending; no user matches skips persistence; deleted/historical/same-ID master skips helper. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution | Approve missing/incomplete/error contract? |

## Validation / cleanup / later questions

```text
python -B scripts/run_scoring_characterization.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
```

Fixed three-class runner, no arbitrary selector or job bypass. All live fixture
mutations go through verified NC-01D harness; offline helpers use no network. Eight
live exits reset fixtures and stop Flask/release lease/clear capture. Semantic schema
and marker ACL verifiers passed; final independent readiness/checksum and connection
refusal passed. Fixture marker SEEDED, jobs disabled, all unscoped mutations false.
Canonical nc-fixtures-v1 checksum:
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Counts restored: 4 users, 2 seasons, 30 teams, 30 fictional standings, other tables empty.
Syntax/format/JSON/matrix/secret/log/whitespace/exact-file-scope audits passed.

Limitations: no live scoring/snapshot writes, DB failure injection, user deletion,
season rollover, scoring cron or browser tests. Offline transport doubles do not prove
PostgREST transaction/constraint behavior. No production code had to change for these
observations. Existing safety restrictions were preserved, not remediated.
Later questions: base and partial/count points; finalist partial policy; full-hit and
equal-time tie definition; recalculation timing/eligibility; master identity; snapshot
frequency/atomicity; retention/deletion; rank formatting/pagination; historical privacy.
Approved bonus/saved-time/privacy rules are not reopened. No business behavior changed,
production contact/mutation/secrets/deployment. Next candidate **NC-01E — Standings /
admin operations / season rollover characterization baseline**; not started.
