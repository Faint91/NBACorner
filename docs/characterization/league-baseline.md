# NC-01C — League characterization / regression baseline

Current behavior only. No fixes, refactors or requirement changes. Passing tests may
record KNOWN GAPs. Frontend main `ce54143006f0409265937f5d548286d0b100d454` and backend
main `d7041e76416387bf14e9960532e75e0d8fc599ce` were initially clean.

## Scope and approved requirements

1. Private-league bracket information requires league membership.
2. Email addresses must never be exposed to other users.
3. Another user may see a bracket only if saved.
4. Past-season history may be public (permission, not mandatory anonymous access).

No approved general creation/limits/owner-leave/transfer/delete/password/join-timing/
kick/admin-league contract is inferred. Unknown behavior remains unreviewed.
26 live sequences + 9 static checks passed (35 distinct tests); 210 offline safety
tests passed. Initial 34-test run had four assertion failures and one fixture error
caused by test-only query admission/owner-role restrictions. Six affected cases were
rechecked successfully after narrow harness corrections; final draft-score/default
score-surface checks also passed. Total attempts=42. Product code never changed.
All live mutations used the guarded local enrolled environment, marker v2, safe
capture/provider fixtures, jobs disabled, production denylist, admission/egress checks,
explicit NC-01C scope and exclusive lease. Canonical reset before/after every sequence.
No browser automation, production contact or score calculations/maintenance execution.

## Complete league and dependent-surface inventory

Seven league routes exist. Member listing doubles as league detail; no GET /leagues/id,
rename/update, ownership transfer, password-change, kick/member-edit, invitation/code,
league-history or admin-specific league management route exists. Owner information
comes from owner_user_id and member is_owner, not a separate owner endpoint.
Dependent bracket/stat/leaderboard routes are inventoried and exercised only for
league access/serialization/presentation, not scoring mathematics.

| Method | Path | Auth | Owner/membership | Admin | Effect | Tables | Frontend caller |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | /bracket/<bracket_id> | JWT | Owner OR admin OR saved; no league membership lookup | DB admin draft bypass (NC-01B) | Read | brackets; matches; seasons; users; teams | BracketPage follows member link |
| GET | /brackets | JWT | league_id filters owners, no league membership gate | Same saved-list scope | Read | leagues; league_members; users; current saved brackets | DashboardPage |
| GET | /leaderboard | None | No league gate; league_id ignored | No gate | Read | bracket_scores; brackets; users; matches; teams | LeaderboardPage then client member filter |
| GET | /stats/champion-picks | JWT | league scope: member OR owner OR admin | JWT admin bypass | Read | leagues; league_members; brackets; bracket_scores; matches; teams; seasons | LeagueStatsPage |
| GET | /leagues/me | JWT | Own memberships | No special admin power | Read | leagues; league_members | LeagueInfoPage; LeaderboardPage; DashboardPage |
| GET | /leagues | JWT | No membership required for metadata | No special admin power | Read | leagues; league_members | FindLeaguesPage |
| POST | /leagues | JWT | Creator becomes owner/member; pre-playoffs | No time bypass | Write | leagues; league_members | LeagueInfoPage |
| POST | /leagues/<league_id>/join | JWT | Caller membership; private password; pre-playoffs | No password/time bypass | Write | leagues; league_members | FindLeaguesPage |
| DELETE | /leagues/<league_id>/membership | JWT | Caller is member, not owner; non-global | Same rules | Write | leagues; league_members | LeagueInfoPage |
| DELETE | /leagues/<league_id> | JWT | Owner only; non-global | No override | Write | leagues; league_members cascade | LeagueInfoPage |
| GET | /leagues/<league_id>/members | JWT | Member OR owner OR admin | JWT admin bypass | Read | leagues; league_members; users; current saved brackets | LeagueInfoPage; LeaderboardPage |

## Implementation and represented state

leagues stores id/name/nullable password_hash/owner_user_id/is_global/timestamps.
league_members stores id/league_id/user_id/joined_at. No formal lifecycle enum,
season linkage, soft-delete columns, invitation token or ownership role membership
column exists. Public means no hash, private means hash; is_global is a separate
special-league flag. Discovery returns all non-global public/private leagues despite
comments calling them all private. Owner/member/nonmember are relations, not states.
Empty owner-not-member leagues are structurally permitted; normal create auto-joins
owner and normal owner leave is denied. Empty/final-leave tests explicitly use this
synthetic structural scenario and do not claim it arises through ordinary create.

Creation trims name/password; name length 3–80 and supplied password minimum four;
public/private request flags are ignored in favor of password presence. Ownership and
membership come from JWT subject, not supplied user_id/owner fields. Multiple leagues
can be created by the same user; no numeric league cap was found. League and owner
membership inserts are separate; membership failure is nonfatal (STATIC, not injected).
Join checks global flag, duplicate membership and bcrypt password, then inserts caller.
Leave deletes only caller membership and retains league/owner/brackets. Owner cannot
leave. Owner deletion hard-deletes league; FK cascades remove memberships but do not
remove member brackets/scores. Live deletion confirmed bracket retention; score
retention follows schema/source and was not a separate score mutation test.

## Enforcement, schema, passwords and timing

Flask JWT decorators cover all seven league routes. Member detail and champion-picks
use membership OR owner OR JWT admin. Ordinary nonmembers cannot enumerate member
lists even in public leagues. Discovery requires JWT but no membership. Delete is
owner-only, with no admin override. No per-user Supabase Auth/RLS session is used;
server-side database access and existing containment ACLs remain unchanged.

DB enforces exact name uniqueness and unique (league_id,user_id), with membership
FK cascades on user/league deletion; owner FK has no cascade. Hash nullable, no league
season FK or automatic owner-membership constraint. No schema/index/trigger changes.
Flask performs nontransactional writes; no league RPC is used. All new test helpers
are lease/identity/owner-thread guarded and reuse existing fixture builders.

Passwords are bcrypt with configured rounds (default 12), checked by checkpw;
create/join strip outer whitespace. Whitespace-only creates public. No password
policy/throttling requirement inferred; no join-specific limiter found statically.
Wrong passwords repeatedly return 400 in representative tests. Discovery/create/join
return boolean requires_password; **own-leagues returns the stored hash in that field**.
Only boolean/type/equality facts were retained; no hash/plaintext appears in reports.
This security-sensitive behavior is unreviewed against an unapproved hash-disclosure
contract, not silently marked compliant or remediated.

Create/join reject all roles after playoff start, including admin. Leave/delete are
not time-gated. League timing has no approved contract here, so those results remain
unreviewed. No blanket request guard or date/clock/product changes were added.

## Privacy and member bracket surfaces

Live member responses expose other users' email for member, owner and admin viewers.
This confirms NC-01A's static warning on an independent league surface, under the
same no-email rule as NC-01A1/NC-01B. Member objects omit password/reset/admin fields;
discovery has owner IDs/counts/metadata, no member identities, brackets or scores.
Member detail has league metadata and member ID/username/email/joined/owner flag plus
has_bracket and bracket_id. No embedded predictions or score payload there.

Only current saved/nondeleted brackets enter member listing. Draft and historical
bracket IDs are omitted; has_bracket=false and UI No bracket yet do not distinguish
no record from unsubmitted record. Members follow a normal bracket detail link.
Other ordinary users cannot read drafts directly (NC-01B cross-reference).

Private-member endpoint denies ordinary nonmembers, but owner/admin nonmembers bypass
that requirement and can receive saved-bracket IDs. A saved bracket in private scope
is also reachable through /brackets?league_id without membership, then normal saved
bracket detail. Public/non-global and private fixtures intentionally share members,
as in the existing builder; the explicitly private-filtered request still lacks a
gate. A bracket has no league ownership column; access scope is derived from membership.
No new privacy contract is inferred to reconcile those architecture details.

## League leaderboard and stats presentation

There is no dedicated league leaderboard backend route. LeaderboardPage downloads
anonymous global /leaderboard and filters rows client-side using member IDs fetched
from the protected member endpoint. Backend ignores league_id. Stored score rows for
private members are returned to nonmembers/anonymous callers. Row fields include
bracket/user IDs and names, points/full/partial/miss/bonus values, saved/updated times
and points_by_match; no email. A stored draft score row also remains visible because
the backend bracket lookup does not filter is_done, even though member listing hides
that draft ID. These are league access/display findings, not score calculations.

Rows without stored scores are absent even when member list has a saved bracket.
A fixed equal-score fixture returned two rows; static ordering is descending points,
then full hits, then earlier saved_at (unknown saved_at last). Exact full ties have no
additional explicit server tiebreak. Mathematics/tie business policy belongs to NC-01D.
Champion-picks accepts league_id and optional season_code and gates member/owner/admin;
ordinary nonmember denial works, but nonmember admin can read private bracket aggregates.
Only access/shape/count presentation was checked, not champion distribution or points.

## Historical handling and frontend (STATIC unless noted live)

Leagues/members persist without season fields; member bracket lookup always uses
current season. Explicit past-season champion stats use current memberships. No
historical league snapshot endpoint exists; general history snapshot routes are
outside this league phase. Permitted public history does not mandate anonymous
league routes or establish identical historical privacy policy.

FindLeaguesPage discovers/filter names and public/private lists and joins with optional
password. LeagueInfoPage creates name/password, offers visibility selection, requires
private password locally, clears form/password state, loads members and provides
owner delete/nonowner leave confirmation controls. API type includes email but the
member table does not render it; the network response still exposes it. Member rows
link saved bracket IDs; otherwise No bracket yet. Passwords remain local React state
for form/join and clear after success; private metadata discovery is not proof of
member/bracket authorization. UI loading/error/owner controls are presentation;
server endpoint checks are the actual access enforcement. No frontend files changed.

## Completion / gap matrix

Counts below are matrix rows, not distinct requirement issues. Private info bypasses
are separated by surface/role; existing bracket privacy findings are cross-referenced.
Each known gap lists the exact approved requirement. STATIC findings are not browser
claims and passing characterization does not mean desired policy is approved.

Classification totals: MATCHES REQUIREMENT=2; KNOWN GAP=8; REQUIREMENT NOT YET REVIEWED=25; UNCLEAR / NEEDS BUSINESS CHECKPOINT=0. Total=35.

### creation

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| creation | Ordinary public/private and admin creation succeed pre-lock; owner membership auto-created; password optional bcrypt hash, no season field. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve creator powers, limits and defaults? |
| creation_forged_fields | Backend ignores visibility/owner/is_global request fields; missing password yields public even if private requested; supplied password yields private even if public requested. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve public/private wire contract and ignored request fields? |
| creation_validation | Names trim and enforce 3–80 characters, exact duplicate names rejected; case-distinct name accepted. Missing/empty name and short password fail. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve naming/uniqueness/password rules? |

### discovery

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| discovery | Authenticated roles discover public/private non-global metadata and member counts; anonymous list/me denied; member-only own list, no emails/brackets/scores in discovery. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve metadata discovery for private leagues? |

### public leagues

Public metadata/member/draft/saved coverage is recorded in discovery, membership and member bracket access rows; no duplicate row is counted here.

### private leagues

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| admin_private_bracket | Nonmember admin obtains private member saved-bracket ID through admin bypass, contrary to membership requirement. | Private-league bracket information requires league membership. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |
| stats_admin_bypass | Admin without membership can read private champion-picks bracket aggregate through bypass. | Private-league bracket information requires league membership. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |
| stats_membership | League champion-picks endpoint denies ordinary nonmember and anonymous requests; members/owner can access; calculations not validated. | Private-league bracket information requires league membership. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset per sequence | None required for classification |

### join

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| join | Public join succeeds; repeated/owner join fails; private missing/wrong password fails, trimmed correct password succeeds; membership is caller identity despite forged user_id. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve join/password/repeat contract? |

### leave

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| empty_final_leave | Final non-owner membership can leave an owner-not-member fixture, leaving empty league and unchanged owner; owner/nonmember rules unchanged after lock. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve owner-not-member/empty-league lifecycle? |
| leave | Ordinary member leaves without changing league/owner/brackets; repeat/nonmember leave fails; owner cannot leave with other members. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve owner-leave and repeated leave rules? |

### delete

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| delete | Only owner can hard-delete public/private leagues, including after lock; memberships cascade, bracket remains; deleted join/member access returns 404. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve hard-delete/cascade/retention policy? |

### membership

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| member_access | Member/owner can list members; ordinary nonmember denied for public/private; no anonymous member listing. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve public member-list visibility contract? |
| route_absences | Membership writes always use JWT subject; no rename/update/transfer/kick/invite/detail GET/admin-specific league routes. Member GET doubles as detail. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Which owner/admin management features are required? |

### privacy/email

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| member_email | Member/owner/admin listing responses actually emit other users' emails on public/private surfaces, confirming NC-01A static warning. | Email addresses must never be exposed to other users. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |

### member bracket access

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| draft_saved_visibility | Public/private member lists hide draft ID and predictions, showing has_bracket=false; saved IDs shown to members. Direct other-user draft denied; nonmembers get no draft via filtered list. | Another user may see a bracket only if that bracket is saved. | MATCHES REQUIREMENT | LIVE guarded local Flask; canonical reset per sequence | None required for classification |
| private_bracket_bypass | Ordinary nonmember is denied private member endpoint, but league-filtered saved list and direct saved-bracket detail bypass membership. | Private-league bracket information requires league membership. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |

### league leaderboard

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| leaderboard_private_surface | Global leaderboard is anonymous and ignores league_id; league filtering is client-side. Nonmember can obtain saved private-member score/bracket rows; no email fields there. | Private-league bracket information requires league membership. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |
| missing_scores | Members with no score rows absent from leaderboard; saved member ID remains in member list; empty score surface returns empty rows. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve missing-score/member presentation and tie policy? |
| frontend_leaderboard | LeaderboardPage fetches global leaderboard then filters rows by IDs from member endpoint; points/full-hits/saved-time ordering and ties are presentation only here. | None explicitly approved | KNOWN GAP | STATIC source/schema/frontend; no browser claim | Approve membership enforcement placement and league tie/display contract? |
| draft_scored_leaderboard | Stored score row for an unsaved member bracket appears in anonymous/global and league-query leaderboard, despite member list hiding its draft ID. | Another user may see a bracket only if that bracket is saved. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |

### owner powers

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| owner_not_member | Owner without membership can read saved member bracket ID through owner bypass on private league. | Private-league bracket information requires league membership. | KNOWN GAP | LIVE guarded local Flask; canonical reset per sequence | None required for classification |
| frontend_owner | UI offers owner deletion and non-owner leave confirmations; no member removal/ownership-transfer/password-change UI. Loading/error states and protected frontend routes are client presentation. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve owner-leave/delete and missing management features? |

### admin powers

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| admin_join_delete | Admin cannot bypass private join password and cannot delete another owner's league; admin own creation/delete works. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve admin league powers? |

### password behavior

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| own_list_hash_surface | Own-leagues requires_password contains actual stored bcrypt hash instead of boolean; other discovery/create/join surfaces use booleans. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve password-derived response contract/security requirement? Hash values withheld. |
| password_normalization | Create/join strip outer password whitespace; whitespace-only creates public; one-/three-character passwords fail minimum; repeated incorrect join remains 400. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve normalization, minimum length and retry policy? |
| password_source | bcrypt hashing/comparison with configured rounds; optional password determines public/private; no join limiter in route; owner auto-membership insertion failure is nonfatal. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve password/attempt throttling and partial-creation contract? |

### historical/cross-season behavior

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| historical | Leagues/membership have no season linkage; current member bracket lookup omits historical bracket; explicit historical champion-picks keeps league membership gate. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve historical league access/public scope separately? |
| history_source | No league history endpoint or season columns; LeagueStatsPage passes optional season_code and league_id to champion-picks; current memberships gate explicit past-season stats. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve historical league privacy scope versus permitted public history? |

### frontend

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| frontend_forms | Create has public/private selection; private requires local password; API sends name/password, clears form. Join passwords held in local React state, cleared after success. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve client validation and password-state lifetime? |
| frontend_members | Member UI shows username/role/join date, links saved bracket ID, otherwise No bracket yet; API type includes email, UI member table does not render it. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve member presentation and not-submitted wording? |

### schema/edge behavior

| Scenario/test | Observed behavior | Approved requirement | Classification | Coverage | Later checkpoint |
| --- | --- | --- | --- | --- | --- |
| errors | Malformed/nonexistent IDs, missing auth, non-object join payloads and repeat delete produce representative 400/404/401/500 errors; no arbitrary user mutation routes. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve error/status contract? |
| global | Global league excluded from discovery/own list; join/leave/delete rejected even for owner; private/public represented independently of is_global. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve global-league special policies? |
| timing | Playoff lock blocks league create/join even for admin; leave/delete remain available. No approved league timing contract assigned. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | LIVE guarded local Flask; canonical reset per sequence | Approve league timing distinct from bracket-content final lock? |
| failure_paths | Leave exception handler returns 200 empty-members fallback; create/join are separate writes with no transaction/RPC or encoded numeric league limit. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve failure category, atomicity and limits? |
| schema | DB enforces exact league-name and league/user membership uniqueness; owner FK no cascade, membership FKs cascade; nullable hash, no league/member season or soft-delete fields. | None explicitly approved | REQUIREMENT NOT YET REVIEWED | STATIC source/schema/frontend; no browser claim | Approve case/uniqueness/owner deletion and season policies? |

## Limitations / later business checkpoint

No provider/production requests, scoring recomputes, snapshots, rollover or unrelated
domain mutations. Existing score/history builder supplies fixed rows only; no scoring
math assertions. No exhaustive fuzzing/load tests, raw malformed JSON syntax, deleted
user identity token, injected DB failure or unbounded creation-limit test. Representative
non-object JSON, missing fields/auth, malformed/nonexistent IDs, invalid password,
forbidden/repeated operations and deleted league access were exercised.

Later questions: creation/limits/naming; private metadata policy; owner leaving,
owner-not-member/empty states and transfer; deletion/retention; private password policy,
rate limits and hash-valued response; admin powers; join/leave timing; management and
invitation features; current-vs-historical privacy; league tie/missing-score display;
nontransactional failure handling. Already approved privacy rules are not reopened.

## Commands / validation / canonical cleanup

```text
python -B scripts/run_league_characterization.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
```

Fixed runner loads only NC-01C classes with current_behavior__league__ naming; no
arbitrary selector/global bypass. Exact league-ID query allowlist is checked at HTTP
admission; unrelated auth writes, bracket writes, jobs and maintenance are refused.
Older scopes remain restricted. Reports/logs retain path/status/shape and safe facts
only; failures sanitized. Secret-value/JWT/private-key, syntax, JSON, formatting and
Git whitespace/scope audits passed.

35 distinct characterization cases passed (26 live/9 static), with targeted recovery
as recorded above; 210 offline safety tests passed. Semantic schema and marker ACL
verifiers passed. Every sequence reset nc-fixtures-v1 to checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Independent final readiness/checksum passed; localhost connection refused. Flask
stopped, lease released, capture cleared, jobs disabled, fixture SEEDED. Canonical
counts: 4 users, 2 seasons, 30 teams, 30 fictional standings; all remaining tables empty.
No application, frontend, schema, fixture builder, environment safety or earlier
reports changed. No business behavior changed; no production contact/mutation/secrets/
deployment. Next candidate: **NC-01D — Scoring / leaderboard / history
characterization baseline**. Not started. No fixes performed.

### NC-01F explicit classification audit: frontend_leaderboard

Previous: REQUIREMENT NOT YET REVIEWED. Corrected: **KNOWN GAP**.
Approved requirement: Private-league bracket information requires membership.

Client-side filtering follows an unrestricted global download; existing leaderboard_private_surface and NC-01D league_surface confirm private data exposure. Other score/rank presentation details remain unreviewed. No observed behavior or original test result changed.
