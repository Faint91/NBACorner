# NC-02A1 — Privacy and private-league access foundation

## Scope and starting state

Backend main `b572b95c1322fe7660d55cd25eba8da99db0dae0` and frontend main
`ce54143006f0409265937f5d548286d0b100d454` both started clean. The user explicitly
approved P1/P2/P3/P6/P7/P8/P10. No schema, production, deployment, frontend, provider,
job, fixture, scoring-formula or bracket-mutation changes are authorized or made.
P4/P5/P9 remain deferred to NC-02A2.

Historical authority remains `docs/characterization/nc-01-consolidated-baseline.md`
and `db/records/nc_01_consolidated.json`, with all four domain reports and source
records unchanged. Separate repair evidence records the approved expectation
transitions; the historical validator now checks original test lines against the
NC-01 checkpoint and also verifies that their named current tests still exist.

## Route inventory and repair

| Route / surface | Before / source finding | Approved repair | Regression / acceptance |
| --- | --- | --- | --- |
| GET /bracket/<id> | Owner email; admin reads others' drafts. NC-01A cross_user_saved_owner_display, cross_user_draft_boundary; NC-01B email_serialization, admin_draft_visibility | P1/P6/P8: allowlisted owner; owner or saved read, no admin privacy exemption | Same named converted tests; public_user_allowlist_and_nested_bracket_payloads |
| GET /brackets | Nested user email. NC-01B email_serialization | P1/P8: select id/username, shared serializer | Same named converted tests |
| GET /brackets?league_id=<id> | Missing private membership gate. NC-01C private_bracket_bypass | P2/P7/P10: private membership before reading member IDs; public behavior unchanged | Converted private_bracket_bypass; direct_api_role_matrix; owner_without_membership_all_private_surfaces |
| GET /leagues | Discovery included private owner identity. NC-01C discovery | P3/P8: private nonmember receives league id/name/flags/timestamps, own membership boolean, aggregate member count, boolean password state; omit owner identity | discovery_and_boolean_password_state |
| GET /leagues/me | requires_password contained stored hash. NC-01C own_list_hash_surface (formerly unreviewed; now explicitly P8-approved) | P8: boolean derived from presence, no hashing/join change | Converted own_list_hash_surface; discovery_and_boolean_password_state |
| GET /leagues/<id>/members | Other-user emails, nonmember owner/admin exceptions; member bracket IDs. NC-01C member_email, admin_private_bracket, owner_not_member | P1/P2/P6/P7/P8/P10: safe display + active private membership; public member/owner/admin rule preserved | Same named converted tests; role matrix; owner nonmember; membership removal |
| GET /stats/champion-picks?league_id=<id>[&season_code=...] | Admin/owner exceptions bypass private membership. NC-01C stats_admin_bypass, stats_membership, historical | P2/P6/P7/P10: private membership before derived member data; public authorization and math unchanged | Converted stats_admin_bypass; role matrix includes historical scope |
| GET /leaderboard?league_id=<private> | league_id ignored. NC-01C leaderboard_private_surface, frontend_leaderboard; NC-01D league_surface | P2/P7/P10: authenticate and authorize before score read, then restrict output to member owners server-side | Same named converted tests; role matrix; revoked membership |
| GET /leaderboard (global or public league_id) | Anonymous global stored-score rows, including drafts, and client filtering | Preserve general/public behavior and score eligibility; P4/P5/P9 deferred | draft_scored_leaderboard now explicitly tests global route; scoring_live; public_access_and_general_saved_visibility_preserved |
| GET /leaderboard/history and /leaderboard/history/<season> | Structured public competition history; no live email join or private league relationship | No repair needed; existing safe projection and auth unchanged | Existing scoring/history regression tests |
| GET /brackets/me; POST /auth/login, /auth/register; GET /auth/test-me | Own-account identity/display | Preserve own-account email/session contract; do not apply other-user serializer to auth | Existing full auth/bracket regression |
| League create/join/leave/delete; admin diagnostics | Explicit projections; create/join already boolean; admin diagnostics masked | Reviewed, unchanged | Existing lifecycle, password/error and admin regression |

There is no standalone private-league detail API: safe league metadata accompanies
the member-list response. No independent league history/score route exists; current
scores are supplied by leaderboard and champion-pick APIs. Global history has no
private-league scope. No endpoint response gains a password hash or security field.
Only auth's own-account registration/login exposes the requester's own email and
login intentionally returns the session token; reset tokens remain internal/captured
only. Operational email-provider payloads are not user-facing serializers.

## Shared enforcement

`app.py:public_user` allows only `id` and `username`, regardless of unexpected stored
fields. Bracket owner/list and league member display reuse it. Their queries no
longer fetch email. Own-account representations remain separate.

`require_private_league_membership` validates UUID/existence, determines private state
from stored password presence, strips the hash, reads the requester's current
membership and returns only safe league metadata plus membership/error. Membership
means an existing league_members row (the current schema has no separate active flag).
Owner/admin never substitutes for private membership. Public member/stat routes keep
the original member/owner/admin predicate. No schema or ACL change.

`require_auth_for_league_scope` authenticates only explicit private leaderboard reads;
public and global anonymous behavior stays intact. The classification lookup fails
closed on DB errors. Private scope is enforced even when there are no scores, and
membership removal takes effect without a new token. The helper is called before
member-specific queries. Existing 400 invalid ID, 404 absent league and JSON error
403 forbidden patterns are retained; private anonymous/invalid auth yields 401.

Discovery preserves the aggregate count explicitly permitted by the prompt and used
by FindLeaguesPage. Private owner identity is omitted for nonmembers, including
nonmember owners/admins; membership reveals it in the existing safe context. The UI
does not depend on removed other-user emails, hash strings or discovery owner IDs;
no frontend compatibility change is needed. Existing unused frontend type fields
are left alone rather than redesigning the client.

## Regression discipline and deferred work

`scripts/nc02a1_acceptance_metadata.py` links each converted test to its original
NC-01 finding, requirement and canonical gap. Original decorators are preserved as
pre-repair metadata, not rewritten historical evidence. Sixteen existing regressions
are explicitly dispositioned: fifteen acceptance transitions and one retained
known-gap observation moved to the unscoped global leaderboard. The mixed
private_bracket_bypass test still proves general saved-detail readability while
requiring denial of private-scoped lists. No source NC-01 JSON/report is overwritten.

Seven new guarded API sequences cover the complete private role matrix (including
current/past champion stats), owner without membership, immediate revocation,
discovery/password state, recursive sensitive-field absence and serializer allowlist,
error contracts, and preserved public/general competition behavior. They reuse the
existing enrolled NC-01C harness and fixtures without expanding safety guards.
The fixed runner executes auth/bracket/league/scoring regression plus these cases,
and writes only new NC-02A1 validation evidence.

| Canonical gap | NC-02A1 status | Limit |
| --- | --- | --- |
| GAP-EMAIL-001 | FIXED | Own-account email remains intentional |
| GAP-ADMIN-DRAFT-001 | FIXED | Read privacy only; admin mutation remains deferred |
| GAP-PRIVATE-LIST-001 | FIXED | Explicit private relationship only |
| GAP-PRIVATE-MEMBERS-001 | FIXED | Owner/admin require membership |
| GAP-PRIVATE-STATS-001 | FIXED | Public predicate and scoring math unchanged |
| GAP-PRIVATE-SCORES-001 | PARTIALLY FIXED | Private scope protected; global/public saved/draft eligibility and existing client filtering remain deferred |
| GAP-PRIVATE-DETAIL-001 | DEFERRED | Current prompt explicitly preserves general-public saved-detail rule; not claimed fixed |
| NC-02A1-P8-HASH | FIXED | Newly approved repair of formerly unreviewed hash-valued response, not invented historical canonical gap |

P4/P5/P9 still require NC-02A2. Global stored draft-score exposure is deliberately
retained. Other gaps remain unchanged: arbitrary admin mutation, games-only resave,
backend/frontend final lock, frontend undo, champion/finalist bonuses, snapshot tie
order, standings provider/freeze, season sources, and league lifecycle/delete policy.
Their passing known-gap regressions confirm retained behavior, not requirement compliance.
No claim that the entire privacy/competition domain is complete.

## Validation and cleanup

Validation results and final cleanup are recorded in `db/records/nc_02a1_privacy_access.json`
and the separate full-suite/privacy-only validation records. The suite uses only the
guarded enrolled local Supabase environment, resets before/after every live sequence,
suppresses raw sensitive exception diagnostics, and retains canonical checksum proofs.

Commands:

```text
python -B scripts/run_privacy_access_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B scripts/run_privacy_access_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations --privacy-only
python -B -m unittest discover -s tests/offline -p "test_*.py"
python -B scripts/validate_consolidated_baseline.py
```

App formatting is deliberately limited to the added helpers and changed lines to
avoid formatting unrelated legacy code. A structural comparison permits changes in
only the seven inventoried existing read handlers; all other application functions
must remain unchanged. Syntax, Black for changed tests/tooling/helpers, whitespace,
artifact credential/hash-pattern scans, semantic schema/marker verification and
canonical readiness/lease/socket/email/job checks complete the validation.
No production contact, deployment, production credential use or production mutation.

Next phase: **NC-02A2 — Draft/saved competitive visibility and eligibility**.
Not started. STOP after NC-02A1 review.

Final validation: 130 existing auth/bracket/league/scoring/history regressions passed,
7 new direct API acceptance sequences passed, and 217 offline safety tests passed.
The initial 137-case attempt had one test-only guard refusal: unscoped /brackets was
outside NC-01C admission. It was corrected to the already allowed public-league list
route without broadening guards. All 7 acceptance cases were then rerun and passed;
the initial attempt remains recorded rather than being represented as a passing run.
Thirteen prior KNOWN-GAP tests became acceptance coverage, one prior approved
regression was adapted, one unreviewed hash test is now explicitly P8-approved, and
one draft-score known-gap test remains a gap regression on the preserved global route.

Final semantic schema/marker v2 verification, fixture checksum, SEEDED nc-fixtures-v1,
Flask socket refusal, released advisory lease, same-process cleared email capture and
disabled jobs all passed. Black, syntax/AST, original-CRLF-aware whitespace, source
preservation and credential/hash-pattern audits passed. No configured Python static
type-checker exists; no frontend/TypeScript source changed. Production untouched.
