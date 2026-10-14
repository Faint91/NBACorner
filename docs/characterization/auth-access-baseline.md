# NC-01A — Auth / account / access-control current-behavior baseline

No behavior was changed. No product auth requirements were inferred from source.
NC-01A1 applies the already-approved requirement: **Other users may see another
user's bracket only if it is saved; email addresses must never be exposed.**
The live saved-bracket owner-email finding is KNOWN GAP: saved-bracket visibility
is permitted, but email exposure violates the requirement. The combined row is
counted once; its visibility and email findings are not conflated or duplicated.
Counts: MATCHES REQUIREMENT=0; KNOWN GAP=1; REQUIREMENT NOT YET REVIEWED=32;
UNCLEAR / NEEDS BUSINESS CHECKPOINT=0 (33 rows total). Other requirements remain
unreviewed. Passing characterization tests records behavior; it does not establish
full product compliance. Safety constraints are separately verified.

## Scope and starting checkpoint

Frontend main ce54143006f0409265937f5d548286d0b100d454; backend main
b0e87c8470b14417e48d2bd42a5521290918afbc. Both initially clean. Frontend/app.py/
application schema/baseline unchanged. All API mutations ran through the approved
GuardedHarness with explicit NC-01A scope and existing identity/marker/baseline/
fixture/email/provider/job/lease/startup/admission/egress gates. No production contact.

25 live isolated sequences and 8 static source checks passed. Live cases reset before
and after every sequence; no static frontend finding is claimed as browser evidence.
No browser automation or frontend changes. Bracket work was limited to one minimal
user-B row per saved/draft access case, with no matches/progression/save workflow.
League/scoring/standings/rollover/history business semantics remain deferred.

## Route inventory

| Method | Path | Auth | Admin | Primary data | Effect | Frontend caller |
| --- | --- | --- | --- | --- | --- | --- |
| POST | /auth/register | No | No | users lookup/insert | Write | RegisterPage |
| POST | /auth/login | No | No | users lookup; JWT creation | DB read/session issue | LoginPage; api/auth |
| GET | /auth/test-me | JWT | No | Decoded JWT only | Read | No caller found |
| POST | /auth/forgot-password | No | No | users lookup; password_resets insert; email capture/live production transport | Write/send | ResetPasswordPage; AccountPage |
| POST | /auth/reset-password | No | No | password_resets lookup/update; users password update | Write | No completion caller found |
| GET | /admin/env-check | JWT | JWT claim + DB role | users lookup; sanitized environment presence | Read | No caller found |
| POST | /test-email | JWT | JWT claim + DB role | users lookup; email send | Send | No caller found |
| GET/HEAD | /health | Optional health token; no JWT | No | In-memory rate buckets | Health/read | No auth UI caller found |
| GET | / | No | No | None | Read | No auth UI caller found |
| GET | /bracket/<id> | JWT | Owner/admin bypass draft restriction | users/brackets/seasons/matches/teams reads; owner display | Read; boundary only | BracketPage; domain semantics deferred |
| GET | /brackets | JWT | No | saved brackets/users; display includes email | Read; static exposure only | Domain UI; NC-01B deferred |
| GET | /leagues/<id>/members | JWT | Membership/owner/admin logic | leagues/members/users; display includes email | Read; static exposure only | LeagueInfoPage; NC-01C deferred |

No server logout, token-refresh/introspection route (beyond auth/test-me), dedicated
account/profile read/write or arbitrary user lookup endpoint exists. AccountPage is
an account UI backed by cached auth user and feature-summary reads, not a profile API.
The harness-only /__test__/identity route is temporary/capability-protected and not a
production app route or product identity feature.

## Auth implementation / effective enforcement

Custom PyJWT, not Supabase Auth: generate_token creates user_id, username, is_admin,
exp (~7 days). decode_token checks signature/expiration with configured algorithm;
require_auth requires case-sensitive Bearer header and places claims in request.user.
The identity endpoint returns those claims without refreshing the user DB row.
JWT algorithm defaults HS256; signing key has a hardcoded development fallback when
configuration is missing (value intentionally omitted). Production configuration was
not inspected. The local harness uses its isolated in-memory signing key.

bcrypt uses configurable cost, default 12, for registration/reset. Registration
lowercases/strips email, strips but preserves username case, and preserves password
whitespace. Login lowercases/strips both identifiers and strips password whitespace.
Email takes precedence over username when both supplied. Email/username regexes and
password length/lowercase/uppercase/digit/symbol checks are existing code, not approved
new rules. The locally tested fixture usernames contain hyphens and fail the current
username regex; email login works. Temporary test usernames use the allowed format.

The effective product access layers are Flask JWT decorator, endpoint owner/admin
checks and server database queries. /admin/env-check and /test-email require both the
JWT admin claim and a DB admin recheck. Bracket display rechecks viewer role in DB and
uses owner/is_done boundary. Frontend is_admin checks only affect UI display/navigation.
The contained DB ACL/RLS design stays unchanged: native service-role server requests
are not per-user Supabase Auth sessions; auth.uid()-based policies do not receive the
custom Flask JWT identity. Direct ordinary-role access remains denied. No RLS/auth
redesign was attempted.

## Rate limits and test differences

Static map: login 10/IP/60s and 5/identifier/60s; forgot-password 5/IP/300s and
3/identifier/300s; register 3/IP/hour; health 30/IP/minute. get_client_ip honors the
first X-Forwarded-For value; deployment proxy trust is not proven here. Unknown buckets
fail open; test_email_ip is used by the endpoint but absent from RATE_LIMITS.
DISABLE_RATE_LIMITS defaults false and remained false in live tests. Each fresh guarded
app import resets process-local buckets; no threshold/load test or spoofing was run.
Local email capture/reset-link origin, random JWT key and fixture credentials differ
intentionally from production delivery/configuration; production values were not used.

## Sensitive fields and cross-user boundary

Registration returns message/user with id/email/username/created_at; no JWT, hash,
reset secret or admin flag. Login returns JWT plus own user id/email/username/is_admin/
created_at. Reports retain only field names and safe TTL/algorithm metadata, not JWTs.
/auth/test-me returns user_id/username/is_admin/exp from claims, not an account profile.
Admin diagnostics return variable names/presence and set/unset previews, never values.
Password-reset API responses contain message/error only; random reset tokens reside
in the local DB/captured link and were inspected only in memory. No password hashes,
reset tokens, provider/service credentials or authorization values appear in evidence.

Live: user A can read saved B bracket owner id/username/email; owner object contains
no password/reset/admin fields. A receives 403 for B draft; B owner and admin receive
200. No arbitrary profile read/write exists. The saved-bracket response's email
exposure is a confirmed KNOWN GAP against the approved no-email-exposure rule;
saved-bracket readability itself is consistent with that rule. The ordinary-user
draft denial supports saved-only visibility; owner/admin requirements remain
separately unreviewed. Static saved-bracket-list and league-member queries include
email. NC-01A did not prove user-facing runtime email emission for those endpoints.
NC-01C — League characterization must verify league-member runtime exposure against
the approved rule; NC-01B retains saved-bracket-list coverage. The static combined
row remains REQUIREMENT NOT YET REVIEWED, not a second confirmed runtime gap.

## Completion / gap matrix

Each row is a current-behavior baseline, not a desired-behavior assertion. Evidence
source is explicit: live guarded Flask or static source. Full status/shape summaries
and safe facts are in db/records/nc_01a_auth_access.json. Test naming is
current_behavior__auth__<scenario> throughout.

### Registration

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| duplicate_email | Duplicate email is normalized to lowercase and rejected with 400. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve email normalization and duplicate response policy? |
| duplicate_username | Duplicate valid username rejected with 400. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve username uniqueness and normalization? |
| registration_invalid_fields | Missing fields, invalid email and invalid username return 400. | REQUIREMENT NOT YET REVIEWED | Live local sequence | What request validation contract should be approved? |
| registration_nonobject | Truthy non-object JSON causes sanitized 500. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should non-object JSON be an explicit client error? |
| registration_password_policy | Weak or non-string passwords rejected with 400. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve the current length/character policy? |
| valid_registration | Valid synthetic registration returns 201, message/user, no JWT or auto-login. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should registration create a session or require login? |

### Login/session

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| fixture_username_login | Fixture usernames contain hyphens and are rejected by current username-login regex; their email login works. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should username format and fixture/user identity conventions be reconciled later? |
| login_failures | Wrong password/unknown user/malformed identifier return 401; missing fields return 400. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve failure categories and enumeration behavior? |
| login_metadata | Email login succeeds with case/outer whitespace normalization; JWT contains identity/admin/expiry and ~7-day expiration. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve JWT lifetime, claims and email-login normalization? |
| password_whitespace | Registration preserves password whitespace while login strips it, preventing login with that stored password. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should password normalization be consistent? |
| public_health | Local health returns 200 without JWT when no health token is configured; identity route remains harness-protected. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve health endpoint and token policy per deployment configuration? |
| username_case_resolution | Username storage is case-sensitive, login lowercases identifiers; case-distinct registered accounts can resolve to the lowercase account. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve case handling and which account a username identifies? |
| implementation_defaults | Custom PyJWT uses user_id/username/is_admin/exp, seven-day tokens, configurable algorithm/key with a hardcoded development fallback; bcrypt defaults to cost 12. Supabase Auth is not the app identity model. | REQUIREMENT NOT YET REVIEWED | Static source inspection: generate_token; decode_token; environment globals | Approve key configuration, lifetime, claim freshness and hashing policy? |
| rate_limit_static | In-memory rate limits: login 10/IP/60s and 5/identifier/60s; forgot 5/IP/300s and 3/identifier/300s; register 3/IP/hour. X-Forwarded-For is honored; unknown buckets fail open. test_email_ip is missing from the configured map. | REQUIREMENT NOT YET REVIEWED | Static source inspection: RATE_LIMITS; get_client_ip; is_rate_limited | Approve proxy trust, thresholds and unknown-bucket behavior? |

### User/profile access

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| cross_user_draft_boundary | Ordinary A gets 403 for B draft; B owner and admin get 200. Only access boundary is tested. Ordinary-user denial supports the approved saved-only visibility rule; separate owner/admin requirements remain unreviewed. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve draft/owner/admin identity visibility boundaries? |
| cross_user_saved_owner_display | Ordinary A can read saved B bracket and its owner id/username/email; no password/reset/admin fields in owner object. Approved requirement permits saved-bracket visibility but forbids email exposure. Visibility is consistent; owner-email exposure is the gap. | KNOWN GAP | Live local sequence | None: the no-email-exposure requirement is already approved. |
| required_identity_access | Missing, malformed and expired tokens return 401; A/B identities come from their JWT claims. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve identity/profile payload and session verification contract? |
| account_route_absence | No dedicated account/profile read/write or server logout route; auth/test-me returns JWT claims, and AccountPage uses cached user fields. | REQUIREMENT NOT YET REVIEWED | Static source inspection: Flask route inventory; AccountPage.tsx; test_me | Which profile/account mutation and session-revocation features are required? |

### Admin authorization

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| admin_boundary | Admin env diagnostic: missing auth 401, ordinary 403, admin 200; response only masks configuration presence. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve admin diagnostic visibility and response schema? |
| admin_claim_db_recheck | Locally signed ordinary-user JWT claiming admin is returned by identity endpoint, but DB admin recheck rejects admin diagnostic with 403. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Which authorization decisions must refresh database roles rather than trust claims? |

### Password reset

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| reset_completion_and_sessions | Valid unused reset changes password and marks token used; old password fails/new succeeds; pre-reset JWT still valid. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should password changes revoke existing sessions? |
| reset_delivery_failure | A capture transport reporting delivery failure still yields neutral 200 and stored unused reset. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve ignored delivery result and operational visibility? |
| reset_expired_invalid | Expired and invalid tokens return 400; expired token remains unused. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve expired/invalid token behavior and cleanup policy? |
| reset_invalid_payload | Missing fields and weak new password return 400; truthy non-object JSON returns sanitized 500. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve input validation and response categories? |
| reset_request_metadata | Existing user request returns neutral 200; stores unused reset and captures a loopback link with ~24-hour expiry. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve lifetime, link contract, storage and delivery behavior? |
| reset_request_repeated | Repeated requests create distinct unused records and captured messages; older record remains unused. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Should newer requests invalidate earlier reset tokens? |
| reset_request_unknown | Unknown/missing/malformed identifiers return neutral 200 without reset rows or email. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve neutral response and error categories? |

### Sensitive-field exposure

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| test_email_boundary | Admin test-email requires JWT + DB admin; missing auth 401/ordinary 403/admin 200, sending to capture only. | REQUIREMENT NOT YET REVIEWED | Live local sequence | Approve test-email authorization and operational endpoint availability? |
| display_fields_static | Existing bracket owner/list and league-member display sources include id/username/email; league access semantics are deferred. Auth payloads omit password/reset hashes; admin env response masks values. Approved no-email-exposure rule applies; the live saved-bracket gap is counted separately. | REQUIREMENT NOT YET REVIEWED | Static source inspection: get_bracket_by_id; list_all_brackets; get_league_members; auth responses; league runtime emission not proven | NC-01C: verify whether league-member API emits email to users against the approved rule. NC-01B: verify saved-bracket listing. |

### Frontend auth behavior

| Scenario/test | Observed current behavior | Classification | Coverage/evidence | Future business checkpoint |
| --- | --- | --- | --- | --- |
| frontend_admin_display | Admin UI is driven by cached user.is_admin checks; tested server admin diagnostic independently verifies JWT claim and DB role. | REQUIREMENT NOT YET REVIEWED | Static source inspection: AdminPage.tsx; AuthContext.tsx; admin_env_check | Approve cached role refresh and server enforcement coverage? |
| frontend_login_register_flow | Login caches returned session and navigates dashboard; registration navigates login with registered/email state; callers use VITE_API_URL. | REQUIREMENT NOT YET REVIEWED | Static source inspection: LoginPage.tsx; RegisterPage.tsx; api/client.ts | Approve login/register navigation and API environment contract? |
| frontend_reset_request_only | ResetPasswordPage requests forgot-password only; no token-query/new-password completion UI or reset-password POST is present. AccountPage also requests reset email. | REQUIREMENT NOT YET REVIEWED | Static source inspection: ResetPasswordPage.tsx; AccountPage.tsx; main.tsx | What complete browser reset flow should be approved? |
| frontend_storage_logout_guard | AuthContext stores/restores auth_token/auth_user in localStorage; logout clears client state only; ProtectedRoute checks token presence, not validity. | REQUIREMENT NOT YET REVIEWED | Static source inspection: AuthContext.tsx; main.tsx | Approve storage, logout/revocation and expired-session handling? |

## Running / cleanup / validation

```text
python -B scripts/run_auth_characterization.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -B -m unittest discover -s tests/offline -p "test_*.py"
```

The fixed runner selects only NC-01A live/static classes. No arbitrary test selector
or global mutation bypass. Default smoke scope still denies registration/reset; the
explicit auth scope denies other feature/job paths. Test-only helpers restrict emails
to reserved domains, signed token variants to local ephemeral credentials, reset
inspection/expiration to this context's synthetic subjects, and boundary fixture to
one user-B bracket row. No product code change was necessary.

Each live sequence ended with Flask shutdown, lease release, cleared capture and
canonical nc-fixtures-v1 checksum:
a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0.
Final independent readiness/semantic application/marker ACL verification passed.
Temporary registered accounts/password changes/reset records/brackets were removed.
Foundation is again 4 users, 2 seasons, 30 teams, 30 fictional standings; other tables
empty. Global mutation permission remains false outside an explicit verified context.

202 offline safety tests passed, including four auth-scope refusal checks; 25 live
current-behavior tests and 8 static tests passed. Formatting/syntax/whitespace and
secret/log/scope scans passed. Logs contain status/shape only; runner failure traces
are sanitized. No browser, live provider, production email, cron, deployment or
production data/secrets were used. Product/app.py, frontend, baseline and fixtures
remain byte-for-byte unchanged. Future single phase candidate: NC-01B Bracket
characterization baseline; not started. No auth fix or requirement change proposed.

## NC-01A1 classification correction

Starting backend main a0d5d35239f87bfef47510ae4194ba7c3d84fb53 and frontend main
ce54143006f0409265937f5d548286d0b100d454 were clean. Only this document and the
sanitized evidence record changed. The saved-bracket owner-email row changed from
REQUIREMENT NOT YET REVIEWED to KNOWN GAP using the explicitly approved requirement.
Original current-behavior observations, HTTP summaries, facts, test results and
cleanup evidence are unchanged. No live verification was needed or rerun.

NC-01A characterization is complete and its classification is now corrected;
full compliance with the approved requirement is not passed because the confirmed
email-exposure gap remains. This phase does not remediate it. No application,
frontend, fixture, environment-safety or production changes were made. NC-01B —
Bracket characterization baseline is the recommended next phase and has not begun.
