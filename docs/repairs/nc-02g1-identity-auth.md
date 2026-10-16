# NC-02G1 — Identity, registration and login correctness

## Scope and checkpoints

Implements A1–A7 and A17–A20 only. Backend started clean on main at
`e28a5231fe2e435f93ff2af7804de298fb1a2893`; frontend at
`4a5718ebeeb5557e8bb516d8b9fb77297c7435e3`.
No production query, migration, deployment, bulk password change or identity repair.
No Supabase Auth migration. No username/email editor, impersonation or mandatory
email verification. NC-02G2 reset-token lifecycle/reset UI/JWT revocation deferred.

## Before repair and route inventory

Architecture remains browser -> Flask -> server-side Supabase/PostgreSQL,
custom bcrypt-compatible authentication and PyJWT. Users hold text username,
nullable historical email/password, UUID identity and admin flag. Existing unique
constraints compare raw text; email has two pre-existing raw unique constraints.
These constraints are retained. User-table browser access remains denied.

Targeted guarded local before evidence is `db/records/nc_02g1_before.json`.
It proves truthy nonobject registration returned sanitized 500; mixed-case and
lowercase username accounts could both register; registration canonicalized email
but login lowercased exact username lookup; registration preserved password spaces
while login stripped them. Unknown identity/wrong password already shared one 401
message, with missing fields 400. Racy uniqueness exceptions formerly became 500.
Historical NC-01 evidence is not rewritten.

Routes and retained architecture:

| Route | Shape/lookup | Success and fields | Error contract after G1 |
| --- | --- | --- | --- |
| POST /auth/register | JSON object; string username/email/password; normalized structural uniqueness; one INSERT | 201 message + own user id/email/username/created_at; no JWT/auto-login | malformed/invalid 400; unavailable identity 409; rate 429; internal failure sanitized 503 |
| POST /auth/login | JSON object; existing email-or-username detection; normalized indexed DB lookup; exact password | 200 message/token + own id/email/username/is_admin/created_at | malformed/missing typed fields 400; unknown/incorrect/formatted nonexistent identity identical 401; rate 429; internal failure sanitized 503 |
| GET /auth/test-me | existing Bearer JWT | original identity/admin/expiry claims; no password/reset data | existing auth errors unchanged |
| GET /admin/env-check | existing Bearer + current DB admin check | configuration presence only; no credential values | original authorization unchanged |
| POST /auth/forgot-password | existing email/username request/reset-email behavior | unchanged | unchanged, G2 deferred |
| POST /auth/reset-password | existing token/new_password reset workflow | unchanged | unchanged, G2 deferred |

No product account/profile identity editing endpoint or admin user-management/
impersonation endpoint exists. Frontend AccountPage uses own session/reset request;
no profile-update API is introduced. Trusted server-role direct DB writes remain
possible under existing architecture but cannot bypass normalized unique indexes.

## Shared identity normalization

`identity_auth_service.py` centralizes display/key/email and password operations.
Username display must be string, trim outer whitespace, preserve chosen case.
The existing naming policy remains 3–30 ASCII letters/digits/underscore.
Valid username keys use lowercase trimmed ASCII; original display is not lowercased.

New email storage is lowercase canonical identity, trimmed, with the existing
simple non-whitespace local@domain.suffix validation (not a new RFC parser).
SQL `auth_identity_key(text)` implements lower(trim(value)). Its explicit trim
set equals Python 3.14 Unicode whitespace, including tabs/nonbreaking space.
For emails the application delegates normalization to that same trusted SQL
function: it does not assume Python Unicode lowercase matches PostgreSQL locale
lowercase. Login uses `find_auth_user(text,text)`, comparing the exact same key
function used by both unique indexes. No string-built SQL or wildcard lookup.
The existing email-or-username identifier detection and both API field names stay.

The frontend trims identity inputs for convenience and preserves display case;
canonical comparison/storage remains authoritative in PostgreSQL. It does not
case-fold or otherwise change passwords. G2 can reuse normalized email lookup.
Existing stored identities are never rewritten by migration.

## Exact password policy and hash compatibility

New registration passwords must be strings of 8–128 Python Unicode code points,
including spaces, without uppercase/digit/symbol requirements. No trimming,
case folding or Unicode normalization. Astral characters count once in Python;
frontend uses Array.from to match code-point counting. The backend rejects invalid
UTF-8 surrogate text as a sanitized field error. UTF-8 byte length is not the new
password policy: multibyte inputs exceeding 72 bytes remain valid through 128
code points.

New stored format is `nc-bcrypt-sha256-v1$` followed by bcrypt output. Bcrypt input
is Base64(SHA256(domain || exact UTF-8 password)); the fixed domain is
`NBA-Corner/account-password/v1` followed by a NUL separator. The resulting bcrypt
input is 44 ASCII bytes. Random bcrypt salts and existing configured BCRYPT_ROUNDS
(default 12) remain. No raw input is truncated and distinct suffixes after byte 72
remain distinct. SHA-256 is an encoding step before salted adaptive bcrypt, not a
replacement password hash. Stored format is never returned publicly.

Verification recognizes both this version and legacy raw $2a$/$2b$/$2y$ hashes.
Legacy correct passwords and whitespace variants are tested. Installed bcrypt 5
already refuses raw inputs over 72 bytes; legacy verification explicitly refuses
rather than truncates them. There is no bulk migration or opportunistic rehash.
A historically truncated long legacy password cannot be reconstructed from its
hash; this phase neither guesses one nor accepts new truncated passwords.
Existing synthetic legacy accounts retain their unchanged hashes and authenticate.

An unusable random dummy hash uses the new versioned path for unknown identities,
so valid long-password attempts do not deliberately skip bcrypt merely because
an account is absent. No timing side-channel elimination is claimed or proven.
Existing IP/identifier rate limits and proxy behavior are unchanged. Grouped test
matrices disable limits in their own context only; an explicit test retains 429.

Reset routes, their existing password policy/hash writes, token lifecycle and
session semantics are deliberately untouched for G2. Legacy-format verification
keeps reset-produced hashes login-compatible. JWT creation/validation, claims,
seven-day lifetime, storage and authorization are unchanged.

## Structural uniqueness and atomic registration

`0010_nc_02g1_identity_auth.sql` adds two unique expression indexes on
`auth_identity_key(username)` and `auth_identity_key(email)`, plus a nonblank/
nonnull identity CHECK. It preflights normalized collisions and invalid blanks
before constraints/indexes. Any failure rolls back the migration. No automatic
rename, canonicalization of old rows, deletion or winner selection occurs.

Registration uses one row INSERT as its atomic boundary. No mutation RPC is
necessary. SQLSTATE 23505 is recognized internally and becomes only the stable
409 `Email or username already in use`; raw exception/SQL/index/connection data
is never returned or logged. Other internal failures return a fixed 503 category.
Application prechecks are not used as race authority. Two real PostgreSQL sessions
prove both normalized username and email contention: second writer waits, exactly
one INSERT commits and the other receives structural uniqueness failure. Route
acceptance verifies real duplicate responses; offline acceptance injects the same
race exception path and confirms sanitized 409 rather than 500.

## Privacy, admin boundaries and frontend

Registration/login expose only the caller's account allowlist. `public_user`,
bracket/league/global/league-history serializers remain unchanged and exclude
another account's email and all credential/reset fields. Ordinary admin product
reads retain the same safe serialization. Admin flags in login input cannot bypass
password checking; registration never accepts an admin flag. No hidden account
lookup or identity-mutation product route was added.

Registration form shares code-point password policy and exact confirmation;
password contents are sent unchanged. Login preserves both identifier types and
exact password. Both forms map response status to safe product messages instead
of displaying arbitrary server text. Existing navigation, signup/login events,
localStorage and AuthContext behavior remain. No reset completion UI or new email
verification step.

## Database security, migration and local proof

New `auth_identity_key(text)` is postgres-owned SQL IMMUTABLE STRICT INVOKER;
`find_auth_user(text,text)` is postgres-owned SQL STABLE INVOKER. Both pin
search_path=pg_catalog,public and execute only for postgres/service_role. The
latter returns only necessary auth fields to the trusted server; PUBLIC/anon/
authenticated cannot execute either function or read users. No browser mutation
RPC or grants are introduced.

Baseline and 0001–0009 are byte-identical. F2 verifier is frozen as
`verify_nc_02f2_schema.sql`. Current verifier preserves all unrelated assertions,
adds the exact two functions/ACL/bodies, two valid unique indexes and validated
CHECK, and updates only their catalog inventories. Reset's verifier SHA is pinned
forward without changing foundation/TABLES/VERSION/checksum inputs.

Fresh proof reuses the existing fixed local disposable database target and full
baseline-through-0009 machinery, then tests four invalid preflights, applies 0010,
runs semantic/security verification, actual Flask registration/login/JWT handlers
over that fresh database, structural access/uniqueness and both real identity races. Prior F2/F1/E proof groups remain included. The disposable database
is removed even on failure. No production source is used.

## Validation and corrected development failures

Use only enrolled isolated local settings:

```
python scripts/run_identity_auth_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -m unittest discover -s tests/offline -q
python scripts/prove_identity_auth_migration.py
python scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
```

Frontend: existing `node --test scripts/test-*.cjs`, `npm run build`, baseline-aware
ESLint comparison. New auth tests execute real form handlers with fixed fetch/
navigation doubles. No browser/E2E framework or external request is introduced.
Existing lint debt is reported, not called clean.

The separate G1 regression runner explicitly adapts approved conflict400->409,
nonobject500->400 and exact-space-login401->200 expectations. The old case-distinct
account scenario is superseded by G1 normalized uniqueness/race acceptance.
Original characterization sources and evidence remain intact. All A–F regressions,
including unchanged reset behavior, remain applicable apart from those documented
approved changes. A packaging defect was found when historical tests prepended
their directory and shadowed the initial service name; the distinct
identity_auth_service module fixes it. No application assertion was weakened.
Initial grouped-matrix rate-limit setup failures are separately recorded. The
legacy duplicate-case adapter was corrected to preserve its initial 201 and change
only the later conflict assertion; the failed case is rechecked independently.
The proof-only psql JSON adapter also needed aligned-output whitespace handling.
Final totals and cleanup evidence are in `db/records/nc_02g1_identity_auth.json`.

## Cleanup and future rollout prerequisites

Canonical local fixture remains SEEDED/nc-fixtures-v1 with four original users,
30 standings and checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`.
Transient auth accounts must be reset; no fixture password/identity changes.
Flask stopped, leases/locks released, mailbox empty, jobs off, no unrestricted
mutation and disposable database removed must be verified before commits.

Separate production authorization would require backup; normalized username/email
collision and invalid/blank identity preflight; migration0010 review; hash-format/
legacy compatibility review; coordinated backend/frontend rollout. Never auto-fix
production collisions. No production contact is performed by G1.

Next approved phase is NC-02G2 — password reset, reset-token security and JWT
revocation. It has not begun.


## Final local result

- 225 unique applicable backend cases verified: 224 passed the complete run and
  the single duplicate-username adapter expectation passed its corrective recheck.
  Initial evidence is preserved. Eight final G1 live groups passed against final
  source, including malformed raw values/NUL/surrogate input, normalization,
  password boundaries/whitespace/long Unicode, legacy login and rate-limit policy.
- 325 offline safety tests and 54 frontend tests passed. TypeScript/Vite build
  passed with existing browser-data-age and bundle-size warnings. Frontend lint
  remains its existing 83 errors/one warning, zero new diagnostics.
- Fresh baseline through 0010, 14 G1 proof groups (including actual route/JWT
  acceptance and two real uniqueness races), 17 F2, nine F1 and 21 post-F2 E SQL
  groups passed. Strict semantic/security verifier and marker verifier passed.
- Canonical SEEDED/nc-fixtures-v1 checksum is unchanged; four original legacy
  bcrypt users, 30 standings, no temporary users/competition/league/history/reset
  records, no active advisory locks, Flask stopped, mailbox empty, jobs and both
  unrestricted/scoped mutation admission off. Disposable DB removed. Legacy
  harness=UNMET denotes no active lease; complete readiness is PASS/AVAILABLE_GUARDED.
- Black, changed-line whitespace, compilation, baseline import comparison,
  credential/privacy/file review and exact baseline-through-0009 preservation
  passed. Only register/login function bodies changed; JWT/reset/public serializers,
  scoring, leagues and canonical fixtures are preserved.
- Normal independent commits are reported in the completing response. No
  production contact occurred. G2 has not begun.
