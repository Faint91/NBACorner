# NC-02G2 — Password reset and session revocation

Scope: approved A8–A16 only, local isolated Supabase. No production contact,
credentials, live reset links, account editing, email verification, session table,
refresh-token redesign, or deployment. G1 registration/login identity/password
policy remains authoritative. Starting clean main checkpoints: backend
6eb31070c55b2a8b2c789fafcf90adea55f017b8 and frontend
2cfc7acb674b71f0bddeded77554d7ba25c164b5.

## Before/after evidence

`db/records/nc_02g2_before.json` preserves four focused, guarded pre-change
characterizations without rewriting NC-01: raw DB token storage, approximately
24-hour naive expiry, two simultaneously outstanding links, ignored email failure,
and old JWT still accepted after password reset. Used-token handling existed but
password update and marking used were separate writes. The frontend public
/reset-password page requested email only; it had no completion form.

G2 keeps the existing table and Flask/PyJWT/Brevo seams. The forward migration
0011 adds users.auth_version (integer, NOT NULL, default 0, nonnegative CHECK),
renames password_resets.token to token_digest, makes user_id non-null, adds
one-row-per-user uniqueness and a 64-lowercase-hex verifier CHECK, and converts
expiry/creation to timestamptz with explicit legacy UTC interpretation. Existing
unique digest index, FK cascade, RLS and browser containment remain in effect.
It deliberately deletes every legacy reset row and clears both obsolete user
reset fields. Baseline and migrations 0001–0010 remain byte-identical.

## Request, token, expiry and delivery

Request accepts a JSON object with the existing email or username identifier.
Malformed/missing/non-string/invalid-format inputs return controlled 400. Email
uses G1/PostgreSQL normalization and username uses the G1 normalized ASCII key.
Known/unknown valid identities, rate-limited requests, DB/issuance failures and
confirmed delivery failures all return the identical generic 200 message and
shape: “If an account matches, reset instructions will be sent.” There are no
existence, delivery, token or user-ID fields. Timing indistinguishability is NOT
claimed. Operator categories are fixed strings; transport exception payloads
are not logged by reset orchestration.

Python secrets.token_urlsafe(32) supplies 256 random bits as 43 URL-safe characters.
Only SHA-256 hex digest reaches PostgREST/database. High-entropy digest lookup
needs no application secret comparison; password checks retain bcrypt's comparison.
Raw token exists only in transient memory and the email URL (or guarded synthetic
in-memory capture), never normal JSON/evidence/storage/logging. Token format is
validated before hashing or RPC. No password or password hash appears in email.

The previous 24-hour TTL was hardcoded, not explicitly configured. Per the prompt,
G2 uses 60 minutes, assigned by DB clock at issuance. The token must be current,
unconsumed, attached to an existing user and have expires_at > clock_timestamp()
after the user lock is acquired. At the exact expiry boundary it is invalid.

`issue_password_reset` locks the existing user row first, deletes all previous
reset rows and inserts the new digest/expiry in one transaction. Concurrent
issuance serializes; only the final committed issuance remains current. Same
lock order is used for cancellation and completion. The established Brevo/capture
abstraction and existing effective production reset URL are preserved. Production
frontend host/route must be verified before release; local capture remains the
enrolled loopback URL and is cleared by every guarded cleanup.

On confirmed delivery false/exception, conditional cancellation deletes only
that request's user+digest and cannot delete a newer issuance. Public response
remains generic. Email is outside the database transaction: no distributed
atomicity is claimed. If cancellation itself fails, the request logs only a fixed
unavailable category; any persisted verifier remains bounded by its 60-minute
expiry. A delivery exception can be ambiguous about actual provider acceptance;
a cancelled link may therefore arrive invalid, requiring a new request.

## Completion transaction and JWTs

Completion validates JSON object, token string/format, password string and G1's
exact 8–128 Unicode-code-point policy. It uses the existing long-password-safe
nc-bcrypt-sha256-v1 hasher, with no trim/complexity requirement. Expensive hashing
occurs in Python before the narrow RPC. No database state changes during hashing.

`complete_password_reset` accepts digest plus a validated-format G1 password hash,
not a user ID. It resolves the token's user, locks that user, re-reads the current
unexpired/unconsumed digest, updates password AND increments auth_version AND
deletes every user reset row in the same transaction. Failure rolls back all
three. Replay, supersession and expiry cannot change password/version. Raw/unknown/
used/malformed links receive a fixed invalid-or-expired error; backend failures
return a sanitized 503. No separate administrator reset/bypass endpoint exists.

New login JWTs include current `av`. Algorithm, key, other claims and seven-day
expiry remain unchanged. Every authenticated path uses the shared decode helper:
signature/expiry plus existing user plus exact integer version equality on every
request; DB/read failure fails closed. No per-JWT rows. Missing `av` means 0 only;
it matches migrated version-0 users, then stops matching after successful reset.
Malformed/negative/noninteger/bool versions fail. A missing user fails. The normal
401 contract does not disclose version/revocation details. /auth/test-me excludes
av from its ordinary user JSON; login user/profile serializers remain explicit.
The required signed JWT claim is intentionally visible to its holder.

Two actual device logins and a pre-G2 missing-av token work before reset, fail
on subsequent requests after commit, and a new exact-password login succeeds.
Other users remain authenticated. A previously authorized in-flight request may
finish; G2 does not claim retroactive cancellation. Row locks serialize two
completions and issuance versus completion; either valid serialization can win,
but stale/superseded tokens cannot remain usable after both commits.

## Frontend and secret boundaries

Existing /reset-password query-link route now contains request and completion
states. The first inline bootstrap captures token into ephemeral memory and
history-replaces the URL BEFORE existing analytics initialization. It removes
all token query parameters, rejects duplicates via malformed-token state, and
preserves unrelated query/route/hash. The module consumes/deletes the bootstrap
slot; React StrictMode can read the module-cached value. No localStorage,
sessionStorage, analytics or console token writes. Tokens still necessarily
arrive in the initial HTTP URL/email, so infrastructure access-log/referrer
policy must be reviewed during coordinated release; browser cleanup cannot
retroactively erase hosting/email-provider logs.

Completion provides password+confirmation, shared G1 frontend code-point
validation, exact password submission, mismatch/error/success states, clear
refresh guidance to reopen the email link, and login link. Successful reset
clears token memory and existing auth/local JWT through normal logout; it never
auto-logs in. All four authenticated API hook methods clear normal auth state
on 401; public login/register/reset calls do not log out unrelated sessions on
ordinary public errors. Frontend does not render raw server diagnostics.

## Security, fixtures and verification

New RPCs are postgres-owned SECURITY INVOKER with pinned pg_catalog,public search
path, executable only by postgres/service_role; no PUBLIC/anon/authenticated
execute. Existing users/reset table and sequence containment is preserved.
No browser write grant on auth_version, no admin digest retrieval, no user-ID-only
reset path. Frozen verify_nc_02g1_schema.sql preserves the previous strict verifier.
Current verifier extends only approved G2 inventories/types/constraints/indexes/
function bodies/security; reset helper pins its reviewed SHA forward.

nc-fixtures-v1's original identity/checksum is frozen by projecting auth_version
out of its v1 user JSON. This is an explicit schema-extension compatibility rule,
not a checksum replacement. A separate readiness assertion requires every
canonical user version = 0. Seed helpers use explicit existing columns so the
new default applies; no passwords/identities change and no live reset rows are
added to foundation. Fixed checksum:
a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0.

Commands (enrolled local target only):

```text
python scripts/run_password_reset_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -m unittest discover -s tests/offline -q
python scripts/prove_password_reset_migration.py
python scripts/local_supabase_environment.py verify
python scripts/reset_local_fixtures.py --config C:/NBACorner/backend/.env.test.nba-local.local --verify-only
```

Frontend: node --test scripts/test-*.cjs, npm run build, and baseline-aware ESLint
comparison. Existing lint debt is reported, not called clean. Actual form handlers,
pre-analytics URL bootstrap and API 401 behavior execute with local deterministic
doubles; no new browser framework/external test traffic is introduced.

The G2 runner explicitly supersedes old raw-token/24-hour/preserved-session reset
contracts and request-only UI expectation while retaining historical evidence.
G1 normalization/password cases run with the required additional av claim only.
The original default/signing/static protections remain, with the obsolete inline
bcrypt substring assertion adapted to delegation to the unchanged G1 hasher.

Fresh proof restores baseline through 0011 in the fixed disposable LOCAL database,
retains prior SQL proof groups, verifies legacy invalidation, exact expiry with a
transactionally controlled clock, update-fault rollback, browser ACL denial,
actual Flask request/completion/login/JWTs, and real two-session issue/issue,
complete/complete, issue/complete and complete/issue lock contention. It removes
the disposable database even on failure. Proof SQL uses named dollar delimiters
to avoid collision with G1's versioned bcrypt hash prefix.

Final validation counts, cleanup assertions and file audit are recorded in
`db/records/nc_02g2_password_reset_sessions.json` plus focused/live/fresh evidence.

## Production readiness — no production changes made

Separate release authorization requires backup, migration0011 review, reset-table
preflight (including duplicates/null users/legacy fields), auth_version default
and missing-av compatibility review, coordinated backend/frontend deployment,
and confirmation the email link points to the deployed frontend reset route.
Deployment INTENTIONALLY INVALIDATES ALL pre-G2 reset links; users must request
new links. Version-0 compatibility preserves existing sessions through deployment,
but each user's successful reset revokes their old sessions immediately on
subsequent authenticated requests. No automatic next phase or deployment.

## Final local completion

The interrupted final focused run completed successfully: **16 groups, zero
failures/errors**, including G1 normalization/exact passwords and G2 reset,
legacy/multi-device revocation, replay, supersession, expiry, capture, input and
admin/privacy boundaries. Its saved evidence was reused on continuation.

**226 unique applicable backend cases** are verified across the preserved full
run, 146 successful first-recheck cases and the one corrective JWT-claim recheck.
`nc_02g2_validation.json` records exact coverage without falsely calling the
interrupted full run green. The G2 adapter adds only the required av expectation;
original identity/algorithm/seven-day expiry assertions remain. Historical NC-01
source/evidence is unchanged. A temporarily changed verifier byte pin interrupted
cleanup during development; canonical state was restored and every affected case
was rechecked. Earlier fixture-column/default, identifier-format and proof-dollar-
delimiter development failures are corrected and preserved in evidence.

**335 offline tests**, **60 frontend tests**, TypeScript/Vite build and the fresh
baseline-through-0011 proof passed. The fresh proof contains **15 G2 groups**, plus
14 G1, 17 F2, nine F1, 21 prior E and 21 post-F2 E groups. It explicitly reseeds
following G2 verification and checks original v1 checksum plus default version 0.
An actual JWT read succeeds during an uncommitted reset, then rejects immediately
after commit in the same application instance. All four real two-session reset
races pass. The disposable proof DB is absent.

Black (13 changed Python files and six scoped app functions), compilation,
whitespace, import and credential/token/file audits pass. Only six intended app
functions change; direct bcrypt/secrets imports became unused and were removed.
G1 validator/hasher, immutable baseline and migrations0001–0010 are byte-identical.
Frontend ESLint retains **82 existing errors and one warning**, down from 83 errors
and one warning; **zero new diagnostics**. Existing Vite/browser-data warnings
remain. The continuation did not rerun completed full tests or the frontend build.

Final current local verification confirms SEEDED/nc-fixtures-v1, unchanged checksum
`a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`,
four canonical users all at auth_version0, 30 standings, canonical season, zero
reset/competition/league/history/audit records, no advisory locks, Flask stopped,
mailbox empty in final focused cleanup, jobs disabled and both unrestricted and
scoped mutation admission false. No new scratch credentials/tokens remain.
Docker Desktop was restarted only to read and verify the enrolled local test state
following the session interruption; no reseeding or test restart was needed.

A8–A16 are complete locally. No production query, migration, reset email or deploy
occurred. Independent normal backend/frontend commits use the requested message;
commit IDs and clean main working trees are reported in the completion response.
No next phase has begun.
