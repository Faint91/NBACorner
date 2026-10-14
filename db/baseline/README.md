# NBA Corner secured current-state baseline

**This baseline is a consolidated current-state bootstrap. It is not historical migration history.**

Version: `nc-env-02-current-secured-v1`. Source backend checkpoint:
`da8c6695be0726ef3893ffefe605f6fa6e368f9c` (NC-ENV-01). NC-00 schema/catalog
exports supply the definitions; committed NC-SEC-01A/01B/01C/01D1 results supply
secured ACLs. Original audit capture date is not recorded in the exports. Source
SHA-256 anchors and security execution records identify evidence; file timestamps
are not asserted to be the capture date.

## Files and application order

- `manifest.json`: full expected application catalog, platform prerequisites,
  extension treatment, security semantics and preserved quirks.
- `000_current_schema.sql`: single transaction; prerequisites/empty-schema guards;
  target-local platform metadata snapshot; functions, tables/view/sequences;
  sequence defaults, keys/indexes, triggers, FKs, policies/RLS; secured object ACLs
  and scoped table/sequence defaults; semantic verification; platform preservation;
  commit. Function bodies precede tables as in the audit dump with transaction-local
  `check_function_bodies=false`. All FKs follow tables, including cyclic pointers.
- `verify_current_schema.sql`: standalone read-only catalog verifier; identical
  assertions are embedded before bootstrap commit.
- `validate_baseline.py`: stdlib offline lexer/evidence validator. No network,
  credentials, database connection or application imports.
- `provenance.json`: source/security evidence and artifact SHA-256 checksums.

Strict CREATE, empty-only bootstrap: no replacement, DROP, reset or idempotent
update. Extension-owned public objects are allowed; other public relations/routines
abort preflight. Other name conflicts fail CREATE. Errors roll back. Use a client
configured to stop on errors (future example: `psql -X -v ON_ERROR_STOP=1`). No
connection details are supplied here. Do not apply this file during NC-ENV-02.

## Supabase/platform prerequisites

NC-ENV-03 must first positively verify/enroll an isolated non-production target
and approve its empty application namespace. Catalog guards do not prove target
identity. NC-ENV-01 remains fail-closed: do not bypass its guards or use ordinary
test/application startup to bootstrap. A reviewed provisioning/bootstrap path and
real identity verification belong to NC-ENV-03.

Owner and session must be postgres, not a normalized substitute. PostgreSQL 17.6
was audited; PostgreSQL 17 is the characterization/deparser target. SQL requires
>=17 for MAINTAIN; newer major versions need review. Platform roles required:
postgres, anon, authenticated, service_role. Schemas: public, auth, extensions.
Supplied functions: auth.uid() and extensions.uuid_generate_v4(), returning uuid.
All four roles must retain public schema USAGE. No roles, memberships, managed
schemas/Auth internals, PostgREST services or extension implementations are created.
Public schema owner/ACL, role attributes/memberships, extensions and out-of-scope
defaults are compared before/after on the new target. This target-local metadata
comparison uses only that target's catalog, not production OIDs/hash constants.

Only plpgsql and uuid-ossp are application DDL prerequisites. uuid-ossp must expose
extensions.uuid_generate_v4(). The extension CSV records versions, not namespaces;
required namespace follows actual DDL. pgcrypto and pg_trgm are relevant installed
platform extensions with no application DDL dependency (31 pg_trgm C functions are
excluded). pg_stat_statements is optional observability-only; supabase_vault is
platform-managed. Installed-by-default availability must be verified in NC-ENV-03;
do not invent substitutes. Audited versions are evidence, not forced version pins.
No extension is installed by this baseline.

## Current security and intentional quirks

All 13 tables, bracket_view and three sequences grant only postgres/service_role.
Four mutation RPCs revoke PUBLIC/anon/authenticated EXECUTE and retain trusted
postgres/service_role EXECUTE. Raw ACLs and effective ordinary access are checked;
explicit column ACLs must remain absent.

Three trigger-only functions retain audited EXECUTE for PUBLIC, anon,
authenticated, postgres and service_role. Their ACLs were outside the four-RPC
containment and their result type is trigger. This is **PRESERVED CURRENT BEHAVIOR /
FUTURE REVIEW**, not approval for new direct RPC access. Function bodies, two
SECURITY DEFINER/five invoker modes, argument defaults, absent proconfig/search_path,
volatility and all trigger behavior are unchanged. Current view definition/options,
RLS flags and 16 policies are preserved.

postgres/public future TABLES and SEQUENCES grant owner/service_role only.
Global defaults are additive: preflight rejects unexpected global relation
recipients because scoped REVOKE cannot cancel them. Other creators and managed
schemas remain outside scope and must not be assumed contained.

Function defaults are deliberately unchanged: supplied built-in global PUBLIC/owner
EXECUTE and public-scoped postgres/anon/authenticated/service_role EXECUTE are
verified. A mismatch stops for review; do not silently broaden or recreate defaults.
Every new application-function migration must revoke EXECUTE from PUBLIC, anon
and authenticated on the exact signature in the same transaction, then grant only
reviewed access, unless direct access is explicitly approved. Secure before commit.

Manifest records preserved quirks: cross-season active-bracket uniqueness; both
master uniqueness indexes with differing soft-delete predicates; duplicate email
uniqueness; missing brackets.user_id FK; standings without season_id/unique code;
nullable legacy fields; text match-team references; cyclic master pointers;
password_resets ALL policies; contained function authorization shortcomings.
No characterization defect is repaired.

## Verification approach and limits

Catalog verification resolves names/signatures on the target, never production
OIDs, row counts or definition hashes. Checks cover exact relation/function
inventories; column order/types/defaults/nullability/identity; sequence
properties/ownership; constraint definitions/flags; indexes/readiness; trigger
definition/enabled state; RLS; policy expressions/roles; view definition/options;
function bodies/signatures/defaults/settings/security modes; owners;
raw/effective relation/function/column privileges; table/sequence scoped/global
defaults; required platform prerequisites. No application function is invoked or
application row queried. Optional extensions are documented inventory, not blockers.

Catalog name/ACL aggregation uses explicit C collation for portable ordering.
Catalog deparsing uses public/pg_catalog search_path, leaving extensions-qualified
UUID defaults visible as qualified names. Definitions normalize identifier quoting,
public qualification and whitespace to
reconcile supplied audit deparser format. Function bodies only normalize line
endings and outer whitespace. This is a PostgreSQL-17 characterization comparison,
not a general SQL equivalence engine. Fresh-platform compatibility must be tested.

From backend root:

```text
python -B db/baseline/validate_baseline.py
python -B db/baseline/validate_baseline.py --audit-dir "C:/NBACornerDBAudit/To send to astra"
```

No PostgreSQL parser or isolated database was available locally. Lexical checks,
byte-for-byte source DDL comparison (only documented CREATE transformations),
function bodies/catalog reconciliation, ACL/dependency review, scans and checksums
provide static evidence. **Live bootstrap execution deferred to NC-ENV-03.**
PostgreSQL grammar validity, executed catalog assertions and successful fresh
Supabase bootstrap are not claimed. Do not declare an environment ready from the
offline validator. The baseline has not been applied anywhere.

## Future bootstrap contract

1. Verify enrolled non-production identity.
2. Verify approved empty target/application namespace.
3. Verify Supabase prerequisites and compatible defaults.
4. Apply transactional baseline with stop-on-error.
5. Run semantic verifier and retain sanitized evidence.
6. Apply versioned synthetic fixtures later (NC-ENV-05).
7. Install/verify server-only environment marker through the approved later path.
8. Verify real identity and baseline/fixture versions plus provider/email safety.
9. Only then permit test backend startup/mutation. NC-ENV-01 guards stay closed
   until authorized provisioning/enrollment/identity work is complete.

No production users, email addresses, hashes, tokens, predictions, league
memberships, standings, scores, leaderboard, reference rows or sequence current
values are included. Schema columns named for passwords/tokens remain; no values
are copied. Teams, seasons and master/reference bracket rows used by runtime paths
must receive later synthetic representations in NC-ENV-05, not production copies.
No infrastructure, marker, seed, reset tooling or provider mocks are implemented.

## Migration discipline

This version characterizes secured state at the source checkpoint. Subsequent
schema changes receive new portable migrations. Existing 16 NC-SEC migration,
rollback, verifier and record files remain historical production-change evidence,
not a bootstrap chain. Never replay their production identity/hash/count guards
on a fresh DB or fabricate historical migrations. New functions secure EXECUTE
inside the same transaction; direct ordinary-role access needs explicit review.
Frontend, Flask application, guards, tests, CI and prior DB artifacts are unchanged.

Catalog references: https://www.postgresql.org/docs/17/functions-info.html and
https://www.postgresql.org/docs/17/catalog-pg-default-acl.html.
