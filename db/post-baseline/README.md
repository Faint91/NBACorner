# Portable post-baseline migration chain

The immutable bootstrap is `db/baseline/000_current_schema.sql`, version
`nc-env-02-current-secured-v1`. Do not edit/reinterpret that historical checkpoint.
The four NC-SEC files in `db/migrations` are historical production-change evidence,
not a bootstrap chain: never replay their source-specific guards on a fresh DB.

Current portable chain after the secured baseline:

1. `0001_nc_02b3_bracket_lifecycle.sql` â€” remove obsolete global active-user index;
   retain active `(user_id, season_id)` uniqueness and both master indexes; add
   trusted-only atomic master creation/replacement.
2. `verify_current_schema.sql` â€” full evolved semantic catalog verification.

The evolved verifier preserves every original baseline assertion except the two
obsolete-global-index assertions and its inventory entry. Its function inventory
adds the new signature, and additional assertions verify its body, owner,
SECURITY INVOKER/search_path/result and ACL containment. All old relation/column
ACLs, RLS/policies, triggers/functions, defaults and schema semantics are still
checked. `tests/offline/test_bracket_lifecycle_migration.py` proves the exact
allowlisted verifier derivation. SQL LF bytes are pinned via scoped `.gitattributes`
and the reviewed verifier SHA in `scripts/reset_local_fixtures.py`.

The existing `uniq_active_bracket_per_user_per_season` remains:
`UNIQUE (user_id, season_id) WHERE deleted_at IS NULL`. It applies to all active
brackets, including masters, as in the prior model; it is not silently weakened.
Soft-deleted rows do not block recreation. Same-user master replacement retires
the old row inside the same transaction before inserting its replacement.
`uq_master_per_season` and `ux_brackets_one_master_per_season` remain unchanged.
The existing soft-delete trigger demotes retired masters and clears their pointer
inside the transaction; the RPC installs the replacement pointer before commit.

## Prerequisites and data preflight

Production has NOT been queried or migrated. Future deployment requires separate
explicit authorization, verified target/backup, the secured baseline/catalog,
existing per-season/master uniqueness and reviewed active user/season identity.
Review active NULL/legacy keys, inconsistent master pointers/flags, and any admin
with a conflicting current ordinary bracket before a future rollout. The retained
all-active user/season constraint continues to refuse that owner conflict safely;
no automatic deletion, merge or unapproved extra ordinary/admin bracket is added.

The portable transaction checks duplicate active user/season and active-master
states and refuses unexpected duplicates. No rows are repaired/deleted by the
migration. Under the original global uniqueness, non-NULL duplicate active
user/season keys are already impossible; removing that stronger index introduces
no new per-season uniqueness conflict. There are no production OID/hash/row-count
constants in the migration. The existing nullable-key model is not redesigned.
Run with stop-on-error. Lock acquisition is bounded by the 5-second lock timeout.

The new RPC locks the named season row, verifies the DB admin, requires explicit
replacement intent for an existing active master, retires the old master, creates
the new bracket and complete initial match graph, then sets the pointer atomically.
Any insert/FK/index failure rolls the entire operation back. It is SECURITY INVOKER
with explicit search_path and same-transaction EXECUTE revocation from
PUBLIC/anon/authenticated; only postgres/service_role receive EXECUTE. Existing
functions, triggers, roles, ACLs, policies and defaults are not modified.

## Verification and reproducibility

Only the enrolled local test target was migrated. First, preflight/migration/full
verification were proven inside a rolled-back transaction; the original verifier
then passed again. The real local migration subsequently passed the full evolved
verifier. Initial verifier-body whitespace normalization was corrected during the
rolled-back proof; no partial migration persisted.

`scripts/prove_bracket_lifecycle_migration.py` creates a uniquely named, fixed
local disposable database only if absent, copies schema-only local Supabase
platform definitions (no row/role/password dump), restores managed ownership under
the local platform admin, and bootstraps the empty application namespace under
postgres. It then applies the forward chain, verifies semantic security, seeds
synthetic data and exercises constraints. It never enrolls a fake API target or
relaxes harness identity gates. Only its own newly created proof DB is removed.
Full HTTP acceptance uses the separately verified enrolled local environment.

The ordinary local bootstrap command now applies baseline -> forward migration ->
evolved verifier -> local marker. Current reset/readiness/runners use the pinned
full evolved verifier. Historical baseline artifacts/reports remain unchanged.
Fixture identity stays `nc-fixtures-v1`; rows/sequences and canonical checksum are
unchanged by the schema evolution.

## Future production rollout and rollback

Migration and application changes are ready for review after local validation,
subject to the production prerequisites above. Coordinate a controlled rollout:
apply/verify DB migration, deploy matching backend and frontend, then verify.
Avoid admin master-creation activity while old backend behavior is still running.
No rollout or production application has been performed in this phase.

`rollback_nc_02b3.sql` is a reviewed strategy, NOT executed on production. It first
refuses rollback if legitimate cross-season active rows would violate the old
global index. It never deletes/merges rows to force rollback. If safe and separately
authorized, coordinate application rollback, recreate the old index and remove
the new RPC in one transaction. Once cross-season rows exist, prefer a forward
fix or an explicitly reviewed data plan rather than forced destructive rollback.

Final validation: 201/201 complete applicable backend regressions, 244/244 offline
tests, 13/13 frontend tests, TypeScript/Vite production build, and full evolved
schema verification passed. Existing frontend lint findings remain unchanged;
no new findings. Fresh disposable baseline/migration/seed proof additionally
passed atomic first-master, confirmation refusal, replacement and forced-failure
rollback, then matched the canonical fixture checksum. Proof serialization uses
the same UTC/ISO/float settings as fixture reset. The proof DB was removed; the
fixture lease is released, guarded Flask stopped, jobs disabled and email capture
empty. Fixture version/checksum remain unchanged. Production was not contacted.


## NC-02C1 canonical designation

Apply baseline -> 0001 -> 0002 -> current verifier. Migration 0002 leaves
application_season empty on purpose. Production requires a separately authorized,
verified existing season designation and valid opening/lock timestamps; runtime
fails closed without it. Guarded local seed deterministically designates the current
synthetic fixture, preserving old row/version/checksum and independently verifying
the pointer. No canonical advancement is added to rollover until NC-02C3.

The new singleton table is postgres-owned, RLS-enabled, no policies, no PUBLIC/anon/
authenticated access; trusted postgres/service_role only. No privileged function
added. Existing B3/baseline security assertions remain intact except the explicit
new relation inventory entry. New strict verifier assertions cover columns, types,
defaults, owner, PK/check/FK, ACL, RLS, policy/trigger/index inventory. See the C1
repair record for preflight, controlled rollout and configuration-preserving rollback.


## NC-02C2 standings publication

Apply 0003 after 0001/0002. No existing table/security/migration data is changed.
New publish_current_standings(uuid,jsonb) is postgres-owned PL/pgSQL SECURITY INVOKER,
search_path pg_catalog,public, trusted postgres/service_role execute only. It fences
canonical ID/freeze, validates complete input, and atomically replaces current rows.
No history, season column, rollover reset or advancement. Explicit primary-key
DELETE predicate honors safe-update enforcement. Full verifier adds only function
inventory and strict new function assertions; earlier checks remain unchanged.
See nc-02c2 repair/evidence for fresh-chain, real rollback, preflight and rollback.


## NC-02C3 canonical transition finalization

Apply 0004 after baseline -> 0001 -> 0002 -> 0003, then the full current verifier.
The prior C2 verifier is frozen as verify_nc_02c2_schema.sql. No prior migration or
existing table/security object is modified. The new finalize_season_transition
(uuid,uuid,text) is postgres-owned PL/pgSQL SECURITY INVOKER with pinned search_path
pg_catalog,public and postgres/service_role-only execution. It fences the expected
source and intended valid target, then moves the singleton and clears current
standings atomically. It shares the canonical lock order with standings publication.
Earlier rollover snapshot/cleanup/insertion calls remain separate transactions;
full recovery/legacy snapshot ambiguity are explicitly not solved. No production
migration or rollover was run. See docs/repairs/nc-02c3-season-transition.md for
acceptance, fresh-chain proof, operational preflight and rollback limits.


## NC-02D1 atomic current score publication

Apply 0005 after baseline and 0001-0004, then verify_current_schema.sql.
The frozen C3 verifier is verify_nc_02c3_schema.sql. The new trusted-only
publish_current_bracket_scores(uuid,uuid,jsonb,jsonb) is postgres-owned PL/pgSQL
SECURITY INVOKER with pinned pg_catalog,public search_path. It fences canonical
season/master and typed scoring/eligibility inputs, verifies the complete eligible
set and components, and replaces current scores atomically. Unchanged output is a
no-write result, preserving timestamps. Existing table/security/history objects
and prior migrations are unchanged. See nc-02d1 repair/evidence for actual rollback,
master mutation integration, preflight and operational recovery limits. No
production migration or score recomputation has been performed by this phase.


NC-02D2 adds `0006_nc_02d2_final_snapshots.sql`: atomic complete/final historical
snapshots, frozen ranking metadata, immutable write guards and SC17 verified zero
participation. The D1 verifier is frozen as `verify_nc_02d1_schema.sql`; current
semantic/security verification includes all additive objects. Prior migrations and
historical values are unchanged. See `docs/repairs/nc-02d2-history-snapshot.md` and
`db/records/nc_02d2_history_snapshot.json`. No production rollout is authorized by
this local repair. Existing unverified structured headers require review before
being treated as final; they are never silently promoted or overwritten.


## NC-02E atomic explicit rollover

Apply 0007 after immutable baseline and 0001–0006, then the current verifier.
The prior D2 verifier is frozen as `verify_nc_02d2_schema.sql`. E adds private
rollover audit and trusted-only completed-master/orchestration/transition functions.
Saved historical bracket graphs remain; every unsaved source bracket is hard deleted
only after verified final snapshot and inside the atomic transition. Failed transition
preserves final snapshot/audit and rolls back all cleanup/activation. Legacy output is
best effort; repeat-success and transaction advisory lock prevent duplicate cleanup.
See `docs/repairs/nc-02e-atomic-rollover.md` for failure proofs, fixed local commands,
fixture digest preservation and backup/hard-deletion operational limitations.
No production action is authorized by this local repair.


## NC-02F1 live league lifecycle

Apply `0008_nc_02f1_league_lifecycle.sql` after immutable baseline and 0001-0007.
The E verifier is frozen as `verify_nc_02e_schema.sql`; the current verifier adds
exact F1 functional-name uniqueness, owner-membership FK and trusted RPC checks.
Local bootstrap and verifier-pinned reset use the complete current chain.

Before any separately authorized production rollout: backup; review normalized
name collisions/invalid names, owner-member consistency and membership duplicates;
review the migration; coordinate backend/frontend rollout. Migration refuses
inconsistent data transactionally and never auto-renames or invents memberships.
All nine new functions are postgres-owned INVOKER with pinned pg_catalog,public
path and postgres/service_role-only execution. Browser grants are unchanged.

`python scripts/prove_league_lifecycle_migration.py` proves a fresh local disposable
baseline-to-0008 chain, real name contention, owner/member rollback and all E SQL
safety groups. The older E proof remains bound to its frozen verifier.
See `docs/repairs/nc-02f1-league-lifecycle.md` and F1 machine evidence.
No production contact or NC-02F2 work is authorized by this local phase.


## NC-02F2 historical league seasons

Apply `0009_nc_02f2_league_history.sql` after immutable baseline and 0001-0008.
The frozen F1 verifier is `verify_nc_02f1_schema.sql`; current strict verification
includes the four private F2 tables, source mapping, cutoff seals, membership
fences and exact forward RPC extensions. No existing history backfill occurs.
Nonempty pre-F2 final sources without internal mapping block for review.

`python scripts/prove_league_history_migration.py` proves the fresh local chain,
all-league rollback, ranking/ties, immutable trusted-only access, six real membership
races and prior E atomic rollover protections in a removed disposable DB.
See `docs/repairs/nc-02f2-league-history.md` and F2 evidence for transaction scopes,
current privacy, deletion, local cleanup and separate production prerequisites.
No production action is authorized by this local phase.


## NC-02G1 identity, registration and login

Apply `0010_nc_02g1_identity_auth.sql` after immutable baseline and 0001-0009.
The frozen prior verifier is `verify_nc_02f2_schema.sql`. Current verification
adds exact normalized username/email indexes, nonblank identity constraint and
trusted-only SQL normalization/lookup functions. No existing users/hashes are
rewritten. Collision/blank preflight fails transactionally without choosing a user.

`python scripts/prove_identity_auth_migration.py` reuses the fixed disposable local
fresh-chain proof and adds collision refusal, exact schema/ACL assertions and two
real concurrent normalized identity races. See `docs/repairs/nc-02g1-identity-auth.md`
and G1 evidence for hash compatibility, canonical fixture checksum and separately
authorized production prerequisites. Reset/session changes remain G2 work.
No production contact or deployment is authorized by this local phase.
