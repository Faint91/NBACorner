# NC-02C3 — canonical season transition and standings reset

Scope: approved S10/S11 only. Starting backend main dc476ca28e8263c1e6ef3c347f8be87a5c0f643b;
frontend main 947a785ed2abf38d0098f588d2edb0910169e6d7, both clean.
No production contact, migration, rollover or deployment. No scoring formula,
bracket rule, history, retention or broader rollover recovery changes.

## Existing flow and integration point

The pre-change inventory is db/records/nc_02c3_rollover_path_inventory.json.
POST /admin/season/rollover requires JWT authentication, the admin claim and a
matching users.is_admin record. The runtime job guard remains first in the helper
and unchanged for production. Source authority is canonical current_season(),
request-pinned and rechecked directly against application_season before work.
The target is the requested new_season_code; an existing code remains refused.
No arbitrary existing season is selected, no retry/resume behavior added.

Existing order is retained: historical snapshot (including the unchanged exact
already-exists success special case), current score deletion, current match
deletion, bracket soft retirement, then target season insertion. Each of these
is still a separate PostgREST transaction. The target must now have a valid season
code and both ordered timing values, using the same validator as canonical reads.
Validation occurs before destructive work, and stored target validation is repeated
after insertion. No dates or preseason standings are invented.

Only after those existing steps and a valid returned target does the helper invoke
finalize_season_transition(source_id, target_id, intended_code). Success now means
that atomic finalization was confirmed. The existing response distinguishes the
retired source from the new target; env_next_actions is compatibility metadata,
explicitly stating no environment changes/restart are required. The request-local
canonical cache is cleared after confirmed success, so even the same process sees
the new authority. Subsequent invocations obtain the new source automatically.

## Narrow atomic finalization and security

Portable migration 0004_nc_02c3_season_transition.sql follows immutable baseline,
0001, 0002 and 0003. Earlier migrations are unchanged. Only one new function is
added: public.finalize_season_transition(uuid,uuid,text), postgres-owned PL/pgSQL,
SECURITY INVOKER, search_path=pg_catalog,public, returns jsonb. PUBLIC, anon and
authenticated execution is revoked within the migration transaction; only postgres
and service_role execute. Existing table grants/RLS/policies are not changed.

The RPC locks the singleton pointer FOR UPDATE, matching the C2 publication lock
order; validates the expected source; requires a distinct existing intended target;
locks its row FOR SHARE; validates code and finite, non-null ordered timestamps.
It then updates the pointer and deletes current standings in one transaction.
The explicit id IS NOT NULL predicate honors local Supabase safeupdate. It creates
no tables, history or season columns and changes no bracket/score/history rows.
A stale source or old in-flight standings publication fails closed after activation.
Two separate API calls cannot expose a committed pointer/reset split.

The prior C2 verifier is frozen byte-for-byte in verify_nc_02c2_schema.sql. The new
full verifier retains every previous assertion except the required new function
inventory entry, and adds exact body/owner/language/settings/ACL checks. The reset
verifier hash is repinned; local bootstrap applies 0004. The prior C2 disposable
proof references its own frozen verifier, not the evolved C3 catalog.

## Failures and explicit limits

Provider/standings behavior from C2 is unchanged. Failure before finalization leaves
the old pointer and standings intact; earlier snapshot/cleanup/target-insertion
writes may remain committed. A finalization database error rolls back its pointer
movement and reset together. A transport error cannot prove whether a complete RPC
committed; the API says confirmation failed and warns against automatic retry.
Inspect both values read-only during separately reviewed recovery. This phase does
not claim full rollover rollback or solve recovery after partial completion.

Repeated same-target calls are refused before cleanup, preserving populated new
standings. Existing target creation remains refused. If finalization fails after
insertion, a repeat is still refused instead of silently selecting/resuming that row.
Concurrent whole-rollover execution and earlier multi-call cleanup remain deferred;
the final pair alone has transactional source fencing.

## Consumer and frontend behavior

Canonical helper, /season, bracket creation, scoring filters/leaderboard, admin
master creation, standings refresh and subsequent rollover all resolve the new
season without a restart or independent environment change. Empty current standings
are expected immediately afterward. There is no standalone /standings GET route;
the actual current-state reader is bracket creation, which retains its existing
empty-table response instead of receiving stale old rows. A valid new-year ESPN
refresh restores 30 validated rows before the new freeze; at the new freeze it skips
fetch/write. Old season timing no longer governs current consumers.

Frontend changes are limited to corrected activation/reset and required-timing
copy plus explicit canonical status refetch after successful rollover. The hook
invalidates stale authority while refetching; failed rollover does not claim a new
season. No UI redesign, build-time season authority or force control was added.

## Local acceptance and reproducibility

The C3 guarded scope requires verified enrolled local identity, fixture checksum,
active lease, owned thread, request nonce, fixed route and explicit per-call job
admission. Only the fixed synthetic 2026-27 transition and its nested existing
snapshot are enabled. Unrelated job guards remain closed. Existing C2 refresh
admission is reused; no overwrite/team-maintenance admission is added to C3.
The explicit 2027 ESPN fixture request reuses the complete deterministic 30-team
synthetic payload; it performs no external provider request.

The existing synthetic competitive fixture inserts explicit legacy history IDs 1/2.
The C3 prerequisite helper aligns that local sequence before exercising a real
snapshot. This is fixture setup only; no snapshot code or canonical seed was changed.
The harness restores all rows, sequences and canonical designation after each test.

Seven live scenarios cover success and immediate consumers/history/retirement,
first new-year refresh, new freeze, later master/ordinary bracket creation and
uniqueness, repeated refusal, incomplete/reversed target and auth rejection,
existing target refusal, snapshot failure, target insertion failure, finalization
transport failure and stale canonical source conflict. Offline coverage validates
canonical target structure, narrow capability refusal and exact prior-verifier
preservation. Existing A1/A2/B1/B2/B3/C1/C2 regressions are included.

The disposable proof creates a new fixed local database only if absent, restores
local platform schema without rows/roles/password dumps, applies the entire empty
baseline/0001/0002/0003/0004 chain and strict verifiers, seeds synthetic data, then
exercises trusted success and untrusted refusal. A temporary scratch-only DELETE
trigger fails after pointer movement; the old pointer and every prior standings
row/ID/timestamp remain exactly intact. Missing/invalid target timing, wrong target,
stale source, old refresh fencing, first target publish and repeated transition
refusal are also checked. Test trigger/function roll back and the owned proof DB
is removed. There is no production failure toggle.

## Production readiness, first refresh and rollback

No production queries were made. A later separately authorized rollout requires:
verified secured C1/C2 schema and current canonical singleton; current source/code
and snapshot prerequisites; intended unused target code and confirmed opening/lock
times; database backup covering history, competition, pointer, standings and seasons;
trusted server role; coordinated migration/backend/frontend release. Do not use
rollover as a dry run: existing cleanup is destructive and not globally atomic.

After controlled successful transition, standings are intentionally empty. Coordinate
a valid pre-freeze ESPN refresh for the new ending year with existing network and
trusted-role configuration; no independent season environment update is needed.
Do not fabricate preseason data or copy old standings into the new season. Until
refresh, bracket creation retains its existing empty-standings response.

Rollback is operationally reviewed, not automatic: pause rollover/refresh callers,
inspect exact committed state, preserve backup/history, and prefer a forward fix.
Removing 0004 or reverting application code does not undo committed cleanup or
restore old standings. Do not blindly move the pointer back, restore only one half,
or automatically retry a partially completed rollover. No rollback was executed.

## Deferred / next checkpoint

Still unresolved: legacy-only snapshot sufficiency; structured snapshot failure;
full rollover transactionality; partial recovery/resume; retry policy; exact trigger
timing; master completion prerequisites; retention beyond approved behavior.
Scoring champion +3/finalists +1 and tie logic, league/auth questions remain untouched.
NC-02C is complete after final validation; stop for an explicit next-domain/checkpoint
instruction rather than automatically implementing any deferred item.

## Validation results

Final totals and cleanup are recorded in db/records/nc_02c3_season_transition.json,
with complete regression findings in nc_02c3_validation.json and fresh SQL proof in
nc_02c3_fresh_migration_proof.json. Frontend ESLint has existing baseline findings;
changed-file diagnostics are compared explicitly rather than reported as lint-clean.
No configured Python lint engine is available; AST import comparison, syntax and
Black checks are used and that limitation is retained in the evidence.


Final validation: 216/216 complete applicable backend regressions passed, followed
by 7/7 focused checks of the final sanitized messages/local guard. Offline safety
266/266 and frontend tests 22/22 passed; TypeScript/Vite build passed. Fresh full
migration chain, actual post-pointer reset-failure rollback, semantic security,
Black, whitespace, secret/privacy/syntax/size and import comparison passed.
All 79 protected historical artifacts are byte-identical. Python full lint tooling
is unavailable; zero new unused imports. Frontend ESLint retains its 83 errors and
3 warnings; changed-file diagnostics are identical to the original checkpoint.
Existing browser-metadata/chunk-size build warnings remain outside this phase.

Final cleanup independently confirmed canonical designated fixture, original 30
standings rows, unchanged nc-fixtures-v1 checksum, released lease, stopped Flask,
empty capture, removed app import, disabled jobs and absent scratch proof database.
Standalone harness UNMET/mutation_permitted=false after cleanup is intentional:
there is no global test-mutation enablement. No production action or next domain.
