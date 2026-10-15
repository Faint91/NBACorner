# NC-02B3 â€” Bracket lifecycle, season uniqueness, master management and history

## Starting state and scope

Backend main `84a0ddc0f245864b8b6c0093f6e3f984e5deafaa`; frontend main
`3ba43ee1fef4e2c63b0169efda01b6e2f2f896d5`; both clean. Approved B10â€“B15 only.
No production contact, deployment, scoring/standings/season-source fixes or next
domain work. B1â€“B9/B16 and NC-02A protections remain required.

## Before/after lifecycle map

| Area | Before | NC-02B3 |
| --- | --- | --- |
| Active ordinary uniqueness | Global partial user index plus per-user/season partial index; historical active row blocked current creation | Remove only `unique_active_bracket_per_user`; retain per-user/season active constraint |
| Master uniqueness | `uq_master_per_season` active predicate plus `ux_brackets_one_master_per_season` all flagged predicate | Both preserved; retirement trigger demotes old master |
| Owner deletion | Soft delete at any deadline/submission state; match rows retained, associated scores cleaned | Owner before lock allowed; at/after lock submitted denied, unsaved draft allowed; B5 still governs recreation |
| Arbitrary admin delete | Legacy bypass, explicitly deferred by B1 | Denied; only owner deletion of ordinary current brackets. Prompt explicitly preferred denial; no separately approved operational admin-delete requirement was found |
| Master create | Admin window bypass; bracket inserted before graph; silent multi-request promotion/demotion/pointer update | Same window bypass; existing master requires strict explicit boolean intent; complete initial graph + retirement + pointer commit atomically |
| Active master generic delete | Allowed, trigger cleared pointer; recreate workaround | Always denied, admin included; controlled explicit replacement or existing rollover is required |
| Current detail | Authenticated, current-season only; owner draft/nonowner submitted privacy | Preserved |
| Historical detail | Current detail returned 404; frozen snapshot history independent | Separate public submitted/owner-private draft read-only detail surface; current URL semantics unchanged |
| Rollover | Direct controlled helper operates on DB, snapshots and season retirement | Unchanged; does not call the newly restricted generic-delete route |

The historical bootstrap includes cyclic season/master FKs, the soft-delete master
trigger and the trusted-only legacy `set_master_bracket` RPC. Those remain intact.
The new function uses the existing trigger to retire an old master without an
externally observable missing/incorrect pointer between commits. Other seasons'
masters and records remain untouched.

## Forward migration and safety

`db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql` is the first portable forward
migration after the secured NC-ENV baseline. The historical NC-SEC migrations are
not replayed. Exact index definitions, preflight, privilege containment, fresh
proof and rollback prerequisites are in `db/post-baseline/README.md`.

No baseline artifacts are edited. A separate full semantic verifier preserves all
unrelated original assertions and checks the new function. Existing reset/startup
identity, lease, capability, egress, email/provider and job controls remain active.
Current tooling uses the evolved verifier and pinned SHA; fixture data/version
and checksum do not change. Fresh bootstrap now applies the forward chain before
marker installation. No production project was queried or migrated.

The retained `(user_id,season_id)` active index includes masters, matching prior
per-season behavior. Replacing a same-owner master retires the old row first in
the transaction. Unexpected conflicting ordinary owner state fails safely rather
than deleting an unrelated bracket. Existing legacy nullable-key constraints are
not redesigned. Migration data preflight rejects duplicates; no merge/deletion.

## Backend behavior

`create_bracket_for_user` retains the ordinary window/final-lock guard and current
standings/team source. It prepares the same initial graph with UUIDs and winner
links before writes. Ordinary creation checks only the current user/season.
DB admin status is verified for master operations. `replace_existing_master` must
be a boolean; ordinary replacement intent is 403. Existing-master creation without
confirmation is 409. Normal first admin creation bypasses the ordinary window.

`create_master_bracket_atomic(uuid,uuid,boolean,jsonb)` is trusted-only and locks
the season row. It retires the previous active master (soft delete, no match/score
purge), inserts the new bracket and graph, and updates the pointer in one DB
transaction. Same-owner replacement and post-lock replacement work. Forced FK
failure proves old row/flag/pointer/graph remain unchanged after rollback.

`delete_bracket` retains current-season and active-record checks. Active master
returns 403 explaining explicit replacement/controlled rollover. Ordinary nonowner
and arbitrary admin requests return 403. A submitted owner's request at/after
lock returns 403 without changing competition/history rows. Owner draft deletion
remains allowed after lock but recreation is denied by B5. Allowed deletes retain
existing soft-delete/match-retention/score-cleanup behavior. Historical generic
delete remains denied; no broader historical master deletion policy is invented.

`get_my_bracket` supplies only a safe master-exists boolean for admin confirmation
and own master flag for controls, not private master IDs or names.

## Historical access and UI

`GET /history/bracket/<id>` accepts anonymous reads only for nondeleted submitted
brackets from seasons strictly earlier than the existing configured current code.
A past draft is readable only by its authenticated owner, never by another user,
anonymous caller or admin merely due to admin status. Invalid tokens refuse rather
than gaining private access. Payloads retain the NC-02A public-user allowlist.
Current IDs are not accepted through the public historical route. Returned
`read_only`/`is_historical` metadata makes the distinction explicit.

`GET /bracket/<id>` stays authenticated/current-only. Existing mutation endpoints
still reject historical season IDs for prediction, undo, counts and submission.
Historical records remain excluded from current competitive eligibility. Frozen
leaderboard history is unchanged and remains independent of current row visibility.

The existing BracketPage renders `/history/bracket/:bracketId` read-only, with no
winner/count/Undo/Save controls and a private-draft label where appropriate. The
route is public for submitted history; private drafts still require owner identity.
The existing PastSeasons frozen snapshot presentation is unchanged: its row IDs
are snapshot-row IDs, not bracket IDs, so no unsafe guessed links/discovery were
introduced. Individual historical detail is available by its actual persisted
bracket ID. No history redesign or new global old-bracket listing was added.

Dashboard master creation requires explicit confirmation before sending the true
replacement flag. Cancellation sends no request; ordinary/first creation never
silently supplies replacement intent. Active-master deletion and post-lock
submitted deletion are visibly disabled. Post-lock draft delete stays available.
The actual router is `src/main.tsx`; stale `src/App.tsx` is untouched.

## Tests, provenance and preservation

Twelve guarded B3 live cases cover cross-season coexistence, same-season/different
user uniqueness, pre-lock delete/recreate and closed opening window, at/after-lock
submitted refusal with scores/history preserved, post-lock draft deletion without
recreation, nonowner/admin delete denial, first master/explicit replace/delete
protection, post-lock replacement/other-season preservation, atomic rollback,
strict replacement intent, public submitted history, private draft history, and
no public-current-ID bypass.

Existing NC-01B lifecycle observations are converted separately through
`scripts/nc02b3_acceptance_metadata.py`, retaining previous metadata. Historical
reports remain immutable. The fixture validator now uses `(user_id,season_id)`
for active uniqueness; canonical foundation rows are unchanged. Six new offline
cases prove strict verifier derivation, migration/rollback security and lifecycle
scope refusals. Six new frontend tests execute the real creation handler with
mocked network/confirmation/navigation/analytics, plus historical/delete controls.

Initial focused harness refusals identified a missing B3 entry in a multiline
allowlist; only registered history/delete routes were then admitted. No identity
or job guard was bypassed. The corrected 12-case focused run passed. All 45 source
regression checks passed before starting the complete applicable suite, including
the corrected B2 static assertion. There is no subset-only completion claim.

B1 lock timing/owner Undo/admin content restrictions, B2 validity/propagation,
NC-02A privacy and explicit resubmission are rerun in the complete suite. The
rollover implementation, champion +3, finalist +1, snapshot tie order, standings
provider/freeze, canonical season source, league lifecycle and unrelated auth are
unchanged. Admin arbitrary deletion is now intentionally removed under this
phase's explicit preference, completing that previously deferred content-vs-delete
aspect without granting new admin authority.

## Evidence, production status and next phase

Final results and canonical cleanup are recorded in
`db/records/nc_02b3_bracket_lifecycle.json`, with separate full/focused regression
and fresh-database proof records. Production is unchanged; migration/app changes
are for review and a later explicitly authorized deployment only. Production
readiness remains conditional on a verified target/backup/catalog/data preflight
and coordinated DB/backend/frontend rollout. Rollback must refuse if legitimate
cross-season active data cannot satisfy the obsolete global index.

No next phase is started. The established consolidated repair order recommends a
separately authorized canonical-seasons/standings requirements review (proposed
NC-05), with a business approval checkpoint before implementation. Scoring and
other unresolved domain gaps remain deferred.

Final validation: 201/201 complete applicable backend regressions, 244/244 offline
tests, 13/13 frontend tests, TypeScript/Vite production build, and full evolved
schema verification passed. Existing frontend lint findings remain unchanged;
no new findings. Fresh disposable baseline/migration/seed proof additionally
passed atomic first-master, confirmation refusal, replacement and forced-failure
rollback, then matched the canonical fixture checksum. Proof serialization uses
the same UTC/ISO/float settings as fixture reset. The proof DB was removed; the
fixture lease is released, guarded Flask stopped, jobs disabled and email capture
empty. Fixture version/checksum remain unchanged. Production was not contacted.
