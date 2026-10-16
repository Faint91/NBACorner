# NC-02F1 — Live league lifecycle

Local implementation of approved L1–L19. No production contact. Historical league requirements L20–L22 remain deliberately deferred to NC-02F2.

## Starting checkpoint and old architecture

Backend main began clean at `78d75564b89bad41e75992a60435ff2436a231e7`; frontend main began clean at `9500a6a81f526ef72fdef4ec0481162cf042bfe7`. The starting-state and local preflight records preserve the inspection evidence. There were no local leagues, normalized-name collisions, invalid owner memberships or duplicate memberships.

Existing `leagues` has UUID ID, display name, `owner_user_id` (NOT NULL user FK), nullable `password_hash`, `is_global` and timestamps. `league_members` has UUID ID, league/user FKs with cascades, joined timestamp and unique `(league_id,user_id)`. Leagues have no season linkage. The old exact-name unique constraint permitted case variants. Create used separate league/member writes with a nonfatal membership failure. Create/join inherited `playoffs_locked()`. Transfer/settings/kick routes were absent. Delete lacked server destructive confirmation. The UI already had create/join, owner deletion and nonowner leave confirmations.

## Approved contracts and route inventory

Every route below requires the existing application JWT. `league_service.py` centralizes owner/member checks and input policy. Existing NC-02A private-membership and safe discovery helpers remain the single read-privacy boundary; no contradictory discovery authorization helper is added.

| Route | Authorization and result | Timing |
| --- | --- | --- |
| POST /leagues | Current account; atomic owner + member creation; safe league metadata, created state | Any time |
| GET /leagues | Authenticated discovery; private nonmembers receive minimal metadata, no owner/member identities, scores or bracket IDs | Unchanged |
| GET /leagues/me | Current memberships; safe member metadata and boolean password state | Unchanged |
| POST /leagues/:id/join | Public or server-verified private password; existing member idempotent; actor from JWT | Any time |
| DELETE /leagues/:id/membership | Self, active nonowner only; membership-only deletion, minimal response | Any time |
| DELETE /leagues/:id | Current owner only and strict JSON boolean confirm_delete=true; live league/member hard deletion | Any time |
| PATCH /leagues/:id | Current owner; name and/or privacy/password settings only; safe metadata | Any time |
| POST /leagues/:id/ownership | Current owner; stable target_user_id must identify a different active member | Any time |
| DELETE /leagues/:id/members/:user_id | Current owner; different active target member; membership-only deletion | Any time |
| GET /leagues/:id/members | Existing member-list policy: private membership required, public policy unchanged; username/role/joined/eligible bracket fields; no email/hash | Unchanged |
| GET /leaderboard?league_id=:id | Existing backend current-membership, canonical season, eligible saved brackets, canonical scores and server ranks; private membership required | Unchanged |
| GET /brackets?league_id=:id and /stats/champion-picks?league_id=:id | Existing NC-02A private membership, safe saved competitive data | Unchanged |

Machine-readable old/new route/decorator inventory: `db/records/nc_02f1_route_inventory.json`. Existing global-league protection remains; `is_global` is not a third public/private privacy model. No new admin bypass. Ordinary administrators must satisfy exactly the same owner/member/password policies.

## Names: L14/L15

Display names preserve case and are trimmed; 1–80 Unicode characters, the existing practical maximum, no NUL or invalid Unicode. No new minimum three-character rule. The central application helper delegates comparison-key calculation to PostgreSQL through `inspect_league_name`, so Python Unicode lower/casefold does not diverge from database collation. PostgreSQL uses `lower(normalize_league_name(name))`. Its explicit Unicode outer-whitespace set matches Python `str.strip()`. No accent folding or Unicode normalization beyond the approved trim/lower contract is invented. Search remains discovery substring search, not an identity lookup or authoritative uniqueness check.

0008 replaces the old exact-name unique constraint with a functional unique index on `league_name_key(name)` and a trimmed/nonempty/80-character CHECK. Names are unique across all public/private leagues. Creation and rename get clean 409 conflicts; the DB handles races. Same-league display-case changes succeed, and hard-deleted names become reusable.

Preflight is transactional and lock-protected. It refuses normalized collisions, invalid/untrimmed names and invalid owner membership; it never renames, deletes or chooses a winner. Membership uniqueness already exists and is preserved, not duplicated. Fresh proof injects collisions and invalid ownership and proves all migration effects roll back without modifying source rows.

## Ownership and live membership: L1–L10, L16, L19

A deferred composite FK `(leagues.id,owner_user_id)` references the existing unique membership key. Together with the original NOT NULL owner/user FK, this structurally guarantees exactly one actual member/owner at commit. Atomic creation inserts both records in one RPC. No committed ownerless league can exist, even through a trusted raw write. Ownership transfer locks the league row, rechecks current owner and target membership, changes only the owner pointer and leaves both memberships intact. No automatic succession or automatic target enrollment.

Owner leave is 409 with a clear transfer/delete instruction. Kick refuses self and nonmember targets. Nonowner leave/kick removes membership only, not accounts, brackets, global scores or global history. Existing current server-scoped league surfaces consult current membership and immediately exclude former members. Rejoining follows normal rules. A row lock serializes application lifecycle writes. A hash-state fence refuses joins/settings if privacy/password changed since server verification. Repeated joins are deterministic `already_member`, without duplicate rows.

Owner delete requires `confirm_delete` to be the JSON boolean true, not string/number truthiness. Frontend confirmation sends that flag. Delete hard-removes the live league with membership cascade and leaves unrelated leagues and all users/brackets/global scores/history untouched. No tombstone or league history was added.

NC-02E rollover code and migrations 0001–0007 are unchanged. Leagues and members persist. F1 acceptance exercises the real atomic rollover route and verifies league, owner and membership preservation and subsequent new-season participation prerequisites.

## Privacy and passwords: L11–L13, L17/L18

Only canonical `password_hash IS NULL` (public) or non-NULL (private). Explicit public requests cannot carry a password. Public→private requires a valid new password; private→public clears the hash; a private password change replaces the hash. Existing memberships are never removed or reauthenticated. Rename-only preserves the hash.

Passwords are strings, outer-whitespace trimmed, nonempty for private creation/change, 1–128 Unicode characters; no complexity or four-character minimum. No previous maximum existed. Bcrypt uses configured rounds. Inputs up to bcrypt's 72-byte boundary retain raw bcrypt compatibility. Longer UTF-8 inputs use base64(SHA-256(password UTF-8)) followed by bcrypt, stored with `bcrypt-sha256:` marker; this prevents silent truncation and permits the full 128-character domain. Existing raw bcrypt hashes remain verifiable with historical 72-byte semantics. Hashes and passwords never appear in API responses or diagnostics. Join normalization is identical. Errors are sanitized (400 validation/password, 401 auth, 403 ownership/privacy, 404 missing league, 409 conflict/owner leave/stale settings, 503 dependency failure).

## Database security

0008 functions are postgres-owned SECURITY INVOKER, pinned `search_path=pg_catalog,public`, execute only for postgres/service_role. No PUBLIC/anon/authenticated execute. No new browser table grants or writes. Flask remains the application authentication/authorization boundary. SQL functions repeat actor/owner/target checks under locks. Name helpers are immutable SQL; inspection is stable SQL; the six lifecycle mutators are PL/pgSQL. All nine exact signatures, bodies, attributes and grants are checked in the strict current verifier alongside all unrelated historical assertions.

Functions: `normalize_league_name(text)`, `league_name_key(text)`, `inspect_league_name(text,uuid)`, `create_league_with_owner(uuid,text,text)`, `join_league_member(uuid,uuid,text)`, `transfer_league_ownership(uuid,uuid,uuid)`, `remove_league_membership(uuid,uuid,uuid)`, `update_league_settings(uuid,uuid,text,boolean,text,text)`, `delete_league_confirmed(uuid,uuid,boolean)`.

## Frontend

Minimal owner settings inside the existing league page: rename, privacy/new password, explicit transfer to another member, confirmed kick. Only actual owner membership shows controls; no admin-based capability. The existing leave/delete modals remain. Stable IDs are used. Successful changes refresh memberships/league metadata; stale/unauthorized requests are enforced by the backend. No redesign, historical selector or unrelated feature changes. The API DELETE helper now accepts an optional JSON body without changing existing no-body callers.

## Local verification and repeatability

Commands (from backend, with enrolled local configuration only):

```
python scripts/run_league_lifecycle_acceptance.py --config C:/NBACorner/backend/.env.test.nba-local.local --allow-local-mutations
python -m unittest discover -s tests/offline -q
python scripts/prove_league_lifecycle_migration.py
```

Frontend: `node --test scripts/test-*.cjs`, `npm run build`. No production configuration is used by local acceptance; egress is guarded and email/provider/job behavior remains isolated. The separate F1 runner records explicitly superseded pre-approval league assumptions while retaining historical test sources/evidence. Invalid owner-not-member synthetic scenarios now install owner-only leagues atomically; they do not invent or repair application data. F1 independently tests the structural invariant and the private role matrix. Frozen E verifier/proof preserves its exact historical scope. Current strict verifier extends it only for approved F1 catalog changes; the fixture reset checksum pin is updated to that reviewed verifier.

Fresh proof creates a new local disposable database from schema-only local platform structure, applies immutable baseline and 0001–0008, runs semantic/security and synthetic lifecycle/race tests, checks prior rollover protections, and removes the disposable database. No source rows/credentials are dumped. Final test totals and canonical cleanup evidence are recorded in `db/records/nc_02f1_league_lifecycle.json`.

## Future production prerequisites — not performed

Backup and review migration 0008; read-only normalized-name collision/invalid-name preflight, actual owner-membership consistency and membership duplicate preflight, reviewed local acceptance evidence, then a separately authorized coordinated backend/frontend rollout. No automatic collision repair. This phase never queries, migrates, deploys or otherwise contacts production.

L20 historical league leaderboards, L21 season membership/result snapshots, L22 historical deletion behavior remain NC-02F2 work. NC-02F2 has not begun.


## Final local result

- 211 unique applicable backend cases passed: 208 passed in the full run and three passed corrective rerun. Initial evidence is retained; the first focused development run is also retained. The corrections were a Unicode fixture encoding error, a synthetic new-season bracket-window setup error, and an explicit adaptation of the legacy malformed-body/unconfirmed-delete error matrix. No bracket timing, scoring or rollover behavior was loosened.
- 307 offline tests and 42 frontend tests passed. Frontend TypeScript and production-mode build passed (local build only). Existing browser-data age and bundle-size warnings remain.
- Global frontend lint remains the pre-existing 83 errors/one warning; changed files add no diagnostic and the new component is clean. No standalone backend linter exists; compilation and baseline unused-import comparison passed. Scoped Black and whitespace checks passed.
- Fresh baseline-to-0008 proof passed, including nine F1 SQL groups and all prior E SQL proof groups. Strict catalog/security verifier and marker verifier passed. Baseline and 0001-0007 bytes are unchanged.
- Independent cleanup: SEEDED / nc-fixtures-v1; exact checksum `a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0`; four synthetic users, 30 standings, zero canonical leagues/members/competition/history/audits. Temporary league scenarios were reset, not added to canonical seed. Flask stopped, locks released, disposable DB removed, email empty, jobs and unrestricted/scoped mutation admission off. The standalone fixture verifier's legacy harness=UNMET field denotes no active lease; the complete harness readiness is PASS / AVAILABLE_GUARDED after cleanup.
- Both repository privacy/file reviews passed; no credentials, environment files, raw dumps or private user data were added. Only four pre-existing Flask league mutator functions changed; unrelated function/class ASTs and old route inventory are preserved, with precisely three owner-management routes added.

NC-02F1 is complete locally. No production contact or next phase began. Normal independent Git commit identifiers are reported in the completing response without amending old commits.
