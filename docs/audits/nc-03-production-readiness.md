# NC-03 — Production readiness: NOT READY

This is a stopped, incomplete readiness audit. It is not deployment approval.
No production connection, preflight, migration or deployment was performed.

## Release blocker

NC03-SEC-001: absent JWT_SECRET selects a nonempty source signing fallback even
in explicit production mode. A locally forged token authenticates through actual
current auth code with a synthetic existing-user read. Deployed configuration is
unknown. Separately authorize narrow repair; do not change keys or rotate secrets
as part of this audit. Re-run NC-03 before any release-readiness claim.

## Outstanding production-preflight checklist

These are required topics, not completed/executable preflight certification:

- Verified restorable backup and current deployed schema/code checkpoints.
- Baseline/security privileges and complete forward0001–0011 applicability.
- Canonical season uniqueness/designation, season timing, bracket owner+season
  uniqueness, canonical active master consistency and current standings assumptions.
- 0008: lower(trim(name)) collisions, owner-membership integrity, duplicate members.
- 0010: normalized username/email collisions and blank/null identities.
- 0011: legacy reset rows/fields, impending link invalidation, auth_version default
  and nonnegative state; verify signing configuration without printing values.
- Structured global/league historical integrity and rollover readiness.
- Inventory exact existing read-only SQL/tool paths and any missing preflight tool
  before authorization. This mapping remains unfinished; no unsafe substitute SQL
  is supplied and no production preflight is claimed to pass.

## Outstanding configuration registry

Classify database/service-role and migration settings, JWT signing/algorithm,
reset frontend URL and Brevo transport, canonical season/timing, ESPN authority,
cron/job authorization, environment classification and forbidden test controls.
JWT_SECRET is required; a source fallback must not satisfy that requirement.
Other fields have not yet received consolidated NC-03 classification.
Do not copy credentials into these audit documents.

## Provisional release order and compatibility boundaries

After repair and completed NC-03 only: authorize controlled read-only production
preflight, verify backup, resolve preflight findings, plan a coordinated maintenance
window, review/apply migration chain, release compatible backend then frontend,
validate canonical config, approved smoke checks/reset links, jobs and monitoring.
This order is provisional until schema/backend compatibility windows are verified.

Prior G2 evidence describes legacy missing-av sessions as version0 until reset,
auth_version enforcement by the new backend, and invalidation of legacy reset
links by0011. Never deploy new frontend against an incompatible old reset backend.
A migration may remove assumptions needed by older backend code; ordinary rolling
rollback is not certified. Preserve a coordinated fallback/recovery plan.

Code rollback is not migration rollback or data recovery. Hard-deleted rollover
drafts require backup recovery. Completed password changes/session revocations and
invalidated legacy links are not undone by reverting code. Immutable finalized
history must not be casually rewritten as rollback. Verify precise boundaries
before separately authorized release.

## Conditional safe production smoke design — DO NOT EXECUTE IN NC-03

Read /season, standings, safe public history and public league discovery. With an
explicit approved test account only, log in and read /auth/test-me. With an approved
nonmember identity, verify private denial. Only send reset mail if an approved test
mailbox exists. Never invent credentials or trigger rollover/destructive bracket
writes. Definitive endpoint/response/error verification remains part of resumed
NC-03; these suggestions do not certify an executable smoke suite.

## Resume boundary

Do not deploy or begin NC-04. Obtain separate authorization for the JWT signing
configuration repair, then resume NC-03 without discarding prior phase evidence.
Fresh full suites, full-chain disposable proof, catalog/function/grant inventory,
118-rule source/coverage mapping, CROSS01–12, frontend/error/config/performance
reviews, preflight tooling mapping and fixture cleanup proof remain uncompleted.
