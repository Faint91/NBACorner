# NC-03 resumed audit — FAIL on NC03-SEC-002

Verified UTC: 2026-10-17T20:00:09.782838+00:00. This resumed audit is **stopped and incomplete**, with
production readiness **NOT READY**. No product repair or production contact.

## Reverified repair

Starting backend main `1f2866f8797c8bbd574c9844425a4dea3f15a91e` and frontend
main `4fa0e9fc11d49354e3da137ee43e9d1ddbc87357` were clean.
NC03-SEC-001 is **PASS / repaired and reverified**: seven unsafe startup cases
refuse; valid configured-key tokens work; old-source-fallback forgery returns 401;
legacy version0 compatibility works. Fresh25-case guarded auth acceptance passed,
including actual app startup/login, reset commits, auth_version increment, old-token
revocation and new-login success. No prior repair result was substituted for this
fresh run. The already-started narrow auth run completed and performed cleanup;
no broad suites were initiated after confirming the new finding.

## Confirmed new finding NC03-SEC-002

`app.py:3500`, **GET /__debug/master-status**, has no authentication decorator.
With a valid canonical-season precondition and a synthetic existing bracket, the
actual current route returns linkage with 200 without Authorization. On a simulated
season-query failure it catches the exception and returns raw `str(e)` in an
`exception` JSON field (500). Its missing-column branch additionally returns
`fix_sql` repair statements and raw exception details (500). A missing bracket-id
control returns 400. The global current before-request hook checks canonical season
but does not authenticate this route.

This violates **resumed NC-03 section 16: no user-facing SQL or raw DB/provider
internals**. That foundational error contract is the narrow failed requirement;
no unsupported FAIL is assigned to one of the 118 product IDs. No real stored
credential disclosure or actual deployed exposure is asserted. The unauthenticated
route was present in the NC-01 static inventory but its fault output had not been
exercised. It is not attributed to R1.

Proof: `python -B scripts/audit_nc03_debug_error.py`. The proof compiles the exact
current route and actual global before-request hook, supplies only synthetic
read doubles/canonical-season success, blocks networking and emits booleans/status
codes rather than raw provider detail/SQL. There are no database mutations and no
application module import/listener. It does not contact production.

## Matrix and audit boundary

The registry retains all 118 exact approved IDs. 117 numbered headings were read
from the approved phase prompts; SC17 comes from the explicit user business decision
and D2 repair documentation. **16 PASS, 102 BLOCKED, 0 product FAIL, 0 NOT APPLICABLE.**
A1–A14 and A19/A20 were individually supported by fresh focused acceptance/current
source. A6 additionally uses prior trustworthy race/semantic proof, corroborated by
matching current function/migration source; no fresh race rerun is claimed. A19 is
current direct route/source inspection, with no new dedicated automated test.
All other rules remain unverified because of the **new** NC03-SEC-002 stop, not
because of the historical NC-03 interruption. This is not a completed118-rule audit.

## Requested52-item completion record

| # | Requested result | Resumed audit disposition |
|---|---|---|
|1|Starting repositories|Both expected main checkpoints, clean; hashes above.|
|2|NC03-SEC-001|PASS / repaired and reverified; fresh offline scenario and25 live auth cases.|
|3|Migration inventory|Ordered post-baseline0001–0011 present; current hashes in JSON. No complete fresh integrity certification.|
|4|Final DB-object inventory|BLOCKED; no final catalog inventory performed.|
|5|118-rule totals|16 PASS,102 BLOCKED,0 FAIL,0 NOT APPLICABLE; separate error-contract FAIL.|
|6|P1–P10|10 BLOCKED; broad privacy audit unfinished.|
|7|B1–B16|16 BLOCKED.|
|8|S1–S14|14 BLOCKED.|
|9|SC1–SC17|17 BLOCKED.|
|10|RR1–RR16|16 BLOCKED; revised RR12 retained as contract, not certified.|
|11|L domain|25 BLOCKED including L20A/L20B/L21A.|
|12|A1–A20|16 PASS: A1–A14,A19,A20; A15–A18 BLOCKED pending broader/frontend/privacy review.|
|13|Foundation|FAIL on error-contract NC03-SEC-002; DB architecture not fully re-certified.|
|14|App functions/grants|BLOCKED; no final DB-function/grant inventory.|
|15|CROSS-01|BLOCKED; complete sequence not run.|
|16|CROSS-02|BLOCKED.|
|17|CROSS-03|BLOCKED.|
|18|CROSS-04|BLOCKED.|
|19|CROSS-05|BLOCKED.|
|20|CROSS-06|BLOCKED.|
|21|CROSS-07|BLOCKED.|
|22|CROSS-08|BLOCKED.|
|23|CROSS-09|BLOCKED.|
|24|CROSS-10|BLOCKED.|
|25|CROSS-11|BLOCKED; auth-current-user reset proof is not the required non-auth product endpoint proof.|
|26|CROSS-12|BLOCKED.|
|27|Frontend/backend contracts|BLOCKED; full contract review unfinished, frontend untouched.|
|28|Error sanitization|FAIL: unauthenticated diagnostic returns raw provider/database exception and SQL fixes.|
|29|Secret/privacy static|New audit artifact pattern checks only; full-project secret audit not completed, absence not claimed.|
|30|JWT/fallback audit|PASS repaired finding; no key rotation; invalid config/forgery rejected.|
|31|Deprecated authorities|Unauthenticated legacy diagnostic remains active. Other obsolete-authority audit unfinished.|
|32|Performance|Not audited; no performance conclusion.|
|33|Coverage gaps|102 product IDs and all 12 complete CROSS sequences lack completed resumed verification. A19 direct audit only.|
|34|Fresh migration chain|Not run after new stop; no new proof database created.|
|35|Backend tests|25 fresh focused auth cases passed; full applicable backend suite not run.|
|36|Offline tests|Focused JWT and diagnostic proofs passed as reproductions; full offline suite not rerun.|
|37|Frontend tests/build/lint|Not run. Prior60-test/build/lint results not counted as fresh.|
|38|Cross integration|0 complete requested CROSS sequences certified.|
|39|Cleanup|Canonical SEEDED/nc-fixtures-v1 checksum unchanged; four users/version 0, 30 standings; no resets/audits/locks/proof DB; Flask stopped/capture empty/jobs and admission disabled.|
|40|Production config|Explicit backend JWT_SECRET prerequisite confirmed; full config registry unfinished.|
|41|Preflights|No production preflight executed; definitive tooling/checklist completion pending.|
|42|Release order|Not finalized; repair/re-audit must precede controlled preflight, backup/migration/release planning.|
|43|Compatibility|Not fully audited; no compatibility/deployment readiness assertion.|
|44|Rollback|Not fully audited; code rollback does not restore deleted data, resets or finalized history.|
|45|Production smoke|Design not finalized; no production login/reset/jobs/destructive action performed.|
|46|Production contact|NONE. No deployment, production queries, emails, votes, schedules or key rotation.|
|47|Audit files|Separate resumed reports/records and audit-only proof/runner; historical files unchanged.|
|48|Git|Normal audit-only commit; hash and final clean state reported in completion response.|
|49|NC-03 status|FAIL; incomplete after reproduced new defect.|
|50|Readiness|NOT READY.|
|51|Repair needed|Separately authorize NC-03R2 — Diagnostic error-response sanitization; no repair performed.|
|52|Next checkpoint|Resume NC-03 after separately authorized repair. Do not begin NC-04.|

## Historical preservation and limits

Original a058752 NC-03 failure artifacts and 1f2866f NC-03R1 evidence are byte-preserved.
Only newly named audit artifacts/tools are added. Application/frontend/schema/
migrations/configuration/C:/1on1ball remain untouched. The original first failure
and local repair chronology remain true; this finding is separately recorded.
