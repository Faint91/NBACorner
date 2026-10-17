# NC-03R3 — Reset-link routing repair

**PASS — repaired locally.** Finding status: **NC04A-CODE-001 = REPAIRED LOCALLY / pending NC-04A re-verification**. NC-03 remains PASS;NC-04A remains BLOCKED. No production contact.

## Completion record

| # | Item | Result |
|---|---|---|
| 1 | Starting repositories | Backend main6f7fb5110cf5de95293b763ee61b86040c3ff7a3; frontend main4fa0e9fc11d49354e3da137ee43e9d1ddbc87357;both clean. |
| 2 | Root cause | NC04A-CODE-001:email helper hardcoded the API origin although frontend owns reset UI. |
| 3 | Frontend contract | Public /reset-password;one query token parameter;ResetPasswordPage;POST /auth/reset-password with token/new_password. No frontend application change. |
| 4 | Previous construction | Hardcoded API host plus frontend path;no backend GET UI or redirect exists. Historical finding preserved. |
| 5 | New construction | One build_reset_link/reset_link_for_settings path validates explicit frontend origin,joins exact route and urlencode-encodes token. No hardcoded production frontend/API host. |
| 6 | Configuration design | Reuse existing FRONTEND_ORIGIN from backend CORS/public frontend config. No new variable. API/test API/VITE_API_URL are not reset UI authorities. Guarded capture setting remains separate. |
| 7 | Missing configuration | Fail closed:no reset email;generic200request response retained;G2 conditional cancellation clears issued digest without leaking config/account state. |
| 8 | Invalid configuration | 28negative origin cases tested,including blank/relative/no-host/unsupported scheme,path/query/fragment/credentials/bad port/markup. No invalid-destination email emitted. |
| 9 | HTTPS | Required in production and legacy real-email mode. Existing enrolled test capture may use explicit loopback HTTP;guard unchanged. |
| 10 | Positive synthetic links | Passed origin/root slash/port/token encoding tests and real guarded capture. Explicit synthetic frontend distinct from local API. |
| 11 | API-host regression | API settings cannot supply a fallback. Read-only preflight rejects missing frontend or same-origin API configuration,including equivalent default443port. |
| 12 | Token parameter | Exactly one query parameter named token;frontend contract unchanged. No path/hash/second location introduced. |
| 13 | Full local flow | PASS:request,capture URL in memory,verify frontend route,extract token,complete API reset,old password401,new password200,old JWT401,new JWT200,replay400. |
| 14 | Enumeration | PASS:unknown/matching requests retain same generic response;unknown sends none;bad config details not exposed. |
| 15 | Delivery failure | PASS:generic response,cancellation of issued verifier;actual local DB proof confirms failure cancellation does not remove a newer issuance. |
| 16 | JWT/session regression | Full focused G2/G1 acceptance and R1 proof pass;auth_version/revocation unchanged. No token/password orchestration code modified. |
| 17 | Frontend token hygiene | 6existing Node reset tests PASS;memory only,pre-analytics token scrub,successful reset clears auth;no frontend changes. |
| 18 | Static search | One authoritative runtime path;no active source/API reset-link fallback or production hostname in email_transport.py. Historical audit proof/references retained as history only. |
| 19 | NC04A tooling | Current entrypoint delegates to repaired routing proof and writes R3 evidence;original finding JSON unchanged. New pure names/booleans config interface can support future authorized read-only preflight. |
| 20 | Validation totals | 359offline tests,19guarded acceptance (8G2+8G1+3R3),6frontend reset tests,R1 proof,R2 46scenarios,TypeScript/Vite build,Black/compile/import/scope/secret/whitespace checks passed. |
| 21 | Cleanup | SEEDED nc-fixtures-v1 checksum a96f2c44f571e830624cef17e91ba02ae883d8a5768a81730d29d6a42adad1b0;4users/version0,reset0,Flaskstopped,mailempty,jobs/admissiondisabled,locks0,proofDB0. |
| 22 | Production | No production contact/configuration changes,deployment,migration,real email or frontend/API probe. |
| 23 | Files | email_transport.py;targeted tests/focused runner;current routing/preflight proof tools;configuration/repair docs and separate R3 evidence. No schema/auth/session/frontend changes. |
| 24 | Git | Normal backend repair commit requested;no amend. Final hash/clean status returned after commit. Frontend remains expected HEAD. |
| 25 | Finding status | NC04A-CODE-001 = REPAIRED LOCALLY / pending NC-04A re-verification. |
| 26 | NC03 | PASS — unchanged;historical audit records not rewritten. |
| 27 | NC04A | BLOCKED — deferred production verification and other prerequisites remain. NC04B not started. |
| 28 | Next step | Explicitly resume NC04A from repaired local HEAD;verify correct actual production FRONTEND_ORIGIN before deployment. Missing/invalid/API-host value is NO-GO. Not resumed automatically. |

## Scope and interpretation

Only runtime email configuration/link construction changed. Existing G2 issuance still generates and stores a digest before attempting link construction/delivery. Invalid configuration follows the same safe failure path:send nothing,conditionally cancel that issuance and preserve the generic response. A newer concurrent issuance is protected. No raw verifier/full generated URL is written to logs or evidence.

FRONTEND_ORIGIN must be the actual public frontend,not merely any syntactically valid host. The pure preflight check verifies syntax/distinction and local routing contract;resumed NC04A must separately confirm real hosting and configuration. R3 did not read or change production values.

The guarded capture-origin gate was deliberately not broadened. Its enrolled loopback origin remains a memory-capture stand-in. The new full-flow test explicitly injects synthetic frontend configuration only into the real production-mode link helper;the actual guarded HTTP API,database reset RPCs and capture transport stay intact. No synthetic frontend listener or external contact is required.

## Reproduction and evidence

- `python -B -m unittest discover -s tests/offline -q`
- `python -B scripts/run_nc03r3_acceptance.py --config <ignored-local-config> --allow-local-mutations`
- `node --test scripts/test-password-reset.cjs` in frontend
- `npm run build` in frontend
- Existing R1/R2 offline proof run functions,with separate R3 JSON output
- `python -B scripts/nc04a_reset_route_proof.py` now evaluates current repaired behavior and writes separate R3 routing evidence

Machine record:`db/records/nc_03r3_reset_link_routing.json`. Focused case IDs:`nc_03r3_acceptance.json`;cleanup:`nc_03r3_cleanup.json`;static/scope:`nc_03r3_static_validation.json`;routing:`nc_03r3_routing_contract.json`;R1/R2:`nc_03r3_jwt_regression.json`/`nc_03r3_diagnostic_regression.json`. Configuration semantics:`docs/reset-email-configuration.md`.

All previous NC03/NC04A records remain unchanged. No NC04A restart,production setting edit,backend reset UI/GET workaround,deploy,migration or NC04B execution occurred.
