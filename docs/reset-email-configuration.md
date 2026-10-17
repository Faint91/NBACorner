# Password-reset email routing

`FRONTEND_ORIGIN` is the existing backend frontend/CORS setting and is now also
required for real reset-email links. Configure the externally reachable browser
frontend origin, never the Flask/API origin. No new environment variable or source
hostname fallback is introduced. Do not commit environment-specific real values.

Example semantics only: `FRONTEND_ORIGIN=https://frontend.example.invalid`.
This synthetic example is not a production configuration recommendation/value.

Production and legacy unset-NBA_CORNER_ENV mode require an absolute HTTPS origin
with a hostname and optional valid port. An optional trailing slash is accepted.
Paths other than root,credentials,query/fragment components,whitespace,malformed
hosts/ports and markup/backslashes are rejected with a fixed private error.

`email_transport.build_reset_link` reads the explicit runtime setting and delegates
to one builder. It attaches exactly `/reset-password` and safely encodes one `token`
query parameter. The existing frontend captures that parameter in memory,removes it
before analytics initialization and POSTs `token` plus `new_password` to the API's
`/auth/reset-password`. No Flask reset UI or GET redirect exists or is needed.

Missing/blank/invalid configuration sends no reset email. Existing G2 orchestration
conditionally cancels the issued digest; clients retain the generic reset-request
response to avoid account/configuration enumeration. A generic200does not prove
email delivery. No generated full link or verifier belongs in logs/docs/evidence.

Guarded test mode remains independent:its explicit `NBA_CORNER_RESET_LINK_ORIGIN`
and capture-only settings must satisfy the unchanged enrollment gate. This pinned
loopback origin is a capture stand-in,not a newly exposed frontend or a production
fallback. R3 acceptance injects an independently explicit synthetic HTTPS frontend
origin into the actual production-mode link helper while leaving the real guarded
HTTP API,DB RPCs and local capture transport intact. No request is made to that
synthetic hostname and no real email is sent.

Before deployment,resumed NC-04A must verify `FRONTEND_ORIGIN` exists,is valid,points
to the intended public frontend and differs from the API origin. Missing or API-host
configuration is NO-GO. Syntax validation alone cannot establish that a host serves
the intended UI. The pure read-only check below returns only names/booleans and route
metadata;it never loads dotenv,connects,issues a token,sends mail or changes config:

```text
python -B scripts/verify_nc03r3_reset_routing.py --check-runtime-config --api-origin <explicit-public-api-origin>
```

Use this later only in an explicitly authorized environment/config-verification
procedure. It reads only FRONTEND_ORIGIN from that caller's environment. It does not
certify other runtime flags,credentials,hosting,backup or full production readiness.
R3 did not contact production or change that setting.
