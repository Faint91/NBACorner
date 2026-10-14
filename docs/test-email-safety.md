# NC-ENV-04A — Test email capture and reset-link isolation

Production retains its existing Brevo implementation. Test mode requires explicit
`NBA_CORNER_EMAIL_MODE=capture` and `NBA_CORNER_RESET_LINK_ORIGIN` matching the
reviewed enrollment's backend origin. The current value is http://127.0.0.1:55410.
These non-secret fields are in the ignored .env.test.nba-local.local and in the
existing local helper's future configure output. No Brevo credential/sender is
needed or accepted in test config. Ambient BREVO_/SENDINBLUE_ configuration refuses
test delivery/readiness; the controlled launcher still drops provider secrets.

## Source map and preserved production semantics

app.py `/auth/forgot-password` creates a token_urlsafe(32) token, saves it to
password_resets with the existing 24-hour expiration and renders the existing HTML
subject/body. `/auth/reset-password` consumes the existing token/expiry/used state
and password policy; it does not send email. `/test-email` retains its admin/JWT/DB
checks, rate limit, message body and success/failure responses. Both sending paths
call send_email_via_brevo, now a central wrapper through email_transport.deliver_email.
The original body is renamed _send_email_via_brevo_production and is otherwise
AST-identical: requests.post to the existing Brevo SMTP endpoint, original api-key
headers, sender NBA Corner / BREVO_SENDER_EMAIL (existing default preserved),
HTML payload, timeout=20, statuses 200/201 and existing exception/log handling.
Production reset URL construction remains exactly the prior backend URL/value.
No email operation occurs at import/startup. Only the capture store is initialized.
No parallel send implementation was found in source; environment diagnostics expose
provider presence only and remain unchanged.

PRESERVED CURRENT BEHAVIOR / FUTURE BUSINESS REVIEW: forgot-password ignores the
send result and retains its neutral response on delivery failure; debug mode can
log the Brevo status twice. Production's hardcoded reset-link destination remains
unchanged. No account eligibility, token lifecycle/expiry, password/JWT rule,
endpoint status or product workflow was repaired here.

## In-memory capture and token safety

email_transport.CaptureMailbox stores recipient, subject and rendered body in
insertion order, with sequence/transport metadata only. No clock dependence,
provider calls, files, DB persistence or real sender. Its clear() resets content
and sequence. Test mode cannot select/inject a non-capture transport.

Future offline tests may deliberately inspect and clear:

```python
from email_transport import test_mailbox
mailbox = test_mailbox()
mailbox.clear()
messages = mailbox.inspect_messages()  # Explicit sensitive in-memory inspection.
# Inspect messages[0].recipient / .subject / .body through private test assertions.
# Do not print or serialize messages, bodies or reset links into reports.
mailbox.clear()
```

CapturedEmail repr hides recipient/subject/body; safe metadata contains only a
sequence and transport label. No mailbox HTTP endpoint exists. Raw token/body/link
access is deliberate in-process inspection, never normal logs or persistent
artifacts. Tests use synthetic addresses/tokens, boolean content checks and
captured stdout/stderr/log streams. Existing production logs remain status/class
only; no token, credential or provider exception payload logging was introduced.

## Readiness and remaining gates

The pure email gate requires test identity, capture mode, no live provider fields,
and an explicit well-formed non-production reset origin equal to enrollment.
verify_test_email_readiness also authenticates the existing local DB marker.
prepare_runtime_environment checks email safety before the remaining startup gate.
It still refuses before Supabase client construction/application mutation. Email
capture can be tested independently of fixture data; it is not an execution permit.

From C:/NBACorner/backend:

```text
python -B scripts/local_supabase_environment.py email-readiness --config C:/NBACorner/backend/.env.test.nba-local.local
python -B -m unittest discover -s tests/offline -p test_environment_safety.py
python -B -m unittest discover -s tests/offline -p test_email_transport.py
```

Live read-only local readiness passed with email_gate_passed=true,
identity_verified=true and mutation_permitted=false. The marker remains UNSEEDED.
61 existing guard tests and 20 email tests passed. AST comparison preserves the
original provider body and all 62 other application functions; forgot-password
changes only its link-builder call. The production URL, sender/payload/request,
status/exception behavior and reset lifecycle were verified offline with mocks.
No Flask/app import, admin endpoint call, password-reset DB workflow, real email,
Brevo/production request or integration mutation occurred.

Provider fixtures/egress, job/schedule neutralization, synthetic fixtures/reset and
the final guarded harness remain pending. Do not start them from this phase.
No frontend, standings, schedules, DB baseline, marker or registry changes.
