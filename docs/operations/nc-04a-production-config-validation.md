# Production configuration validation — restricted procedure specification

NC-04A gate closure, 2026-10-18. PLANNING / READ ONLY ONLY. Not run against production.
This specification does not authorize retrieving credentials, creating an executor,
changing config, deploying, importing app.py, or sending email. Render Free has no
Shell; an operator must first establish an approved secure validation channel.
Names and masked presence are not successful validation.

## Identity and secret boundary

1. Bind the check to NBA Corner Render service srv-d4239u6uk2gs73b8fts0 and the
   intended production runtime configuration. Record service/revision and UTC time.
2. Use the service's existing effective environment in an approved secure runtime,
   or a separately approved operator-controlled equivalent whose exact service
   provenance is demonstrated. Local .env, a guessed configuration, browser hidden
   state, a different service and build-only variables are not production proof.
3. Do not enumerate/export the environment. Read only the named settings below in
   memory; no clipboard, files, logs, subprocess command arguments or remote URL
   may contain their values. Disable tracing and verbose exception output.
4. Output only the fixed boolean/UNKNOWN schema below. Never output JWT/provider
   material, substrings, hashes, lengths, sender addresses or full reset links.
5. Do not import app.py, construct Supabase clients or invoke providers/routes.
   Validators must be pure. No synthetic token needs to be issued or emailed.

## Required boolean results

- jwt_present, jwt_nonblank, jwt_final_validator_pass: run the existing pure
  jwt_configuration.validate_jwt_secret against JWT_SECRET in memory. Do not
  silently strip/replace it. Report pass/fail only, not its length.
- jwt_not_legacy_fallback: compare in memory against known unsafe legacy signing
  fallback(s) from the audited old source, without including literals in output.
  The current validator alone establishes presence/minimum length, not every
  placeholder or entropy property. If fallback exclusion cannot be proved, UNKNOWN.
- jwt_algorithm_supported: verify JWT_ALGORITHM matches the reviewed application
  contract. Preserve the existing valid signing key; no rotation.
- frontend_origin_valid, frontend_hostname_expected, frontend_distinct_api,
  reset_routing_contract_valid: reuse the pure
  scripts.verify_nc03r3_reset_routing.inspect_config with FRONTEND_ORIGIN and the
  public API https://nbacorner.onrender.com. Additionally require hostname exactly
  www.nbacorner.com, HTTPS and the intended root origin. Do not print configured
  origin or the synthetic link. Syntax/distinction alone is not actual host proof.
- email_credential_present: BREVO_API_KEY nonblank, output boolean only.
- email_sender_configured: BREVO_SENDER_EMAIL is explicit, nonblank and syntactically
  valid; BREVO_SENDER_NAME follows current sender semantics. No fallback address is
  accepted as explicit configuration evidence. Provider-approved sender readiness
  requires existing provider metadata/operator evidence; syntax is insufficient.
- real_email_mode, no_capture, no_fixture, no_test_admission: inspect only
  NBA_CORNER_ENV, NBA_CORNER_TEST_CONFIG, NBA_CORNER_EMAIL_MODE,
  NBA_CORNER_PROVIDER_MODE, NBA_CORNER_ALLOW_MUTATING_TESTS and the actual reviewed
  guard/transport branches. Missing NBA_CORNER_ENV uses the supported legacy real
  production branch; record this separately from explicit production classification.
  Do not read a test-config file, validate enrollment by network or invoke a job.
- production_cors_branch: FLASK_ENV exactly production and the validated frontend
  origin. NBA_CORNER_ENV alone does not select Flask's CORS branch.
- flask_debug_disabled, diagnostic_debug_disabled: evaluate FLASK_DEBUG and
  ENABLE_DEBUG_LOGS using their real code semantics; fixed gunicorn app:app start
  is separately verified. No development/debug execution.
- rate_limits_enabled: DISABLE_RATE_LIMITS must not select its literal enabling
  value for bypass. Also review intended limits from approved local code; key
  presence is insufficient.
- production_guard_correct: test tooling denies the production project; no test
  registry/lease/config path admitted. NBA_CORNER_JOBS_ENABLED is a test-only flag,
  not a production maintenance or pause switch.

## Acceptance record

Record only service identity, UTC observation, audited target source revision,
validator version, named boolean results, provider/sender metadata availability and
PASS/BLOCKED. Include proof that values apply to the intended runtime. Any unknown
mandatory result is BLOCKED. Do not label an unexecuted procedure as production PASS.

Existing pure CLI for the origin check (only within the approved environment):

    python scripts/verify_nc03r3_reset_routing.py --check-runtime-config --api-origin https://nbacorner.onrender.com

This command does not load dotenv or contact providers. It does not replace JWT,
provider/sender, flags or source-service verification. No command was run against
production during this gate-closure pass.
