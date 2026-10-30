# AUTH-STATS local issuer

`POST /auth/daily-assertion` adds the dedicated Daily-only RS256 assertion after
the existing normal NBA authentication checks. No account profile or ordinary NBA
token is returned. It is private/no-store and uses dedicated rate buckets.

Future configuration (not populated by this work):

* `DAILY_STATS_ASSERTION_PRIVATE_KEY`: SECRET, NBA backend only, dedicated RSA.
* `DAILY_STATS_ASSERTION_KEY_ID`: PUBLIC_CONFIGURATION, `daily-stats-*` version.
* `DAILY_STATS_ASSERTION_ISSUER`: PUBLIC_CONFIGURATION, exactly
  `https://www.nbacorner.com`.

No ordinary NBA JWT signing secret is reused or shared with Daily. Missing key
configuration fails closed with sanitized 503. Tokens last 45 seconds and include
only the reviewed Daily contract claims. Existing `require_auth` checks user
existence/auth_version on every issuance; older assertions have only bounded
expiry lag. No distributed revocation or NBA auth policy change is introduced.

The frontend's standalone `/daily-stats-auth.html` helper alone reads existing NBA
auth storage and sends the ordinary NBA credential directly to this backend. It
passes only the short-lived assertion/status to Daily, with exact origin/window
and nonce checks. No assertion is persisted or placed in a URL.

Full cross-repository contract, framing headers, key rotation, Worker proposal and
local validation design: [Daily identity bridge](C:/1on1ball/docs/auth-stats-identity-bridge.md).

Offline test entrypoint:
`python -m unittest discover -s tests/offline -p test_daily_assertion.py`.
Tests execute the real auth/issuer functions under an isolated Flask fixture and
synthetic DB/keys without importing the production application or using network.

This is local implementation only: no deploy, production credentials/configuration,
production migration, Daily cutover or stats tracking is enabled.
