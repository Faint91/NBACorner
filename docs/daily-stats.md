# Monthly Daily stats facade — STATS-02D (local only)

`GET /daily/stats?month=YYYY-MM` uses the existing NBA signature, expiration,
user-existence and auth_version verification. The subject is server-derived.
Omit month for the current America/Vancouver month; future, malformed, duplicate
and extra parameters return 400. No UI/helper changes are included.

Future NBA-only configuration (not populated): `DAILY_STATS_READ_URL`
(PUBLIC_CONFIGURATION, mandatory HTTPS controlled NBA `/1on1` internal-read
target, no default) and `DAILY_STATS_READ_TOKEN` (SECRET). The same token belongs
only in Daily candidate server configuration. No Vite/client or Worker secret.
Use at least 32 cryptographically random bytes encoded as base64url/hex, 43–128
characters; never reuse another secret. Tests use conspicuously synthetic strings.

The service creates one fresh Requests session, disables inherited netrc/proxy
configuration, uses only Accept/read-token headers, follows no redirects and makes
no retries. Timeouts are 2 seconds connect / 3 seconds read, with a seven-second
stream budget checked after each chunk (an in-progress read can add up to the read
timeout). Maximum decoded response is 512 KiB / 500 subjects. Missing config,
disabled Daily policy, timeouts, invalid data and upstream failure return a generic
private/no-store 503. Existing auth failures remain 401; rate limits are 60/IP and
30/verified-user per minute.

Every upstream object/key/type/count/UUID/month/timezone/version is validated before
ranking. Duplicate UUIDs and JSON keys fail closed. Counts must fit calendar-month
gameplay bounds (two players and one prediction per matchup day; up to three hints
per correct player). No partial/truncated ranking is returned.

One batched NBA users lookup selects only `id,username` for all input UUIDs plus
the current user, after the ordinary authentication lookup. Physical absence is
the current NBA account-deletion model. Missing, blank, over-80-character or
Unicode-control-containing names are excluded. A current user disappearing between
authentication and the batch fails unavailable. No JWT-cached username fallback.

Sort eligible rows by `(-correctPlayers, Fraction(hintNumerator,
hintDenominator), NFC(casefold(NFC(currentUsername))), canonicalUUID)`.
Positions are unique index+1. Display names remain unchanged. Python Fraction
performs exact ordering; JSON averageHints is ordinary unrounded numeric division.
UUID is a hidden final fallback and is never emitted to the browser.

The response contains contract/month/timezone, `me` (username, correctPlayers,
correctPredictions, averageHints, rank), participantCount, top3 and neighborhood.
Public leaderboard rows contain only rank/username/correctPlayers/averageHints;
only the neighborhood self row additionally has isCurrentUser=true.
An absent Daily subject produces personal 0/0/null/null without enrollment.
Correct predictions alone do not confer a rank. Neighborhood is empty at ranks
1–3 or when unranked; otherwise two existing rows above/self/two below, without
boundary compensation. No UUID, raw fractions or service credential is returned.

Complexity: one aggregate HTTP call, one batched lookup, O(S log S) ordering and
O(S) memory. V1 fails closed beyond 500 active subjects or 512 KiB rather than
silently excluding candidates. Growth requires an explicitly reviewed bounded
pagination/batched RPC design; URI size of the UUID filter and Supabase row limits
must be revisited then. No caching, write tables or rank persistence are added.

Tests: `python -m unittest discover -s tests/offline` (offline only; do not start
the production-configured app for these tests). Full contracts and cross-project
validation are recorded in Daily `docs/stats-02d-monthly-read-facade.md`.
