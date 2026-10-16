from history_service import (
    create_final_leaderboard_snapshot,
    SnapshotError,
    public_snapshot_rows,
    public_columns,
)
from scoring_engine import rank_live_rows
from scoring_service import (
    recompute_current_scores,
    get_current_scoring_master,
    ScoringError,
)
from standings_service import refresh_current_standings, StandingsRefreshError, log_result
from canonical_season import get_current_season, SeasonConfigurationError
from bracket_rules import game_count_error, apply_prediction, submission_error
# app.py
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, make_response, send_from_directory, g, has_request_context
from flask_cors import CORS
from supabase import create_client
from environment_safety import prepare_runtime_environment
from email_transport import deliver_email, build_reset_link
from job_safety import guard_runtime_job
from collections import defaultdict
import time
import threading
import secrets, requests
import jwt
import re
import os
import bcrypt
import uuid

# --------------------------------------------------------
# ----------------- Environment variables  ---------------
# --------------------------------------------------------

class APIError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

# load .env
prepare_runtime_environment()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
DISABLE_RATE_LIMITS = os.getenv("DISABLE_RATE_LIMITS", "0") == "1"
STANDINGS_CRON_TOKEN = os.getenv("STANDINGS_CRON_TOKEN")
BALLDONTLIE_API_KEY = os.getenv("BALLDONTLIE_API_KEY")

HEADERS = {}
if BALLDONTLIE_API_KEY:
    HEADERS["Authorization"] = BALLDONTLIE_API_KEY

# ✅ Healthcheck secret (optional; if set, /health requires it)
HEALTHCHECK_TOKEN = os.getenv("HEALTHCHECK_TOKEN")

# ✅ Bcrypt work factor (cost). 12 is a good starting point.
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# ✅ Password policy
PASSWORD_MIN_LENGTH = 10

# ✅ Shared identifier validation regexes
EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
USERNAME_REGEX = r"^[a-zA-Z0-9_]{3,30}$"


# --- NBA standings sync config ---

# Unofficial NBA Stats endpoint used by many community tools and libraries
# Example docs: leaguestandingsv3 on stats.nba.com :contentReference[oaicite:2]{index=2}
NBA_STATS_STANDINGS_URL = "https://stats.nba.com/stats/leaguestandingsv3"

# Usually "Regular Season"; you *could* override via env if needed
NBA_STATS_SEASON_TYPE = os.getenv("NBA_STATS_SEASON_TYPE", "Regular Season")

# Optional: shared secret so a cron job (Render or cron-job.org) can hit the refresh endpoint
STANDINGS_CRON_TOKEN = os.getenv("STANDINGS_CRON_TOKEN")



if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def parse_iso8601_utc(val):
    """
    Accepts:
      - ISO-8601 strings ('2026-04-12T18:59:50Z', '2026-04-12T11:59:50-07:00', '2026-04-12T18:59:50')
      - datetime (naive or tz-aware)
      - None / empty
    Returns a timezone-aware UTC datetime, or None if not set/parsable.
    """
    if not val:
        return None

    try:
        # Already a datetime?
        if isinstance(val, datetime):
            dt = val
        else:
            s = str(val).strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            safe_print(f"⚠️ Could not parse datetime value: {val}")
        except Exception:
            pass
        return None


def current_season():
    """Pin one canonical row per request; no stale process-wide season cache."""
    if not has_request_context():
        return get_current_season(supabase)
    if "canonical_season" not in g:
        g.canonical_season = get_current_season(supabase)
    return g.canonical_season


def _resolve_season_globals():
    # Compatibility entry for guarded test tooling: validate, never set globals.
    return current_season()


app = Flask(__name__)

# --- NBA helpers: teamSlug -> team code mapping used for standings sync ---

NBA_TEAM_SLUG_TO_CODE = {
    # East
    "hawks": "ATL",
    "celtics": "BOS",
    "nets": "BKN",
    "hornets": "CHA",
    "bulls": "CHI",
    "cavaliers": "CLE",
    "pistons": "DET",
    "pacers": "IND",
    "heat": "MIA",
    "bucks": "MIL",
    "knicks": "NYK",
    "magic": "ORL",
    "sixers": "PHI",   # Philadelphia 76ers
    "raptors": "TOR",
    "wizards": "WAS",

    # West
    "mavericks": "DAL",
    "nuggets": "DEN",
    "warriors": "GSW",
    "rockets": "HOU",
    "clippers": "LAC",
    "lakers": "LAL",
    "grizzlies": "MEM",
    "timberwolves": "MIN",
    "pelicans": "NOP",
    "thunder": "OKC",
    "suns": "PHX",
    "blazers": "POR",  # Portland Trail Blazers
    "kings": "SAC",
    "spurs": "SAS",
    "jazz": "UTA",
}


# CORS configuration
# -------------------
# In production: only allow your real frontend origin
# In development: allow localhost (or everything, if you prefer)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")  # e.g. "https://nbacorner.com"
FLASK_ENV = os.getenv("FLASK_ENV", "development")

if FLASK_ENV == "production" and FRONTEND_ORIGIN:
    # Strict prod: only your real frontend
    CORS(app, origins=[FRONTEND_ORIGIN])
else:
    # Dev / fallback: allow localhost dev frontends
    CORS(app, origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ])

BREVO_API_KEY = os.getenv("BREVO_API_KEY")

SENSITIVE_TOKENS = [t for t in [
    os.getenv("SUPABASE_KEY"),
    os.getenv("SUPABASE_SERVICE_ROLE_KEY"),
    os.getenv("SUPABASE_ANON_KEY"),
    os.getenv("BREVO_API_KEY"),
] if t]

# Optional: enable noisy debug logging only in dev
ENABLE_DEBUG_LOGS = os.getenv("ENABLE_DEBUG_LOGS", "0") == "1"


# --------------------------------------------------------
# ------------------ Static logos route  -----------------
# --------------------------------------------------------

LOGOS_FOLDER = os.path.join(app.root_path, "logos")

@app.route("/logos/<path:filename>", methods=["GET"])
def serve_logo(filename):
    """
    Serve team logo images from the /logos folder.
    Example: /logos/LAL.png
    """
    return send_from_directory(LOGOS_FOLDER, filename)


# --------------------------------------------------------
# ---------------- In-memory rate limiting  --------------
# --------------------------------------------------------

RATE_LIMITS = {
    # bucket_name: (max_attempts, window_seconds)
    "login_ip": (10, 60),              # 10 login attempts per IP per 60s
    "login_identifier": (5, 60),       # 5 login attempts per email/username per 60s

    "forgot_ip": (5, 300),             # 5 forgot-password requests per IP per 5min
    "forgot_identifier": (3, 300),     # 3 forgot-password per email/username per 5min

    "register_ip": (3, 3600),          # 3 registrations per IP per hour (example)

    # ✅ Added: rate limit bucket for /health when token missing/wrong
    "health_ip": (30, 60),             # 30 checks per IP per minute
}

_rate_events = defaultdict(list)
_rate_lock = threading.Lock()


def get_client_ip():
    """
    Try to get the real client IP, honoring X-Forwarded-For when behind a proxy.
    """
    xfwd = request.headers.get("X-Forwarded-For", "")
    if xfwd:
        # X-Forwarded-For: client, proxy1, proxy2, ...
        return xfwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(bucket: str, key: str) -> bool:
    """
    Returns True if this (bucket, key) has exceeded its limit within the window.
    Otherwise records the attempt and returns False.
    """
    # 🔧 Disable all rate limits when toggled (useful for dev/testing)
    if DISABLE_RATE_LIMITS:
        return False

    try:
        limit, window = RATE_LIMITS[bucket]
    except KeyError:
        # If we typo a bucket name, log minimally (no key) and fail open
        if ENABLE_DEBUG_LOGS:
            safe_print(f"[RL] Unknown bucket: {bucket}")
        return False

    now = time.time()

    with _rate_lock:
        events = _rate_events[(bucket, key)]

        # Keep only events within the time window
        events = [t for t in events if now - t < window]
        _rate_events[(bucket, key)] = events

        if ENABLE_DEBUG_LOGS:
            # Do NOT log the key (could be email/username/IP)
            safe_print(f"[RL] bucket={bucket} count_before={len(events)} limit={limit}")

        if len(events) >= limit:
            if ENABLE_DEBUG_LOGS:
                safe_print(f"[RL] 🚫 RATE LIMITED bucket={bucket}")
            return True

        # Record this attempt
        events.append(now)
        _rate_events[(bucket, key)] = events

        if ENABLE_DEBUG_LOGS:
            safe_print(f"[RL] ✅ recorded bucket={bucket} new_count={len(events)}")

    return False


def is_strong_password(pw):
    """
    Enforce a basic password policy:
      - at least PASSWORD_MIN_LENGTH characters
      - at least one lowercase
      - at least one uppercase
      - at least one digit
      - at least one symbol
    """
    if not isinstance(pw, str):
        return False, "Password is required."

    if len(pw) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."

    if not re.search(r"[a-z]", pw):
        return False, "Password must include at least one lowercase letter."

    if not re.search(r"[A-Z]", pw):
        return False, "Password must include at least one uppercase letter."

    if not re.search(r"\d", pw):
        return False, "Password must include at least one number."

    if not re.search(r"[^\w\s]", pw):  # any non-alphanumeric, non-whitespace
        return False, "Password must include at least one symbol (e.g. !@#$%)."

    return True, ""


def is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


def playoffs_locked() -> bool:
    """
    Playoffs considered 'locked' at or after PLAYOFFS_START_UTC.
    """
    return bool(
        current_season().playoff_lock_at
        and now_utc() >= current_season().playoff_lock_at
    )


def bracket_final_lock_error():
    return jsonify({"error": "Bracket content is locked once the playoffs start."}), 403


def current_master_bracket(bracket):
    is_master = bool(bracket.get("is_master"))
    if not is_master:
        seasons = (
            supabase.table("seasons")
            .select("master_bracket_id")
            .eq("id", current_season().id)
            .limit(1)
            .execute()
            .data
            or []
        )
        is_master = bool(
            seasons and str(seasons[0].get("master_bracket_id")) == str(bracket["id"])
        )
    return is_master


def bracket_content_mutation_error(bracket, user_id):
    """Only ordinary owners before lock, or DB admins on the current master.

    Reuse the existing current-season master flag OR season-pointer semantics.
    This is content authorization only: deletion/lifecycle and other actions stay separate.
    """
    users = (
        supabase.table("users")
        .select("id, is_admin")
        .eq("id", user_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not users:
        return jsonify({"error": "User not found"}), 404
    is_admin = bool(users[0].get("is_admin"))
    is_master = current_master_bracket(bracket)
    if is_master:
        if is_admin:
            return None
    elif not is_admin and bracket.get("user_id") == user_id:
        return bracket_final_lock_error() if playoffs_locked() else None
    return (
        jsonify({"error": "Unauthorized: You are not allowed to modify this bracket"}),
        403,
    )


def bracket_creation_open() -> bool:
    """
    Creation is allowed only after regular season has ended AND before playoffs start.
    Canonical timestamps are required; missing configuration fails closed.
    """
    now = now_utc()

    # Too early?
    if (
        current_season().bracket_creation_opens_at
        and now < current_season().bracket_creation_opens_at
    ):
        return False

    # Too late?
    if current_season().playoff_lock_at and now >= current_season().playoff_lock_at:
        return False

    return True


def now_utc():
    return datetime.now(timezone.utc)


def _fetch_matches_for_bracket(bracket_id: str):
    """
    Load all matches for a bracket and key them by (conference-round-slot),
    but only if the bracket belongs to the CURRENT_SEASON_ID and is not deleted.

    Key format example: 'east-1-4'
    """
    # Verify the bracket is in the current season and not soft-deleted
    br = (
        supabase.table("brackets")
        .select("id, season_id, deleted_at")
        .eq("id", bracket_id)
        .limit(1)
        .execute()
        .data
    )
    if not br or br[0].get("deleted_at") is not None:
        raise APIError("Bracket not found", 404)

    if br[0].get("season_id") != current_season().id:
        raise APIError("Bracket is not in the current season", 400)

    rows = (
        supabase.table("matches")
        .select(
            "id, conference, round, slot, "
            "team_a, team_b, "
            "predicted_winner, predicted_winner_games"
        )
        .eq("bracket_id", bracket_id)
        .execute()
        .data
    )

    by_key = {}
    for m in rows:
        conf = (m.get("conference") or "").lower()
        rnd = m.get("round")
        slot = m.get("slot")
        key = f"{conf}-{rnd}-{slot}"
        by_key[key] = m
    return by_key


def with_current_season(q, col_name: str = "season_id"):
    """Filter by the validated canonical season; never select legacy NULL rows."""
    return q.eq(col_name, current_season().id)


def competitive_bracket_eligible(bracket, *, season_id=...):
    """Canonical live competition rule: saved, active (not deleted), right season.

    is_done is the existing submission flag. saved_at is submission/tie metadata,
    not an independent flag: a timestamp cannot make is_done=False eligible.
    Explicit season_id supports past-season live stats, never snapshot reads.
    """
    target = current_season().id if season_id is ... else season_id
    return (
        bracket.get("is_done") is True
        and bracket.get("deleted_at") is None
        and bracket.get("season_id") == target
    )


def invalidate_bracket_submission(bracket_id):
    """Reuse prediction/undo invalidation for every accepted content edit."""
    supabase.table("brackets").update({"is_done": False, "saved_at": None}).eq(
        "id", bracket_id
    ).execute()


def ensure_season_globals():
    return current_season()


@app.before_request
def _season_bootstrap():
    try:
        ensure_season_globals()
    except SeasonConfigurationError:
        return (
            jsonify(
                {"error": "Canonical season configuration is unavailable or invalid"}
            ),
            503,
        )


@app.route("/season", methods=["GET"])
def season_status():
    return jsonify(current_season().status(now_utc()))


# --------------------------------------------------------
# -------------------- Admin endpoints  ------------------
# --------------------------------------------------------

def generate_token(user_id, username, is_admin=False):
    payload = {
        "user_id": user_id,
        "username": username,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ")[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        request.user = payload
        return f(*args, **kwargs)
    return wrapper


def bracket_read_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.path.startswith("/history/bracket/"):
            return require_auth(f)(*args, **kwargs)
        header = request.headers.get("Authorization")
        if header:
            if not header.startswith("Bearer "):
                return jsonify({"error": "Invalid Authorization header"}), 401
            payload = decode_token(header.split(" ", 1)[1])
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            request.user = payload
        else:
            request.user = {}
        return f(*args, **kwargs)

    return wrapper


def active_current_master_exists():
    seasons = (
        supabase.table("seasons")
        .select("master_bracket_id")
        .eq("id", current_season().id)
        .limit(1)
        .execute()
        .data
        or []
    )
    pointer = seasons[0].get("master_bracket_id") if seasons else None
    rows = (
        supabase.table("brackets")
        .select("id, is_master")
        .eq("season_id", current_season().id)
        .is_("deleted_at", None)
        .execute()
        .data
        or []
    )
    return any(row.get("is_master") or row["id"] == pointer for row in rows)


def public_user(user):
    """Allowlisted other-user identity; own-account auth responses stay separate."""
    return {"id": user.get("id"), "username": user.get("username")}


def require_private_league_membership(league_id, user, *, public_members_only=False):
    """Private member data requires a current membership, never ownership/admin alone.

    Public member/stat endpoints retain their existing member/owner/admin policy.
    Returned metadata cannot carry the stored password hash into a response.
    """
    if not is_uuid(league_id):
        return None, False, (jsonify({"error": "Invalid league id"}), 400)
    rows = (
        supabase.table("leagues")
        .select(
            "id, name, owner_user_id, is_global, password_hash, created_at, updated_at"
        )
        .eq("id", league_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not rows:
        return None, False, (jsonify({"error": "League not found"}), 404)
    league = dict(rows[0])
    private = bool(league.pop("password_hash", None))
    league["requires_password"] = private
    user_id = user.get("user_id")
    membership = (
        (
            supabase.table("league_members")
            .select("id")
            .eq("league_id", league_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
            or []
        )
        if user_id
        else []
    )
    is_member = bool(membership)
    public_allowed = (
        is_member
        or league.get("owner_user_id") == user_id
        or bool(user.get("is_admin"))
    )
    if (private and not is_member) or (
        not private and public_members_only and not public_allowed
    ):
        return (
            None,
            is_member,
            (jsonify({"error": "You are not a member of this league."}), 403),
        )
    return league, is_member, None


def require_auth_for_league_scope(f):
    """Authenticate explicit league competition scopes; preserve public global reads."""
    authenticated = require_auth(f)

    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.args.get("league_id"):
            return authenticated(*args, **kwargs)
        return f(*args, **kwargs)

    return wrapper


@app.route("/auth/test-me", methods=["GET"])
@require_auth
def test_me():
    return jsonify({"user": request.user}), 200


@app.route("/admin/env-check", methods=["GET"])
@require_auth
def admin_env_check():
    """
    Admin-only: returns a sanitized snapshot indicating which critical env vars exist.
    Does NOT return actual secret values.
    """
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    # First line of defense: token says not admin
    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # Optionally verify admin in DB too (defense-in-depth)
    try:
        res = supabase.table("users").select("id, username, is_admin").eq("id", user_id).execute()
        users = res.data or []
    except Exception as e:
        safe_print("🔴 DB error in /admin/env-check (class):", type(e).__name__)
        return jsonify({"error": "Database error"}), 500

    if len(users) == 0:
        return jsonify({"error": "User not found"}), 404

    user = users[0]
    is_admin_db = str(user.get("is_admin")).lower() in ("true", "t", "1", "yes")

    if not is_admin_db:
        return jsonify({"error": "Forbidden"}), 403

    def mask_present(name):
        return {
            "name": name,
            "present": bool(os.getenv(name)),
            "preview": "set" if os.getenv(name) else "unset"
        }

    env_summary = [
        mask_present("SUPABASE_URL"),
        mask_present("SUPABASE_KEY"),
        mask_present("SUPABASE_SERVICE_ROLE_KEY"),
        mask_present("SUPABASE_ANON_KEY"),
        mask_present("BREVO_API_KEY"),
        mask_present("BREVO_SENDER_EMAIL"),
    ]

    return jsonify({
        "ok": True,
        "env": env_summary
    }), 200


def redact(s: str) -> str:
    if not isinstance(s, str):
        return s
    redacted = s
    for token in SENSITIVE_TOKENS:
        if token and token in redacted:
            redacted = redacted.replace(token, "[REDACTED]")
    return redacted


def safe_print(*args, **kwargs):
    parts = []
    for a in args:
        parts.append(redact(str(a)))
    print(*parts, **kwargs)


# --- Safe error handler (add this) ---
@app.errorhandler(500)
def handle_500(e):
    # Avoid logging full exception message; just the class name
    safe_print("🔴 500 error (class):", type(e).__name__)
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(Exception)
def handle_any(e):
    # If this is our custom APIError (even if coming from another module),
    # use its message and status_code instead of hiding it.
    if e.__class__.__name__ == "APIError":
        message = getattr(e, "message", str(e))
        status_code = getattr(e, "status_code", 400)

        safe_print(f"APIError (handled in generic handler): {message}")
        return jsonify({"error": message}), status_code

    # Fallback for all other unexpected exceptions
    safe_print("🔴 Unhandled exception (class):", type(e).__name__)
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(APIError)
def handle_api_error(err: APIError):
    # This still avoids leaking stack traces / secrets,
    # but it gives you a meaningful error message + status code.
    safe_print(f"APIError: {err.message}")
    return jsonify({"error": err.message}), err.status_code


@app.route("/admin/leaderboard/snapshot", methods=["POST"])
@require_auth
def admin_snapshot_leaderboard():
    """
    Admin-only: snapshot the CURRENT season leaderboard into leaderboard_history.

    - Fails if:
      * user is not admin
      * CURRENT_SEASON_ID is missing
      * canonical recomputation or structured publication fails
    A verified zero-competitor final snapshot is supported (SC17).
    """
    guard_runtime_job("leaderboard-snapshot")
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    # First gate: token must say admin
    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # Optional: defense-in-depth admin check in DB
    try:
        user_row = (
            supabase.table("users")
            .select("id, is_admin")
            .eq("id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if not user_row or not user_row[0].get("is_admin", False):
            return jsonify({"error": "Forbidden"}), 403
    except Exception as e:
        safe_print(
            "🔴 DB error verifying admin in /admin/leaderboard/snapshot (class):",
            type(e).__name__,
        )
        return jsonify({"error": "Unexpected error"}), 500

    # Run the snapshot helper
    try:
        result = _snapshot_leaderboard_for_current_season()
        if not result.get("ok"):
            # Bubble up helper error & status
            return jsonify(
                {"error": result.get("error", "Snapshot failed")}
            ), result.get("status", 400)

        return jsonify(result), 200

    except Exception as e:
        safe_print("🔴 Error in /admin/leaderboard/snapshot (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/admin/season/rollover", methods=["POST"])
@require_auth
def admin_season_rollover():
    """
    Admin-only: close the CURRENT season and create the next season row.

    Expected JSON body:
      {
        "new_season_code": "2025-26",
        "regular_season_end_utc": "2026-04-15T07:00:00Z",   // required
        "playoffs_start_utc": "2026-04-18T07:00:00Z"        // required
      }

    Successful rollover atomically advances canonical state and clears current
    standings. Both target timing fields are required; no environment update is needed.
    """
    guard_runtime_job("season-rollover")
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    # First gate: token must say admin
    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # Second gate: DB check on users.is_admin
    try:
        rows = (
            supabase.table("users")
            .select("id, is_admin")
            .eq("id", user_id)
            .limit(1)
            .execute()
        ).data or []
        if not rows or not bool(rows[0].get("is_admin", False)):
            return jsonify({"error": "Forbidden"}), 403
    except Exception as e:
        safe_print(
            "🔴 DB error verifying admin in /admin/season/rollover:", type(e).__name__
        )
        return jsonify({"error": "Unexpected error"}), 500

    data = request.get_json(silent=True) or {}
    new_code_raw = data.get("new_season_code")
    regular_end_raw = data.get("regular_season_end_utc")
    playoffs_start_raw = data.get("playoffs_start_utc")

    new_code = (new_code_raw or "").strip()
    if not new_code:
        return jsonify({"error": "new_season_code is required"}), 400

    # Rollover requires explicit aware timings; do not assume UTC for naive input.
    from canonical_season import timestamp, SeasonConfigurationError

    try:
        reg_dt = timestamp(regular_end_raw) if regular_end_raw else None
        pl_dt = timestamp(playoffs_start_raw) if playoffs_start_raw else None
    except SeasonConfigurationError:
        return (
            jsonify(
                {
                    "ok": False,
                    "state": "failed",
                    "status": 400,
                    "stage": "prerequisite",
                    "error": "Target timing must use timezone-aware ISO-8601 values.",
                }
            ),
            400,
        )

    try:
        result = _rollover_current_season(
            new_season_code=new_code,
            regular_season_end_utc=reg_dt,
            playoffs_start_utc=pl_dt,
            created_by_user_id=user_id,
        )
    except Exception as e:
        safe_print("🔴 Unexpected error in /admin/season/rollover:", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500

    status = result.get("status", 200)
    if not result.get("ok"):
        return jsonify(result), status

    return jsonify(result), status


# --------------------------------------------------------
# --------- Helper: fetch + sync NBA standings -----------
# --------------------------------------------------------

def fetch_and_sync_standings_from_nba():
    """Compatibility name; the sole standings provider is now ESPN."""
    guard_runtime_job("standings-refresh")
    try:
        result = refresh_current_standings(supabase, now=now_utc)
        log_result(result)
        return result
    except StandingsRefreshError as error:
        log_result({"state": error.stage})
        raise APIError(str(error), 502) from None


@app.route("/admin/standings/refresh", methods=["POST"])
@require_auth
def admin_refresh_standings():
    """
    Admin-only: fetch authoritative ESPN standings and atomically publish the
    'standings' table for the CURRENT season.

    Usage:
      - Call manually from an admin UI / Postman with a valid admin JWT.
      - Or let a scheduled job (see /internal/standings/refresh) call the same helper.
    """
    guard_runtime_job("standings-refresh")
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # Optional: defense-in-depth, re-check admin flag in DB
    try:
        users = (
            supabase.table("users")
            .select("id, is_admin")
            .eq("id", user_id)
            .limit(1)
            .execute()
        ).data or []
        if not users or not bool(users[0].get("is_admin", False)):
            return jsonify({"error": "Forbidden"}), 403
    except Exception as e:
        safe_print("🔴 DB error in /admin/standings/refresh (class):", type(e).__name__)
        return jsonify({"error": "Database error"}), 500

    result = fetch_and_sync_standings_from_nba()
    return jsonify({"ok": True, **result}), 200


@app.route("/internal/standings/refresh", methods=["POST"])
def internal_cron_refresh_standings():
    """
    Internal-only endpoint intended for cron jobs.

    Auth:
      - Requires STANDINGS_CRON_TOKEN to be set in env.
      - Caller must send it as either:
          * Header: X-Cron-Token: <token>
          * Or query param: ?token=<token>
    """
    guard_runtime_job("standings-refresh")
    token_supplied = (
        request.headers.get("X-Cron-Token")
        or request.args.get("token")
    )

    if not STANDINGS_CRON_TOKEN or token_supplied != STANDINGS_CRON_TOKEN:
        # Do not leak whether the token is set; just say forbidden.
        return jsonify({"error": "Forbidden"}), 403

    result = fetch_and_sync_standings_from_nba()
    return jsonify({"ok": True, **result}), 200


@app.route("/internal/standings/overwrite", methods=["POST"])
def internal_overwrite_standings():
    """Retired caller-supplied overwrite; use authenticated ESPN refresh."""
    guard_runtime_job("standings-overwrite")
    token_supplied = request.headers.get("X-Cron-Token") or request.args.get("token")
    if not STANDINGS_CRON_TOKEN or token_supplied != STANDINGS_CRON_TOKEN:
        return jsonify({"error": "Forbidden"}), 403
    return (
        jsonify(
            {
                "error": "Caller-supplied standings overwrite is retired; use /internal/standings/refresh"
            }
        ),
        410,
    )


@app.route("/admin/insert_test_teams", methods=["POST"])
@require_auth
def admin_insert_test_teams():
    """
    Admin helper to (re)insert the 10 test teams for both conferences.
    Idempotent via upsert.

    Standings seeding is retired; ESPN refresh owns all normal standings writes.
    """
    guard_runtime_job("team-insert")
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # (Optional) verify admin in DB as defense-in-depth
    try:
        res = (
            supabase.table("users")
            .select("id, username, is_admin")
            .eq("id", user_id)
            .limit(1)
            .execute()
        ).data or []
        if not res or not bool(res[0].get("is_admin", False)):
            return jsonify({"error": "Forbidden"}), 403
    except Exception as e:
        safe_print("🔴 DB error in /admin/insert_test_teams (class):", type(e).__name__)
        return jsonify({"error": "Database error"}), 500

    # Parse body flag
    body = request.get_json(silent=True) or {}
    seed_standings = bool(body.get("seed_standings"))

    if seed_standings:
        return (
            jsonify(
                {
                    "error": "Synthetic standings seeding is disabled; use ESPN standings refresh"
                }
            ),
            409,
        )

    # --- Test teams (unchanged shape vs your prior helper) ---
    east = [
        {"id": "T1E", "name": "TestEast1", "conference": "east"},
        {"id": "T2E", "name": "TestEast2", "conference": "east"},
        {"id": "T3E", "name": "TestEast3", "conference": "east"},
        {"id": "T4E", "name": "TestEast4", "conference": "east"},
        {"id": "T5E", "name": "TestEast5", "conference": "east"},
        {"id": "T6E", "name": "TestEast6", "conference": "east"},
        {"id": "T7E", "name": "TestEast7", "conference": "east"},
        {"id": "T8E", "name": "TestEast8", "conference": "east"},
        {"id": "T9E", "name": "TestEast9", "conference": "east"},
        {"id": "T10E", "name": "TestEast10", "conference": "east"},
    ]
    west = [
        {"id": "LAL", "name": "Los Angeles Lakers", "conference": "west"},
        {"id": "T2W", "name": "TestWest2", "conference": "west"},
        {"id": "T3W", "name": "TestWest3", "conference": "west"},
        {"id": "T4W", "name": "TestWest4", "conference": "west"},
        {"id": "T5W", "name": "TestWest5", "conference": "west"},
        {"id": "T6W", "name": "TestWest6", "conference": "west"},
        {"id": "T7W", "name": "TestWest7", "conference": "west"},
        {"id": "T8W", "name": "TestWest8", "conference": "west"},
        {"id": "T9W", "name": "TestWest9", "conference": "west"},
        {"id": "T10W", "name": "TestWest10", "conference": "west"},
    ]
    teams_to_upsert = east + west

    # Upsert test teams exactly like before (no changes to other fields)
    for t in teams_to_upsert:
        supabase.table("teams").upsert(t).execute()

    seeded_standings = 0
    standings_mode = "skipped"

    return (
        jsonify(
            {
                "message": "Test teams inserted/updated",
                "seed_standings_requested": seed_standings,
                "standings_seeded_rows": seeded_standings,
                "standings_mode": standings_mode,
                "season_id": current_season().id,
            }
        ),
        200,
    )


# small health endpoint
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message":"NBACorner backend running"}), 200


@app.route("/health", methods=["GET", "HEAD"])
def health():
    # ✅ First: if a healthcheck token is configured, see if caller has it
    supplied = None
    if HEALTHCHECK_TOKEN:
        supplied = (
            request.headers.get("X-Health-Token")
            or request.args.get("token")
        )

        if supplied == HEALTHCHECK_TOKEN:
            # ✅ Blessed caller (e.g. UptimeRobot) → NO rate limit, always 200
            resp = make_response("OK", 200)
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            return resp

        # Token is set in env but missing/wrong → treat as suspicious
        # (we'll still rate-limit these to avoid abuse; see below)

    # ✅ Everyone else (no token configured, or bad/missing token) → apply rate limit
    ip = get_client_ip()
    if is_rate_limited("health_ip", ip):
        resp = make_response("Too Many Requests", 429)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        return resp

    # If HEALTHCHECK_TOKEN is set but caller didn't provide correct one → hide endpoint
    if HEALTHCHECK_TOKEN and supplied != HEALTHCHECK_TOKEN:
        resp = make_response("Not Found", 404)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        return resp

    # Public OK (no token configured)
    resp = make_response("OK", 200)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/admin/score/recompute", methods=["POST"])
@app.route("/admin/score/master/<master_bracket_id>/recompute", methods=["POST"])
@require_auth
def recompute_scores(master_bracket_id=None):
    """Admin maintenance: complete canonical recomputation, never caller-selected truth."""
    guard_runtime_job("score-recompute")
    user = request.user or {}
    if not user.get("is_admin"):
        return jsonify({"error": "Forbidden"}), 403
    admins = (
        supabase.table("users")
        .select("is_admin")
        .eq("id", user.get("user_id"))
        .limit(1)
        .execute()
        .data
        or []
    )
    if not admins or admins[0].get("is_admin") is not True:
        return jsonify({"error": "Forbidden"}), 403
    try:
        result = recompute_current_scores(
            supabase,
            expected_season_id=current_season().id,
            expected_master_id=master_bracket_id,
        )
    except ScoringError as error:
        status = 400 if error.stage == "caller_master_mismatch" else 503
        return (
            jsonify({"error": str(error), "code": "SCORE_RECOMPUTATION_FAILED"}),
            status,
        )
    return jsonify(dict(result, message="Scores recomputed")), 200


def recompute_after_master_change(bracket, *, truth_changed=True):
    """Master edit is already committed; preserve last-good scores on publish failure."""
    if not truth_changed or not current_master_bracket(bracket):
        return None
    try:
        recompute_current_scores(
            supabase,
            expected_season_id=current_season().id,
            expected_master_id=bracket["id"],
        )
    except ScoringError as error:
        return (
            jsonify(
                {
                    "error": str(error),
                    "code": "SCORE_RECOMPUTATION_FAILED",
                    "master_mutation_committed": True,
                    "message": "Master change committed; score recomputation failed or could not be confirmed. Score publication is atomic. An admin must inspect and recompute scores to recover.",
                }
            ),
            503,
        )
    return None


def _build_leaderboard_rows_for_current_season():
    """
    Build leaderboard-style rows for the CURRENT season, similar to /leaderboard
    but without master_matchups or master bracket info.

    Returns a list of dicts with:
      - bracket_id
      - bracket_name
      - user_id
      - username
      - total_points, full_hits, partial_hits, misses
      - bonus_finalists, bonus_champion
      - points_by_match
    """
    # 1) Scores for current season
    scores_res = (
        with_current_season(
            supabase.table("bracket_scores").select(
                "season_id, bracket_id, total_points, full_hits, "
                "partial_hits, misses, bonus_finalists, bonus_champion, "
                "points_by_match, updated_at"
            )
        )
        .execute()
    )

    scores = scores_res.data or []
    if not scores:
        return []

    # 2) Brackets (non-deleted) for those scores
    bracket_ids = list({
        s.get("bracket_id")
        for s in scores
        if s.get("bracket_id")
    })

    if not bracket_ids:
        return []

    br_res = (
        with_current_season(
            supabase.table("brackets")
            .select("id, user_id, name, is_done, deleted_at, season_id")
            .in_("id", bracket_ids)
            .is_("deleted_at", None)
        )
        .execute()
    )
    br_rows = [b for b in (br_res.data or []) if competitive_bracket_eligible(b)]
    br_by_id = {b["id"]: b for b in br_rows}

    # 3) Users for those brackets
    user_ids = list({
        b.get("user_id")
        for b in br_rows
        if b.get("user_id")
    })

    users_by_id = {}
    if user_ids:
        users_res = (
            supabase.table("users")
            .select("id, username")
            .in_("id", user_ids)
            .execute()
        )
        users = users_res.data or []
        users_by_id = {u["id"]: u for u in users}

    # 4) Build rows in the same shape as /leaderboard
    rows_out = []
    for s in scores:
        bid = s.get("bracket_id")
        b = br_by_id.get(bid)
        if not bid or not b:
            continue

        u = users_by_id.get(b["user_id"], {})
        rows_out.append({
            "bracket_id": bid,
            "bracket_name": b.get("name") or "Unnamed bracket",
            "user_id": b.get("user_id"),
            "username": u.get("username") or "unknown",
            "total_points": int(s.get("total_points") or 0),
            "full_hits": int(s.get("full_hits") or 0),
            "partial_hits": int(s.get("partial_hits") or 0),
            "misses": int(s.get("misses") or 0),
            "bonus_finalists": int(s.get("bonus_finalists") or 0),
            "bonus_champion": int(s.get("bonus_champion") or 0),
            "points_by_match": s.get("points_by_match") or {},
        })

    return rows_out


def _snapshot_leaderboard_for_current_season():
    """Only a confirmed complete structured final snapshot satisfies preservation."""
    guard_runtime_job("leaderboard-snapshot")
    try:
        return create_final_leaderboard_snapshot(
            supabase,
            expected_season_id=current_season().id,
            created_by=(getattr(request, "user", None) or {}).get("user_id"),
        )
    except SnapshotError as error:
        return {"ok": False, "error": str(error), "status": 503}


def _rollover_current_season(
    new_season_code,
    regular_season_end_utc=None,
    playoffs_start_utc=None,
    created_by_user_id=None,
):
    """Explicit admin workflow; database owns lock, snapshot gate and atomic cleanup."""
    guard_runtime_job("season-rollover")
    from rollover_service import run_rollover

    return run_rollover(
        supabase,
        target_code=new_season_code,
        opening=regular_season_end_utc,
        lock=playoffs_start_utc,
        requested_by=created_by_user_id,
    )


# --------------------------------------------------------
# --------------- Authentication endpoints  --------------
# --------------------------------------------------------
# NOTE ON CSRF:
# --------------
# We authenticate using JWTs sent in the Authorization: Bearer header.
# Browsers don't attach this header automatically on cross-site requests,
# so classic cookie-based CSRF does not apply here.
#
# If we ever switch to cookie-based auth (HttpOnly session cookies, etc.),
# we MUST add CSRF protection (e.g. SameSite cookies + CSRF token header).

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    ip = get_client_ip()
    if is_rate_limited("register_ip", ip):
        return jsonify({
            "error": "Too many sign-up attempts from this IP. Please try again later."
        }), 429

    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Email, username, and password are required"}), 400

    # 🔐 Validate email/username format
    if not re.match(EMAIL_REGEX, email):
        return jsonify({"error": "Invalid email format"}), 400

    if not re.match(USERNAME_REGEX, username):
        return jsonify({"error": "Invalid username format"}), 400

    # ✅ Enforce password policy
    ok, msg = is_strong_password(password)
    if not ok:
        return jsonify({"error": msg}), 400

    # ✅ Check if email or username already exists (no .or_ with raw input)
    existing_email = (
        supabase.table("users")
        .select("id")
        .eq("email", email)
        .execute()
        .data
    )
    if existing_email:
        return jsonify({"error": "Email or username already in use"}), 400

    existing_username = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .execute()
        .data
    )
    if existing_username:
        return jsonify({"error": "Email or username already in use"}), 400

    # ✅ Use explicit bcrypt cost
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")

    try:
        user = (
            supabase.table("users")
            .insert({
                "email": email,
                "username": username,
                "password": hashed_password
            })
            .execute()
            .data[0]
        )
        return jsonify({
            "message": "User registered successfully",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "created_at": user.get("created_at")
            }
        }), 201
    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /auth/register (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    # 1) Per-IP rate limit
    ip = get_client_ip()
    if is_rate_limited("login_ip", ip):
        return jsonify({
            "error": "Too many login attempts. Please wait a bit and try again."
        }), 429

    # 2) Normalize identifier (email or username)
    identifier = (data.get("email") or data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not identifier or not password:
        return jsonify({"error": "Invalid credentials"}), 400

    # 3) Per-identifier rate limit (email/username)
    if is_rate_limited("login_identifier", identifier):
        return jsonify({
            "error": "Too many login attempts. Please wait a bit and try again."
        }), 429

    # 4) Decide whether this is an email or username; validate format
    if re.match(EMAIL_REGEX, identifier):
        lookup_field = "email"
    elif re.match(USERNAME_REGEX, identifier):
        lookup_field = "username"
    else:
        # Invalid format → treat as bad credentials (no extra info)
        return jsonify({"error": "Invalid username/email or password"}), 401

    user_res = (
        supabase.table("users")
        .select("*")
        .eq(lookup_field, identifier)
        .execute()
        .data
    )
    if not user_res:
        return jsonify({"error": "Invalid username/email or password"}), 401

    user = user_res[0]
    stored_password = user.get("password")

    if not bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
        return jsonify({"error": "Invalid username/email or password"}), 401

    # ✅ Generate JWT
    token = generate_token(user["id"], user["username"], user.get("is_admin", False))

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "is_admin": user.get("is_admin", False),
            "created_at": user.get("created_at")
        }
    }), 200


@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}

    # 1) Per-IP limit for forgot-password
    ip = get_client_ip()
    if is_rate_limited("forgot_ip", ip):
        # Same generic response to avoid info leaks
        return jsonify({
            "message": "If a username or email exists, a reset password email will be sent."
        }), 200

    # 2) Normalize identifier
    identifier = (data.get("email") or data.get("username") or "").strip().lower()

    if re.match(EMAIL_REGEX, identifier):
        lookup_field = "email"
    elif re.match(USERNAME_REGEX, identifier):
        lookup_field = "username"
    else:
        return jsonify({"message": "If a username or email exists, a reset password email will be sent."}), 200

    # 3) Per-identifier forgot-password limit
    if is_rate_limited("forgot_identifier", identifier):
        return jsonify({
            "message": "If a username or email exists, a reset password email will be sent."
        }), 200

    # Perform a single, parameterized lookup (no string building / .or_)
    try:
        user_res = (
            supabase.table("users")
            .select("id, email, username")
            .eq(lookup_field, identifier)
            .execute()
            .data
        )
    except Exception as e:
        safe_print("🔴 DB lookup failed (class):", type(e).__name__)
        return jsonify({"error": "Database error"}), 500

    # Always return neutral response if not found (no user enumeration)
    if not user_res:
        return jsonify({
            "message": "If a username or email exists, a reset password email will be sent."
        }), 200

    user = user_res[0]
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    # Store reset token
    try:
        supabase.table("password_resets").insert({
            "user_id": user["id"],
            "token": token,
            "expires_at": expires_at
        }).execute()
    except Exception as e:
        # Do NOT log token or full exception text (it might include the payload)
        safe_print("🔴 Error inserting reset token (class):", type(e).__name__)
        return jsonify({"error": "Failed to save reset token"}), 500

    # Send reset email via Brevo
    reset_link = build_reset_link(token)
    subject = "NBACorner Password Reset"
    body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <p>Hello <strong>{user['username']}</strong>,</p>
            <p>A reset password has been requested. Please click the button below to set a new password:</p>
            <p>
              <a href="{reset_link}"
                 style="display:inline-block; background-color:#007bff; color:#ffffff; text-decoration:none;
                        padding:10px 20px; border-radius:5px; font-weight:bold;"
                 target="_blank">
                 Reset Password
              </a>
            </p>
            <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
            <p><a href="{reset_link}" target="_blank">{reset_link}</a></p>
            <p>This link will stay active for 24 hours or until the password has been successfully reset.</p>
            <p>Thanks,<br>NBA Corner</p>
          </body>
        </html>
    """

    send_email_via_brevo(user["email"], subject, body)

    return jsonify({
        "message": "If a username or email exists, a reset password email will be sent."
    }), 200


@app.route("/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400

    # ✅ Enforce password policy on reset as well
    ok, msg = is_strong_password(new_password)
    if not ok:
        return jsonify({"error": msg}), 400

    # Lookup token
    token_res = (
        supabase.table("password_resets")
        .select("id, user_id, expires_at, used")
        .eq("token", token)
        .execute()
        .data
    )

    if not token_res:
        return jsonify({"error": "Invalid or expired token"}), 400

    reset = token_res[0]
    if reset["used"]:
        return jsonify({"error": "Token already used"}), 400

    # Check expiry
    if datetime.utcnow() > datetime.fromisoformat(reset["expires_at"]):
        return jsonify({"error": "Token expired"}), 400

    # ✅ Use explicit bcrypt cost
    hashed_password = bcrypt.hashpw(
        new_password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")

    # Update user password
    supabase.table("users").update({"password": hashed_password}).eq("id", reset["user_id"]).execute()

    # Mark token as used
    supabase.table("password_resets").update({"used": True}).eq("id", reset["id"]).execute()

    return jsonify({"message": "Password reset successfully"}), 200


@app.route("/test-email", methods=["POST"])
@require_auth
def test_email():
    """Test email sending via Brevo API (admin-only)."""
    # ✅ Admin check from JWT
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # Optional: defense-in-depth – verify admin in DB too
    try:
        user_res = (
            supabase.table("users")
            .select("id, is_admin")
            .eq("id", user_id)
            .execute()
            .data
        )
    except Exception as e:
        safe_print("🔴 DB error in /test-email (class):", type(e).__name__)
        return jsonify({"error": "Database error"}), 500

    if not user_res or not user_res[0].get("is_admin", False):
        return jsonify({"error": "Forbidden"}), 403

    # ✅ Per-IP rate limit for this endpoint
    ip = get_client_ip()
    if is_rate_limited("test_email_ip", ip):
        return jsonify({
            "error": "Too many test email attempts from this IP. Please try again later."
        }), 429

    data = request.get_json() or {}
    recipient = data.get("to")

    if not recipient:
        return jsonify({"error": "Missing recipient email"}), 400

    subject = "NBACorner test email"
    body = """
    <h3>✅ NBACorner email test successful!</h3>
    <p>If you're reading this, the Brevo API integration works perfectly.</p>
    <br/>
    <p>Cheers,<br/>NBA Corner</p>
    """

    success = send_email_via_brevo(recipient, subject, body)

    if success:
        return jsonify({"message": f"Test email sent to {recipient}"}), 200
    else:
        return jsonify({"error": "Failed to send email"}), 500


def _send_email_via_brevo_production(to_email, subject, body):
    """Send an email using Brevo's transactional email API."""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    data = {
        "sender": {
            "name": "NBA Corner",
            "email": os.getenv("BREVO_SENDER_EMAIL", "donotreply@nbacorner.com")
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": body
    }

    try:
        response = requests.post(url, json=data, headers=headers, timeout=20)
        if ENABLE_DEBUG_LOGS:
            safe_print(f"📬 Brevo response: {response.status_code}")
        safe_print(f"📬 Brevo response: {response.status_code}")
        return response.status_code in (200, 201)
    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🚨 Error sending email via Brevo (class):", type(e).__name__)
        return False


def send_email_via_brevo(to_email, subject, body):
    """Central seam: unchanged production Brevo or verified test-only capture."""
    return deliver_email(_send_email_via_brevo_production, to_email, subject, body)


# --------------------------------------------------------
# ------------------ Bracket endpoints  ------------------
# --------------------------------------------------------


@app.route("/bracket/create", methods=["POST"])
@require_auth
def create_bracket_for_user():
    user_info = request.user or {}
    user_id = user_info["user_id"]
    accounts = (
        supabase.table("users")
        .select("is_admin")
        .eq("id", user_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    is_admin = bool(accounts and accounts[0].get("is_admin"))
    body = request.get_json(silent=True) or {}
    replace = (
        body.get("replace_existing_master", False) if isinstance(body, dict) else False
    )
    if type(replace) is not bool:
        return jsonify({"error": "replace_existing_master must be a boolean"}), 400
    if replace and not is_admin:
        return jsonify({"error": "Only an admin may replace the master bracket"}), 403
    if is_admin and active_current_master_exists() and not replace:
        return (
            jsonify({"error": "Explicit master replacement confirmation required"}),
            409,
        )

    # Admin master creation keeps its existing window bypass/lifecycle.
    if not is_admin:
        if playoffs_locked():
            return bracket_final_lock_error()
        if (
            current_season().bracket_creation_opens_at
            and now_utc() < current_season().bracket_creation_opens_at
        ):
            return (
                jsonify(
                    {"error": "Bracket creation opens after the regular season ends."}
                ),
                403,
            )

    if not is_admin:
        existing = (
            supabase.table("brackets")
            .select("id")
            .eq("user_id", user_id)
            .eq("season_id", current_season().id)
            .is_("deleted_at", None)
            .execute()
            .data
        )
        if existing:
            return jsonify({"error": "User already has a bracket for this season"}), 400

    # ------------------------------------------------------------------
    # 🔢 Fetch teams (canonical conference) + standings (no season filter)
    # ------------------------------------------------------------------
    try:
        teams = (
            supabase.table("teams").select("id, name, conference, code").execute().data
        )
    except Exception as e:
        app.logger.exception("Failed to fetch teams for bracket creation: %s", e)
        return jsonify({"error": "Failed to fetch teams"}), 500

    team_by_code = {}
    for t in teams:
        code = (t.get("code") or "").strip().upper()
        if code:
            team_by_code[code] = t

    try:
        # standings is always "current season", no season_id column anymore
        standings_rows = supabase.table("standings").select("code, seed").execute().data
    except Exception as e:
        app.logger.exception("Failed to fetch standings for bracket creation: %s", e)
        return jsonify({"error": "Failed to fetch standings"}), 500

    if not standings_rows:
        return (
            jsonify(
                {
                    "error": "Standings table is empty. Make sure the standings script has been run."
                }
            ),
            400,
        )

    # ------------------------------------------------------------------
    # 🧮 Build seeded lists per conference using the seed column
    # ------------------------------------------------------------------
    east_seed_pairs = []  # list of (seed, team_dict)
    west_seed_pairs = []

    for row in standings_rows:
        seed = row.get("seed")
        if seed is None:
            continue

        code = (row.get("code") or "").strip().upper()
        if not code:
            continue

        team = team_by_code.get(code)
        if not team:
            app.logger.error(
                "Standings row has code %s but no matching team in teams table",
                code,
            )
            continue

        conf = (team.get("conference") or "").strip().lower()
        if conf == "east":
            east_seed_pairs.append((seed, team))
        elif conf == "west":
            west_seed_pairs.append((seed, team))
        else:
            app.logger.warning(
                "Team %s (code %s) has unexpected conference %r",
                team.get("name"),
                code,
                team.get("conference"),
            )

    # Sort by seed and pick first 10
    east_seed_pairs.sort(key=lambda p: p[0])
    west_seed_pairs.sort(key=lambda p: p[0])

    east_teams = [team for (seed, team) in east_seed_pairs[:10]]
    west_teams = [team for (seed, team) in west_seed_pairs[:10]]

    if len(east_teams) < 10 or len(west_teams) < 10:
        app.logger.error(
            "Not enough seeded teams: EAST=%d, WEST=%d (need at least 10 each)",
            len(east_teams),
            len(west_teams),
        )
        if len(east_teams) < 10:
            return (
                jsonify(
                    {
                        "error": f"Not enough seeded teams (need 10) for conference EAST, found {len(east_teams)}. "
                        "Check that the standings script has set seeds 1–10 for EAST."
                    }
                ),
                400,
            )
        else:
            return (
                jsonify(
                    {
                        "error": f"Not enough seeded teams (need 10) for conference WEST, found {len(west_teams)}. "
                        "Check that the standings script has set seeds 1–10 for WEST."
                    }
                ),
                400,
            )

    # 🧱 From here on, east_teams[0..9] and west_teams[0..9] are seeds 1..10

    def create_conference_matches(conference, teams_):
        matches = []
        # ---- PLAY-IN ROUND ----
        # seeds 9 vs 10
        m1 = {
            "round": 0,
            "slot": 1,
            "conference": conference,
            "team_a": teams_[8]["id"],
            "team_b": teams_[9]["id"],
        }
        # seeds 7 vs 8
        m2 = {
            "round": 0,
            "slot": 2,
            "conference": conference,
            "team_a": teams_[6]["id"],
            "team_b": teams_[7]["id"],
        }
        m3 = {"round": 0, "slot": 3, "conference": conference}
        matches.extend([m1, m2, m3])

        # ---- ROUND 1 ----
        # 1 vs play-in winner, 2 vs play-in winner, 3 vs 6, 4 vs 5
        r1 = [
            {
                "round": 1,
                "slot": 4,
                "conference": conference,
                "team_a": teams_[0]["id"],
            },  # 1 seed
            {
                "round": 1,
                "slot": 5,
                "conference": conference,
                "team_a": teams_[1]["id"],
            },  # 2 seed
            {
                "round": 1,
                "slot": 6,
                "conference": conference,
                "team_a": teams_[2]["id"],  # 3 seed
                "team_b": teams_[5]["id"],  # 6 seed
            },
            {
                "round": 1,
                "slot": 7,
                "conference": conference,
                "team_a": teams_[3]["id"],  # 4 seed
                "team_b": teams_[4]["id"],  # 5 seed
            },
        ]
        matches.extend(r1)

        # ---- SEMIFINALS ----
        matches.append({"round": 2, "slot": 8, "conference": conference})
        matches.append({"round": 2, "slot": 9, "conference": conference})

        # ---- CONFERENCE FINALS ----
        matches.append({"round": 3, "slot": 10, "conference": conference})
        return matches

    # 1️⃣ Create all match entries
    all_matches = []
    all_matches.extend(create_conference_matches("east", east_teams))
    all_matches.extend(create_conference_matches("west", west_teams))
    all_matches.append({"round": 4, "slot": 11, "conference": "nba"})  # NBA Finals

    # Prepare the same existing graph before writing. Master creation commits
    # bracket, matches, retirement and pointer together inside the trusted RPC.
    by_key = {}
    for m in all_matches:
        m["id"] = str(uuid.uuid4())
        by_key[(m["conference"], m["slot"])] = m
    links = [
        (1, 3, "a"),
        (2, 5, "b"),
        (3, 4, "b"),
        (4, 9, "a"),
        (7, 9, "b"),
        (5, 8, "b"),
        (6, 8, "a"),
        (8, 10, "b"),
        (9, 10, "a"),
    ]
    for conf in ("east", "west"):
        for src, dest, slot in links:
            by_key[(conf, src)].update(
                next_match_id=by_key[(conf, dest)]["id"], next_slot=slot
            )
        by_key[(conf, 10)].update(
            next_match_id=by_key[("nba", 11)]["id"],
            next_slot="a" if conf == "east" else "b",
        )
    try:
        if is_admin:
            bracket = (
                supabase.rpc(
                    "create_master_bracket_atomic",
                    {
                        "p_user_id": user_id,
                        "p_season_id": current_season().id,
                        "p_replace": replace,
                        "p_matches": all_matches,
                    },
                )
                .execute()
                .data
            )
        else:
            bracket = (
                supabase.table("brackets")
                .insert({"user_id": user_id, "season_id": current_season().id})
                .execute()
                .data[0]
            )
            supabase.table("matches").insert(
                [dict(m, bracket_id=bracket["id"]) for m in all_matches]
            ).execute()
    except Exception as error:
        code = getattr(error, "code", None)
        if code == "P0001":
            return (
                jsonify({"error": "Explicit master replacement confirmation required"}),
                409,
            )
        if code == "23505":
            return jsonify({"error": "User already has a bracket for this season"}), 400
        return (
            jsonify(
                {"error": "Bracket creation failed; no master replacement committed"}
            ),
            500,
        )

    if is_admin:
        score_error = recompute_after_master_change(bracket)
        if score_error:
            return score_error

    return jsonify({"message": "Bracket created successfully", "bracket": bracket}), 200


@app.route("/bracket/<bracket_id>/save", methods=["PATCH"])
@require_auth
def save_bracket(bracket_id):
    try:
        if not is_uuid(bracket_id):
            return jsonify({"error": "Invalid bracket id"}), 400

        user_id = request.user["user_id"]

        data = request.get_json(silent=True) or {}
        raw_name = data.get("name", "")
        name = (raw_name or "").strip()

        if not name:
            return jsonify({"error": "Bracket name is required"}), 400

        # Bracket must exist, be active, and be in CURRENT season
        bracket_res = (
            supabase.table("brackets")
            .select("id, user_id, deleted_at, season_id, is_master")
            .eq("id", bracket_id)
            .is_("deleted_at", None)
            .limit(1)
            .execute()
            .data
        )
        if not bracket_res:
            return jsonify({"error": "Bracket not found"}), 404

        bracket = bracket_res[0]
        if bracket.get("season_id") != current_season().id:
            return jsonify({"error": "Bracket is not in the current season"}), 400

        access_error = bracket_content_mutation_error(bracket, user_id)
        if access_error:
            return access_error

        # Validate fully predicted
        matches = (
            supabase.table("matches")
            .select(
                "id, round, slot, conference, team_a, team_b, predicted_winner, predicted_winner_games, next_match_id, next_slot"
            )
            .eq("bracket_id", bracket_id)
            .execute()
            .data
        )

        validity_error = submission_error(
            matches, master=current_master_bracket(bracket)
        )
        if validity_error:
            return jsonify({"error": validity_error}), 400

        now = datetime.utcnow().isoformat()
        supabase.table("brackets").update(
            {"name": name, "is_done": True, "saved_at": now}
        ).eq("id", bracket_id).execute()

        return jsonify({"message": "Bracket saved", "saved_at": now, "name": name}), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /bracket/save (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/brackets/me", methods=["GET"])
@require_auth
def get_my_bracket():
    """
    Return the current user's active bracket for the CURRENT season,
    plus season flags for the frontend.
    """
    user_id = request.user["user_id"]

    try:
        res = (
            with_current_season(
                supabase.table("brackets")
                .select(
                    "id, user_id, name, is_done, created_at, saved_at, deleted_at, is_master"
                )
                .eq("user_id", user_id)
                .is_("deleted_at", None)
            )
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []

        master_exists = (
            active_current_master_exists() if request.user.get("is_admin") else False
        )
        locked = playoffs_locked()
        creation_open = bracket_creation_open()

        if not rows:
            return (
                jsonify(
                    {
                        "bracket": None,
                        "master_exists": master_exists,
                        "playoffs_locked": locked,
                        "bracket_creation_open": creation_open,
                        "regular_season_end_utc": (
                            current_season().bracket_creation_opens_at.isoformat()
                            if current_season().bracket_creation_opens_at
                            else None
                        ),
                        "playoffs_deadline_utc": (
                            current_season().playoff_lock_at.isoformat()
                            if current_season().playoff_lock_at
                            else None
                        ),
                    }
                ),
                200,
            )

        b = rows[0]

        user_res = (
            supabase.table("users")
            .select("id, username")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        u_rows = user_res.data or []
        u = u_rows[0] if u_rows else {}

        return (
            jsonify(
                {
                    "bracket": {
                        "bracket_id": b["id"],
                        "name": b.get("name"),
                        "created_at": b.get("created_at"),
                        "saved_at": b.get("saved_at"),
                        "is_done": b.get("is_done"),
                        "is_master": bool(b.get("is_master")),
                        "user": {"id": b["user_id"], "username": u.get("username")},
                    },
                    "master_exists": master_exists,
                    "playoffs_locked": locked,
                    "bracket_creation_open": creation_open,
                    "regular_season_end_utc": (
                        current_season().bracket_creation_opens_at.isoformat()
                        if current_season().bracket_creation_opens_at
                        else None
                    ),
                    "playoffs_deadline_utc": (
                        current_season().playoff_lock_at.isoformat()
                        if current_season().playoff_lock_at
                        else None
                    ),
                }
            ),
            200,
        )

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /brackets/me (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/bracket/<bracket_id>", methods=["GET"])
@app.route("/history/bracket/<bracket_id>", methods=["GET"])
@bracket_read_auth
def get_bracket_by_id(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    viewer = getattr(request, "user", None) or {}
    viewer_id = viewer.get("user_id")

    br_res = (
        supabase.table("brackets")
        .select(
            "id, user_id, is_done, deleted_at, name, created_at, saved_at, season_id, is_master"
        )
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .limit(1)
        .execute()
    )
    br_rows = br_res.data or []
    if not br_rows:
        return jsonify({"error": "Bracket not found"}), 404

    bracket = br_rows[0]

    historical = request.path.startswith("/history/bracket/")
    if not historical and bracket.get("season_id") != current_season().id:
        return jsonify({"error": "Bracket is not in the current season"}), 404

    # 🔎 Derive true master flag from season.master_bracket_id OR brackets.is_master
    season_row = None
    if bracket.get("season_id"):
        season_res = (
            supabase.table("seasons")
            .select("id, code, master_bracket_id")
            .eq("id", bracket["season_id"])
            .limit(1)
            .execute()
        )
        srows = season_res.data or []
        season_row = srows[0] if srows else None

    if historical:
        code = (season_row or {}).get("code", "")
        if (
            bracket.get("season_id") == current_season().id
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}", code)
            or code >= current_season().code
        ):
            return jsonify({"error": "Historical bracket not found"}), 404

    derived_is_master = bool(bracket.get("is_master")) or (
        season_row is not None
        and str(season_row.get("master_bracket_id")) == str(bracket["id"])
    )

    owner_id = bracket.get("user_id")
    is_owner = str(viewer_id) == str(owner_id)

    if not is_owner and not competitive_bracket_eligible(
        bracket, season_id=bracket["season_id"] if historical else current_season().id
    ):
        return jsonify({"error": "Bracket not yet saved or not accessible"}), 403

    matches_res = (
        supabase.table("matches")
        .select("*")
        .eq("bracket_id", bracket["id"])
        .order("round", desc=False)
        .execute()
    )
    matches = matches_res.data or []

    team_ids = set()
    for m in matches:
        if m.get("team_a"):
            team_ids.add(m["team_a"])
        if m.get("team_b"):
            team_ids.add(m["team_b"])

    teams_by_id = {}
    if team_ids:
        teams_res = (
            supabase.table("teams")
            .select("id, name, code, logo_url, primary_color, secondary_color")
            .in_("id", list(team_ids))
            .execute()
        )
        team_rows = teams_res.data or []
        teams_by_id = {t["id"]: t for t in team_rows}

    grouped = {}
    for match in matches:
        conf = (match.get("conference") or "unknown").lower()
        rnd = match.get("round")
        grouped.setdefault(conf, {}).setdefault(rnd, [])
        enriched = dict(match)

        ta = teams_by_id.get(match.get("team_a"))
        tb = teams_by_id.get(match.get("team_b"))
        if ta:
            enriched.update(
                {
                    "team_a_name": ta.get("name"),
                    "team_a_code": ta.get("code"),
                    "team_a_logo_url": ta.get("logo_url"),
                    "team_a_primary_color": ta.get("primary_color"),
                    "team_a_secondary_color": ta.get("secondary_color"),
                }
            )
        if tb:
            enriched.update(
                {
                    "team_b_name": tb.get("name"),
                    "team_b_code": tb.get("code"),
                    "team_b_logo_url": tb.get("logo_url"),
                    "team_b_primary_color": tb.get("primary_color"),
                    "team_b_secondary_color": tb.get("secondary_color"),
                }
            )
        grouped[conf][rnd].append(enriched)

    owner_res = (
        supabase.table("users")
        .select("id, username")
        .eq("id", owner_id)
        .limit(1)
        .execute()
    )
    owner_rows = owner_res.data or []
    owner = owner_rows[0] if owner_rows else {}

    # 👇 Inject both snake_case and camelCase for the frontend
    return (
        jsonify(
            {
                "bracket": {
                    **bracket,
                    "owner": public_user(owner),
                    "is_owner": is_owner,
                    "is_historical": historical,
                    "read_only": historical,
                    "is_master": bool(derived_is_master),
                    "isMaster": bool(derived_is_master),
                },
                "matches": grouped,
            }
        ),
        200,
    )


@app.route("/brackets", methods=["GET"])
@require_auth
def list_all_brackets():
    """
    Returns saved brackets (is_done = true) for the CURRENT season,
    excluding deleted and excluding master.

    Optional query params:
    - league_id: if provided, only return brackets whose owners are members
      of that league (season is still always the current one).

    NOTE: This endpoint now requires authentication.
    """
    # Auth check (require_auth has already validated the token)
    user_info = getattr(request, "user", None) or {}
    user_id = user_info.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # Optional league filter
        league_id = request.args.get("league_id")
        league_user_ids = None

        if league_id:
            _, _, error = require_private_league_membership(league_id, user_info)
            if error:
                return error

            # 2) Get members of this league
            mem_res = (
                supabase.table("league_members")
                .select("user_id")
                .eq("league_id", league_id)
                .execute()
            )
            mem_rows = mem_res.data or []
            league_user_ids = {m["user_id"] for m in mem_rows if m.get("user_id")}

            # If league has no members, return empty list
            if not league_user_ids:
                return jsonify([]), 200

        # Time-gating info (same helpers you already use elsewhere)
        locked = playoffs_locked()
        creation_open = bracket_creation_open()

        # Base query: all non-master, done, non-deleted brackets for current season
        query = with_current_season(
            supabase.table("brackets")
            .select(
                "id, user_id, name, saved_at, created_at, "
                "deleted_at, is_done, is_master, season_id"
            )
            .eq("is_done", True)
            .eq("is_master", False)
            .is_("deleted_at", None)
        )

        # If league_id provided, restrict to owners who are members of that league
        if league_user_ids is not None:
            query = query.in_("user_id", list(league_user_ids))

        brackets_res = query.order("saved_at", desc=True).execute()
        brackets = [
            b for b in (brackets_res.data or []) if competitive_bracket_eligible(b)
        ]

        if not brackets:
            return jsonify([]), 200

        # Fetch owner user info in bulk
        user_ids = list({b["user_id"] for b in brackets if b.get("user_id")})
        users_by_id = {}
        if user_ids:
            users_res = (
                supabase.table("users")
                .select("id, username")
                .in_("id", user_ids)
                .execute()
            )
            for u in users_res.data or []:
                users_by_id[u["id"]] = u

        output = []
        for b in brackets:
            user_info = users_by_id.get(b["user_id"], {})
            output.append(
                {
                    "bracket_id": b["id"],
                    "name": b.get("name"),
                    "saved_at": b.get("saved_at"),
                    "created_at": b.get("created_at"),
                    "is_done": b.get("is_done", False),
                    "user": public_user({**user_info, "id": b["user_id"]}),
                    # convenience flags for the UI
                    "playoffs_locked": locked,
                    "bracket_creation_open": creation_open,
                    "regular_season_end_utc": (
                        current_season().bracket_creation_opens_at.isoformat()
                        if current_season().bracket_creation_opens_at
                        else None
                    ),
                    "playoffs_deadline_utc": (
                        current_season().playoff_lock_at.isoformat()
                        if current_season().playoff_lock_at
                        else None
                    ),
                }
            )

        return jsonify(output), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /brackets:", type(e).__name__, str(e))
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/bracket/<bracket_id>", methods=["DELETE"])
@require_auth
def delete_bracket(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    user_id = request.user["user_id"]

    user_res = (
        supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    )
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    bracket_res = (
        supabase.table("brackets")
        .select("id, user_id, deleted_at, season_id, is_master, is_done")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not bracket_res:
        return jsonify({"error": "Bracket not found"}), 404

    bracket = bracket_res[0]

    # Season guard
    if bracket.get("season_id") != current_season().id:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    if current_master_bracket(bracket):
        return (
            jsonify(
                {
                    "error": "Active master must be explicitly replaced or retired through controlled rollover"
                }
            ),
            403,
        )
    if bracket["user_id"] != user_id:
        return jsonify({"error": "Only the owner may delete this bracket"}), 403
    if playoffs_locked() and bracket.get("is_done") is True:
        return (
            jsonify(
                {
                    "error": "Submitted brackets cannot be deleted after the final deadline"
                }
            ),
            403,
        )

    update_fields = {
        "deleted_at": datetime.utcnow().isoformat(),
        "deleted_by_user_id": user_id,
    }
    supabase.table("brackets").update(update_fields).eq("id", bracket_id).execute()

    # Clean up scores referencing this bracket
    try:
        supabase.table("bracket_scores").delete().eq("bracket_id", bracket_id).execute()
        supabase.table("bracket_scores").delete().eq(
            "master_bracket_id", bracket_id
        ).execute()
    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print(
                "🔴 Error cleaning bracket_scores on delete (class):", type(e).__name__
            )

    return jsonify({"message": "Bracket deleted successfully"})


@app.route("/bracket/<bracket_id>/match/<match_id>", methods=["PATCH"])
@require_auth
def update_match(bracket_id, match_id):
    if not is_uuid(bracket_id) or not is_uuid(match_id):
        return jsonify({"error": "Invalid id"}), 400
    user_id = request.user["user_id"]

    data = request.get_json() or {}
    action = data.get("action")

    # ------------------------------------------------------------------
    # Preload all matches for this bracket so we can:
    #  - find the current match from this set, and
    #  - do in-memory updates with a single scan.
    # This removes the extra "single match by id" query in the normal path.
    # ------------------------------------------------------------------
    matches_resp = (
        supabase.table("matches")
        .select(
            "id, bracket_id, conference, round, slot, "
            "team_a, team_b, predicted_winner, predicted_winner_games, "
            "next_match_id, next_slot"
        )
        .eq("bracket_id", bracket_id)
        .execute()
    )
    all_matches = matches_resp.data or []
    matches_by_id = {m["id"]: m for m in all_matches}

    # Find the match we are updating from the bracket's matches
    match = matches_by_id.get(match_id)
    if not match:
        # Fallback: check if the match exists at all, to preserve
        # previous error semantics between "not found" vs "wrong bracket".
        res_any = (
            supabase.table("matches")
            .select("id, bracket_id")
            .eq("id", match_id)
            .limit(1)
            .execute()
            .data
        )
        if not res_any:
            return jsonify({"error": "Match not found"}), 404
        return jsonify({"error": "Match does not belong to the specified bracket"}), 400

    # Ownership/admin and SEASON guard
    bracket_check = (
        supabase.table("brackets")
        .select("id, user_id, season_id, is_master")
        .eq("id", match["bracket_id"])
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not bracket_check:
        return jsonify({"error": "Bracket not found"}), 404

    if bracket_check[0].get("season_id") != current_season().id:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    access_error = bracket_content_mutation_error(bracket_check[0], user_id)
    if access_error:
        return access_error

    if action == "set_winner":
        team = data.get("team")
        if (
            not match.get("team_a")
            or not match.get("team_b")
            or match["team_a"] == match["team_b"]
        ):
            return (
                jsonify(
                    {
                        "error": "Both participants must be established before prediction."
                    }
                ),
                400,
            )
        if team not in (match["team_a"], match["team_b"]):
            return (
                jsonify({"error": "Winner must be team_a or team_b for this match"}),
                400,
            )
        games = data.get("games")
        if match["round"] == 0 and "games" not in data:
            games = 1
        count_error = game_count_error(match, games, allow_missing=True)
        if count_error:
            return jsonify({"error": count_error}), 400
    elif action == "undo":
        team, games = None, None
    else:
        return jsonify({"error": "Invalid or unsupported action"}), 400

    try:
        changed = apply_prediction(all_matches, match_id, team, games)
    except (ValueError, KeyError, TypeError):
        return jsonify({"error": "Bracket dependencies are invalid."}), 400
    now_iso = datetime.utcnow().isoformat()
    for row in changed:
        supabase.table("matches").update(
            {
                "team_a": row.get("team_a"),
                "team_b": row.get("team_b"),
                "predicted_winner": row.get("predicted_winner"),
                "predicted_winner_games": row.get("predicted_winner_games"),
                "updated_at": now_iso,
            }
        ).eq("id", row["id"]).execute()
    invalidate_bracket_submission(match["bracket_id"])
    truth_fields = ("team_a", "team_b", "predicted_winner", "predicted_winner_games")
    truth_changed = any(
        any(row.get(k) != matches_by_id[row["id"]].get(k) for k in truth_fields)
        for row in changed
    )
    score_error = recompute_after_master_change(
        bracket_check[0], truth_changed=truth_changed
    )
    if score_error:
        return score_error
    return (
        jsonify(
            {"message": "Prediction undone" if action == "undo" else "Winner updated"}
        ),
        200,
    )


# Lightweight endpoint: set only predicted_winner_games for a match (already covered by set_games above)
# but keep for convenience
@app.route("/bracket/match/<match_id>/games", methods=["PATCH"])
@require_auth
def set_match_games(match_id):
    if not is_uuid(match_id):
        return jsonify({"error": "Invalid match id"}), 400

    body = request.get_json() or {}
    games = body.get("games")
    if games is None:
        return jsonify({"error": "games required"}), 400

    user_id = request.user["user_id"]

    m_resp = supabase.table("matches").select("*").eq("id", match_id).limit(1).execute()
    if not m_resp.data:
        return jsonify({"error": "match not found"}), 404
    match = m_resp.data[0]

    br = (
        supabase.table("brackets")
        .select("id, user_id, season_id, is_master")
        .eq("id", match["bracket_id"])
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not br:
        return jsonify({"error": "forbidden"}), 403

    # 🔒 Season guard
    if br[0].get("season_id") != current_season().id:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    access_error = bracket_content_mutation_error(br[0], user_id)
    if access_error:
        return access_error

    count_error = game_count_error(match, games, count_edit=True)
    if count_error:
        return jsonify({"error": count_error}), 400

    supabase.table("matches").update(
        {"predicted_winner_games": games, "updated_at": datetime.utcnow().isoformat()}
    ).eq("id", match_id).execute()
    invalidate_bracket_submission(match["bracket_id"])
    score_error = recompute_after_master_change(
        br[0], truth_changed=games != match.get("predicted_winner_games")
    )
    if score_error:
        return score_error
    return jsonify({"ok": True}), 200


@app.route("/leaderboard", methods=["GET"])
@require_auth_for_league_scope
def leaderboard():
    """
    Returns leaderboard rows for the CURRENT season plus a full master_matchups map.
    Each matchup includes team codes; if a side isn't known yet we return "TBD".
    """
    try:
        league_id = request.args.get("league_id")
        league_user_ids = None
        if league_id:
            league, _, error = require_private_league_membership(
                league_id, getattr(request, "user", None) or {}
            )
            if error:
                return error
            members = (
                supabase.table("league_members")
                .select("user_id")
                .eq("league_id", league_id)
                .execute()
                .data
                or []
            )
            league_user_ids = {m["user_id"] for m in members if m.get("user_id")}

        # -------- 1) Scores for current season --------
        scores_q = supabase.table("bracket_scores").select(
            "season_id, bracket_id, master_bracket_id, total_points, full_hits, "
            "partial_hits, misses, bonus_finalists, bonus_champion, "
            "points_by_match, updated_at"
        )
        if current_season().id is None:
            scores_q = scores_q.is_("season_id", None)
        else:
            scores_q = scores_q.eq("season_id", current_season().id)

        scores = (scores_q.execute().data) or []
        if not scores:
            return (
                jsonify(
                    {
                        "rows": [],
                        "master_bracket_id": None,
                        "master_updated_at": None,
                        "master_matchups": {},
                    }
                ),
                200,
            )

        master_bracket_id = None

        # -------- 3) Brackets & owners (current season, not deleted) --------
        bracket_ids = list({s["bracket_id"] for s in scores if s.get("bracket_id")})
        if not bracket_ids:
            return (
                jsonify(
                    {
                        "rows": [],
                        "master_bracket_id": master_bracket_id,
                        "master_updated_at": None,
                        "master_matchups": {},
                    }
                ),
                200,
            )

        br_q = (
            supabase.table("brackets")
            .select("id, user_id, name, is_done, deleted_at, season_id, saved_at")
            .in_("id", bracket_ids)
            .is_("deleted_at", None)
        )
        if current_season().id is None:
            br_q = br_q.is_("season_id", None)
        else:
            br_q = br_q.eq("season_id", current_season().id)

        br_rows = [
            b for b in (br_q.execute().data or []) if competitive_bracket_eligible(b)
        ]
        br_by_id = {b["id"]: b for b in br_rows}
        # Stale/draft rows cannot influence even the live score-derived metadata.
        scores = [score for score in scores if score.get("bracket_id") in br_by_id]
        if not scores:
            return (
                jsonify(
                    {
                        "rows": [],
                        "master_bracket_id": None,
                        "master_updated_at": None,
                        "master_matchups": {},
                    }
                ),
                200,
            )

        _, scoring_master = get_current_scoring_master(
            supabase, expected_season_id=current_season().id
        )
        master_bracket_id = scoring_master["id"]
        # Replaced-master rows cannot masquerade as scores for current truth.
        scores = [
            row for row in scores if row.get("master_bracket_id") == master_bracket_id
        ]

        user_ids = list({b["user_id"] for b in br_rows if b.get("user_id")})
        users = (
            supabase.table("users")
            .select("id, username")
            .in_("id", user_ids)
            .execute()
            .data
        ) or []
        users_by_id = {u["id"]: u for u in users}

        # -------- 4) Build leaderboard rows --------
        rows_out = []
        for s in scores:
            bid = s.get("bracket_id")
            b = br_by_id.get(bid)
            if not bid or not b:
                continue
            if league_user_ids is not None and b.get("user_id") not in league_user_ids:
                continue
            u = users_by_id.get(b["user_id"], {})
            rows_out.append(
                {
                    "bracket_id": bid,
                    "bracket_name": b.get("name"),
                    "user_id": b["user_id"],
                    "username": u.get("username", "unknown"),
                    "total_points": s.get("total_points", 0),
                    "full_hits": s.get("full_hits", 0),
                    "partial_hits": s.get("partial_hits", 0),
                    "misses": s.get("misses", 0),
                    "bonus_finalists": s.get("bonus_finalists", 0),
                    "bonus_champion": s.get("bonus_champion", 0),
                    "updated_at": s.get("updated_at"),
                    "saved_at": b.get("saved_at"),
                    "points_by_match": s.get("points_by_match") or {},
                }
            )

        rows_out = rank_live_rows(rows_out)

        # -------- 5) Build a canonical master_matchups map --------
        master_matchups = {}
        master_updated_at = None

        if master_bracket_id:
            # (a) Canonical key set the UI expects
            ALL_KEYS = [
                "east-0-1",
                "west-0-1",
                "east-0-2",
                "west-0-2",
                "east-0-3",
                "west-0-3",
                "east-1-4",
                "east-1-5",
                "east-1-6",
                "east-1-7",
                "west-1-4",
                "west-1-5",
                "west-1-6",
                "west-1-7",
                "east-2-8",
                "east-2-9",
                "west-2-8",
                "west-2-9",
                "east-3-10",
                "west-3-10",
                "nba-4-11",
            ]
            # Pre-fill with TBDs so every column has a value
            for k in ALL_KEYS:
                conf, r, s = k.split("-")
                master_matchups[k] = {
                    "conference": conf,
                    "round": int(r),
                    "slot": int(s),
                    "team_a_code": "TBD",
                    "team_b_code": "TBD",
                }

            # (b) Load actual matches from the master bracket
            matches = (
                supabase.table("matches")
                .select("conference, round, slot, team_a, team_b")
                .eq("bracket_id", master_bracket_id)
                .execute()
                .data
            ) or []

            # Collect unique team IDs
            team_ids = set()
            for m in matches:
                if m.get("team_a"):
                    team_ids.add(m["team_a"])
                if m.get("team_b"):
                    team_ids.add(m["team_b"])

            teams_by_id = {}
            if team_ids:
                trows = (
                    supabase.table("teams")
                    .select("id, code")
                    .in_("id", list(team_ids))
                    .execute()
                    .data
                ) or []
                teams_by_id = {t["id"]: (t.get("code") or "").strip() for t in trows}

            def code_or_tbd(team_id):
                code = teams_by_id.get(team_id)
                return code if code else "TBD"

            # (c) Fill actual codes into the canonical map
            for m in matches:
                conf = (m.get("conference") or "").lower()
                rnd = m.get("round")
                slot = m.get("slot")
                key = f"{conf}-{rnd}-{slot}"
                if key in master_matchups:
                    master_matchups[key]["team_a_code"] = code_or_tbd(m.get("team_a"))
                    master_matchups[key]["team_b_code"] = code_or_tbd(m.get("team_b"))
                else:
                    # In case a new/unexpected key appears in DB, include it anyway.
                    master_matchups[key] = {
                        "conference": conf,
                        "round": rnd,
                        "slot": slot,
                        "team_a_code": code_or_tbd(m.get("team_a")),
                        "team_b_code": code_or_tbd(m.get("team_b")),
                    }

            # (d) Derive "last updated" from rows tied to this master
            master_updates = [
                s.get("updated_at")
                for s in scores
                if s.get("master_bracket_id") == master_bracket_id
                and s.get("updated_at")
            ]
            if master_updates:
                master_updated_at = max(master_updates)

        return (
            jsonify(
                {
                    "rows": rows_out,
                    "master_bracket_id": master_bracket_id,
                    "master_updated_at": master_updated_at,
                    "master_matchups": master_matchups,
                }
            ),
            200,
        )

    except ScoringError as error:
        return (
            jsonify({"error": str(error), "code": "SCORING_CONFIGURATION_UNAVAILABLE"}),
            503,
        )
    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            try:
                safe_print(
                    "🔴 Error in /leaderboard:",
                    type(e).__name__,
                    str(e),
                )
            except Exception:
                pass

        # Fail-open: same shape as the "no scores" path
        return (
            jsonify(
                {
                    "rows": [],
                    "master_bracket_id": None,
                    "master_updated_at": None,
                    "master_matchups": {},
                }
            ),
            200,
        )


@app.route("/stats/champion-picks", methods=["GET"])
@require_auth
def champion_pick_stats():
    """
    Distribution of NBA champion picks (predicted winner of the NBA Finals)
    for the current season.

    Optional query params:
      - league_id: if provided, restrict to brackets whose owners are
        members of that league.

    Access:
    - Global (no league_id): any authenticated user.
    - Private league scope: active membership, including owners/admins.
    - Public league scope: existing member/owner/admin rule.
    """
    # Auth context
    user = getattr(request, "user", None) or {}

    league_id = request.args.get("league_id") or None
    scope = "global"
    season_code = request.args.get("season_code") or None

    try:
        league_user_ids = None
        league_row = None
        least_matchup = None
        most_matchup = None

        # --- If league_id is provided, validate & enforce access ---
        if league_id:
            if not is_uuid(league_id):
                return jsonify({"error": "Invalid league id"}), 400

            scope = "league"

            league_row, _, error = require_private_league_membership(
                league_id, user, public_members_only=True
            )
            if error:
                return error

            # Load all members of the league
            mem_res = (
                supabase.table("league_members")
                .select("user_id")
                .eq("league_id", league_row["id"])
                .execute()
            )
            mem_rows = mem_res.data or []
            league_user_ids = {m["user_id"] for m in mem_rows if m.get("user_id")}

            if not league_user_ids:
                return (
                    jsonify(
                        {
                            "scope": scope,
                            "league_id": league_id,
                            "total_brackets": 0,
                            "rows": [],
                        }
                    ),
                    200,
                )

        target_season_id = None

        if season_code:
            season_res = (
                supabase.table("seasons")
                .select("id, code")
                .eq("code", season_code)
                .limit(1)
                .execute()
            )
            season_rows = season_res.data or []
            if not season_rows:
                return jsonify({"error": "Season not found"}), 404
            target_season_id = season_rows[0]["id"]

        # --- Load brackets for current season, done, not deleted ---
        base_brackets = (
            supabase.table("brackets")
            .select("id, user_id, is_done, deleted_at, season_id")
            .eq("is_done", True)
            .is_("deleted_at", None)
        )

        if target_season_id:
            # Explicit past season via season_code
            brackets_q = base_brackets.eq("season_id", target_season_id)
        else:
            # Default: current season
            brackets_q = with_current_season(base_brackets)

        if league_user_ids is not None:
            brackets_q = brackets_q.in_("user_id", list(league_user_ids))

        br_res = brackets_q.execute()
        br_rows = [
            b
            for b in (br_res.data or [])
            if competitive_bracket_eligible(
                b, season_id=target_season_id if season_code else current_season().id
            )
        ]

        if not br_rows:
            return (
                jsonify(
                    {
                        "scope": scope,
                        "league_id": league_id,
                        "total_brackets": 0,
                        "rows": [],
                    }
                ),
                200,
            )

        bracket_ids = [b["id"] for b in br_rows if b.get("id")]
        if not bracket_ids:
            return (
                jsonify(
                    {
                        "scope": scope,
                        "league_id": league_id,
                        "total_brackets": 0,
                        "rows": [],
                    }
                ),
                200,
            )

        # --- Aggregate per-match points across these brackets to find least/most predicted matchups ---
        scores_res = (
            supabase.table("bracket_scores")
            .select("bracket_id, master_bracket_id, points_by_match")
            .in_("bracket_id", bracket_ids)
            .execute()
        )
        scores_rows = scores_res.data or []

        totals_by_key = {}
        master_freq = {}

        for s in scores_rows:
            mid = s.get("master_bracket_id")
            if mid:
                master_freq[mid] = master_freq.get(mid, 0) + 1

            points_by_match = s.get("points_by_match") or {}
            if not isinstance(points_by_match, dict):
                continue

            for key, info in points_by_match.items():
                if not isinstance(info, dict):
                    continue

                status = info.get("status")
                # Skip matchups that are still pending in the master bracket
                if status == "pending":
                    continue

                pts = info.get("points") or 0
                conf = (info.get("conference") or "").lower()
                rnd = info.get("round")
                slot = info.get("slot")

                agg = totals_by_key.get(key)
                if not agg:
                    totals_by_key[key] = {
                        "total_points": float(pts),
                        "conference": conf,
                        "round": rnd,
                        "slot": slot,
                    }
                else:
                    agg["total_points"] += float(pts)

        if totals_by_key:
            # Least and most points awarded overall
            least_key, least_agg = min(
                totals_by_key.items(),
                key=lambda kv: (kv[1]["total_points"], kv[0]),
            )
            most_key, most_agg = max(
                totals_by_key.items(),
                key=lambda kv: (kv[1]["total_points"], kv[0]),
            )

            # Resolve team names / codes from the master bracket, if we can
            master_bracket_id = None
            if master_freq:
                master_bracket_id = max(master_freq, key=master_freq.get)

            match_map = {}
            teams_by_id = {}
            if master_bracket_id:
                matches_res2 = (
                    supabase.table("matches")
                    .select("conference, round, slot, team_a, team_b")
                    .eq("bracket_id", master_bracket_id)
                    .execute()
                )
                matches_rows2 = matches_res2.data or []
                team_ids = set()

                for m in matches_rows2:
                    conf = (m.get("conference") or "").lower()
                    rnd = m.get("round")
                    slot = m.get("slot")
                    mk = f"{conf}-{rnd}-{slot}"
                    match_map[mk] = m
                    if m.get("team_a"):
                        team_ids.add(m["team_a"])
                    if m.get("team_b"):
                        team_ids.add(m["team_b"])

                if team_ids:
                    teams_res2 = (
                        supabase.table("teams")
                        .select("id, code, name")
                        .in_("id", list(team_ids))
                        .execute()
                    )
                    for t in teams_res2.data or []:
                        teams_by_id[t["id"]] = t

            def build_match_dict(key, agg):
                team_a_code = "TBD"
                team_b_code = "TBD"
                team_a_name = "TBD"
                team_b_name = "TBD"

                if match_map:
                    mrow = match_map.get(key) or {}
                    ta = mrow.get("team_a")
                    tb = mrow.get("team_b")

                    if ta and ta in teams_by_id:
                        team_a_code = teams_by_id[ta].get("code") or "TBD"
                        team_a_name = teams_by_id[ta].get("name") or team_a_code
                    if tb and tb in teams_by_id:
                        team_b_code = teams_by_id[tb].get("code") or "TBD"
                        team_b_name = teams_by_id[tb].get("name") or team_b_code

                return {
                    "match_key": key,
                    "conference": agg.get("conference"),
                    "round": agg.get("round"),
                    "slot": agg.get("slot"),
                    "team_a_code": team_a_code,
                    "team_b_code": team_b_code,
                    "team_a_name": team_a_name,
                    "team_b_name": team_b_name,
                    "total_points": agg.get("total_points", 0.0),
                }

            least_matchup = build_match_dict(least_key, least_agg)
            most_matchup = build_match_dict(most_key, most_agg)

        # --- Fetch NBA Finals champion picks for these brackets ---
        matches_res = (
            supabase.table("matches")
            .select("bracket_id, conference, round, slot, predicted_winner")
            .in_("bracket_id", bracket_ids)
            .eq("conference", "nba")
            .eq("round", 4)
            .eq("slot", 11)
            .execute()
        )
        matches_rows = matches_res.data or []

        from collections import defaultdict

        counts = defaultdict(int)
        for row in matches_rows:
            team_id = row.get("predicted_winner")
            if team_id:
                counts[team_id] += 1

        total_picks = sum(counts.values())
        if total_picks == 0:
            # No champion picks yet for these brackets
            return (
                jsonify(
                    {
                        "scope": scope,
                        "league_id": league_id,
                        "total_brackets": len(br_rows),
                        "rows": [],
                    }
                ),
                200,
            )

        team_ids = list(counts.keys())

        # --- Load team metadata (id, code, name) ---
        teams_by_id = {}
        if team_ids:
            teams_res = (
                supabase.table("teams")
                .select("id, code, name")
                .in_("id", team_ids)
                .execute()
            )
            for t in teams_res.data or []:
                teams_by_id[t["id"]] = t

        rows_out = []
        for team_id, count in counts.items():
            meta = teams_by_id.get(team_id) or {}
            code = meta.get("code") or "UNK"
            name = meta.get("name") or code
            percent = (count * 100.0) / float(total_picks) if total_picks else 0.0

            rows_out.append(
                {
                    "team_id": team_id,
                    "team_code": code,
                    "team_name": name,
                    "brackets": count,
                    "percent": percent,
                }
            )

        # Sort: most-picked first, then by team name
        rows_out.sort(key=lambda r: (-r["brackets"], r["team_name"] or ""))

        return (
            jsonify(
                {
                    "scope": scope,
                    "league_id": league_id,
                    "total_brackets": total_picks,
                    "rows": rows_out,
                    "least_predicted_matchup": least_matchup,
                    "most_predicted_matchup": most_matchup,
                }
            ),
            200,
        )

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /stats/champion-picks:", type(e).__name__, str(e))
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/leaderboard/history", methods=["GET"])
def leaderboard_history_index():
    """
    Returns one entry per season that has a history snapshot.
    Used by the Past Seasons page to populate the season selector.
    """
    try:
        res = (
            supabase.table("leaderboard_history_snapshots")
            .select("id, season_id, season_code, snapshot_at")
            .or_("is_final.is.null,is_final.eq.true")
            .order("snapshot_at", desc=True)
            .execute()
        )
        snaps = getattr(res, "data", None) or []

        # Keep only the latest snapshot per season_code
        by_code = {}
        for s in snaps:
            code = (s.get("season_code") or "").strip()
            if not code:
                continue
            prev = by_code.get(code)
            if not prev or (prev.get("snapshot_at") or "") < (
                s.get("snapshot_at") or ""
            ):
                by_code[code] = {
                    "season_id": s.get("season_id"),
                    "season_code": code,
                    "snapshot_at": s.get("snapshot_at"),
                }

        seasons = list(by_code.values())
        return jsonify({"seasons": seasons}), 200

    except Exception as e:
        safe_print("🔴 Error in GET /leaderboard/history:", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/leaderboard/history/<season_code>", methods=["GET"])
def leaderboard_history_season(season_code):
    """
    Returns the frozen leaderboard snapshot for a given season code.

    Response:
      {
        "season_code": "...",
        "snapshot_at": "...",
        "columns": [...],
        "rows": [
          {
            "id": ...,
            "rank": ...,
            "display_name": "...",
            "total_points": ...,
            "bonus_finalists": ...,
            "bonus_champion": ...,
            "full_hits": ...,
            "partial_hits": ...,
            "misses": ...,
            "per_match_points": { "<match-key>": <points>, ... }
          },
          ...
        ]
      }
    """
    code = (season_code or "").strip()
    if not code:
        return jsonify({"error": "season_code is required"}), 400

    # Find the most recent snapshot for this season
    snap_res = (
        supabase.table("leaderboard_history_snapshots")
        .select("id, season_code, snapshot_at, columns")
        .eq("season_code", code)
        .or_("is_final.is.null,is_final.eq.true")
        .order("snapshot_at", desc=True)
        .limit(1)
        .execute()
    )
    snaps = getattr(snap_res, "data", None) or []
    if not snaps:
        return jsonify({"error": "No snapshot found for this season"}), 404

    snap = snaps[0]
    snapshot_id = snap.get("id")

    # Load rows for this snapshot
    rows_res = (
        supabase.table("leaderboard_history_rows")
        .select(
            "id, rank, display_name, total_points, bonus_finalists, "
            "bonus_champion, full_hits, partial_hits, misses, per_match_points, saved_at, base_points, points_by_round"
        )
        .eq("snapshot_id", snapshot_id)
        .order("rank")
        .order("display_order")
        .order("id")
        .execute()
    )
    rows = getattr(rows_res, "data", None) or []

    # 🔧 Sanitize per_match_points: always return numeric points
    sanitized_rows = []
    for row in rows:
        pm_raw = row.get("per_match_points") or {}
        pm_clean: Dict[str, int] = {}

        if isinstance(pm_raw, dict):
            for mk, cell in pm_raw.items():
                if isinstance(cell, dict):
                    pts = cell.get("points")
                else:
                    pts = cell
                try:
                    pm_clean[str(mk)] = int(pts) if pts is not None else 0
                except Exception:
                    pm_clean[str(mk)] = 0

        row["per_match_points"] = pm_clean
        sanitized_rows.append(row)

    return (
        jsonify(
            {
                "season_code": snap.get("season_code"),
                "snapshot_at": snap.get("snapshot_at"),
                "columns": public_columns(snap.get("columns")),
                "rows": public_snapshot_rows(sanitized_rows),
            }
        ),
        200,
    )


@app.get("/__debug/master-status")
def debug_master_status():
    bid = request.args.get("bracket_id")
    if not bid:
        return jsonify({"error": "missing bracket_id"}), 400

    b_res = (
        supabase.table("brackets")
        .select("id, season_id, deleted_at")
        .eq("id", bid)
        .single()
        .execute()
    )
    b = getattr(b_res, "data", None) or {}
    if not b:
        return jsonify({"error": "bracket not found"}), 404

    sid = b.get("season_id")
    if not sid:
        return jsonify({"error": "bracket has no season_id"}), 400

    # Try select with master_bracket_id; if the column doesn't exist, return a helpful message.
    try:
        s_res = (
            supabase.table("seasons")
            .select("id, code, master_bracket_id")
            .eq("id", sid)
            .single()
            .execute()
        )
        s_err = getattr(s_res, "error", None)
        if s_err and "master_bracket_id" in str(s_err):
            return jsonify({
                "error": "seasons.master_bracket_id is missing",
                "fix_sql": [
                    "ALTER TABLE public.seasons ADD COLUMN IF NOT EXISTS master_bracket_id uuid;",
                    "ALTER TABLE public.seasons ADD CONSTRAINT seasons_master_bracket_fk "
                    "FOREIGN KEY (master_bracket_id) REFERENCES public.brackets(id) ON DELETE SET NULL;",
                    "CREATE INDEX IF NOT EXISTS idx_seasons_master_bracket_id ON public.seasons(master_bracket_id);"
                ]
            }), 500

        s = getattr(s_res, "data", None) or {}
        mid = s.get("master_bracket_id")
        return jsonify({
            "bracket_id": b["id"],
            "season_id": sid,
            "season_code": s.get("code"),
            "season.master_bracket_id": mid,
            "bracket_deleted": bool(b.get("deleted_at")),
            "is_master_computed": (mid == b["id"]),
        }), 200

    except Exception as e:
        # If the supabase client throws instead of returning an error field.
        msg = str(e)
        if "master_bracket_id" in msg:
            return jsonify({
                "error": "seasons.master_bracket_id is missing",
                "exception": msg,
                "fix_sql": [
                    "ALTER TABLE public.seasons ADD COLUMN IF NOT EXISTS master_bracket_id uuid;",
                    "ALTER TABLE public.seasons ADD CONSTRAINT seasons_master_bracket_fk "
                    "FOREIGN KEY (master_bracket_id) REFERENCES public.brackets(id) ON DELETE SET NULL;",
                    "CREATE INDEX IF NOT EXISTS idx_seasons_master_bracket_id ON public.seasons(master_bracket_id);"
                ]
            }), 500
        return jsonify({"error": "unexpected", "exception": msg}), 500


# --------------------------------------------------------
# ----------------------  LEAGUES  -----------------------
# --------------------------------------------------------

@app.route("/leagues/me", methods=["GET"])
@require_auth
def get_my_leagues():
    """
    Return all *private* leagues the current user belongs to.

    - Excludes the global league (is_global = true).
    - This is season-agnostic; it just returns group memberships.
    """
    user_info = getattr(request, "user", None) or {}
    user_id = user_info.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # 1) Get membership rows for this user
        mem_res = (
            supabase.table("league_members")
            .select("league_id, joined_at")
            .eq("user_id", user_id)
            .execute()
        )
        mem_rows = mem_res.data or []

        if not mem_rows:
            # No memberships yet → empty list is fine
            return jsonify({"leagues": []}), 200

        league_ids = list({m["league_id"] for m in mem_rows if m.get("league_id")})
        if not league_ids:
            return jsonify({"leagues": []}), 200

        # 2) Fetch leagues for those IDs
        leagues_res = (
            supabase.table("leagues")
            .select("id, name, owner_user_id, is_global, password_hash, created_at, updated_at")
            .in_("id", league_ids)
            .execute()
        )
        league_rows = leagues_res.data or []
        league_by_id = {l["id"]: l for l in league_rows}

        # 3) Build response, skipping global league
        leagues_out = []
        for m in mem_rows:
            lid = m.get("league_id")
            league = league_by_id.get(lid)
            if not league:
                continue

            # Skip global league (we don't want it in "My Leagues")
            if league.get("is_global"):
                continue

            leagues_out.append(
                {
                    "id": league["id"],
                    "name": league.get("name"),
                    "owner_user_id": league.get("owner_user_id"),
                    "is_global": league.get("is_global", False),
                    "created_at": league.get("created_at"),
                    "updated_at": league.get("updated_at"),
                    "joined_at": m.get("joined_at"),
                    "requires_password": bool(league.get("password_hash")),
                }
            )

        return jsonify({"leagues": leagues_out}), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /leagues/me:", type(e).__name__, str(e))
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/leagues", methods=["GET"])
@require_auth
def list_leagues():
    """
    List all *private* leagues (is_global = false).

    - Requires authentication.
    - Returns all leagues, plus a flag indicating whether the current user
      is already a member of each league.
    - Does NOT include the global league.
    """
    user_info = getattr(request, "user", None) or {}
    user_id = user_info.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # 1) Fetch all (non-global) leagues
        leagues_res = (
            supabase.table("leagues")
            .select("id, name, owner_user_id, password_hash, is_global, created_at, updated_at")
            .eq("is_global", False)
            .order("created_at", desc=True)
            .execute()
        )
        league_rows = leagues_res.data or []

        if not league_rows:
            return jsonify({"leagues": []}), 200

        league_ids = [l["id"] for l in league_rows if l.get("id")]

        # 2) Fetch memberships for the current user so we can add "is_member"
        mem_res = (
            supabase.table("league_members")
            .select("league_id")
            .eq("user_id", user_id)
            .in_("league_id", league_ids)
            .execute()
        )
        mem_rows = mem_res.data or []
        member_league_ids = {m["league_id"] for m in mem_rows if m.get("league_id")}
        
        # 2b) Fetch all memberships so we can compute member_count per league
        all_mem_res = (
            supabase.table("league_members")
            .select("league_id")
            .in_("league_id", league_ids)
            .execute()
        )
        all_mem_rows = all_mem_res.data or []

        member_counts = defaultdict(int)
        for m in all_mem_rows:
            lid2 = m.get("league_id")
            if lid2:
                member_counts[lid2] += 1

        # 3) Build output, marking whether current user is a member
        leagues_out = []
        for league in league_rows:
            lid = league.get("id")
            if not lid:
                continue

            leagues_out.append(
                {
                    "id": lid,
                    "name": league.get("name"),
                    **(
                        {"owner_user_id": league.get("owner_user_id")}
                        if lid in member_league_ids or not league.get("password_hash")
                        else {}
                    ),
                    "is_global": league.get("is_global", False),
                    "created_at": league.get("created_at"),
                    "updated_at": league.get("updated_at"),
                    "is_member": lid in member_league_ids,
                    "member_count": member_counts.get(lid, 0),
                    "requires_password": bool(league.get("password_hash")),
                }
            )

        return jsonify({"leagues": leagues_out}), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in GET /leagues:", type(e).__name__, str(e))
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/leagues", methods=["POST"])
@require_auth
def create_league():
    return _league_lifecycle_action("create")


@app.route("/leagues/<league_id>/join", methods=["POST"])
@require_auth
def join_league(league_id):
    return _league_lifecycle_action("join", league_id)


@app.route("/leagues/<league_id>/membership", methods=["DELETE"])
@require_auth
def leave_league(league_id):
    return _league_lifecycle_action("leave", league_id)



@app.route("/leagues/<league_id>", methods=["DELETE"])
@require_auth
def delete_league(league_id):
    return _league_lifecycle_action("delete", league_id)


@app.route("/leagues/<league_id>/members", methods=["GET"])
@require_auth
def get_league_members(league_id):
    """
    Get all members of a league, plus whether they have a bracket for
    the current season.

    Private member data requires active membership. Public leagues retain the
    existing member/owner/admin access rule. User display never includes email.
    """
    user_info = getattr(request, "user", None) or {}
    user_id = user_info.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_uuid(league_id):
        return jsonify({"error": "Invalid league id"}), 400

    try:
        league, _, error = require_private_league_membership(
            league_id, user_info, public_members_only=True
        )
        if error:
            return error

        # 3) Get all memberships for this league
        mem_res = (
            supabase.table("league_members")
            .select("user_id, joined_at")
            .eq("league_id", league["id"])
            .execute()
        )
        mem_rows = mem_res.data or []

        if not mem_rows:
            return jsonify(
                {
                    "league": league,
                    "members": [],
                }
            ), 200

        user_ids = list({m["user_id"] for m in mem_rows if m.get("user_id")})

        # 4) Load user details
        users_by_id = {}
        if user_ids:
            users_res = (
                supabase.table("users")
                .select("id, username")
                .in_("id", user_ids)
                .execute()
            )
            for u in users_res.data or []:
                users_by_id[u["id"]] = u

        # 5) Load brackets for current season for these users
        brackets_by_user = {}
        if user_ids:
            brackets_res = (
                with_current_season(
                    supabase.table("brackets")
                    .select("id, user_id, is_done, deleted_at, season_id")
                    .eq("is_done", True)
                    .is_("deleted_at", None)
                )
                .in_("user_id", user_ids)
                .execute()
            )
            for b in brackets_res.data or []:
                if not competitive_bracket_eligible(b):
                    continue
                uid = b.get("user_id")
                if not uid:
                    continue
                # In case of multiple brackets in data (shouldn't happen), last one wins
                brackets_by_user[uid] = b

        # 6) Build members array
        members_out = []
        owner_id = league.get("owner_user_id")

        joined_by_user = {m["user_id"]: m["joined_at"] for m in mem_rows if m.get("user_id")}

        for uid in user_ids:
            u = public_user(users_by_id.get(uid, {}))
            bracket = brackets_by_user.get(uid)
            members_out.append(
                {
                    "user_id": uid,
                    "username": u.get("username"),
                    "joined_at": joined_by_user.get(uid),
                    "is_owner": uid == owner_id,
                    "has_bracket": bracket is not None,
                    "bracket_id": bracket["id"] if bracket else None,
                }
            )

        resp = {
            "league": {
                "id": league["id"],
                "name": league.get("name"),
                "owner_user_id": league.get("owner_user_id"),
                "is_global": league.get("is_global", False),
                "created_at": league.get("created_at"),
                "updated_at": league.get("updated_at"),
            },
            "members": members_out,
        }

        return jsonify(resp), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in GET /leagues/<id>/members:", type(e).__name__, str(e))
        return jsonify({"error": "Unexpected error"}), 500


def _league_lifecycle_action(action, league_id=None, target_user_id=None):
    from league_service import mutate, LeagueError

    if league_id is not None and not is_uuid(league_id):
        return jsonify({"error": "Invalid league id"}), 400
    data = request.get_json(silent=True)
    if data is None:
        data = {}
    if action == "transfer" and isinstance(data, dict):
        target_user_id = data.get("target_user_id")
    if action in {"transfer", "remove"} and not is_uuid(target_user_id):
        return jsonify({"error": "Invalid target user id"}), 400
    try:
        result = mutate(
            supabase,
            action,
            (request.user or {}).get("user_id"),
            lid=league_id,
            target=target_user_id,
            body=data,
            rounds=BCRYPT_ROUNDS,
        )
        return jsonify(result), result.get("status", 200)
    except LeagueError as error:
        return jsonify({"error": str(error)}), error.status
    except Exception:
        return jsonify({"error": "League operation unavailable; please retry"}), 503


@app.route("/leagues/<league_id>", methods=["PATCH"])
@require_auth
def update_league(league_id):
    return _league_lifecycle_action("settings", league_id)


@app.route("/leagues/<league_id>/ownership", methods=["POST"])
@require_auth
def transfer_league_owner(league_id):
    return _league_lifecycle_action("transfer", league_id)


@app.route("/leagues/<league_id>/members/<target_user_id>", methods=["DELETE"])
@require_auth
def remove_league_member(league_id, target_user_id):
    return _league_lifecycle_action("remove", league_id, target_user_id)


def optional_league_history_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization")
        if header:
            if not header.startswith("Bearer "):
                return jsonify({"error": "Invalid Authorization header"}), 401
            payload = decode_token(header.split(" ", 1)[1])
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            request.user = payload
        else:
            request.user = {}
        return f(*args, **kwargs)

    return wrapper


def _league_history_read(league_id, season_code=None):
    from league_history_service import read_history
    from league_service import LeagueError

    try:
        league, _, error = require_private_league_membership(
            league_id, request.user or {}
        )
        if error:
            return error
        return jsonify(read_history(supabase, league, season_code)), 200
    except LeagueError as error:
        return jsonify({"error": str(error)}), error.status
    except Exception:
        return jsonify({"error": "League history unavailable"}), 503


@app.route("/leagues/<league_id>/history", methods=["GET"])
@optional_league_history_auth
def league_history_seasons(league_id):
    return _league_history_read(league_id)


@app.route("/leagues/<league_id>/history/<season_code>", methods=["GET"])
@optional_league_history_auth
def league_history_season(league_id, season_code):
    return _league_history_read(league_id, season_code)


# --------------------------------------------------------
# --------------------- M  A  I  N  ----------------------
# --------------------------------------------------------

if __name__ == "__main__":
    # Use FLASK_DEBUG=1 in your local env if you want debug mode
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
