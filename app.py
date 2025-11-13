# app.py
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
from supabase import create_client
from dotenv import load_dotenv
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
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
DISABLE_RATE_LIMITS = os.getenv("DISABLE_RATE_LIMITS", "0") == "1"

# ✅ Healthcheck secret (optional; if set, /health requires it)
HEALTHCHECK_TOKEN = os.getenv("HEALTHCHECK_TOKEN")

# ✅ Bcrypt work factor (cost). 12 is a good starting point.
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# ✅ Password policy
PASSWORD_MIN_LENGTH = 10

# ✅ Shared identifier validation regexes
EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
USERNAME_REGEX = r"^[a-zA-Z0-9_]{3,30}$"

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Season + gate globals (resolved from DB, with env fallback) ---

# Resolved globals
CURRENT_SEASON_ID = None
REGULAR_SEASON_END_UTC = None
PLAYOFFS_START_UTC = None

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


def _resolve_season_globals():
    """
    Resolve CURRENT_SEASON_ID and the gate datetimes from DB (seasons table),
    falling back to env vars REGULAR_SEASON_END_UTC / PLAYOFFS_START_UTC.
    Safe defaults:
      - If PLAYOFFS_START_UTC is still None → set very far future
      - If REGULAR_SEASON_END_UTC is None → 'too-early' check is skipped
    """
    global CURRENT_SEASON_ID, REGULAR_SEASON_END_UTC, PLAYOFFS_START_UTC

    # 1) Try DB first
    try:
        row = (
            supabase.table("seasons")
            .select("id, code, regular_season_end_utc, playoffs_start_utc")
            .eq("code", CURRENT_SEASON_CODE)
            .limit(1)
            .execute()
        ).data
        season = row[0] if row else None

        if season:
            CURRENT_SEASON_ID = season["id"]
            REGULAR_SEASON_END_UTC = parse_iso8601_utc(season.get("regular_season_end_utc"))
            PLAYOFFS_START_UTC = parse_iso8601_utc(season.get("playoffs_start_utc"))
        else:
            try:
                safe_print(f"⚠️ CURRENT_SEASON '{CURRENT_SEASON_CODE}' not found in DB. Falling back to env dates.")
            except Exception:
                pass
    except Exception as e:
        try:
            safe_print("⚠️ Could not load season row (class):", type(e).__name__)
        except Exception:
            pass

    # 2) Env fallbacks/overrides
    if REGULAR_SEASON_END_UTC is None:
        REGULAR_SEASON_END_UTC = parse_iso8601_utc(os.getenv("REGULAR_SEASON_END_UTC"))

    if PLAYOFFS_START_UTC is None:
        PLAYOFFS_START_UTC = parse_iso8601_utc(os.getenv("PLAYOFFS_START_UTC"))

    # 3) Final safety default so brackets don't lock accidentally
    if PLAYOFFS_START_UTC is None:
        from datetime import datetime, timezone
        PLAYOFFS_START_UTC = datetime(2099, 1, 1, tzinfo=timezone.utc)


CURRENT_SEASON_CODE = os.getenv("CURRENT_SEASON_CODE")
if not CURRENT_SEASON_CODE:
    raise RuntimeError("CURRENT_SEASON (or CURRENT_SEASON_CODE) must be set")

# Call once at startup (after supabase is created)
_resolve_season_globals()

app = Flask(__name__)

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
    return bool(PLAYOFFS_START_UTC and now_utc() >= PLAYOFFS_START_UTC)


def bracket_creation_open() -> bool:
    """
    Creation is allowed only after regular season has ended AND before playoffs start.
    If either timestamp is missing, we 'fail open' for that side (same behavior as before).
    """
    now = now_utc()

    # Too early?
    if REGULAR_SEASON_END_UTC and now < REGULAR_SEASON_END_UTC:
        return False

    # Too late?
    if PLAYOFFS_START_UTC and now >= PLAYOFFS_START_UTC:
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

    if br[0].get("season_id") != CURRENT_SEASON_ID:
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


def _compute_score_for_bracket(master_matches_by_key: dict, master_bracket_id: str, bracket_id: str):
    """
    Compare one user bracket against the master bracket and upsert into bracket_scores.
    Ensures both brackets are in the CURRENT_SEASON_ID.

    Scoring rules unchanged (see original docstring).
    """
    # Sanity: both brackets must exist, be active, and belong to CURRENT_SEASON_ID
    brs = (
        supabase.table("brackets")
        .select("id, season_id, deleted_at")
        .in_("id", [master_bracket_id, bracket_id])
        .execute()
        .data
    )
    if not brs or len(brs) < 2:
        return None

    season_ok = True
    for b in brs:
        if b.get("deleted_at") is not None or b.get("season_id") != CURRENT_SEASON_ID:
            season_ok = False
            break
    if not season_ok:
        return None

    user_matches = _fetch_matches_for_bracket(bracket_id)
    if not user_matches:
        return None

    total_points = 0
    full_hits = 0
    partial_hits = 0
    misses = 0

    # bonuses (for later; leave as 0 for now)
    bonus_finalists = 0
    bonus_champion = 0

    points_by_round = {}   # e.g. { "0": 5, "1": 12, ... }
    points_by_match = {}   # e.g. { "east-1-4": { ... }, ... }

    for key, m_master in master_matches_by_key.items():
        m_user = user_matches.get(key)

        conf = (m_master.get("conference") or "").lower()
        rnd = m_master.get("round")
        slot = m_master.get("slot")
        match_key = f"{conf}-{rnd}-{slot}"

        actual_winner = m_master.get("predicted_winner")
        actual_games = m_master.get("predicted_winner_games")

        # If the master bracket doesn't have a final result yet, mark as pending
        if not actual_winner or actual_games is None:
            points_by_match[match_key] = {
                "points": 0,
                "status": "pending",
                "conference": conf,
                "round": rnd,
                "slot": slot,
            }
            continue

        # If the user bracket somehow doesn't have a match here, treat as miss
        if not m_user:
            misses += 1
            points_by_match[match_key] = {
                "points": 0,
                "status": "no_match",
                "conference": conf,
                "round": rnd,
                "slot": slot,
            }
            continue

        user_winner = m_user.get("predicted_winner")
        user_games = m_user.get("predicted_winner_games")

        # No pick at all
        if not user_winner:
            misses += 1
            points_by_match[match_key] = {
                "points": 0,
                "status": "no_pick",
                "conference": conf,
                "round": rnd,
                "slot": slot,
            }
            continue

        # Basic correctness flags
        winner_correct = user_winner == actual_winner
        series_len_correct = user_games == actual_games

        master_teams = {
            m_master.get("team_a"),
            m_master.get("team_b"),
        }
        user_teams = {
            m_user.get("team_a"),
            m_user.get("team_b"),
        }
        participants_correct = (
            None not in master_teams
            and None not in user_teams
            and master_teams == user_teams
        )

        # Special scoring rule for play-in (round 0)
        is_play_in = int(rnd) == 0 if rnd is not None else False

        if is_play_in:
            if winner_correct and participants_correct:
                pts = 1
                status = "full"
                full_hits += 1
            else:
                pts = 0
                status = "miss"
                misses += 1
        else:
            if winner_correct and series_len_correct and participants_correct:
                pts = 3
                status = "full"
                full_hits += 1
            elif winner_correct:
                pts = 1
                status = "partial"
                partial_hits += 1
            else:
                pts = 0
                status = "miss"
                misses += 1

        total_points += pts
        round_key = str(rnd)
        points_by_round[round_key] = points_by_round.get(round_key, 0) + pts

        points_by_match[match_key] = {
            "points": pts,
            "status": status,
            "conference": conf,
            "round": rnd,
            "slot": slot,
            "winner_correct": winner_correct,
            "series_len_correct": series_len_correct,
            "participants_correct": participants_correct,
        }

    record = {
        "season_id": CURRENT_SEASON_ID,   # 👈 ensure season tagged
        "bracket_id": bracket_id,
        "master_bracket_id": master_bracket_id,
        "total_points": total_points + bonus_finalists + bonus_champion,
        "full_hits": full_hits,
        "partial_hits": partial_hits,
        "misses": misses,
        "bonus_finalists": bonus_finalists,
        "bonus_champion": bonus_champion,
        "points_by_round": points_by_round,
        "points_by_match": points_by_match,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Upsert into bracket_scores (PK is bracket_id)
    supabase.table("bracket_scores").upsert(record).execute()
    return record


def with_current_season(q, col_name: str = "season_id"):
    """
    Apply current-season filter to a Supabase query builder.
    If CURRENT_SEASON_ID is None (legacy data), we filter for NULL season_id.
    """
    if CURRENT_SEASON_ID is None:
        return q.is_(col_name, None)
    else:
        return q.eq(col_name, CURRENT_SEASON_ID)


def ensure_season_globals():
    """
    Resolve season globals at request time if they weren't set at import time
    (e.g., Supabase not ready during boot).
    """
    global CURRENT_SEASON_ID
    if CURRENT_SEASON_ID is None:
        _resolve_season_globals()


@app.before_request
def _season_bootstrap():
    ensure_season_globals()


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


@app.route("/admin/insert_test_teams", methods=["POST"])
@require_auth
def admin_insert_test_teams():
    """
    Admin helper to (re)insert the 10 test teams for both conferences.
    Idempotent via upsert.

    NEW: Optional seasonized seeding for standings.
    - Request body can include: {"seed_standings": true}
    - If the 'standings' table has a 'season_id' column, rows are tied to CURRENT_SEASON_ID.
      If not, it falls back to inserting without season_id (or skips if constraints prevent it).
    - If team codes are missing (required by standings FK), standings seeding is skipped for those teams.
    """
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

    # --- Test teams (unchanged shape vs your prior helper) ---
    east = [
        {"id": "T1E",  "name": "TestEast1",  "conference": "east"},
        {"id": "T2E",  "name": "TestEast2",  "conference": "east"},
        {"id": "T3E",  "name": "TestEast3",  "conference": "east"},
        {"id": "T4E",  "name": "TestEast4",  "conference": "east"},
        {"id": "T5E",  "name": "TestEast5",  "conference": "east"},
        {"id": "T6E",  "name": "TestEast6",  "conference": "east"},
        {"id": "T7E",  "name": "TestEast7",  "conference": "east"},
        {"id": "T8E",  "name": "TestEast8",  "conference": "east"},
        {"id": "T9E",  "name": "TestEast9",  "conference": "east"},
        {"id": "T10E", "name": "TestEast10", "conference": "east"},
    ]
    west = [
        {"id": "LAL",  "name": "Los Angeles Lakers", "conference": "west"},
        {"id": "T2W",  "name": "TestWest2",         "conference": "west"},
        {"id": "T3W",  "name": "TestWest3",         "conference": "west"},
        {"id": "T4W",  "name": "TestWest4",         "conference": "west"},
        {"id": "T5W",  "name": "TestWest5",         "conference": "west"},
        {"id": "T6W",  "name": "TestWest6",         "conference": "west"},
        {"id": "T7W",  "name": "TestWest7",         "conference": "west"},
        {"id": "T8W",  "name": "TestWest8",         "conference": "west"},
        {"id": "T9W",  "name": "TestWest9",         "conference": "west"},
        {"id": "T10W", "name": "TestWest10",        "conference": "west"},
    ]
    teams_to_upsert = east + west

    # Upsert test teams exactly like before (no changes to other fields)
    for t in teams_to_upsert:
        supabase.table("teams").upsert(t).execute()

    seeded_standings = 0
    standings_mode = "skipped"

    if seed_standings:
        # We will try to seed standings for CURRENT season if schema allows.
        try:
            # 1) Detect whether standings has season_id (by attempting a filtered select).
            has_season_id = True
            try:
                _ = (
                    supabase.table("standings")
                    .select("id")
                    .eq("season_id", CURRENT_SEASON_ID)
                    .limit(1)
                    .execute()
                )
            except Exception:
                has_season_id = False

            # 2) Fetch codes for inserted teams (needed for standings FK on code).
            #    If codes are missing in your test rows, we’ll try to re-use the 'id' as 'code' if possible.
            #    First, get any existing codes:
            ids = [t["id"] for t in teams_to_upsert]
            team_rows = (
                supabase.table("teams")
                .select("id, name, conference, code")
                .in_("id", ids)
                .execute()
            ).data or []

            rows_with_codes = []
            missing_code_ids = []

            for tr in team_rows:
                code = tr.get("code")
                if code and isinstance(code, str) and code.strip():
                    rows_with_codes.append(tr)
                else:
                    missing_code_ids.append(tr.get("id"))

            # Optional: Try to set code = id for those missing (best-effort, safe to skip if schema disallows)
            if missing_code_ids:
                try:
                    # Build patch objects where code := id (simple/safe fallback)
                    patches = [{"id": tid, "code": tid} for tid in missing_code_ids if tid]
                    if patches:
                        supabase.table("teams").upsert(patches).execute()
                        # Refresh rows to pick up code
                        team_rows = (
                            supabase.table("teams")
                            .select("id, name, conference, code")
                            .in_("id", ids)
                            .execute()
                        ).data or []
                        rows_with_codes = [tr for tr in team_rows if tr.get("code")]
                except Exception:
                    # If this fails (e.g., unique constraint), we just proceed with those that have codes
                    pass

            # 3) Build standings rows for available rows_with_codes
            #    Seeds 1..10 for each conference in listing order of our test arrays.
            #    If has_season_id, include season_id; else omit.
            code_by_id = {r["id"]: r.get("code") for r in team_rows if r.get("code")}
            east_order = [t["id"] for t in east]
            west_order = [t["id"] for t in west]

            standings_rows = []

            def add_conf(conf_name: str, ordered_ids: list[str]):
                for idx, tid in enumerate(ordered_ids, start=1):
                    code = code_by_id.get(tid)
                    if not code:
                        continue  # skip if we still don't have code
                    row = {
                        "name": next((t["name"] for t in teams_to_upsert if t["id"] == tid), tid),
                        "code": code,
                        "conference": conf_name,
                        "wins": 0,
                        "losses": 0,
                        "seed": idx,
                        "updated_at": datetime.utcnow().isoformat(),
                    }
                    if has_season_id:
                        row["season_id"] = CURRENT_SEASON_ID
                    standings_rows.append(row)

            add_conf("east", east_order)
            add_conf("west", west_order)

            if standings_rows:
                # Upsert standings (by (code, season_id) or (code) uniqueness depending on schema)
                # If your table lacks a proper composite unique constraint, this may insert duplicates on repeated calls.
                supabase.table("standings").upsert(standings_rows).execute()
                seeded_standings = len(standings_rows)
                standings_mode = "season_id" if has_season_id else "no_season_id"
            else:
                standings_mode = "no_codes"

        except Exception as e:
            safe_print("⚠️ standings seeding skipped (class):", type(e).__name__)
            standings_mode = "error"

    return jsonify({
        "message": "Test teams inserted/updated",
        "seed_standings_requested": seed_standings,
        "standings_seeded_rows": seeded_standings,
        "standings_mode": standings_mode,
        "season_id": CURRENT_SEASON_ID,
    }), 200


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


@app.route("/admin/score/master/<master_bracket_id>/recompute", methods=["POST"])
@require_auth
def recompute_scores(master_bracket_id):
    """
    Admin-only: recompute bracket_scores for ALL saved brackets
    in the CURRENT season against the given master_bracket_id.
    """
    # --- Admin check (JWT flag) ---
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    if not is_uuid(master_bracket_id):
        return jsonify({"error": "Invalid master bracket id"}), 400

    if not CURRENT_SEASON_ID:
        return jsonify({"error": "CURRENT_SEASON not resolved on server"}), 500

    # Ensure the master bracket exists, is active, and is in the CURRENT season
    br_res = (
        supabase.table("brackets")
        .select("id, deleted_at, season_id")
        .eq("id", master_bracket_id)
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not br_res:
        return jsonify({"error": "Master bracket not found"}), 404
    if br_res[0].get("season_id") != CURRENT_SEASON_ID:
        return jsonify({"error": "Master bracket is not in the current season"}), 400

    # Load master matches once (will validate season internally)
    master_matches = _fetch_matches_for_bracket(master_bracket_id)
    if not master_matches:
        return jsonify({"error": "Master bracket has no matches"}), 400

    # Get all saved brackets in CURRENT season (exclude deleted)
    brackets_res = (
        supabase.table("brackets")
        .select("id, is_done, deleted_at, season_id")
        .is_("deleted_at", None)
        .eq("is_done", True)
        .eq("season_id", CURRENT_SEASON_ID)   # 👈 season scope
        .execute()
        .data
    )

    updated_count = 0
    for b in brackets_res:
        bid = b["id"]
        rec = _compute_score_for_bracket(master_matches, master_bracket_id, bid)
        if rec:
            updated_count += 1

    return jsonify({
        "message": "Scores recomputed",
        "master_bracket_id": master_bracket_id,
        "season_id": CURRENT_SEASON_ID,
        "updated_brackets": updated_count,
    }), 200


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
                "username": user["username"]
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
            "is_admin": user.get("is_admin", False)
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
    reset_link = f"https://nbacorner.onrender.com/reset-password?token={token}"
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


def send_email_via_brevo(to_email, subject, body):
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
            "email": os.getenv("BREVO_SENDER_EMAIL", "nbacorner91@gmail.com")
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


# --------------------------------------------------------
# ------------------ Bracket endpoints  ------------------
# --------------------------------------------------------


@app.route("/bracket/create", methods=["POST"])
@require_auth
def create_bracket_for_user():
    user_info = request.user or {}
    user_id = user_info["user_id"]
    is_admin = user_info.get("is_admin", False)

    # ⛔ Window check (admins bypass playoffs, but still blocked before regular season ends)
    if not is_admin:
        # Too early (regular season not finished)
        if REGULAR_SEASON_END_UTC and now_utc() < REGULAR_SEASON_END_UTC:
            return jsonify({"error": "Bracket creation opens after the regular season ends."}), 403
        # Too late (playoffs started)
        if playoffs_locked():
            return jsonify({"error": "Bracket creation is closed once the playoffs start."}), 403

    # ✅ Check if the user already has a bracket for the CURRENT season
    existing = (
        supabase.table("brackets")
        .select("id, deleted_at, season_id")
        .eq("user_id", user_id)
        .eq("season_id", CURRENT_SEASON_ID)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if existing:
        return jsonify({"error": "User already has a bracket for this season"}), 400

    # ✅ Create bracket bound to CURRENT season
    try:
        bracket = (
            supabase.table("brackets")
            .insert({"user_id": user_id, "season_id": CURRENT_SEASON_ID})
            .execute()
            .data[0]
        )
    except Exception as e:
        if hasattr(e, "args") and e.args and "duplicate key value" in str(e.args[0]):
            return jsonify({"error": "User already has a bracket for this season"}), 400
        return jsonify({"error": "Unexpected error creating bracket", "details": str(e)}), 500

    # Fetch teams (global table; season-agnostic)
    teams = supabase.table("teams").select("id, name, conference").execute().data
    east_teams = [t for t in teams if (t["conference"] or "").lower() == "east"]
    west_teams = [t for t in teams if (t["conference"] or "").lower() == "west"]

    if len(east_teams) < 10 or len(west_teams) < 10:
        return jsonify({"error": "Not enough teams in database"}), 400

    def create_conference_matches(conference, teams_):
        matches = []
        # ---- PLAY-IN ROUND ----
        m1 = {"round": 0, "slot": 1, "conference": conference, "team_a": teams_[8]["id"], "team_b": teams_[9]["id"]}
        m2 = {"round": 0, "slot": 2, "conference": conference, "team_a": teams_[6]["id"], "team_b": teams_[7]["id"]}
        m3 = {"round": 0, "slot": 3, "conference": conference}
        matches.extend([m1, m2, m3])

        # ---- ROUND 1 ----
        r1 = [
            {"round": 1, "slot": 4, "conference": conference, "team_a": teams_[0]["id"]},
            {"round": 1, "slot": 5, "conference": conference, "team_a": teams_[1]["id"]},
            {"round": 1, "slot": 6, "conference": conference, "team_a": teams_[2]["id"], "team_b": teams_[5]["id"]},
            {"round": 1, "slot": 7, "conference": conference, "team_a": teams_[3]["id"], "team_b": teams_[4]["id"]},
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

    for m in all_matches:
        m["bracket_id"] = bracket["id"]

    # 2️⃣ Insert matches
    supabase.table("matches").insert(all_matches).execute()

    # 3️⃣ Retrieve IDs for linking
    inserted = (
        supabase.table("matches")
        .select("id, round, slot, conference")
        .eq("bracket_id", bracket["id"])
        .execute()
        .data
    )

    # 4️⃣ Link matches (unchanged)
    def link(conference, from_slot, to_slot, next_slot):
        src = next((m for m in inserted if m["conference"] == conference and m["slot"] == from_slot), None)
        dest = next((m for m in inserted if m["conference"] == conference and m["slot"] == to_slot), None)
        if src and dest:
            supabase.table("matches").update({"next_match_id": dest["id"], "next_slot": next_slot}).eq("id", src["id"]).execute()

    # 🏀 PLAY-IN ROUND
    link("east", 1, 3, "a"); link("west", 1, 3, "a")
    link("east", 2, 3, "b"); link("west", 2, 3, "b")
    link("east", 2, 5, "b"); link("west", 2, 5, "b")
    link("east", 3, 4, "b"); link("west", 3, 4, "b")

    # ---- Round 1 → Semifinals ----
    link("east", 4, 9, "a"); link("east", 7, 9, "b")
    link("east", 5, 8, "b"); link("east", 6, 8, "a")
    link("west", 4, 9, "a"); link("west", 7, 9, "b")
    link("west", 5, 8, "b"); link("west", 6, 8, "a")

    # ---- Semifinals → Conference Finals ----
    link("east", 8, 10, "b"); link("east", 9, 10, "a")
    link("west", 8, 10, "b"); link("west", 9, 10, "a")

    # ----- Conference Finals → NBA Finals -----
    nba_final = next((m for m in inserted if m["conference"] == "nba" and m["slot"] == 11), None)
    if nba_final:
        east_final = next((m for m in inserted if m["conference"] == "east" and m["slot"] == 10), None)
        west_final = next((m for m in inserted if m["conference"] == "west" and m["slot"] == 10), None)
        if east_final:
            supabase.table("matches").update({"next_match_id": nba_final["id"], "next_slot": "a"}).eq("id", east_final["id"]).execute()
        if west_final:
            supabase.table("matches").update({"next_match_id": nba_final["id"], "next_slot": "b"}).eq("id", west_final["id"]).execute()

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
            .select("id, user_id, deleted_at, season_id")
            .eq("id", bracket_id)
            .is_("deleted_at", None)
            .limit(1)
            .execute()
            .data
        )
        if not bracket_res:
            return jsonify({"error": "Bracket not found"}), 404

        bracket = bracket_res[0]
        if bracket.get("season_id") != CURRENT_SEASON_ID:
            return jsonify({"error": "Bracket is not in the current season"}), 400

        # Ownership or admin
        user_res = (
            supabase.table("users")
            .select("id, is_admin")
            .eq("id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if not user_res:
            return jsonify({"error": "User not found"}), 404

        is_admin = user_res[0].get("is_admin", False)

        if bracket["user_id"] != user_id and not is_admin:
            return jsonify({"error": "Unauthorized"}), 403

        # Once playoffs are locked, only admins can save
        if playoffs_locked() and not is_admin:
            return jsonify({"error": "Bracket saving is closed once the playoffs start."}), 403

        # Validate fully predicted
        matches = (
            supabase.table("matches")
            .select("id, round, team_a, team_b, predicted_winner, predicted_winner_games")
            .eq("bracket_id", bracket_id)
            .execute()
            .data
        )

        for m in matches:
            if not m.get("team_a") or not m.get("team_b"):
                continue
            if not m.get("predicted_winner"):
                return jsonify({"error": "Bracket is not fully predicted"}), 400
            if m["round"] > 0 and m.get("predicted_winner_games") is None:
                return jsonify({"error": "Bracket is not fully predicted"}), 400

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
                .select("id, user_id, name, is_done, created_at, saved_at, deleted_at")
                .eq("user_id", user_id)
                .is_("deleted_at", None)
            )
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []

        locked = playoffs_locked()
        creation_open = bracket_creation_open()

        if not rows:
            return jsonify({
                "bracket": None,
                "playoffs_locked": locked,
                "bracket_creation_open": creation_open,
                "regular_season_end_utc": REGULAR_SEASON_END_UTC.isoformat() if REGULAR_SEASON_END_UTC else None,
                "playoffs_deadline_utc": PLAYOFFS_START_UTC.isoformat() if PLAYOFFS_START_UTC else None,
            }), 200

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

        return jsonify({
            "bracket": {
                "bracket_id": b["id"],
                "name": b.get("name"),
                "created_at": b.get("created_at"),
                "saved_at": b.get("saved_at"),
                "is_done": b.get("is_done"),
                "user": {"id": b["user_id"], "username": u.get("username")},
            },
            "playoffs_locked": locked,
            "bracket_creation_open": creation_open,
            "regular_season_end_utc": REGULAR_SEASON_END_UTC.isoformat() if REGULAR_SEASON_END_UTC else None,
            "playoffs_deadline_utc": PLAYOFFS_START_UTC.isoformat() if PLAYOFFS_START_UTC else None,
        }), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /brackets/me (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/bracket/<bracket_id>", methods=["GET"])
@require_auth
def get_bracket_by_id(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    viewer = getattr(request, "user", None) or {}
    viewer_id = viewer.get("user_id")

    viewer_res = (
        supabase.table("users")
        .select("id, is_admin")
        .eq("id", viewer_id)
        .limit(1)
        .execute()
    )
    viewer_rows = viewer_res.data or []
    is_admin = bool(viewer_rows and str(viewer_rows[0].get("is_admin")).lower() in ("true", "t", "1", "yes"))

    br_res = (
        supabase.table("brackets")
        .select("id, user_id, is_done, deleted_at, name, created_at, saved_at, season_id, is_master")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .limit(1)
        .execute()
    )
    br_rows = br_res.data or []
    if not br_rows:
        return jsonify({"error": "Bracket not found"}), 404

    bracket = br_rows[0]

    # Season consistency
    if bracket.get("season_id") != CURRENT_SEASON_ID:
        return jsonify({"error": "Bracket is not in the current season"}), 404

    # 🔎 Derive true master flag from season.master_bracket_id OR brackets.is_master
    season_row = None
    if bracket.get("season_id"):
        season_res = (
            supabase.table("seasons")
            .select("id, master_bracket_id")
            .eq("id", bracket["season_id"])
            .limit(1)
            .execute()
        )
        srows = season_res.data or []
        season_row = srows[0] if srows else None

    derived_is_master = bool(bracket.get("is_master")) or (
        season_row is not None
        and str(season_row.get("master_bracket_id")) == str(bracket["id"])
    )

    owner_id = bracket.get("user_id")
    is_owner = str(viewer_id) == str(owner_id)

    if not (is_owner or is_admin) and not bracket.get("is_done", False):
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
        if m.get("team_a"): team_ids.add(m["team_a"])
        if m.get("team_b"): team_ids.add(m["team_b"])

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
            enriched.update({
                "team_a_name": ta.get("name"),
                "team_a_code": ta.get("code"),
                "team_a_logo_url": ta.get("logo_url"),
                "team_a_primary_color": ta.get("primary_color"),
                "team_a_secondary_color": ta.get("secondary_color"),
            })
        if tb:
            enriched.update({
                "team_b_name": tb.get("name"),
                "team_b_code": tb.get("code"),
                "team_b_logo_url": tb.get("logo_url"),
                "team_b_primary_color": tb.get("primary_color"),
                "team_b_secondary_color": tb.get("secondary_color"),
            })
        grouped[conf][rnd].append(enriched)

    owner_res = (
        supabase.table("users")
        .select("id, username, email")
        .eq("id", owner_id)
        .limit(1)
        .execute()
    )
    owner_rows = owner_res.data or []
    owner = owner_rows[0] if owner_rows else {}

    # 👇 Inject both snake_case and camelCase for the frontend
    return jsonify({
        "bracket": {
            **bracket,
            "owner": {"id": owner.get("id"), "username": owner.get("username"), "email": owner.get("email")},
            "is_owner": is_owner,
            "is_master": bool(derived_is_master),
            "isMaster": bool(derived_is_master),
        },
        "matches": grouped,
    }), 200


@app.route("/brackets", methods=["GET"])
def list_all_brackets():
    """
    Returns saved brackets (is_done = true) for the CURRENT season,
    excluding deleted and excluding master.
    """
    try:
        brackets_res = (
            with_current_season(
                supabase.table("brackets")
                .select("id, user_id, name, saved_at, created_at, deleted_at, is_done, is_master, season_id")
                .eq("is_done", True)
                .eq("is_master", False)
                .is_("deleted_at", None)
            )
            .order("saved_at", desc=True)
            .execute()
        )
        brackets = brackets_res.data

        if not brackets:
            return jsonify([]), 200

        user_ids = list({b["user_id"] for b in brackets if b.get("user_id")})

        users_res = (
            supabase.table("users")
            .select("id, username, email")
            .in_("id", user_ids)
            .execute()
        )
        users = {u["id"]: u for u in users_res.data}

        locked = playoffs_locked()
        creation_open = bracket_creation_open()

        output = []
        for b in brackets:
            user_info = users.get(b["user_id"], {})
            output.append({
                "bracket_id": b["id"],
                "name": b.get("name"),
                "saved_at": b.get("saved_at"),
                "created_at": b.get("created_at"),
                "is_done": b.get("is_done", False),
                "user": {"id": b["user_id"], "username": user_info.get("username"), "email": user_info.get("email")},
                "playoffs_locked": locked,
                "bracket_creation_open": creation_open,
                "regular_season_end_utc": REGULAR_SEASON_END_UTC.isoformat() if REGULAR_SEASON_END_UTC else None,
                "playoffs_deadline_utc": PLAYOFFS_START_UTC.isoformat() if PLAYOFFS_START_UTC else None,
            })

        return jsonify(output), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /brackets (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/bracket/<bracket_id>", methods=["DELETE"])
@require_auth
def delete_bracket(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    user_id = request.user["user_id"]

    user_res = (
        supabase.table("users")
        .select("id, is_admin")
        .eq("id", user_id)
        .execute()
        .data
    )
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    bracket_res = (
        supabase.table("brackets")
        .select("id, user_id, deleted_at, season_id")
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
    if bracket.get("season_id") != CURRENT_SEASON_ID:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    if bracket["user_id"] != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: Only the owner or an admin can delete this bracket"}), 403

    update_fields = {
        "deleted_at": datetime.utcnow().isoformat(),
        "deleted_by_user_id": user_id,
    }
    supabase.table("brackets").update(update_fields).eq("id", bracket_id).execute()

    # Clean up scores referencing this bracket
    try:
        supabase.table("bracket_scores").delete().eq("bracket_id", bracket_id).execute()
        supabase.table("bracket_scores").delete().eq("master_bracket_id", bracket_id).execute()
    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error cleaning bracket_scores on delete (class):", type(e).__name__)

    return jsonify({"message": "Bracket deleted successfully"})


@app.route("/bracket/<bracket_id>/match/<match_id>", methods=["PATCH"])
@require_auth
def update_match(bracket_id, match_id):
    if not is_uuid(bracket_id) or not is_uuid(match_id):
        return jsonify({"error": "Invalid id"}), 400
    user_id = request.user["user_id"]

    data = request.get_json() or {}
    action = data.get("action")

    res = supabase.table("matches").select(
        "id, bracket_id, conference, round, slot, team_a, team_b, "
        "predicted_winner, predicted_winner_games, next_match_id, next_slot"
    ).eq("id", match_id).limit(1).execute().data
    if not res:
        return jsonify({"error": "Match not found"}), 404
    match = res[0]

    if str(match["bracket_id"]) != str(bracket_id):
        return jsonify({"error": "Match does not belong to the specified bracket"}), 400

    # Ownership/admin and SEASON guard
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).limit(1).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    bracket_check = (
        supabase.table("brackets")
        .select("user_id, season_id")
        .eq("id", match["bracket_id"])
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not bracket_check:
        return jsonify({"error": "Bracket not found"}), 404

    if bracket_check[0].get("season_id") != CURRENT_SEASON_ID:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    bracket_owner_id = bracket_check[0]["user_id"]
    if bracket_owner_id != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: You are not allowed to modify this bracket"}), 403

    # --- helper functions (unchanged) ---
    def clear_dest(dest_id):
        if not dest_id: return
        supabase.table("matches").update({
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", dest_id).execute()

    def set_in_dest(dest_id, slot_letter, team_id):
        if not dest_id or not slot_letter: return
        supabase.table("matches").update({
            f"team_{slot_letter}": team_id,
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", dest_id).execute()

    def clear_in_dest_slot(dest_id, slot_letter, team_id=None):
        if not dest_id or not slot_letter: return
        dest = supabase.table("matches").select("id, team_a, team_b").eq("id", dest_id).execute().data
        if not dest: return
        dest = dest[0]
        field = f"team_{slot_letter}"
        current_val = dest.get(field)
        if team_id is None or current_val == team_id:
            supabase.table("matches").update({
                field: None,
                "predicted_winner": None,
                "predicted_winner_games": None,
                "updated_at": datetime.utcnow().isoformat()
            }).eq("id", dest_id).execute()

    def get_match(conference, round_num, slot_num):
        rows = (supabase.table("matches")
                .select("id, team_a, team_b, predicted_winner, predicted_winner_games")
                .eq("bracket_id", match["bracket_id"])
                .eq("conference", conference)
                .eq("round", round_num)
                .eq("slot", slot_num)
                .execute().data)
        return rows[0] if rows else None

    def cleanup_future_matches(losing_team_id):
        if not match.get("next_match_id"): return
        to_check = [match["next_match_id"]]
        visited = set()
        while to_check:
            current_id = to_check.pop()
            if current_id in visited: continue
            visited.add(current_id)
            res = supabase.table("matches").select("id, team_a, team_b, next_match_id").eq("id", current_id).execute().data
            if not res: continue
            next_match = res[0]
            updated_fields = {}
            if next_match["team_a"] == losing_team_id: updated_fields["team_a"] = None
            if next_match["team_b"] == losing_team_id: updated_fields["team_b"] = None
            if updated_fields:
                updated_fields["predicted_winner"] = None
                updated_fields["predicted_winner_games"] = None
                updated_fields["updated_at"] = datetime.utcnow().isoformat()
                supabase.table("matches").update(updated_fields).eq("id", next_match["id"]).execute()
            if next_match.get("next_match_id"):
                to_check.append(next_match["next_match_id"])

    # ------------------ ACTIONS ------------------
    if action == "set_winner":
        team = data.get("team")
        games = data.get("games")
        if not team:
            return jsonify({"error": "Missing team"}), 400

        # ✅ NEW: force best-of-one for play-in round
        if match["round"] == 0:
            games = 1

        if team not in (match["team_a"], match["team_b"]):
            return jsonify({"error": "Winner must be team_a or team_b for this match"}), 400

        old_winner = match.get("predicted_winner")
        old_games = match.get("predicted_winner_games")
        loser = match["team_b"] if match["team_a"] == team else match["team_a"]

        if old_winner and old_winner != team:
            if match.get("next_match_id") and match.get("next_slot"):
                clear_in_dest_slot(match["next_match_id"], match["next_slot"], old_winner)
                clear_dest(match["next_match_id"])
            cleanup_future_matches(old_winner)
            if match["round"] == 0 and match["slot"] == 2:
                m3 = get_match(match["conference"], 0, 3)
                if m3:
                    supabase.table("matches").update({
                        "team_b": None,
                        "predicted_winner": None,
                        "predicted_winner_games": None,
                        "updated_at": datetime.utcnow().isoformat()
                    }).eq("id", m3["id"]).execute()

        if old_winner == team:
            if games != old_games:
                supabase.table("matches").update({
                    "predicted_winner_games": games,
                    "updated_at": datetime.utcnow().isoformat()
                }).eq("id", match_id).execute()
            if match["round"] == 0 and match["slot"] == 2:
                m3 = get_match(match["conference"], 0, 3)
                if m3 and m3.get("team_b") != loser:
                    set_in_dest(m3["id"], "b", loser)
            # ✅ Mark bracket as not saved
            supabase.table("brackets").update({
                "is_done": False,
                "saved_at": None
            }).eq("id", match["bracket_id"]).execute()
            return jsonify({"message": "Winner updated"}), 200

        supabase.table("matches").update({
            "predicted_winner": team,
            "predicted_winner_games": games,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", match_id).execute()

        if match.get("next_match_id") and match.get("next_slot"):
            set_in_dest(match["next_match_id"], match["next_slot"], team)

        if match["round"] == 0 and match["slot"] == 2:
            m3 = get_match(match["conference"], 0, 3)
            if m3:
                set_in_dest(m3["id"], "b", loser)

        # ✅ Mark bracket as not saved
        supabase.table("brackets").update({
            "is_done": False,
            "saved_at": None
        }).eq("id", match["bracket_id"]).execute()

        return jsonify({"message": "Winner set"}), 200

    elif action == "undo":
        old_winner = match.get("predicted_winner")
        supabase.table("matches").update({
            "predicted_winner": None,
            "predicted_winner_games": None,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", match_id).execute()

        if old_winner and match.get("next_match_id") and match.get("next_slot"):
            clear_in_dest_slot(match["next_match_id"], match["next_slot"], old_winner)
            clear_dest(match["next_match_id"])
            cleanup_future_matches(old_winner)

        if match["round"] == 0 and match["slot"] == 2:
            m3 = get_match(match["conference"], 0, 3)
            if m3:
                supabase.table("matches").update({
                    "team_b": None,
                    "predicted_winner": None,
                    "predicted_winner_games": None,
                    "updated_at": datetime.utcnow().isoformat()
                }).eq("id", m3["id"]).execute()

        # ✅ Mark bracket as not saved
        supabase.table("brackets").update({
            "is_done": False,
            "saved_at": None
        }).eq("id", match["bracket_id"]).execute()

        return jsonify({"message": "Prediction undone"}), 200

    else:
        return jsonify({"error": "Invalid or unsupported action"}), 400


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
        return jsonify({"error":"match not found"}), 404
    match = m_resp.data[0]

    br = (
        supabase.table("brackets")
        .select("id, user_id, season_id")
        .eq("id", match["bracket_id"])
        .is_("deleted_at", None)
        .limit(1)
        .execute()
        .data
    )
    if not br or br[0]["user_id"] != user_id:
        return jsonify({"error":"forbidden"}), 403

    # 🔒 Season guard
    if br[0].get("season_id") != CURRENT_SEASON_ID:
        return jsonify({"error": "Bracket is not in the current season"}), 403

    supabase.table("matches").update({
        "predicted_winner_games": games,
        "updated_at": datetime.utcnow().isoformat()
    }).eq("id", match_id).execute()
    return jsonify({"ok": True}), 200


@app.route("/leaderboard", methods=["GET"])
def leaderboard():
    """
    Returns leaderboard rows for the CURRENT season plus a full master_matchups map.
    Each matchup includes team codes; if a side isn't known yet we return "TBD".
    """
    try:
        # -------- 1) Scores for current season --------
        scores_q = (
            supabase.table("bracket_scores")
            .select(
                "season_id, bracket_id, master_bracket_id, total_points, full_hits, "
                "partial_hits, misses, bonus_finalists, bonus_champion, "
                "points_by_match, updated_at"
            )
        )
        if CURRENT_SEASON_ID is None:
            scores_q = scores_q.is_("season_id", None)
        else:
            scores_q = scores_q.eq("season_id", CURRENT_SEASON_ID)

        scores = (scores_q.execute().data) or []
        if not scores:
            return jsonify({
                "rows": [],
                "master_bracket_id": None,
                "master_updated_at": None,
                "master_matchups": {},
            }), 200

        # -------- 2) Determine master_bracket_id robustly --------
        freq = {}
        for s in scores:
            mid = s.get("master_bracket_id")
            if mid:
                freq[mid] = freq.get(mid, 0) + 1
        master_bracket_id = max(freq, key=freq.get) if freq else None

        # -------- 3) Brackets & owners (current season, not deleted) --------
        bracket_ids = list({s["bracket_id"] for s in scores if s.get("bracket_id")})
        if not bracket_ids:
            return jsonify({
                "rows": [],
                "master_bracket_id": master_bracket_id,
                "master_updated_at": None,
                "master_matchups": {},
            }), 200

        br_q = (
            supabase.table("brackets")
            .select("id, user_id, name, deleted_at, season_id")
            .in_("id", bracket_ids)
            .is_("deleted_at", None)
        )
        if CURRENT_SEASON_ID is None:
            br_q = br_q.is_("season_id", None)
        else:
            br_q = br_q.eq("season_id", CURRENT_SEASON_ID)

        br_rows = (br_q.execute().data) or []
        br_by_id = {b["id"]: b for b in br_rows}

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
            u = users_by_id.get(b["user_id"], {})
            rows_out.append({
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
                "points_by_match": s.get("points_by_match") or {},
            })

        # -------- 5) Build a canonical master_matchups map --------
        master_matchups = {}
        master_updated_at = None

        if master_bracket_id:
            # (a) Canonical key set the UI expects
            ALL_KEYS = [
                "east-0-1","west-0-1","east-0-2","west-0-2","east-0-3","west-0-3",
                "east-1-4","east-1-5","east-1-6","east-1-7",
                "west-1-4","west-1-5","west-1-6","west-1-7",
                "east-2-8","east-2-9","west-2-8","west-2-9",
                "east-3-10","west-3-10",
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
                if m.get("team_a"): team_ids.add(m["team_a"])
                if m.get("team_b"): team_ids.add(m["team_b"])

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
                if s.get("master_bracket_id") == master_bracket_id and s.get("updated_at")
            ]
            if master_updates:
                master_updated_at = max(master_updates)

        return jsonify({
            "rows": rows_out,
            "master_bracket_id": master_bracket_id,
            "master_updated_at": master_updated_at,
            "master_matchups": master_matchups,
        }), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /leaderboard (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


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
# --------------------- M  A  I  N  ----------------------
# --------------------------------------------------------

if __name__ == "__main__":
    # Use FLASK_DEBUG=1 in your local env if you want debug mode
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
