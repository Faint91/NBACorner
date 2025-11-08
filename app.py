# app.py
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from supabase import create_client
from dotenv import load_dotenv
from collections import defaultdict
from .auth import require_auth
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
# ---------------- In-memory rate limiting  --------------
# --------------------------------------------------------

RATE_LIMITS = {
    # bucket_name: (max_attempts, window_seconds)
    "login_ip": (10, 60),              # 10 login attempts per IP per 60s
    "login_identifier": (5, 60),       # 5 login attempts per email/username per 60s

    "forgot_ip": (5, 300),             # 5 forgot-password requests per IP per 5min
    "forgot_identifier": (3, 300),     # 3 forgot-password per email/username per 5min

    "register_ip": (3, 3600),          # 3 registrations per IP per hour (example)
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
        
        
def get_current_user_id():
    """
    Development helper: read X-User-Id header to identify the user.
    When testing with Postman: after /login grab the returned user.id
    and set header X-User-Id: <user-id> in subsequent calls.
    """
    uid = request.headers.get("X-User-Id")
    if not uid:
        # also support Authorization: Bearer <user-id> for convenience
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            uid = auth.split()[1]
    return uid


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
    Admin helper to re-insert the 10 test teams for both conferences.
    (This is idempotent: uses upsert behavior.)
    """
    user_info = request.user or {}
    user_id = user_info.get("user_id")
    is_admin_token = user_info.get("is_admin", False)

    # First line of defense: token says not admin
    if not is_admin_token:
        return jsonify({"error": "Forbidden"}), 403

    # these match the SQL test teams inserted earlier; safe to re-run
    east = [
        {"id":"T1E","name":"TestEast1","conference":"east"},
        {"id":"T2E","name":"TestEast2","conference":"east"},
        {"id":"T3E","name":"TestEast3","conference":"east"},
        {"id":"T4E","name":"TestEast4","conference":"east"},
        {"id":"T5E","name":"TestEast5","conference":"east"},
        {"id":"T6E","name":"TestEast6","conference":"east"},
        {"id":"T7E","name":"TestEast7","conference":"east"},
        {"id":"T8E","name":"TestEast8","conference":"east"},
        {"id":"T9E","name":"TestEast9","conference":"east"},
        {"id":"T10E","name":"TestEast10","conference":"east"}
    ]
    west = [
        {"id":"T1W","name":"TestWest1","conference":"west"},
        {"id":"T2W","name":"TestWest2","conference":"west"},
        {"id":"T3W","name":"TestWest3","conference":"west"},
        {"id":"T4W","name":"TestWest4","conference":"west"},
        {"id":"T5W","name":"TestWest5","conference":"west"},
        {"id":"T6W","name":"TestWest6","conference":"west"},
        {"id":"T7W","name":"TestWest7","conference":"west"},
        {"id":"T8W","name":"TestWest8","conference":"west"},
        {"id":"T9W","name":"TestWest9","conference":"west"},
        {"id":"T10W","name":"TestWest10","conference":"west"}
    ]
    # Upsert: supabase-py doesn't have upsert convenience; we'll try insert and ignore conflicts
    for t in east + west:
        supabase.table("teams").upsert(t).execute()

    return jsonify({"message":"test teams inserted/updated"}), 200


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
        # Status code alone is safe
        safe_print(f"📬 Brevo response: {response.status_code}")
        return response.status_code in (200, 201)
    except Exception as e:
        # Do NOT log full exception; it may include request body with reset links
        if ENABLE_DEBUG_LOGS:
            safe_print("🚨 Error sending email via Brevo (class):", type(e).__name__)
        return False


# --------------------------------------------------------
# ------------------ Bracket endpoints  ------------------
# --------------------------------------------------------

@app.route("/bracket/create", methods=["POST"])
@require_auth
def create_bracket_for_user():
    user_id = request.user["user_id"]

    # ✅ Check if the user already has a bracket before inserting
    existing = (
        supabase.table("brackets")
        .select("id")
        .eq("user_id", user_id)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if existing:
        return jsonify({"error": "User already has a bracket"}), 400

    # ✅ Handle duplicate bracket creation gracefully (redundant safety)
    try:
        bracket = supabase.table("brackets").insert({"user_id": user_id}).execute().data[0]
    except Exception as e:
        if hasattr(e, "args") and e.args and "duplicate key value" in str(e.args[0]):
            return jsonify({"error": "User already has a bracket"}), 400
        return jsonify({"error": "Unexpected error creating bracket", "details": str(e)}), 500

    # Fetch teams
    teams = supabase.table("teams").select("id, name, conference").execute().data
    east_teams = [t for t in teams if t["conference"].lower() == "east"]
    west_teams = [t for t in teams if t["conference"].lower() == "west"]

    if len(east_teams) < 10 or len(west_teams) < 10:
        return jsonify({"error": "Not enough teams in database"}), 400

    def create_conference_matches(conference, teams):
        matches = []

        # ---- PLAY-IN ROUND ----
        m1 = {"round": 0, "slot": 1, "conference": conference, "team_a": teams[8]["id"], "team_b": teams[9]["id"]}
        m2 = {"round": 0, "slot": 2, "conference": conference, "team_a": teams[6]["id"], "team_b": teams[7]["id"]}
        m3 = {"round": 0, "slot": 3, "conference": conference}
        matches.extend([m1, m2, m3])

        # ---- ROUND 1 ----
        r1 = [
            {"round": 1, "slot": 4, "conference": conference, "team_a": teams[0]["id"]},
            {"round": 1, "slot": 5, "conference": conference, "team_a": teams[1]["id"]},
            {"round": 1, "slot": 6, "conference": conference, "team_a": teams[2]["id"], "team_b": teams[5]["id"]},
            {"round": 1, "slot": 7, "conference": conference, "team_a": teams[3]["id"], "team_b": teams[4]["id"]},
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
    all_matches.append({
        "round": 4, "slot": 11, "conference": "nba"
    })  # NBA Finals

    for m in all_matches:
        m["bracket_id"] = bracket["id"]

    # 2️⃣ Insert matches
    supabase.table("matches").insert(all_matches).execute()

    # 3️⃣ Retrieve IDs for linking
    inserted = supabase.table("matches").select("id, round, slot, conference").eq("bracket_id", bracket["id"]).execute().data

    # 4️⃣ Link matches
    def link(conference, from_slot, to_slot, next_slot):
        src = next((m for m in inserted if m["conference"] == conference and m["slot"] == from_slot), None)
        dest = next((m for m in inserted if m["conference"] == conference and m["slot"] == to_slot), None)
        if src and dest:
            supabase.table("matches").update({
                "next_match_id": dest["id"],
                "next_slot": next_slot
            }).eq("id", src["id"]).execute()

    # 🏀 PLAY-IN ROUND
    link("east", 1, 3, "a")
    link("west", 1, 3, "a")
    link("east", 2, 3, "b")
    link("west", 2, 3, "b")
    link("east", 2, 5, "b")
    link("west", 2, 5, "b")
    link("east", 3, 4, "b")
    link("west", 3, 4, "b")

    # ---- Round 1 → Semifinals ----
    link("east", 4, 9, "a")
    link("east", 7, 9, "b")
    link("east", 5, 8, "a")
    link("east", 6, 8, "b")
    link("west", 4, 9, "a")
    link("west", 7, 9, "b")
    link("west", 5, 8, "a")
    link("west", 6, 8, "b")

    # ---- Semifinals → Conference Finals ----
    link("east", 8, 10, "a")
    link("east", 9, 10, "b")
    link("west", 8, 10, "a")
    link("west", 9, 10, "b")

    # ----- Conference Finals → NBA Finals -----
    nba_final = next((m for m in inserted if m["conference"] == "nba" and m["slot"] == 11), None)
    if nba_final:
        east_final = next((m for m in inserted if m["conference"] == "east" and m["slot"] == 10), None)
        west_final = next((m for m in inserted if m["conference"] == "west" and m["slot"] == 10), None)
        if east_final:
            supabase.table("matches").update({
                "next_match_id": nba_final["id"],
                "next_slot": "a"
            }).eq("id", east_final["id"]).execute()
        if west_final:
            supabase.table("matches").update({
                "next_match_id": nba_final["id"],
                "next_slot": "b"
            }).eq("id", west_final["id"]).execute()

    return jsonify({"message": "Bracket created successfully", "bracket": bracket})


@app.route("/bracket/<bracket_id>/save", methods=["PATCH"])
@require_auth
def save_bracket(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400
    user_id = request.user["user_id"]

    # ✅ Fetch the requesting user's admin status
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    # ✅ Retrieve target bracket by ID
    bracket_data = (
        supabase.table("brackets")
        .select("id, user_id, is_done, deleted_at")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if not bracket_data:
        return jsonify({"error": "Bracket not found"}), 404
    bracket = bracket_data[0]

    # 🔒 Ownership or admin check
    if str(bracket["user_id"]) != str(user_id) and not is_admin:
        return jsonify({"error": "Unauthorized: Only the owner or an admin can save this bracket"}), 403

    # Prevent re-saving an already done bracket
    if bracket.get("is_done"):
        return jsonify({"error": "Bracket already saved"}), 400

    # ✅ Mark as done and add timestamp
    saved_at = datetime.utcnow().isoformat()
    supabase.table("brackets").update({
        "is_done": True,
        "saved_at": saved_at
    }).eq("id", bracket_id).execute()

    return jsonify({
        "message": "Bracket successfully saved!",
        "bracket_id": bracket_id,
        "saved_at": saved_at
    }), 200


@app.route("/bracket/<bracket_id>", methods=["GET"])
@require_auth
def get_bracket_by_id(bracket_id):
    """
    Allows any user to view a specific bracket by ID (read-only).
    Rules:
      - Owner and admins can view their bracket even if it's not finished.
      - Other users can only view if is_done = True.
    """
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    # viewer_id is the authenticated user's id from the JWT
    viewer_id = request.user["user_id"]

    # ✅ Fetch viewer info (to check admin rights)
    viewer_data = (
        supabase.table("users")
        .select("id, is_admin")
        .eq("id", viewer_id)
        .execute()
        .data
    )
    is_admin = viewer_data[0]["is_admin"] if viewer_data else False

    # ✅ Fetch the bracket (no is_done filter yet)
    bracket_data = (
        supabase.table("brackets")
        .select("id, user_id, is_done, deleted_at, saved_at")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if not bracket_data:
        return jsonify({"error": "Bracket not found"}), 404

    bracket = bracket_data[0]

    # ✅ Access control:
    #   - Owner or admin → allowed even if not done
    #   - Other users → allowed only if is_done = True
    is_owner = str(viewer_id) == str(bracket["user_id"])
    if not is_owner and not is_admin and not bracket.get("is_done", False):
        return jsonify({"error": "Bracket not yet saved or not accessible"}), 403

    # ✅ Retrieve matches
    matches = (
        supabase.table("matches")
        .select("*")
        .eq("bracket_id", bracket["id"])
        .order("round", desc=False)
        .execute()
        .data
    )

    # ✅ Group matches by conference + round
    grouped = {}
    for match in matches:
        conf = match["conference"].lower() if match["conference"] else "unknown"
        rnd = match["round"]
        if conf not in grouped:
            grouped[conf] = {}
        if rnd not in grouped[conf]:
            grouped[conf][rnd] = []
        grouped[conf][rnd].append(match)

    # ✅ Fetch bracket owner info
    owner_data = (
        supabase.table("users")
        .select("id, username, email")
        .eq("id", bracket["user_id"])
        .execute()
        .data
    )
    owner = owner_data[0] if owner_data else {}

    return jsonify({
        "bracket": {
            **bracket,
            "owner": {
                "id": owner.get("id"),
                "username": owner.get("username"),
                "email": owner.get("email")
            },
            "is_owner": is_owner
        },
        "matches": grouped
    })


@app.route("/brackets", methods=["GET"])
@require_auth
def list_all_brackets():
    """
    Returns a list of all brackets that are marked as is_done = True,
    along with the user who created each one.
    Only basic info: bracket_id, saved_at, and user info.
    """
    try:
        viewer_id = request.user["user_id"]

        # ✅ 1) Fetch *viewer’s* bracket (if any), regardless of is_done
        my_brackets_res = (
            supabase.table("brackets")
            .select("id, user_id, saved_at, created_at, deleted_at")
            .eq("user_id", viewer_id)
            .is_("deleted_at", None)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        my_brackets = my_brackets_res.data or []

        # ✅ 2) Fetch *other users’* brackets, only those that are saved (is_done = True)
        other_brackets_res = (
            supabase.table("brackets")
            .select("id, user_id, saved_at, created_at, deleted_at")
            .neq("user_id", viewer_id)
            .eq("is_done", True)
            .is_("deleted_at", None)
            .order("saved_at", desc=True)
            .execute()
        )
        other_brackets = other_brackets_res.data or []

        # Merge, avoiding duplicates just in case
        brackets = []
        seen_ids = set()
        for b in my_brackets + other_brackets:
            bid = b["id"]
            if bid in seen_ids:
                continue
            seen_ids.add(bid)
            brackets.append(b)

        if not brackets:
            return jsonify([]), 200

        # Collect unique user_ids
        user_ids = list({b["user_id"] for b in brackets if b.get("user_id")})

        # Fetch user info
        users_res = (
            supabase.table("users")
            .select("id, username, email")
            .in_("id", user_ids)
            .execute()
        )
        users = {u["id"]: u for u in users_res.data}

        # Merge user info into output
        output = []
        for b in brackets:
            user_info = users.get(b["user_id"], {})
            output.append({
                "bracket_id": b["id"],
                "saved_at": b.get("saved_at"),
                "created_at": b.get("created_at"),
                "user": {
                    "id": b["user_id"],
                    "username": user_info.get("username"),
                    "email": user_info.get("email")
                }
            })

        return jsonify(output), 200

    except Exception as e:
        if ENABLE_DEBUG_LOGS:
            safe_print("🔴 Error in /auth/register (class):", type(e).__name__)
        return jsonify({"error": "Unexpected error"}), 500


@app.route("/bracket/<bracket_id>", methods=["DELETE"])
@require_auth
def delete_bracket(bracket_id):
    if not is_uuid(bracket_id):
        return jsonify({"error": "Invalid bracket id"}), 400

    user_id = request.user["user_id"]

    # ✅ Fetch user and admin status
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

    # ✅ Fetch target bracket (only non-deleted)
    bracket_res = (
        supabase.table("brackets")
        .select("id, user_id, deleted_at")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if not bracket_res:
        # Either never existed, or already soft-deleted
        return jsonify({"error": "Bracket not found"}), 404

    bracket = bracket_res[0]

    # ✅ Check permissions (owner or admin)
    if bracket["user_id"] != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: Only the owner or an admin can delete this bracket"}), 403

    # ✅ Soft delete: mark deleted_at + who deleted
    update_fields = {
        "deleted_at": datetime.utcnow().isoformat(),
        "deleted_by_user_id": user_id,
        # optional: decide if you want to flip this:
        # "is_done": False,
    }

    supabase.table("brackets").update(update_fields).eq("id", bracket_id).execute()

    return jsonify({"message": "Bracket deleted successfully"})



@app.route("/bracket/<bracket_id>/match/<match_id>", methods=["PATCH"])
@require_auth
def update_match(bracket_id, match_id):
    if not is_uuid(bracket_id) or not is_uuid(match_id):
        return jsonify({"error": "Invalid id"}), 400
    user_id = request.user["user_id"]

    data = request.get_json() or {}
    action = data.get("action")

    # Load the match we’re updating
    res = supabase.table("matches").select(
        "id, bracket_id, conference, round, slot, team_a, team_b, "
        "predicted_winner, predicted_winner_games, next_match_id, next_slot"
    ).eq("id", match_id).execute().data
    if not res:
        return jsonify({"error": "Match not found"}), 404
    match = res[0]

    # ✅ Verify match belongs to this bracket
    if str(match["bracket_id"]) != str(bracket_id):
        return jsonify({"error": "Match does not belong to the specified bracket"}), 400

    # ✅ Ownership and admin check
    user_res = supabase.table("users").select("id, is_admin").eq("id", user_id).execute().data
    if not user_res:
        return jsonify({"error": "User not found"}), 404
    is_admin = user_res[0].get("is_admin", False)

    bracket_check = (
        supabase.table("brackets")
        .select("user_id")
        .eq("id", bracket_id)
        .is_("deleted_at", None)
        .execute()
        .data
    )
    
    if not bracket_check:
        return jsonify({"error": "Bracket not found"}), 404
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
    user_id = request.user["user_id"]

    body = request.get_json() or {}
    games = body.get("games")
    if games is None:
        return jsonify({"error":"games required"}), 400
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error":"X-User-Id header required"}), 401
    # check ownership
    m_resp = supabase.table("matches").select("*").eq("id", match_id).execute()
    if not m_resp.data:
        return jsonify({"error":"match not found"}), 404
    match = m_resp.data[0]
    br = (
        supabase.table("brackets")
        .select("*")
        .eq("id", match["bracket_id"])
        .is_("deleted_at", None)
        .execute()
        .data
    )
    if not br or br[0]["user_id"] != user_id:
        return jsonify({"error":"forbidden"}), 403

    supabase.table("matches").update({"predicted_winner_games": games, "updated_at": "now()"}).eq("id", match_id).execute()
    return jsonify({"ok": True}), 200


# --------------------------------------------------------
# --------------------- M  A  I  N  ----------------------
# --------------------------------------------------------

if __name__ == "__main__":
    # Use FLASK_DEBUG=1 in your local env if you want debug mode
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
