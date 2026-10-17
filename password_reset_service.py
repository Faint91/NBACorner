"""G2 high-entropy one-time reset orchestration; raw secrets stay in memory/email."""

import hashlib
import re
import secrets
from identity_auth_service import (
    normalize_email,
    normalize_username_display,
    normalize_username_key,
    valid_email,
    valid_username,
    validate_password,
    hash_password,
)

REQUEST_MESSAGE = "If an account matches, reset instructions will be sent."
INVALID_LINK = "Invalid or expired reset link"


def token_digest(token):
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        raise ValueError(INVALID_LINK)
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def request_identity(data, client):
    if not isinstance(data, dict):
        raise ValueError("A JSON object is required")
    field = "email" if "email" in data else "username"
    raw = data.get(field)
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Email or username is required")
    display = normalize_username_display(raw)
    if field == "email" and valid_email(display):
        return "email", normalize_email(raw, client)
    if field == "username" and valid_username(display):
        return "username", normalize_username_key(raw)
    raise ValueError("Enter a valid email or username")


def issue_reset(user, client, send, link, log):
    raw = secrets.token_urlsafe(32)
    digest = token_digest(raw)
    issued = (
        client.rpc(
            "issue_password_reset", {"p_user_id": user["id"], "p_digest": digest}
        )
        .execute()
        .data
    )
    if issued is not True:
        raise RuntimeError("Reset issuance unavailable")
    delivered = False
    try:
        url = link(raw)
        delivered = (
            send(
                user["email"],
                "NBACorner Password Reset",
                f'<p>A password reset was requested.</p><p><a href="{url}">Reset password</a></p>'
                "<p>This link expires in 60 minutes. Only the latest link works. Ignore this email if you did not request it.</p>",
            )
            is True
        )
    except Exception:
        log("Password reset delivery unavailable")
    if not delivered:
        log("Password reset delivery failed; cancelling issued verifier")
        # Conditional cancellation cannot remove a newer concurrent issuance.
        client.rpc(
            "cancel_password_reset", {"p_user_id": user["id"], "p_digest": digest}
        ).execute()


def complete_reset(data, client, rounds):
    if not isinstance(data, dict):
        raise ValueError("A JSON object is required")
    digest = token_digest(data.get("token"))
    password = validate_password(data.get("new_password"))
    # Expensive G1 hashing precedes the transaction; no DB state changes before RPC.
    hashed = hash_password(password, rounds=rounds)
    return (
        client.rpc(
            "complete_password_reset", {"p_digest": digest, "p_password_hash": hashed}
        )
        .execute()
        .data
        is True
    )
