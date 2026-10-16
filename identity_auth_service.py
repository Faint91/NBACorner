"""G1 identity and exact-password helpers. Reset/session lifecycle stays unchanged."""

import base64
import hashlib
import re
import bcrypt

EMAIL_PATTERN = r"[^@\s]+@[^@\s]+\.[^@\s]+"
USERNAME_PATTERN = r"[a-zA-Z0-9_]{3,30}"
HASH_PREFIX = "nc-bcrypt-sha256-v1$"
DOMAIN = b"NBA-Corner/account-password/v1\x00"


def normalize_username_display(value):
    if not isinstance(value, str):
        raise ValueError("Username must be a string")
    return value.strip()


def normalize_username_key(value):
    # Valid usernames are ASCII under the unchanged product naming policy.
    return normalize_username_display(value).lower()


def normalize_email(value, client):
    if not isinstance(value, str):
        raise ValueError("Email must be a string")
    # PostgreSQL is authoritative for Unicode lower(), including locale behavior.
    # Do not substitute Python lower(): Unicode expansions may differ.
    normalized = client.rpc("auth_identity_key", {"p_value": value}).execute().data
    if not isinstance(normalized, str):
        raise RuntimeError("Identity normalization unavailable")
    return normalized


def validate_password(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 128:
        raise ValueError("Password must contain 8 to 128 characters")
    # Python Unicode code points, not encoded bytes or JS UTF-16 units.
    value.encode("utf-8")
    return value


def prehash(value):
    return base64.b64encode(hashlib.sha256(DOMAIN + value.encode("utf-8")).digest())


def hash_password(value, rounds=12):
    validate_password(value)
    return HASH_PREFIX + bcrypt.hashpw(prehash(value), bcrypt.gensalt(rounds)).decode(
        "ascii"
    )


def verify_password(value, stored_hash):
    if not isinstance(value, str) or not isinstance(stored_hash, str):
        return False
    try:
        if stored_hash.startswith(HASH_PREFIX):
            if not 8 <= len(value) <= 128:
                return False
            return bcrypt.checkpw(
                prehash(value), stored_hash[len(HASH_PREFIX) :].encode("ascii")
            )
        # Existing bcrypt 5 rejects inputs above 72 bytes. Never truncate them.
        encoded = value.encode("utf-8")
        if len(encoded) > 72:
            return False
        if not stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return False
        return bcrypt.checkpw(encoded, stored_hash.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


def valid_username(value):
    return re.fullmatch(USERNAME_PATTERN, value) is not None


def valid_email(value):
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return re.fullmatch(EMAIL_PATTERN, value) is not None
