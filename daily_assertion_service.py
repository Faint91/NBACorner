"""Dedicated Daily credential issuer. Never accepts an unverified browser subject."""

from datetime import datetime, timezone
from functools import wraps
import os
import re
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import make_response

CONTRACT = "daily-stats-auth-v1"
ISSUER = "https://www.nbacorner.com"
AUDIENCE = "daily-stats"
SCOPE = "daily:stats"
TOKEN_TYPE = "daily-stats+jwt"
TTL_SECONDS = 45
KEY_ID_PATTERN = r"daily-stats-[A-Za-z0-9_-]{1,64}"


def daily_assertion_private_response(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        response = make_response(fn(*args, **kwargs))
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Vary"] = "Authorization, Origin"
        return response
    return wrapped


def issue_daily_assertion(verified_user_id, *, environ=None, now=None):
    """Caller is the existing require_auth route; not a public UUID issuance API."""
    config = os.environ if environ is None else environ
    subject = str(uuid.UUID(verified_user_id))
    if config.get("DAILY_STATS_ASSERTION_ISSUER") != ISSUER:
        raise ValueError("Daily assertion configuration unavailable")
    kid = config.get("DAILY_STATS_ASSERTION_KEY_ID", "")
    if not re.fullmatch(KEY_ID_PATTERN, kid):
        raise ValueError("Daily assertion configuration unavailable")
    private_key = serialization.load_pem_private_key(
        config.get("DAILY_STATS_ASSERTION_PRIVATE_KEY", "").encode(), password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
        raise ValueError("Daily assertion configuration unavailable")
    issued_at = int(time.time() if now is None else now)
    claims = dict(
        iss=ISSUER, aud=AUDIENCE, sub=subject, iat=issued_at, nbf=issued_at,
        exp=issued_at + TTL_SECONDS, jti=str(uuid.uuid4()), scope=SCOPE,
        contract=CONTRACT,
    )
    assertion = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid, "typ": TOKEN_TYPE})
    return {
        "assertion": assertion,
        "expiresAt": datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat().replace("+00:00", "Z"),
        "contract": CONTRACT,
    }
