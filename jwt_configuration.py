"""Explicit backend signing configuration; never supplies a signing-key default."""

import os

MINIMUM_SECRET_CHARACTERS = 32


class JWTConfigurationError(RuntimeError):
    """Fixed diagnostics deliberately exclude all supplied configuration values."""


def validate_jwt_secret(value):
    if not isinstance(value, str) or not value.strip():
        raise JWTConfigurationError("JWT_SECRET is required")
    if len(value) < MINIMUM_SECRET_CHARACTERS:
        raise JWTConfigurationError("JWT_SECRET must contain at least 32 characters")
    # Preserve exact configured bytes/characters; this repair never rotates a key.
    return value


def runtime_jwt_secret():
    identity = os.environ.get("NBA_CORNER_ENV")
    config = os.environ.get("NBA_CORNER_TEST_CONFIG")
    if identity not in {None, "production", "test"}:
        raise JWTConfigurationError("Invalid JWT runtime environment")
    if identity == "test" or config is not None:
        if identity not in {None, "test"}:
            raise JWTConfigurationError("Invalid JWT runtime environment")
        from integration_harness import startup_jwt_secret

        # Only the verified, leased, owner-thread startup context can inject this.
        return validate_jwt_secret(startup_jwt_secret())
    return validate_jwt_secret(os.environ.get("JWT_SECRET"))
