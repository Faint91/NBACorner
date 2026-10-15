"""Small GET seam: production callback unchanged; test responses strictly local."""

import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from environment_safety import (
    SafetyError,
    runtime_safety_settings,
    load_enrollments,
    validate_test_target,
    validate_test_provider_settings,
)

FIXTURES = Path(__file__).parent / "tests/fixtures/providers"


class FixtureResponse:
    status_code = 200
    headers = {"Content-Type": "application/json", "X-NBA-Corner-Transport": "fixture"}

    def __init__(self, filename):
        self.url = "fixture://" + filename
        self.text = (FIXTURES / filename).read_text(encoding="utf-8")
        json.loads(self.text)

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        return None


def provider_mode(settings, *, ambient=None):
    identity = settings.get("NBA_CORNER_ENV")
    if identity in {None, "production"}:
        if settings.get("NBA_CORNER_TEST_CONFIG") is not None:
            raise SafetyError("Production provider cannot use test configuration.")
        return "live"
    if identity != "test":
        raise SafetyError("Unrecognized provider environment identity.")
    target = validate_test_target(settings, load_enrollments(), identity_only=True)
    validate_test_provider_settings(settings, target, ambient=ambient)
    return "fixtures"


def provider_uses_fixtures():
    return provider_mode(runtime_safety_settings()) == "fixtures"


def provider_get(production_get, url, *, settings=None, ambient=None, **kwargs):
    settings = runtime_safety_settings() if settings is None else settings
    if provider_mode(settings, ambient=ambient) == "live":
        return production_get(url, **kwargs)
    # No callback, DNS, socket, redirect or arbitrary file lookup on this branch.
    headers = kwargs.get("headers") or {}
    if any(
        str(k).lower() in {"authorization", "api-key", "apikey", "x-api-key"} and v
        for k, v in headers.items()
    ):
        raise SafetyError("Provider credentials are prohibited in fixture requests.")
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment:
        raise SafetyError("Unexpected fixture destination.")
    if (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "site.web.api.espn.com",
        "/apis/v2/sports/basketball/nba/standings",
    ):
        query = parse_qs(parsed.query)
        if query.get("season") != ["2026"] or kwargs.get("params"):
            raise SafetyError("ESPN fixture supports only its explicit season.")
        return FixtureResponse("espn-standings-complete-2026.json")
    if (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "api.balldontlie.io",
        "/v1/games",
    ) and not parsed.query:
        params = kwargs.get("params") or {}
        if (
            params.get("seasons[]") != 2025
            or params.get("per_page") != 100
            or set(params) - {"seasons[]", "per_page", "cursor"}
        ):
            raise SafetyError("Unexpected Balldontlie fixture parameters.")
        cursor = params.get("cursor")
        if cursor is None:
            return FixtureResponse("balldontlie-games-2025-page-1.json")
        if cursor == 100:
            return FixtureResponse("balldontlie-games-2025-page-2.json")
    raise SafetyError("Unexpected external provider destination or fixture request.")
