"""Pure reset-routing contract check. No app startup, DB, email or network."""

import argparse
import ast
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from email_transport import frontend_reset_origin, reset_link_for_settings
from environment_safety import SafetyError


def origin_identity(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError()
    return (
        parsed.scheme,
        parsed.hostname.encode("idna").decode("ascii").lower().rstrip("."),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def inspect_config(settings, api_origin):
    """Names/booleans only for later authorized preflight; never emit the full link."""
    result = dict(
        frontend_origin_present=isinstance(settings.get("FRONTEND_ORIGIN"), str)
        and bool(settings["FRONTEND_ORIGIN"].strip()),
        frontend_origin_valid=False,
        api_origin_valid=False,
        frontend_distinct_from_api=False,
        route="/reset-password",
        token_location="query",
        token_parameter="token",
        routing_contract_valid=False,
    )
    try:
        origin = frontend_reset_origin(settings)
        result["frontend_origin_valid"] = True
        api_identity = origin_identity(api_origin)
        result["api_origin_valid"] = True
        result["frontend_distinct_from_api"] = origin_identity(origin) != api_identity
        parsed = urlsplit(
            reset_link_for_settings("non-issued-synthetic-marker", settings)
        )
        result["routing_contract_valid"] = bool(
            result["frontend_distinct_from_api"]
            and parsed.path == result["route"]
            and parse_qs(parsed.query) == {"token": ["non-issued-synthetic-marker"]}
        )
    except (SafetyError, ValueError, UnicodeError, TypeError):
        pass
    return result


def run():
    result = inspect_config(
        {
            "NBA_CORNER_ENV": "production",
            "FRONTEND_ORIGIN": "https://frontend.example.invalid/",
        },
        "https://api.example.invalid",
    )
    assert result["routing_contract_valid"]
    assert not inspect_config({}, "https://api.example.invalid")[
        "routing_contract_valid"
    ]
    assert not inspect_config(
        {"FRONTEND_ORIGIN": "https://api.example.invalid:443/"},
        "https://api.example.invalid",
    )["routing_contract_valid"]
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8-sig"))
    rules = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in node.decorator_list:
            if (
                isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and isinstance(d.func.value, ast.Name)
                and d.func.value.id == "app"
                and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
            ):
                assert len(d.args) == 1 and isinstance(d.args[0], ast.Constant)
                methods = next(
                    (
                        ast.literal_eval(x.value)
                        for x in d.keywords
                        if x.arg == "methods"
                    ),
                    ["GET"] if d.func.attr == "route" else [d.func.attr.upper()],
                )
                rules.append(
                    Rule(
                        d.args[0].value,
                        endpoint=node.name + str(node.lineno),
                        methods=methods,
                    )
                )
    try:
        Map(rules).bind("api.example.invalid").match("/reset-password", method="GET")
        raise AssertionError("Backend reset UI/redirect unexpectedly added")
    except NotFound:
        pass
    frontend = (ROOT.parent / "frontend/src/main.tsx").read_text(encoding="utf-8")
    assert 'path="/reset-password"' in frontend
    return dict(
        finding="NC04A-CODE-001",
        status="REPAIRED LOCALLY / pending NC-04A re-verification",
        configuration_variable="FRONTEND_ORIGIN",
        synthetic_config_check=result,
        backend_reset_UI_or_redirect_added=False,
        frontend_route_unchanged=True,
        missing_or_API_origin_blocks_preflight=True,
        production_contact=False,
        no_tokens_or_full_reset_URLs_recorded=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-runtime-config",
        action="store_true",
        help="Read only FRONTEND_ORIGIN from explicit caller environment; never load dotenv or connect anywhere",
    )
    parser.add_argument(
        "--api-origin",
        help="Explicit public API origin, required for config-check mode",
    )
    args = parser.parse_args()
    if args.check_runtime_config:
        if not args.api_origin:
            parser.error("Explicit public API origin required")
        value = inspect_config(
            {
                "NBA_CORNER_ENV": "production",
                "FRONTEND_ORIGIN": os.environ.get("FRONTEND_ORIGIN"),
            },
            args.api_origin,
        )
    else:
        value = run()
    print(json.dumps(value, indent=2))
