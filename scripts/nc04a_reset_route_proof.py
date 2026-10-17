"""NC-04A offline reset-link/route proof; no app startup, email, DB or network."""

import ast
import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from email_transport import reset_link_for_settings


def run():
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8-sig"))
    rules = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "app"
                and decorator.func.attr
                in {"route", "get", "post", "patch", "put", "delete"}
            ):
                continue
            assert len(decorator.args) == 1 and isinstance(
                decorator.args[0], ast.Constant
            )
            path = decorator.args[0].value
            methods = next(
                (
                    ast.literal_eval(x.value)
                    for x in decorator.keywords
                    if x.arg == "methods"
                ),
                (
                    ["GET"]
                    if decorator.func.attr == "route"
                    else [decorator.func.attr.upper()]
                ),
            )
            if "GET" in methods and "HEAD" not in methods:
                methods = methods + ["HEAD"]
            rules.append(
                Rule(path, endpoint=node.name + ":" + str(node.lineno), methods=methods)
            )
    rules.append(
        Rule(
            "/static/<path:filename>",
            endpoint="flask-default-static",
            methods=["GET", "HEAD"],
        )
    )
    # Synthetic marker is neither a verifier nor a token issued for any account.
    parsed = urlparse(
        reset_link_for_settings(
            "NC04A-SYNTHETIC-NOT-A-RESET-VERIFIER", {"NBA_CORNER_ENV": "production"}
        )
    )
    assert (
        parsed.hostname == "nbacorner.onrender.com" and parsed.path == "/reset-password"
    )
    adapter = Map(rules).bind(parsed.hostname, url_scheme="https")
    try:
        adapter.match(parsed.path, method="GET")
        raise AssertionError("Expected backend reset UI route to be absent")
    except NotFound:
        pass
    frontend = (ROOT.parent / "frontend/src/main.tsx").read_text(encoding="utf-8")
    assert 'path="/reset-password"' in frontend
    return dict(
        finding_id="NC04A-CODE-001",
        classification="CONFIRMED LOCAL RELEASE DEFECT / STOP",
        production_email_link_origin="https://nbacorner.onrender.com",
        production_email_link_path=parsed.path,
        backend_route_match_status=404,
        backend_route_rules_checked=len(rules),
        frontend_reset_route_exists=True,
        hosting_evidence="Render NBACorner web service srv-d4239u6uk2gs73b8fts0 serves that origin via gunicorn app:app",
        root_cause="Production link builder always selects API origin; FRONTEND_ORIGIN cannot override it, and API route map has no GET reset UI/redirect.",
        scope="Offline actual helper plus exact current AST route-map proof; no live product HTTP probe or real token used.",
        required_repair_phase="NC-03R3 (separate explicit authorization required)",
        production_mutations=0,
        production_requests=0,
        email_sends=0,
        credentials_read_or_emitted=False,
    )


if __name__ == "__main__":
    value = run()
    (ROOT / "db/records/nc_04a_reset_route_finding.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(value, indent=2))
