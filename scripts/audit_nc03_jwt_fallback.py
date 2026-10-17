"""NC-03 offline reproduction only: no app import, DB, network or secret output."""

import ast
import json
import os
import socket
import sys
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from environment_safety import prepare_runtime_environment


def run():
    source = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    names = {"JWT_SECRET", "JWT_ALGORITHM"}
    assignments = [
        node
        for node in source.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
    ]
    functions = {
        node.name: node
        for node in source.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"decode_token", "require_auth", "test_me"}
    }
    assert len(assignments) == 2
    assert len(functions) == 3
    calls = []
    user_id = "00000000-0000-4000-8000-000000000003"

    class UsersRead:
        def table(self, name):
            assert name == "users"
            return self

        def select(self, fields):
            assert fields == "id,auth_version"
            return self

        def eq(self, field, value):
            assert field == "id"
            self.identity = value
            return self

        def execute(self):
            calls.append("synthetic_user_version_read")
            return SimpleNamespace(
                data=(
                    [{"id": user_id, "auth_version": 0}]
                    if self.identity == user_id
                    else []
                )
            )

    # Never read dotenv files or ambient credentials. Disable any network connection.
    with patch.dict(os.environ, {"NBA_CORNER_ENV": "production"}, clear=True), patch(
        "socket.socket.connect", side_effect=AssertionError("Network prohibited")
    ), patch(
        "socket.create_connection", side_effect=AssertionError("Network prohibited")
    ):
        prepare_runtime_environment(dotenv_loader=lambda: None)
        missing_key_accepted = "JWT_SECRET" not in os.environ
        app = Flask("nc03_offline_auth_audit")
        env = dict(
            os=os,
            jwt=jwt,
            app=app,
            wraps=wraps,
            request=request,
            jsonify=jsonify,
            supabase=UsersRead(),
        )
        # Execute exact current configuration assignments and actual auth functions.
        exec(
            compile(
                ast.Module(
                    body=assignments
                    + [
                        functions[n]
                        for n in ("decode_token", "require_auth", "test_me")
                    ],
                    type_ignores=[],
                ),
                "app.py (NC-03 selected current nodes)",
                "exec",
            ),
            env,
        )
        assert isinstance(env["JWT_SECRET"], str) and env["JWT_SECRET"]
        client = app.test_client()
        statuses = {"no_token": client.get("/auth/test-me").status_code}
        claims = dict(
            user_id=user_id,
            username="nc03-synthetic-subject",
            is_admin=False,
            av=0,
            exp=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        # All tokens are transient; neither keys nor token bodies are emitted.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            forged = jwt.encode(
                claims, env["JWT_SECRET"], algorithm=env["JWT_ALGORITHM"]
            )
            response = client.get(
                "/auth/test-me", headers={"Authorization": "Bearer " + forged}
            )
            statuses["source_fallback_signed_token"] = response.status_code
            assert response.get_json()["user"]["user_id"] == user_id
            wrong = jwt.encode(
                claims,
                "nc03-unrelated-synthetic-key-32bytes",
                algorithm=env["JWT_ALGORITHM"],
            )
            statuses["wrong_key_token"] = client.get(
                "/auth/test-me", headers={"Authorization": "Bearer " + wrong}
            ).status_code
            absent = jwt.encode(
                dict(claims, user_id="00000000-0000-4000-8000-000000000004"),
                env["JWT_SECRET"],
                algorithm=env["JWT_ALGORITHM"],
            )
            statuses["nonexistent_user_token"] = client.get(
                "/auth/test-me", headers={"Authorization": "Bearer " + absent}
            ).status_code
        assert statuses == {
            "no_token": 401,
            "source_fallback_signed_token": 200,
            "wrong_key_token": 401,
            "nonexistent_user_token": 401,
        }
        return dict(
            finding="NC03-SEC-001",
            classification="FAIL",
            reproduction_completed=True,
            explicit_production_mode_accepts_missing_jwt_secret=missing_key_accepted,
            nonempty_source_signing_fallback_present=True,
            actual_current_auth_route_statuses=statuses,
            database="in-memory synthetic existing-user/version read double only",
            limitation="Not a full application startup or real DB integration; no inference about deployed configuration.",
            controls=3,
            exploit_cases=1,
            production_contact=False,
            network_used=False,
            database_mutations=0,
            credentials_or_tokens_emitted=False,
        )


if __name__ == "__main__":
    # Preserve the original vulnerable proof above and its committed evidence.
    # The same command now exercises the repaired startup/forgery scenario.
    from verify_nc03r1_jwt_config import run as verify_repaired_scenario

    try:
        print(json.dumps(verify_repaired_scenario(), indent=2))
    except Exception:
        print("NC-03R1 proof failed; sensitive diagnostics withheld", file=sys.stderr)
        raise SystemExit(1) from None
