"""NC-03R2 actual diagnostic/auth code proof; synthetic reads, no external IO."""

import ast
import contextlib
import io
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parents[1]


def run():
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    names = (
        "is_uuid",
        "decode_token",
        "require_auth",
        "_season_bootstrap",
        "debug_master_status",
    )
    functions = {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name in names
    }
    assert len(functions) == len(names)
    uid = "00000000-0000-4000-8000-000000000001"
    bid = "00000000-0000-4000-8000-000000000002"
    sid = "00000000-0000-4000-8000-000000000003"
    other = "00000000-0000-4000-8000-000000000004"
    key = "nc03r2-explicit-synthetic-signing-key-for-offline-tests"
    marker = "NC03R2_SYNTHETIC_PRIVATE_FAULT"
    outcomes = []
    captured = io.StringIO()

    class Query:
        def __init__(self, table, state):
            self.table, self.state = table, state

        def select(self, fields):
            self.fields = fields
            return self

        def eq(self, *args):
            return self

        def single(self):
            return self

        def limit(self, *args):
            return self

        def execute(self):
            s = self.state
            if self.table == "users":
                if self.fields == "id,auth_version":
                    return SimpleNamespace(data=[{"id": uid, "auth_version": 0}])
                s.admin_reads += 1
                if s.mode == "admin_failure":
                    raise RuntimeError(marker)
                return SimpleNamespace(data=[{"is_admin": s.db_admin}])
            s.diagnostic_reads += 1
            if self.table == "brackets":
                if s.mode == "bracket_failure":
                    raise RuntimeError(marker)
                if s.mode == "missing_bracket":
                    return SimpleNamespace(data=None)
                if s.mode == "malformed_bracket":
                    return SimpleNamespace(data=[])
                return SimpleNamespace(
                    data={
                        "id": bid,
                        "season_id": None if s.mode == "missing_season" else sid,
                        "deleted_at": None,
                    }
                )
            assert self.table == "seasons"
            if s.mode == "generic_failure":
                raise RuntimeError(marker)
            if s.mode == "missing_column_failure":
                raise RuntimeError(marker + " master_bracket_id")
            if s.mode == "error_field":
                return SimpleNamespace(data=None, error=marker)
            if s.mode == "malformed_season":
                return SimpleNamespace(data=[])
            data = {"id": sid, "master_bracket_id": bid}
            if s.mode == "absent_column":
                data.pop("master_bracket_id")
            if s.mode == "null_master":
                data["master_bracket_id"] = None
            if s.mode == "different_master":
                data["master_bracket_id"] = other
            if s.mode == "malformed_master":
                data["master_bracket_id"] = {"private": marker}
            return SimpleNamespace(data=data)

    with patch(
        "socket.socket.connect", side_effect=AssertionError("Network prohibited")
    ), patch(
        "socket.create_connection", side_effect=AssertionError("Network prohibited")
    ), contextlib.redirect_stdout(
        captured
    ), contextlib.redirect_stderr(
        captured
    ):
        for mode_env in ("production", "test"):
            with patch.dict(
                os.environ, {"NBA_CORNER_ENV": mode_env, "JWT_SECRET": key}, clear=True
            ):
                state = SimpleNamespace(
                    mode="healthy", admin_reads=0, diagnostic_reads=0, db_admin=True
                )
                app = Flask("nc03r2-" + mode_env)
                env = dict(
                    app=app,
                    request=request,
                    jsonify=jsonify,
                    wraps=wraps,
                    uuid=uuid,
                    jwt=jwt,
                    JWT_SECRET=key,
                    JWT_ALGORITHM="HS256",
                    supabase=SimpleNamespace(table=lambda table: Query(table, state)),
                    ensure_season_globals=lambda: None,
                    SeasonConfigurationError=type(
                        "SeasonConfigurationError", (Exception,), {}
                    ),
                )
                exec(
                    compile(
                        ast.Module(body=[functions[n] for n in names], type_ignores=[]),
                        "app.py current route/auth/hook",
                        "exec",
                    ),
                    env,
                )
                client = app.test_client()
                claims = dict(
                    user_id=uid,
                    username="synthetic",
                    is_admin=True,
                    av=0,
                    exp=datetime.now(timezone.utc) + timedelta(minutes=5),
                )
                for role, db_admin, modes in (
                    (
                        "anonymous",
                        True,
                        (
                            "healthy",
                            "generic_failure",
                            "missing_column_failure",
                            "malformed_season",
                        ),
                    ),
                    ("ordinary", False, ("healthy", "generic_failure")),
                    ("forged_admin_claim", False, ("healthy",)),
                    (
                        "admin",
                        True,
                        (
                            "healthy",
                            "null_master",
                            "different_master",
                            "generic_failure",
                            "missing_column_failure",
                            "bracket_failure",
                            "admin_failure",
                            "error_field",
                            "malformed_bracket",
                            "missing_season",
                            "malformed_season",
                            "absent_column",
                            "malformed_master",
                            "missing_bracket",
                            "invalid_id",
                            "missing_id",
                        ),
                    ),
                ):
                    for mode in modes:
                        state.mode, state.db_admin = mode, db_admin
                        state.admin_reads = state.diagnostic_reads = 0
                        headers = {}
                        if role != "anonymous":
                            token = jwt.encode(
                                dict(claims, is_admin=role != "ordinary"),
                                key,
                                algorithm="HS256",
                            )
                            headers = {"Authorization": "Bearer " + token}
                        query = (
                            {}
                            if mode == "missing_id"
                            else {
                                "bracket_id": "invalid" if mode == "invalid_id" else bid
                            }
                        )
                        response = client.get(
                            "/__debug/master-status",
                            query_string=query,
                            headers=headers,
                        )
                        body = response.get_json()
                        assert marker not in response.get_data(as_text=True)
                        assert not (
                            {
                                "exception",
                                "sql",
                                "fix_sql",
                                "repair_sql",
                                "query",
                                "statement",
                                "traceback",
                                "bracket_id",
                                "season_id",
                                "season.master_bracket_id",
                            }
                            & set(body)
                        )
                        if role == "anonymous":
                            expected = 401
                        elif role != "admin":
                            expected = 403
                        elif mode in {"healthy", "null_master", "different_master"}:
                            expected = 200
                            assert body == {
                                "ok": True,
                                "bracket_deleted": False,
                                "is_master_computed": mode == "healthy",
                            }
                        elif mode == "missing_bracket":
                            expected = 404
                        elif mode in {"invalid_id", "missing_id"}:
                            expected = 400
                        else:
                            expected = 503
                            assert body == {
                                "ok": False,
                                "error": "Diagnostic check failed.",
                            }
                        assert response.status_code == expected
                        if role != "admin":
                            assert state.diagnostic_reads == 0
                        if role in {"anonymous", "ordinary"}:
                            assert state.admin_reads == 0
                        outcomes.append(
                            dict(
                                environment=mode_env,
                                role=role,
                                scenario=mode,
                                status=expected,
                                diagnostic_reads=state.diagnostic_reads,
                                sanitized=True,
                            )
                        )
    assert not captured.getvalue(), "Unexpected logs; raw details withheld"
    return dict(
        finding="NC03-SEC-002",
        status="REPAIRED LOCALLY / pending NC-03 re-audit",
        scenarios=len(outcomes),
        outcomes=outcomes,
        provider_markers_exposed=False,
        repair_SQL_exposed=False,
        identifiers_exposed=False,
        logs_empty=True,
        actual_route_auth_helpers_and_season_hook_used=True,
        limitation="Offline actual-code proof with synthetic read doubles and canonical success; not a production observation or full deployed startup.",
        production_contact=False,
        database_mutations=0,
        network_used=False,
    )


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2))
    except Exception:
        print(
            "Diagnostic proof failed; sensitive diagnostics withheld", file=sys.stderr
        )
        raise SystemExit(1) from None
