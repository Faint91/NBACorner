"""Offline follow-up to NC03-SEC-001; network blocked, secrets/tokens never emitted."""

import ast
import json
import os
import subprocess
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
from jwt_configuration import JWTConfigurationError, runtime_jwt_secret


def historical_source_fallback():
    # Only the original committed app source is read, never local secret files.
    result = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=" + ROOT.as_posix(),
            "show",
            "c5f24396f7387e250982bf2c124ba9753ad9550a:app.py",
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    tree = ast.parse(result.stdout.decode("utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "JWT_SECRET" for t in node.targets)
    )
    return ast.literal_eval(assignment.value.args[1])


def run():
    source = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    start = next(
        i
        for i, n in enumerate(source.body)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Name)
        and n.value.func.id == "prepare_runtime_environment"
    )
    end = next(
        i
        for i, n in enumerate(source.body)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "JWT_SECRET" for t in n.targets)
    )
    startup = compile(
        ast.Module(body=source.body[start : end + 1], type_ignores=[]),
        "app.py actual startup through JWT configuration",
        "exec",
    )
    functions = {
        n.name: n
        for n in source.body
        if isinstance(n, ast.FunctionDef)
        and n.name in {"generate_token", "decode_token", "require_auth", "test_me"}
    }
    algorithm = next(
        n
        for n in source.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "JWT_ALGORITHM" for t in n.targets)
    )
    user_id = "00000000-0000-4000-8000-000000000003"
    old = historical_source_fallback()
    # Explicit test-only fixture injection; never used by application runtime default.
    supplied = "nc03r1-explicit-synthetic-runtime-secret-for-offline-proof"
    base = {"NBA_CORNER_ENV": "production"}
    startup_results = {}
    db = SimpleNamespace(version=0)

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
            return SimpleNamespace(
                data=(
                    [{"id": user_id, "auth_version": db.version}]
                    if self.identity == user_id
                    else []
                )
            )

    def namespace():
        return dict(
            os=os,
            runtime_jwt_secret=runtime_jwt_secret,
            prepare_runtime_environment=lambda: prepare_runtime_environment(
                dotenv_loader=lambda: None
            ),
        )

    with patch(
        "socket.socket.connect", side_effect=AssertionError("Network prohibited")
    ), patch(
        "socket.create_connection", side_effect=AssertionError("Network prohibited")
    ):
        for name, value in {
            "missing": None,
            "empty": "",
            "whitespace": " \t\n",
            "too_short": "x" * 31,
            "known_source_fallback": old,
            "placeholder_secret": "secret",
            "placeholder_changeme": "changeme",
        }.items():
            settings = dict(base)
            if value is not None:
                settings["JWT_SECRET"] = value
            with patch.dict(os.environ, settings, clear=True):
                try:
                    exec(startup, namespace())
                except JWTConfigurationError as error:
                    assert str(error) in {
                        "JWT_SECRET is required",
                        "JWT_SECRET must contain at least 32 characters",
                    }
                    startup_results[name] = "REJECTED_BEFORE_AUTH_OR_CLIENT_CREATION"
                else:
                    raise AssertionError("Unsafe startup accepted; secret withheld")
        with patch.dict(os.environ, dict(base, JWT_SECRET=supplied), clear=True):
            env = namespace()
            exec(startup, env)
            assert env["JWT_SECRET"] == supplied
            # A second initialization with identical explicit configuration does not rotate it.
            second = namespace()
            exec(startup, second)
            assert second["JWT_SECRET"] == env["JWT_SECRET"]
            app = Flask("nc03r1-offline-auth-proof")
            env.update(
                app=app,
                jwt=jwt,
                datetime=datetime,
                timedelta=timedelta,
                wraps=wraps,
                request=request,
                jsonify=jsonify,
                supabase=UsersRead(),
            )
            exec(
                compile(
                    ast.Module(
                        body=[algorithm]
                        + [
                            functions[n]
                            for n in (
                                "generate_token",
                                "decode_token",
                                "require_auth",
                                "test_me",
                            )
                        ],
                        type_ignores=[],
                    ),
                    "app.py actual current JWT functions",
                    "exec",
                ),
                env,
            )
            client = app.test_client()

            def status(token):
                return client.get(
                    "/auth/test-me", headers={"Authorization": "Bearer " + token}
                ).status_code

            claims = dict(
                user_id=user_id,
                username="synthetic",
                is_admin=False,
                av=0,
                exp=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                token = env["generate_token"](user_id, "synthetic", False, 0)
                decoded = jwt.decode(token, supplied, algorithms=["HS256"])
                assert set(decoded) == {"user_id", "username", "is_admin", "av", "exp"}
                lifetime = decoded["exp"] - datetime.now(timezone.utc).timestamp()
                assert 604795 < lifetime <= 604800
                statuses = {
                    "valid_explicit_key": status(token),
                    "no_token": client.get("/auth/test-me").status_code,
                    "forged_old_source_fallback": status(
                        jwt.encode(claims, old, algorithm="HS256")
                    ),
                    "wrong_key": status(
                        jwt.encode(
                            claims,
                            "unrelated-synthetic-wrong-key-for-proof",
                            algorithm="HS256",
                        )
                    ),
                    "nonexistent_user": status(
                        jwt.encode(
                            dict(claims, user_id="nonexistent"),
                            supplied,
                            algorithm="HS256",
                        )
                    ),
                    "malformed": status("malformed"),
                    "wrong_algorithm": status(
                        jwt.encode(claims, supplied, algorithm="HS384")
                    ),
                    "missing_expiry": status(
                        jwt.encode(
                            {k: v for k, v in claims.items() if k != "exp"},
                            supplied,
                            algorithm="HS256",
                        )
                    ),
                    "expired": status(
                        jwt.encode(dict(claims, exp=1), supplied, algorithm="HS256")
                    ),
                }
                legacy = jwt.encode(
                    {k: v for k, v in claims.items() if k != "av"},
                    supplied,
                    algorithm="HS256",
                )
                statuses["pre_g2_missing_av_version_zero"] = status(legacy)
                db.version = 1
                statuses["revoked_av_after_version_increment"] = status(token)
                statuses["legacy_after_version_increment"] = status(legacy)
                statuses["new_av_after_version_increment"] = status(
                    env["generate_token"](user_id, "synthetic", False, 1)
                )
                db.version = 0
                statuses["existing_token_same_config"] = status(token)
            accepted = {
                "valid_explicit_key",
                "pre_g2_missing_av_version_zero",
                "new_av_after_version_increment",
                "existing_token_same_config",
            }
            for name, code in statuses.items():
                assert code == (200 if name in accepted else 401)
    return dict(
        finding="NC03-SEC-001",
        status="REPAIRED LOCALLY / pending NC-03 re-audit",
        unsafe_startup_cases=startup_results,
        actual_current_route_statuses=statuses,
        actual_generation_claims_and_seven_day_expiry_unchanged=True,
        explicit_config_preserved_exactly=True,
        minimum_characters=32,
        database="Synthetic in-memory user/version read double; live G1/G2 tested separately",
        production_contact=False,
        network_used=False,
        secret_or_token_values_emitted=False,
    )


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2))
    except Exception:
        print(
            "NC-03R1 offline proof failed; sensitive diagnostics withheld",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
