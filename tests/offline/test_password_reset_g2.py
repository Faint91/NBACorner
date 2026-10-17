"""G2 offline orchestration failures and secret-boundary acceptance."""

import ast
import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from password_reset_service import (
    issue_reset,
    complete_reset,
    request_identity,
    token_digest,
)
from identity_auth_service import verify_password


class PasswordResetOffline(unittest.TestCase):
    def client(self, results=None):
        calls = []

        def rpc(name, params):
            calls.append((name, params))

            def execute():
                result = (results or {}).get(name, True)
                if isinstance(result, Exception):
                    raise result
                return SimpleNamespace(data=result)

            return SimpleNamespace(execute=execute)

        return SimpleNamespace(rpc=rpc), calls

    def test_entropy_digest_and_email_only_raw(self):
        client, calls = self.client()
        mail = []
        logs = []

        def send(recipient, subject, body):
            mail.append(body)
            return True

        with patch(
            "password_reset_service.secrets.token_urlsafe", return_value="a" * 43
        ) as random:
            issue_reset(
                {"id": "synthetic", "email": "synthetic@example.test"},
                client,
                send,
                lambda t: "http://example.test/reset-password?token=" + t,
                logs.append,
            )
        random.assert_called_once_with(32)
        self.assertEqual(
            calls[0][1]["p_digest"], hashlib.sha256(("a" * 43).encode()).hexdigest()
        )
        self.assertNotIn("a" * 43, str(calls))
        self.assertIn("token=" + "a" * 43, mail[0])
        self.assertFalse(logs)

    def test_confirmed_failure_cancels_only_issued_digest(self):
        for delivery in (False, RuntimeError("synthetic provider diagnostics")):
            client, calls = self.client()
            logs = []

            def send(*args):
                if isinstance(delivery, Exception):
                    raise delivery
                return delivery

            issue_reset(
                {"id": "synthetic", "email": "synthetic@example.test"},
                client,
                send,
                lambda t: t,
                logs.append,
            )
            self.assertEqual(
                [n for n, _ in calls], ["issue_password_reset", "cancel_password_reset"]
            )
            self.assertEqual(calls[0][1], calls[1][1])
            self.assertNotIn("diagnostics", str(logs))

    def test_issuance_failure_never_sends(self):
        client, calls = self.client({"issue_password_reset": False})
        sent = []
        with self.assertRaises(RuntimeError):
            issue_reset(
                {"id": "synthetic", "email": "synthetic@example.test"},
                client,
                lambda *a: sent.append(a),
                lambda t: t,
                lambda *a: None,
            )
        self.assertFalse(sent)
        self.assertEqual(len(calls), 1)

    def test_completion_only_sends_digest_and_g1_hash(self):
        client, calls = self.client()
        password = " " + "界" * 40 + " "
        self.assertTrue(
            complete_reset({"token": "b" * 43, "new_password": password}, client, 4)
        )
        name, params = calls[0]
        self.assertEqual(name, "complete_password_reset")
        self.assertNotIn("b" * 43, str(params))
        self.assertNotIn(password, str(params))
        self.assertTrue(verify_password(password, params["p_password_hash"]))

    def test_invalid_password_never_calls_completion(self):
        for value in (None, 7, [], "short", "a" * 129):
            client, calls = self.client()
            with self.assertRaises(ValueError):
                complete_reset({"token": "b" * 43, "new_password": value}, client, 4)
            self.assertFalse(calls)

    def test_invalid_token_never_calls_rpc(self):
        for value in (None, 7, [], "short", "a" * 44, "%" * 43, "界" * 43):
            with self.assertRaises(ValueError):
                token_digest(value)

    def test_identity_shape_validation_precedes_normalization(self):
        for data in (None, [], "text", {}, {"email": 4}, {"username": []}):
            client, calls = self.client()
            with self.assertRaises(ValueError):
                request_identity(data, client)
            self.assertFalse(calls)

    def test_auth_db_failure_fails_closed(self):
        source = ast.parse(Path("app.py").read_text(encoding="utf-8"))
        node = next(
            n
            for n in source.body
            if isinstance(n, ast.FunctionDef) and n.name == "decode_token"
        )

        def broken(*a):
            raise RuntimeError("private database transport")

        env = {
            "jwt": SimpleNamespace(
                decode=lambda *a, **kw: {"user_id": "synthetic", "av": 0}
            ),
            "JWT_SECRET": "synthetic",
            "JWT_ALGORITHM": "HS256",
            "supabase": SimpleNamespace(table=broken),
        }
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "actual JWT helper", "exec"
            ),
            env,
        )
        self.assertIsNone(env["decode_token"]("synthetic"))

    def test_completion_exceptions_never_echo_transport_or_token(self):
        import flask

        source = ast.parse(Path("app.py").read_text(encoding="utf-8"))
        node = next(
            n
            for n in source.body
            if isinstance(n, ast.FunctionDef) and n.name == "reset_password"
        )
        app = flask.Flask("g2-errors")
        env = dict(
            app=app,
            request=flask.request,
            jsonify=flask.jsonify,
            supabase=None,
            BCRYPT_ROUNDS=4,
            safe_print=lambda *args: None,
        )
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]),
                "actual G2 error route",
                "exec",
            ),
            env,
        )
        for failure, status in (
            (ValueError("private transport secret"), 400),
            (UnicodeError("private transport secret"), 400),
            (RuntimeError("private transport secret"), 503),
        ):
            with patch("password_reset_service.complete_reset", side_effect=failure):
                response = app.test_client().post(
                    "/auth/reset-password", json={"token": "synthetic"}
                )
            self.assertEqual(response.status_code, status)
            self.assertNotIn("private", response.get_data(as_text=True))

    def test_missing_exp_is_rejected_by_actual_jwt_helper(self):
        import jwt

        source = ast.parse(Path("app.py").read_text(encoding="utf-8"))
        node = next(
            n
            for n in source.body
            if isinstance(n, ast.FunctionDef) and n.name == "decode_token"
        )
        from unittest.mock import Mock
        from datetime import datetime, timezone, timedelta

        db = Mock()
        db.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
            {"auth_version": 0}
        ]
        env = dict(
            jwt=jwt,
            JWT_SECRET="synthetic-only-signing-key-for-offline-tests",
            JWT_ALGORITHM="HS256",
            supabase=db,
        )
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "actual JWT helper", "exec"
            ),
            env,
        )
        token = jwt.encode(
            {"user_id": "synthetic", "av": 0}, env["JWT_SECRET"], algorithm="HS256"
        )
        self.assertIsNone(env["decode_token"](token))
        valid = jwt.encode(
            {
                "user_id": "synthetic",
                "av": 0,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=1),
            },
            env["JWT_SECRET"],
            algorithm="HS256",
        )
        self.assertIsNotNone(env["decode_token"](valid))
