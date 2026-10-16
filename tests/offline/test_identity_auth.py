"""Network-free G1 password, malformed-request and auth non-bypass checks."""

import ast
import bcrypt
import unittest
from pathlib import Path
from unittest.mock import Mock
from flask import Flask
from identity_auth_service import (
    hash_password,
    verify_password,
    validate_password,
    normalize_username_display,
    normalize_username_key,
)

ROOT = Path(__file__).resolve().parents[2]


class ExactPasswordTests(unittest.TestCase):
    def test_boundaries_codepoints_and_long_shared_prefix(self):
        for value in (
            "a" * 8,
            "a" * 72,
            "a" * 73,
            "a" * 128,
            "界" * 40,
            "😀" * 128,
            " " * 8,
        ):
            stored = hash_password(value, rounds=4)
            self.assertTrue(verify_password(value, stored))
            self.assertFalse(verify_password(value + "x", stored))
        value = "a" * 72 + "first"
        stored = hash_password(value, rounds=4)
        self.assertFalse(verify_password("a" * 72 + "second", stored))

    def test_policy(self):
        for value in (None, False, [], {}, 42, "a" * 7, "a" * 129):
            with self.assertRaises(ValueError):
                validate_password(value)
        for value in (" abcdefgh", "abcdefgh ", " abcdefgh "):
            stored = hash_password(value, rounds=4)
            self.assertTrue(verify_password(value, stored))
            self.assertFalse(verify_password(value.strip(), stored))

    def test_legacy_invalid_hash_no_truncation(self):
        stored = bcrypt.hashpw(b"legacy-exact", bcrypt.gensalt(4)).decode()
        self.assertTrue(verify_password("legacy-exact", stored))
        self.assertFalse(verify_password(" legacy-exact", stored))
        self.assertFalse(verify_password("legacy-exact ", stored))
        for invalid in (None, "invalid", "nc-bcrypt-sha256-v1$invalid"):
            self.assertFalse(verify_password("legacy-exact", invalid))
        self.assertFalse(verify_password("a" * 73, stored))

    def test_username_normalization(self):
        self.assertEqual(normalize_username_display(" \tMiXeD\u00a0"), "MiXeD")
        self.assertEqual(normalize_username_key(" MiXeD "), "mixed")
        with self.assertRaises(ValueError):
            normalize_username_display(4)


class RouteTests(unittest.TestCase):
    def app(self, db):
        import flask

        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        app = Flask(__name__)
        nodes = [
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name in {"register", "login"}
        ]
        env = dict(
            app=app,
            request=flask.request,
            jsonify=flask.jsonify,
            is_rate_limited=lambda *a: False,
            get_client_ip=lambda: "local",
            supabase=db,
            BCRYPT_ROUNDS=4,
            DUMMY_LOGIN_HASH=bcrypt.hashpw(b"dummy", bcrypt.gensalt(4)).decode(),
            generate_token=lambda *args: "synthetic",
        )
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]), "G1 extracted routes", "exec"
            ),
            env,
        )
        return app.test_client()

    def test_malformed_raw_json_and_types_no_database_access(self):
        db = Mock()
        client = self.app(db)
        for body in (
            "null",
            "[]",
            '"text"',
            "42",
            "{broken",
            '{"username":42,"email":[],"password":false}',
            '{"username":"ValidG1","email":"bad\\u0000@example.test","password":"abcdefgh"}',
            '{"username":"ValidG1","email":"bad\\ud800@example.test","password":"abcdefgh"}',
        ):
            for route in ("register", "login"):
                response = client.post(
                    "/auth/" + route, data=body, content_type="application/json"
                )
                self.assertTrue(400 <= response.status_code < 500)
                self.assertEqual(set(response.json), {"error"})
        db.table.assert_not_called()
        db.rpc.assert_not_called()

    def test_database_error_sanitized(self):
        db = Mock()
        db.rpc.side_effect = RuntimeError("private SQL connection data")
        client = self.app(db)
        for route, payload in (
            (
                "register",
                dict(username="ValidG1", email="g1@example.test", password="abcdefgh"),
            ),
            ("login", dict(username="ValidG1", password="abcdefgh")),
        ):
            response = client.post("/auth/" + route, json=payload)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("private", response.get_data(as_text=True))

    def test_registration_race_constraint_error_is_conflict(self):
        db = Mock()
        db.rpc.return_value.execute.return_value.data = "g1@example.test"
        error = RuntimeError("private index name and SQLSTATE")
        error.code = "23505"
        db.table.return_value.insert.return_value.execute.side_effect = error
        response = self.app(db).post(
            "/auth/register",
            json=dict(username="ValidG1", email="g1@example.test", password="abcdefgh"),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json, {"error": "Email or username already in use"})

    def test_no_admin_password_bypass(self):
        db = Mock()
        db.rpc.return_value.execute.return_value.data = dict(
            id="ordinary",
            username="ordinary",
            password=hash_password("abcdefgh", rounds=4),
            is_admin=False,
        )
        client = self.app(db)
        for extras in (
            {"is_admin": True},
            {"impersonate": True},
            {"user_id": "ordinary"},
        ):
            response = client.post(
                "/auth/login",
                json=dict(username="ordinary", password="wrong", **extras),
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(set(response.json), {"error"})
