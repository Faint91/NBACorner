"""AUTH-STATS: actual issuer/auth decorators, synthetic keys/DB, no app startup."""
import ast
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request
from daily_assertion_service import issue_daily_assertion, daily_assertion_private_response, ISSUER

ROOT = Path(__file__).resolve().parents[2]


class DailyAssertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.config = {
            "DAILY_STATS_ASSERTION_PRIVATE_KEY": cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            "DAILY_STATS_ASSERTION_KEY_ID": "daily-stats-offline-1",
            "DAILY_STATS_ASSERTION_ISSUER": ISSUER,
        }

    def setUp(self):
        self.network = patch("socket.socket.connect", side_effect=AssertionError("No network permitted"))
        self.network.start(); self.addCleanup(self.network.stop)
        self.user_id = str(uuid.uuid4())
        self.rows = [{"id": self.user_id, "auth_version": 3}]
        self.rate = Mock(return_value=False)
        query = Mock(); query.select.return_value = query; query.eq.return_value = query
        query.execute.side_effect = lambda: SimpleNamespace(data=self.rows)
        db = Mock(); db.table.return_value = query
        app = Flask(__name__)
        env = dict(app=app, request=request, jsonify=jsonify, wraps=wraps, jwt=jwt,
                   JWT_SECRET="offline-nba-only-secret-at-least-32-bytes", JWT_ALGORITHM="HS256", supabase=db,
                   daily_assertion_private_response=daily_assertion_private_response,
                   issue_daily_assertion=lambda subject: issue_daily_assertion(subject, environ=self.config),
                   is_rate_limited=self.rate, get_client_ip=lambda: "offline")
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"decode_token", "require_auth", "daily_assertion"}]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "isolated auth issuer routes", "exec"), env)
        self.client = app.test_client()
        self.secret = env["JWT_SECRET"]

    def token(self, **changes):
        payload = dict(user_id=self.user_id, username="NEVER-IN-DAILY", is_admin=True, av=3,
                       exp=datetime.now(timezone.utc) + timedelta(minutes=1))
        payload.update(changes)
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def post(self, token=None, body=None):
        return self.client.post("/auth/daily-assertion", headers={"Authorization": "Bearer " + token} if token else {}, json={} if body is None else body)

    def test_valid_auth_has_only_daily_claims_and_short_lifetime(self):
        response = self.post(self.token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json), {"assertion", "expiresAt", "contract"})
        claims = jwt.decode(response.json["assertion"], self.key.public_key(), algorithms=["RS256"], audience="daily-stats", issuer=ISSUER)
        self.assertEqual(set(claims), {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "scope", "contract"})
        self.assertEqual(claims["sub"], self.user_id)
        self.assertEqual(claims["exp"] - claims["iat"], 45)
        self.assertEqual(claims["nbf"], claims["iat"])
        self.assertEqual(claims["scope"], "daily:stats")
        self.assertEqual(claims["contract"], "daily-stats-auth-v1")
        self.assertEqual(jwt.get_unverified_header(response.json["assertion"]), {"alg": "RS256", "kid": "daily-stats-offline-1", "typ": "daily-stats+jwt"})
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_missing_invalid_expired_and_wrong_signature_auth(self):
        bad = jwt.encode({"user_id": self.user_id, "exp": 9999999999}, "different-offline-secret-at-least32", algorithm="HS256")
        for token in (None, "invalid", bad, self.token(exp=datetime.now(timezone.utc) - timedelta(seconds=1))):
            response = self.post(token)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(set(response.json), {"error"})
            self.assertIn("no-store", response.headers["Cache-Control"])

    def test_auth_version_invalidation_and_missing_user(self):
        token = self.token()
        self.rows[0]["auth_version"] = 4
        self.assertEqual(self.post(token).status_code, 401)
        self.rows = []
        self.assertEqual(self.post(token).status_code, 401)

    def test_body_cannot_choose_identity_or_claims(self):
        for body in ({"sub": str(uuid.uuid4())}, {"userId": str(uuid.uuid4())}, {"scope": "admin"}, [], "bad"):
            self.assertEqual(self.post(self.token(), body).status_code, 400)
        for body in ("null", "{broken", "arbitrary-uuid-text"):
            response = self.client.post("/auth/daily-assertion", data=body, content_type="application/json",
                                        headers={"Authorization": "Bearer " + self.token()})
            self.assertEqual(response.status_code, 400)

    def test_throttle_and_missing_configuration_fail_sanitized(self):
        self.rate.return_value = True
        self.assertEqual(self.post(self.token()).status_code, 429)
        self.rate.return_value = False
        with patch.dict(self.config, {"DAILY_STATS_ASSERTION_PRIVATE_KEY": "invalid"}):
            response = self.post(self.token())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json, {"error": "Daily authentication unavailable"})

    def test_issuer_rotation_key_validation(self):
        for field, value in (("DAILY_STATS_ASSERTION_ISSUER", "https://wrong.test"), ("DAILY_STATS_ASSERTION_KEY_ID", "ordinary-key")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                issue_daily_assertion(self.user_id, environ={**self.config, field: value})
        one = issue_daily_assertion(self.user_id, environ=self.config)
        two = issue_daily_assertion(self.user_id, environ=self.config)
        a = jwt.decode(one["assertion"], self.key.public_key(), algorithms=["RS256"], audience="daily-stats")
        b = jwt.decode(two["assertion"], self.key.public_key(), algorithms=["RS256"], audience="daily-stats")
        self.assertNotEqual(a["jti"], b["jti"])


if __name__ == "__main__": unittest.main()
