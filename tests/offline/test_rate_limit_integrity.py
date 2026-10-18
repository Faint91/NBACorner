"""R4 actual throttle/routes in isolated Flask; no application startup or IO."""

import ast
from collections import defaultdict
from functools import wraps
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from flask import Flask, jsonify, make_response, request

ROOT = Path(__file__).resolve().parents[2]
BASELINE = {
    "login_ip": (10, 60),
    "login_identifier": (5, 60),
    "forgot_ip": (5, 300),
    "forgot_identifier": (3, 300),
    "register_ip": (3, 3600),
    "health_ip": (30, 60),
}


class RateLimitIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.network = patch(
            "socket.socket.connect", side_effect=AssertionError("No network")
        )
        self.network.start()
        self.addCleanup(self.network.stop)
        self.tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        assignment = next(
            n
            for n in self.tree.body
            if isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "RATE_LIMITS" for t in n.targets
            )
        )
        self.assignment = assignment
        self.rates = ast.literal_eval(assignment.value)
        self.clock = SimpleNamespace(time=Mock(return_value=1000.0))
        self.role = {"user_id": "synthetic-admin", "is_admin": True}
        self.db_admin = True
        query = Mock()
        query.select.return_value = query
        query.eq.return_value = query
        query.execute.side_effect = lambda: SimpleNamespace(
            data=[{"is_admin": self.db_admin}]
        )
        self.db = Mock()
        self.db.table.return_value = query
        self.mail = Mock(return_value=True)
        self.app = Flask(__name__)
        self.env = dict(
            app=self.app,
            request=request,
            jsonify=jsonify,
            make_response=make_response,
            wraps=wraps,
            RATE_LIMITS=self.rates,
            DISABLE_RATE_LIMITS=False,
            ENABLE_DEBUG_LOGS=False,
            _rate_events=defaultdict(list),
            _rate_lock=threading.Lock(),
            time=self.clock,
            decode_token=lambda token: self.role,
            supabase=self.db,
            send_email_via_brevo=self.mail,
            safe_print=Mock(),
            HEALTHCHECK_TOKEN=None,
        )
        names = {
            "is_rate_limited",
            "get_client_ip",
            "require_auth",
            "test_email",
            "health",
            "register",
            "login",
            "forgot_password",
        }
        nodes = [
            n
            for n in self.tree.body
            if isinstance(n, ast.FunctionDef) and n.name in names
        ]
        self.assertEqual(len(nodes), len(names))
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]),
                "app.py isolated R4 routes",
                "exec",
            ),
            self.env,
        )
        self.client = self.app.test_client()

    def limited(self, bucket, key="192.0.2.10"):
        return self.env["is_rate_limited"](bucket, key)

    def email(self, ip="192.0.2.10", authenticated=True):
        headers = (
            {"Authorization": "Bearer synthetic-local-only"} if authenticated else {}
        )
        return self.client.post(
            "/test-email",
            json={"to": "admin@example.invalid"},
            headers=headers,
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def test_approved_bucket_and_existing_policies_unchanged(self):
        self.assertEqual(self.rates, dict(BASELINE, test_email_ip=(5, 900)))

    def test_runtime_inventory_and_no_duplicate_definitions(self):
        references = set()
        import subprocess

        files = (
            subprocess.check_output(
                ["git", "-c", "safe.directory=" + ROOT.as_posix(), "ls-files", "*.py"],
                cwd=ROOT,
            )
            .decode()
            .splitlines()
        )
        for file in files:
            if (
                file.startswith(("tests/", "scripts/", "test-infrastructure/"))
                or file == "conftest.py"
            ):
                continue
            tree = ast.parse((ROOT / file).read_text(encoding="utf-8-sig"))
            for n in ast.walk(tree):
                if (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name)
                    and n.func.id == "is_rate_limited"
                ):
                    self.assertIsInstance(n.args[0], ast.Constant, file)
                    references.add(n.args[0].value)
        self.assertEqual(references, set(self.rates))
        keys = [ast.literal_eval(k) for k in self.assignment.value.keys]
        self.assertEqual(len(keys), len(set(keys)))
        definitions = [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Name)
            and n.id == "RATE_LIMITS"
            and isinstance(n.ctx, ast.Store)
        ]
        self.assertEqual(len(definitions), 1)

    def test_first_four_fifth_and_sixth_http_contract(self):
        for _ in range(4):
            self.assertEqual(self.email().status_code, 200)
        self.assertEqual(self.email().status_code, 200)
        response = self.email()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.get_json(),
            {
                "error": "Too many test email attempts from this IP. Please try again later."
            },
        )
        self.assertEqual(self.mail.call_count, 5)
        self.mail.assert_called_with(
            "admin@example.invalid", "NBACorner test email", unittest.mock.ANY
        )

    def test_rolling_window_exact_expiry_and_denials_not_counted(self):
        for now in [1000, 1100, 1200, 1300, 1400]:
            self.clock.time.return_value = now
            self.assertEqual(self.email().status_code, 200)
        self.clock.time.return_value = 1899.99
        self.assertEqual(self.email().status_code, 429)
        self.clock.time.return_value = 1900
        self.assertEqual(self.email().status_code, 200)
        self.assertEqual(self.email().status_code, 429)
        self.clock.time.return_value = 2000
        self.assertEqual(self.email().status_code, 200)

    def test_independent_ips_and_other_buckets(self):
        for _ in range(5):
            self.assertEqual(self.email().status_code, 200)
        self.assertEqual(self.email().status_code, 429)
        self.assertEqual(self.email("192.0.2.11").status_code, 200)
        self.assertFalse(self.limited("login_ip"))
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_intentional_bypass_does_not_record_attempts(self):
        self.env["DISABLE_RATE_LIMITS"] = True
        for _ in range(8):
            self.assertEqual(self.email().status_code, 200)
        self.assertFalse(self.env["_rate_events"])
        self.env["DISABLE_RATE_LIMITS"] = False
        self.assertEqual(
            [self.email().status_code for _ in range(6)], [200] * 5 + [429]
        )

    def test_anonymous_and_non_admin_denied_before_mail_or_throttle(self):
        self.assertEqual(self.email(authenticated=False).status_code, 401)
        self.role = {"user_id": "ordinary", "is_admin": False}
        self.assertEqual(self.email().status_code, 403)
        self.role = {"user_id": "forged-admin", "is_admin": True}
        self.db_admin = False
        self.assertEqual(self.email().status_code, 403)
        self.mail.assert_not_called()
        self.assertFalse(self.env["_rate_events"])

    def test_existing_bucket_boundaries_and_expiry(self):
        for bucket, (limit, window) in BASELINE.items():
            with self.subTest(bucket=bucket):
                self.assertEqual(
                    [self.limited(bucket) for _ in range(limit)], [False] * limit
                )
                self.assertTrue(self.limited(bucket))
                self.clock.time.return_value = 1000 + window
                self.assertFalse(self.limited(bucket))
                self.clock.time.return_value = 1000

    def test_login_register_and_forgot_route_throttling(self):
        for bucket, route in [
            ("login_ip", "/auth/login"),
            ("register_ip", "/auth/register"),
        ]:
            with self.subTest(bucket=bucket):
                self.env["_rate_events"][(bucket, "192.0.2.10")] = [1000] * self.rates[
                    bucket
                ][0]
                response = self.client.post(
                    route, json={}, environ_overrides={"REMOTE_ADDR": "192.0.2.10"}
                )
                self.assertEqual(response.status_code, 429)
        with patch(
            "password_reset_service.request_identity",
            return_value=("username", "synthetic"),
        ):
            self.env["_rate_events"][("forgot_ip", "192.0.2.10")] = [1000] * 5
            response = self.client.post(
                "/auth/forgot-password",
                json={},
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            )
            self.assertEqual(response.status_code, 200)
            self.db.rpc.assert_not_called()
        self.mail.assert_not_called()

    def test_health_limit_and_existing_token_exemption(self):
        self.assertEqual(
            [self.client.get("/health").status_code for _ in range(30)], [200] * 30
        )
        self.assertEqual(self.client.get("/health").status_code, 429)
        self.env["HEALTHCHECK_TOKEN"] = "synthetic-local-health-token"
        self.assertEqual(
            self.client.get(
                "/health", headers={"X-Health-Token": "synthetic-local-health-token"}
            ).status_code,
            200,
        )

    def test_unknown_bucket_advisory_and_before_repair_evidence(self):
        self.rates.pop("test_email_ip")
        self.assertEqual([self.email().status_code for _ in range(8)], [200] * 8)
        self.assertFalse(self.env["_rate_events"])
