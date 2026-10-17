"""Approved A8-A16 acceptance; synthetic links inspected in memory only."""

import hashlib
import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import jwt
from email_transport import test_mailbox, CaptureMailbox
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class PasswordResetAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01A"
        )
        self.c.__enter__()
        self.c.stack.enter_context(
            patch.object(self.c.module, "DISABLE_RATE_LIMITS", True)
        )

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            dict(
                phase="NC-02G2",
                scenario=self._testMethodName,
                canonical_cleanup=True,
                cleanup_checksum=CANONICAL_CHECKSUM,
            )
        )

    def call(self, path, data=None, role=None, method="POST"):
        return self.c.auth_request(method, path, payload=data, role=role)

    def issue(self, who="user-a@nba-corner.example", field="email"):
        result = self.call("/auth/forgot-password", {field: who})
        self.assertEqual(result[0], 200)
        mail = test_mailbox().inspect_messages()[-1]
        token = re.search(r"\?token=([A-Za-z0-9_-]+)", mail.body)[1]
        self.assertEqual(len(token), 43)
        return token

    def reset(self, token, password="a" * 73):
        return self.call(
            "/auth/reset-password", dict(token=token, new_password=password)
        )

    def version(self, role="user-a"):
        return (
            self.c.module.supabase.table("users")
            .select("auth_version,password")
            .eq("id", identity(role))
            .execute()
            .data[0]
        )

    def login(
        self, password="NCFixture!2026-user-a", email="user-a@nba-corner.example"
    ):
        return self.call("/auth/login", dict(email=email, password=password))

    def test_enumeration_digest_entropy_capture_ttl(self):
        unknown = self.call(
            "/auth/forgot-password", {"email": "unknown@nba-corner.example"}
        )
        self.assertFalse(test_mailbox().inspect_messages())
        known = self.call(
            "/auth/forgot-password", {"email": " USER-A@NBA-CORNER.EXAMPLE "}
        )
        self.assertEqual(known, unknown)
        self.assertEqual(set(known[1]), {"message"})
        rows = self.c.auth_reset_records()
        self.assertEqual(len(rows), 1)
        token = re.search(
            r"\?token=([A-Za-z0-9_-]+)", test_mailbox().inspect_messages()[0].body
        )[1]
        self.assertEqual(
            rows[0]["token_digest"], hashlib.sha256(token.encode()).hexdigest()
        )
        self.assertNotIn(token, str(rows))
        self.assertNotIn(token, str(known))
        ttl = (
            datetime.fromisoformat(rows[0]["expires_at"]) - datetime.now(timezone.utc)
        ).total_seconds()
        self.assertTrue(3580 < ttl <= 3600)
        self.assertEqual(self.version()["auth_version"], 0)

    def test_supersession_success_replay_and_single_increment(self):
        old = self.issue()
        new = self.issue()
        self.assertNotEqual(old, new)
        self.assertEqual(len(self.c.auth_reset_records()), 1)
        self.assertEqual(self.reset(old)[0], 400)
        self.assertEqual(self.reset(new)[0], 200)
        state = self.version()
        self.assertEqual(state["auth_version"], 1)
        self.assertTrue(state["password"].startswith("nc-bcrypt-sha256-v1$"))
        self.assertFalse(self.c.auth_reset_records())
        self.assertEqual(self.reset(new)[0], 400)
        self.assertEqual(self.version(), state)

    def test_multidevice_and_legacy_revocation_new_login(self):
        for role in ("device-a", "device-b"):
            status, body = self.login()
            self.assertEqual(status, 200)
            self.c._tokens[role] = body["token"]
        claims = jwt.decode(
            self.c._tokens["device-a"],
            self.c.module.JWT_SECRET,
            algorithms=[self.c.module.JWT_ALGORITHM],
        )
        claims.pop("av")
        self.c._tokens["legacy"] = jwt.encode(
            claims, self.c.module.JWT_SECRET, algorithm=self.c.module.JWT_ALGORITHM
        )
        self.c.login("user-b")
        for role in ("device-a", "device-b", "legacy", "user-b"):
            self.assertEqual(
                self.call("/auth/test-me", role=role, method="GET")[0], 200
            )
        self.assertEqual(self.reset(self.issue(), " exact password ")[0], 200)
        for role in ("device-a", "device-b", "legacy"):
            self.assertEqual(
                self.call("/auth/test-me", role=role, method="GET")[0], 401
            )
        self.assertEqual(
            self.call("/auth/test-me", role="user-b", method="GET")[0], 200
        )
        self.assertEqual(self.login()[0], 401)
        status, body = self.login(" exact password ")
        self.assertEqual(status, 200)
        self.assertEqual(
            jwt.decode(
                body["token"],
                self.c.module.JWT_SECRET,
                algorithms=[self.c.module.JWT_ALGORITHM],
            )["av"],
            1,
        )
        self.c._tokens["fresh"] = body["token"]
        status, body = self.call("/auth/test-me", role="fresh", method="GET")
        self.assertEqual(status, 200)
        self.assertNotIn("av", body["user"])
        self.assertEqual(self.login("exact password")[0], 401)

    def test_expired_invalid_and_malformed(self):
        token = self.issue()
        self.c.expire_auth_reset(token)
        before = self.version()
        for value in (token, "x" * 43, "short", None, [], 12):
            self.assertEqual(self.reset(value)[0], 400)
        for data in (
            None,
            [],
            "text",
            {},
            {"token": token},
            {"new_password": "abcdefgh"},
        ):
            self.assertEqual(self.call("/auth/reset-password", data)[0], 400)
        self.assertEqual(self.version(), before)

    def test_password_exactness_unicode_long_and_boundaries(self):
        for value in ("a" * 7, "a" * 129, None, 3, [], "\ud800" * 8):
            self.assertEqual(self.reset(self.issue(), value)[0], 400)
        for value in (" " * 8, "a" * 128, "😀" * 128, "界" * 40, "a" * 72 + "left"):
            self.assertEqual(self.reset(self.issue(), value)[0], 200)
            self.assertEqual(self.login(value)[0], 200)
            self.assertEqual(self.login(value + "x")[0], 401)
        self.assertEqual(self.login("a" * 72 + "right")[0], 401)

    def test_request_input_and_username_normalization(self):
        for data in (
            None,
            [],
            "text",
            {},
            {"email": 4},
            {"username": []},
            {"email": "invalid"},
        ):
            self.assertEqual(self.call("/auth/forgot-password", data)[0], 400)
        self.assertEqual(
            self.call(
                "/auth/register",
                dict(
                    email="g2@nba-corner.example",
                    username="G2Name",
                    password="abcdefgh",
                ),
            )[0],
            201,
        )
        token = self.issue(" G2NAME ", "username")
        self.assertEqual(self.reset(token)[0], 200)

    def test_delivery_failure_conditional_cleanup_and_generic_response(self):
        unknown = self.call(
            "/auth/forgot-password", {"email": "unknown@nba-corner.example"}
        )
        with patch.object(CaptureMailbox, "send", return_value=False):
            self.assertEqual(
                self.call(
                    "/auth/forgot-password", {"email": "user-a@nba-corner.example"}
                ),
                unknown,
            )
        self.assertFalse(self.c.auth_reset_records())
        self.assertFalse(test_mailbox().inspect_messages())
        self.assertEqual(self.version()["auth_version"], 0)

    def test_jwt_bad_versions_missing_subject_and_admin_nonbypass(self):
        self.c.login("admin")
        original = jwt.decode(
            self.c._tokens["admin"],
            self.c.module.JWT_SECRET,
            algorithms=[self.c.module.JWT_ALGORITHM],
        )
        for change in (
            {"av": 1},
            {"av": True},
            {"av": "0"},
            {"av": None},
            {"user_id": identity("missing-g2")},
            {"user_id": "malformed"},
        ):
            self.c._tokens["bad"] = jwt.encode(
                dict(original, **change),
                self.c.module.JWT_SECRET,
                algorithm=self.c.module.JWT_ALGORITHM,
            )
            self.assertEqual(
                self.call("/auth/test-me", role="bad", method="GET")[0], 401
            )
        self.assertEqual(
            self.call(
                "/auth/reset-password",
                {"user_id": identity("user-a"), "new_password": "abcdefgh"},
                role="admin",
            )[0],
            400,
        )
        self.assertEqual(self.version()["auth_version"], 0)
