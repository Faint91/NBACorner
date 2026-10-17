"""R3 actual local reset flow with independently explicit synthetic frontend links."""

import hashlib
import re
import secrets
import unittest
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch
from email_transport import reset_link_for_settings, test_mailbox, CaptureMailbox
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class ResetRoutingAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01A"
        )
        self.c.__enter__()
        self.c.stack.enter_context(
            patch.object(self.c.module, "DISABLE_RATE_LIMITS", True)
        )
        # Only the link-builder configuration is injected. The actual HTTP API,
        # database RPCs and separately guarded capture transport remain unchanged.
        self.origin = "https://frontend.example.invalid"
        self.c.stack.enter_context(
            patch.object(
                self.c.module,
                "build_reset_link",
                lambda raw: reset_link_for_settings(
                    raw,
                    {"NBA_CORNER_ENV": "production", "FRONTEND_ORIGIN": self.origin},
                ),
            )
        )

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertTrue(self.c.cleanup_proof["fixture_checksum"] == CANONICAL_CHECKSUM)
        self.assertFalse(test_mailbox().inspect_messages())
        RESULTS.append(dict(scenario=self._testMethodName, canonical_cleanup=True))

    def call(self, path, data=None, role=None, method="POST"):
        return self.c.auth_request(method, path, payload=data, role=role)

    def test_frontend_link_real_reset_old_password_and_sessions(self):
        status, body = self.call(
            "/auth/login",
            {"email": "user-a@nba-corner.example", "password": "NCFixture!2026-user-a"},
        )
        self.assertEqual(status, 200)
        self.c._tokens["old"] = body["token"]
        self.assertEqual(self.call("/auth/test-me", role="old", method="GET")[0], 200)
        unknown = self.call(
            "/auth/forgot-password", {"email": "unknown@nba-corner.example"}
        )
        self.assertFalse(test_mailbox().inspect_messages())
        self.assertEqual(
            self.call("/auth/forgot-password", {"email": "user-a@nba-corner.example"}),
            unknown,
        )
        mail = test_mailbox().inspect_messages()[0]
        parsed = urlsplit(re.search(r'href="([^\"]+)"', mail.body)[1])
        params = parse_qs(parsed.query)
        raw = params["token"][0]
        self.assertTrue(
            parsed.scheme == "https"
            and parsed.hostname == "frontend.example.invalid"
            and parsed.path == "/reset-password"
        )
        self.assertTrue(set(params) == {"token"} and len(raw) == 43)
        self.assertTrue(parsed.hostname != "127.0.0.1")
        self.assertFalse(raw in repr(mail))
        self.assertEqual(
            self.call(
                "/auth/reset-password",
                {"token": raw, "new_password": "R3 synthetic exact password"},
            )[0],
            200,
        )
        self.assertEqual(
            self.call(
                "/auth/login",
                {
                    "email": "user-a@nba-corner.example",
                    "password": "NCFixture!2026-user-a",
                },
            )[0],
            401,
        )
        self.assertEqual(self.call("/auth/test-me", role="old", method="GET")[0], 401)
        status, body = self.call(
            "/auth/login",
            {
                "email": "user-a@nba-corner.example",
                "password": "R3 synthetic exact password",
            },
        )
        self.assertEqual(status, 200)
        self.c._tokens["fresh"] = body["token"]
        self.assertEqual(self.call("/auth/test-me", role="fresh", method="GET")[0], 200)
        self.assertEqual(
            self.call(
                "/auth/reset-password",
                {"token": raw, "new_password": "R3 synthetic exact password"},
            )[0],
            400,
        )
        self.assertFalse(self.c.auth_reset_records())

    def test_invalid_origin_cancels_without_enumeration_or_email(self):
        unknown = self.call(
            "/auth/forgot-password", {"email": "unknown@nba-corner.example"}
        )
        for value in [
            None,
            "",
            "/relative",
            "https://",
            "ftp://frontend.example.invalid",
            "http://frontend.example.invalid",
        ]:
            with patch.object(
                self.c.module,
                "build_reset_link",
                lambda raw: reset_link_for_settings(raw, {"FRONTEND_ORIGIN": value}),
            ):
                known = self.call(
                    "/auth/forgot-password", {"email": "user-a@nba-corner.example"}
                )
            self.assertEqual(known, unknown)
            self.assertFalse(test_mailbox().inspect_messages())
            self.assertFalse(self.c.auth_reset_records())

    def test_failed_delivery_does_not_cancel_newer_issuance(self):
        newer = secrets.token_urlsafe(32)
        digest = hashlib.sha256(newer.encode()).hexdigest()

        def newer_then_fail(*args):
            result = (
                self.c.module.supabase.rpc(
                    "issue_password_reset",
                    {"p_user_id": identity("user-a"), "p_digest": digest},
                )
                .execute()
                .data
            )
            self.assertTrue(result is True)
            return False

        unknown = self.call(
            "/auth/forgot-password", {"email": "unknown@nba-corner.example"}
        )
        with patch.object(CaptureMailbox, "send", side_effect=newer_then_fail):
            self.assertEqual(
                self.call(
                    "/auth/forgot-password", {"email": "user-a@nba-corner.example"}
                ),
                unknown,
            )
        rows = self.c.auth_reset_records()
        self.assertTrue(len(rows) == 1 and rows[0]["token_digest"] == digest)
        self.assertFalse(test_mailbox().inspect_messages())
        self.assertEqual(
            self.call(
                "/auth/reset-password",
                {"token": newer, "new_password": "R3 newer synthetic password"},
            )[0],
            200,
        )
