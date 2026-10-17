"""Approved G1 live acceptance through the existing guarded auth test lane."""

import unittest
from unittest.mock import patch
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class IdentityAuthAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01A"
        )
        self.c.__enter__()
        # Grouped matrices deliberately exceed per-IP limits; preserve rate-limit acceptance separately.
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
                cleanup_checksum=CANONICAL_CHECKSUM,
            )
        )

    def call(self, path, payload):
        return self.c.auth_request("POST", path, payload=payload)

    def register(
        self, name="G1Mixed", email="g1@nba-corner.example", password="abcdefgh"
    ):
        return self.call(
            "/auth/register", dict(username=name, email=email, password=password)
        )

    def login(self, identity_value, password, field="email"):
        return self.call("/auth/login", {field: identity_value, "password": password})

    def test_request_shapes_and_field_types(self):
        for payload in (
            None,
            [],
            [1],
            "text",
            42,
            {},
            {"email": 4, "username": 3, "password": []},
            {
                "username": True,
                "email": "g1@nba-corner.example",
                "password": "abcdefgh",
            },
        ):
            for route in ("/auth/register", "/auth/login"):
                status, body = self.call(route, payload)
                self.assertTrue(400 <= status < 500)
                self.assertEqual(set(body), {"error"})
        for email in ("bad\x00@nba-corner.example", "bad\ud800@nba-corner.example"):
            self.assertEqual(self.register(email=email)[0], 400)
            self.assertEqual(self.login(email, "abcdefgh")[0], 401)
        for missing in ("username", "email", "password"):
            payload = dict(
                username="G1Mixed", email="g1@nba-corner.example", password="abcdefgh"
            )
            payload.pop(missing)
            self.assertEqual(self.call("/auth/register", payload)[0], 400)

    def test_identity_normalization_display_and_conflicts(self):
        status, body = self.register(" \tG1Mixed\u00a0 ", " G1@NBA-CORNER.EXAMPLE ")
        self.assertEqual(status, 201)
        self.assertEqual(body["user"]["username"], "G1Mixed")
        self.assertEqual(body["user"]["email"], "g1@nba-corner.example")
        self.assertEqual(self.register("g1mixed", "other@nba-corner.example")[0], 409)
        self.assertEqual(self.register("anotherG1", " G1@NBA-CORNER.EXAMPLE ")[0], 409)
        self.assertEqual(self.register(" ", "other@nba-corner.example")[0], 400)
        for value, field in (
            (" G1MIXED ", "username"),
            (" G1@NBA-CORNER.EXAMPLE ", "email"),
        ):
            result = self.login(value, "abcdefgh", field)
            self.assertEqual(result[0], 200)
            self.assertEqual(result[1]["user"]["id"], body["user"]["id"])

    def test_password_boundaries_and_no_complexity(self):
        for i, password in enumerate(
            ("a" * 8, "a" * 72, "a" * 73, "a" * 128, "界" * 40, "😀" * 32, " " * 8)
        ):
            email = f"g1-{i}@nba-corner.example"
            self.assertEqual(self.register(f"G1Long{i}", email, password)[0], 201)
            self.assertEqual(self.login(email, password)[0], 200)
            self.assertEqual(self.login(email, password + "x")[0], 401)
        for password in ("a" * 7, "a" * 129, 5, [], None):
            self.assertEqual(self.register(password=password)[0], 400)

    def test_long_shared_prefix_never_authenticates(self):
        value = "a" * 72 + "left"
        self.assertEqual(self.register(password=value)[0], 201)
        self.assertEqual(self.login("g1@nba-corner.example", value)[0], 200)
        self.assertEqual(
            self.login("g1@nba-corner.example", "a" * 72 + "right")[0], 401
        )
        self.assertEqual(self.login("g1@nba-corner.example", "a" * 72)[0], 401)

    def test_outer_password_whitespace_is_exact(self):
        for i, value in enumerate((" abcdefgh", "abcdefgh ", " abcdefgh ")):
            email = f"g1-space-{i}@nba-corner.example"
            self.assertEqual(self.register(f"G1Space{i}", email, value)[0], 201)
            self.assertEqual(self.login(email, value)[0], 200)
            self.assertEqual(self.login(email, value.strip())[0], 401)
            self.assertEqual(self.login(email, value + " ")[0], 401)

    def test_legacy_and_generic_login_and_jwt(self):
        expected = None
        for value, password in (
            ("unknown_name", "wrong"),
            ("user-a@nba-corner.example", "wrong"),
            ("invalid format!", "wrong"),
        ):
            result = self.login(value, password)
            if expected is None:
                expected = result
            self.assertEqual(result, expected)
        self.assertEqual(expected[0], 401)
        status, body = self.login(
            " USER-A@NBA-CORNER.EXAMPLE ", "NCFixture!2026-user-a"
        )
        self.assertEqual(status, 200)
        claims = self.c.module.decode_token(body["token"])
        self.assertEqual(set(claims), {"user_id", "username", "is_admin", "exp", "av"})
        self.assertEqual(claims["user_id"], identity("user-a"))
        self.assertEqual(
            set(body["user"]), {"id", "email", "username", "is_admin", "created_at"}
        )
        for variant in (" NCFixture!2026-user-a", "NCFixture!2026-user-a "):
            self.assertEqual(self.login("user-a@nba-corner.example", variant)[0], 401)

    def test_unicode_email_uses_database_normalization(self):
        email = "\tİG1@NBA-CORNER.EXAMPLE\u00a0"
        status, body = self.register(email=email)
        self.assertEqual(status, 201)
        normalized = (
            self.c.module.supabase.rpc("auth_identity_key", {"p_value": email})
            .execute()
            .data
        )
        self.assertEqual(body["user"]["email"], normalized)
        self.assertEqual(self.login(email, "abcdefgh")[0], 200)
        self.assertEqual(self.register("G1Other", email)[0], 409)

    def test_existing_registration_rate_limit_remains(self):
        self.c.module.DISABLE_RATE_LIMITS = False
        for _ in range(3):
            self.assertEqual(self.register(name="bad-name")[0], 400)
        self.assertEqual(self.register(name="bad-name")[0], 429)
