"""NC-02A1 direct API acceptance using unchanged NC-01C guarded facilities."""

import re
import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


def acceptance(*requirements):
    def decorate(fn):
        fn.metadata = {
            "scenario": fn.__name__,
            "classification": "APPROVED REQUIREMENT",
            "requirements": list(requirements),
            "phase": "NC-02A1",
        }
        return fn

    return decorate


class PrivacyAccessAcceptance(unittest.TestCase):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01C"
        )
        self.context.__enter__()

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.assertEqual(
            self.context.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM
        )
        RESULTS.append(
            {
                **getattr(self, self._testMethodName).metadata,
                "evidence": self.context.summary,
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def setup_leagues(self, *, empty=False):
        self.context.bracket_timing("open")
        ids = self.context.install_league_scenario(empty=empty)
        for role in ("user-a", "user-b", "owner", "admin"):
            self.context.login(role)
        return ids

    def call(self, path, status, role=None):
        actual, body = self.context.league_request("GET", path, role=role)
        self.assertEqual(actual, status)
        self.safe(body)
        return body

    def safe(self, value):
        if isinstance(value, dict):
            self.assertFalse(
                set(value)
                & {
                    "email",
                    "password",
                    "password_hash",
                    "reset_token",
                    "token",
                    "jwt",
                    "access_token",
                    "service_role_key",
                    "is_admin",
                }
            )
            for item in value.values():
                self.safe(item)
        elif isinstance(value, list):
            for item in value:
                self.safe(item)
        elif isinstance(value, str):
            self.assertFalse(
                bool(re.search(r"\$2[aby]\$\d\d\$|eyJ[\w-]+\.[\w-]+\.[\w-]+", value))
            )

    @acceptance("P1", "P2", "P6", "P7", "P8", "P10")
    def test_private_direct_api_role_matrix(self):
        ids = self.setup_leagues()
        self.context.install_league_score_surface()
        before = self.context.league_snapshot()
        lid = ids["private"]
        paths = [
            f"/leagues/{lid}/members",
            f"/brackets?league_id={lid}",
            f"/leaderboard?league_id={lid}",
            f"/stats/champion-picks?league_id={lid}",
            f"/stats/champion-picks?league_id={lid}&season_code=2024-25",
        ]
        for path in paths:
            for role, status in [
                (None, 401),
                ("user-b", 403),
                ("admin", 403),
                ("user-a", 200),
                ("owner", 200),
            ]:
                self.call(path, status, role)
        self.assertTrue(before == self.context.league_snapshot())

    @acceptance("P2", "P6", "P7", "P10")
    def test_owner_without_membership_all_private_surfaces(self):
        ids = self.setup_leagues(empty=True)
        status, _ = self.context.league_request(
            "POST",
            f"/leagues/{ids['private']}/join",
            role="user-a",
            payload={"password": "NCFixture!2026-private-league"},
        )
        self.assertEqual(status, 201)
        self.context.install_league_score_surface()
        lid = ids["private"]
        for path in [
            f"/leagues/{lid}/members",
            f"/brackets?league_id={lid}",
            f"/leaderboard?league_id={lid}",
            f"/stats/champion-picks?league_id={lid}",
        ]:
            self.call(path, 403, "owner")
            self.call(path, 403, "admin")
            self.call(path, 200, "user-a")

    @acceptance("P2", "P7", "P10")
    def test_membership_removal_takes_effect_without_new_token(self):
        ids = self.setup_leagues()
        lid = ids["private"]
        self.call(f"/leaderboard?league_id={lid}", 200, "user-a")
        status, _ = self.context.league_request(
            "DELETE", f"/leagues/{lid}/membership", role="user-a"
        )
        self.assertEqual(status, 200)
        for path in [
            f"/leagues/{lid}/members",
            f"/brackets?league_id={lid}",
            f"/leaderboard?league_id={lid}",
            f"/stats/champion-picks?league_id={lid}",
        ]:
            self.call(path, 403, "user-a")

    @acceptance("P1", "P3", "P8")
    def test_discovery_and_boolean_password_state(self):
        ids = self.setup_leagues()
        for role in ("user-a", "user-b", "owner", "admin"):
            rows = self.call("/leagues", 200, role)["leagues"]
            private = next(r for r in rows if r["id"] == ids["private"])
            self.assertIs(private["requires_password"], True)
            self.assertEqual(private["member_count"], 2)
            if role in {"user-b", "admin"}:
                self.assertEqual(
                    set(private),
                    {
                        "id",
                        "name",
                        "is_global",
                        "created_at",
                        "updated_at",
                        "is_member",
                        "member_count",
                        "requires_password",
                    },
                )
            for row in self.call("/leagues/me", 200, role)["leagues"]:
                self.assertIsInstance(row["requires_password"], bool)

    @acceptance("P1", "P8")
    def test_public_user_allowlist_and_nested_bracket_payloads(self):
        ids = self.setup_leagues()
        bid = self.context.install_bracket_scenario("saved", role="user-a")
        body = self.call(f"/bracket/{bid}", 200, "user-b")
        self.assertEqual(set(body["bracket"]["owner"]), {"id", "username"})
        self.call(f"/brackets?league_id={ids['public']}", 200, "user-b")
        safe = self.context.module.public_user(
            {
                "id": identity("user-a"),
                "username": "fixture",
                "email": "not-returned",
                "password_hash": "not-returned",
                "reset_token": "not-returned",
                "is_admin": True,
                "provider_key": "not-returned",
            }
        )
        self.assertEqual(set(safe), {"id", "username"})
        self.safe(safe)

    @acceptance("P2", "P7")
    def test_scoped_error_contracts(self):
        self.setup_leagues()
        for route in ("brackets", "leaderboard", "stats/champion-picks"):
            self.call(f"/{route}?league_id=invalid", 400, "user-a")
            self.call(f"/{route}?league_id={identity('missing-league')}", 404, "user-a")

    @acceptance("P1", "P2", "P6", "P8")
    def test_public_access_and_general_saved_visibility_preserved(self):
        ids = self.setup_leagues(empty=True)
        for role in ("owner", "admin"):
            self.call(f"/leagues/{ids['public']}/members", 200, role)
            self.call(f"/stats/champion-picks?league_id={ids['public']}", 200, role)
        self.call(f"/leagues/{ids['public']}/members", 403, "user-b")
        self.call(f"/brackets?league_id={ids['public']}", 200, "user-b")
        self.context.install_league_score_surface(draft_member=True)
        # NC-02A2 P4/P5/P9: only saved competitors; public scope requires auth.
        self.assertEqual(len(self.call("/leaderboard", 200)["rows"]), 1)
        self.call(f"/leaderboard?league_id={ids['public']}", 401)
        self.assertEqual(
            self.call(f"/leaderboard?league_id={ids['public']}", 200, "user-b")["rows"],
            [],
        )


PrivacyAccessAcceptance.test_public_access_and_general_saved_visibility_preserved.metadata.update(
    repair_phase="NC-02A2",
    additional_requirements=["P4", "P5", "P9"],
    prior_checkpoint="c2543b8aa97ee63b683a2a86f0ff047020cc5a29",
    transition="Previously deferred draft/public leaderboard assertions now enforce approved eligibility; all prior privacy assertions retained",
)
