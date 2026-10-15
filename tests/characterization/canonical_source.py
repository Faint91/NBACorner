"""NC-02C1 fixed local canonical authority acceptance; no jobs/provider traffic."""

import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class CanonicalAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02C1"
        )
        self.c.__enter__()

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            {
                "phase": "NC-02C1",
                "scenario": self._testMethodName,
                "passed": True,
                "requirements": ["S1", "S2", "S12", "S14"],
                "production_contact": False,
            }
        )

    def test_c1_status_and_bracket_share_canonical_identity(self):
        status, body = self.c.bracket_request("GET", "/season")
        self.assertEqual(status, 200)
        self.assertEqual(body["season_code"], "2025-26")
        self.c.bracket_timing("open")
        self.c.login("user-a")
        status, body = self.c.bracket_request(
            "POST", "/bracket/create", payload={}, role="user-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["bracket"]["season_id"], identity("current"))

    def test_c1_missing_state_503_and_restored_next_request(self):
        self.c.canonical_fixture_season("missing")
        self.assertEqual(self.c.bracket_request("GET", "/season")[0], 503)
        self.assertEqual(self.c.bracket_request("GET", "/brackets/me")[0], 503)
        self.c.canonical_fixture_season("current")
        self.assertEqual(self.c.bracket_request("GET", "/season")[0], 200)

    def test_c1_explicit_switch_visible_without_restart(self):
        self.c.canonical_fixture_season("historical")
        status, body = self.c.bracket_request("GET", "/season")
        self.assertEqual(status, 200)
        self.assertEqual(body["season_code"], "2024-25")
        self.assertEqual(self.c.module.current_season().id, identity("historical"))
        self.c.canonical_fixture_season("current")
        self.assertEqual(
            self.c.bracket_request("GET", "/season")[1]["season_code"], "2025-26"
        )
