"""NC-02B1 scope remains fail-closed; no app import/network/database."""

import unittest
from unittest.mock import Mock
import environment_safety as safety
from integration_harness import GuardedHarness


class BracketLockScopeTests(unittest.TestCase):
    def context(self):
        c = object.__new__(GuardedHarness)
        c.characterization_scope = "NC-02B1"
        c._brackets = {"fixture-bracket"}
        c._matches = {("fixture-bracket", "fixture-match")}
        c._leagues = {"fixture-league"}
        return c

    def test_only_registered_content_and_existing_reads_allowed(self):
        c = self.context()
        for method, path in [
            ("POST", "/bracket/create"),
            ("PATCH", "/bracket/fixture-bracket/save"),
            ("PATCH", "/bracket/fixture-bracket/match/fixture-match"),
            ("PATCH", "/bracket/match/fixture-match/games"),
            ("GET", "/leaderboard?league_id=fixture-league"),
        ]:
            c._check_path(method, path)
        for method, path in [
            ("DELETE", "/bracket/fixture-bracket"),
            ("POST", "/admin/season/rollover"),
            ("POST", "/admin/standings/refresh"),
            ("PATCH", "/bracket/unknown/save"),
            ("GET", "https://example.invalid"),
            ("GET", "/__test__/identity"),
        ]:
            with self.assertRaises(safety.SafetyError):
                c._check_path(method, path)

    def test_boundary_helper_requires_live_lease(self):
        c = self.context()
        c._require_bracket_scope = Mock(
            side_effect=safety.SafetyError("Lease required")
        )
        with self.assertRaises(safety.SafetyError):
            c.bracket_deadline_boundary("at")

    def test_boundary_helper_rejects_other_scope_and_unreviewed_mode(self):
        c = self.context()
        c._require_bracket_scope = Mock()
        with self.assertRaises(safety.SafetyError):
            c.bracket_deadline_boundary("unknown")
        c.characterization_scope = "NC-02A2"
        with self.assertRaises(safety.SafetyError):
            c.bracket_deadline_boundary("at")
