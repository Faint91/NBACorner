"""Offline NC-01D scope and retained runtime job refusal checks."""

import unittest
from unittest.mock import patch
from integration_harness import GuardedHarness
from environment_safety import SafetyError


class ScoringScopeSafetyTests(unittest.TestCase):
    def test_narrow_routes(self):
        c = object.__new__(GuardedHarness)
        c.characterization_scope = "NC-01D"
        c._brackets = set()
        for method, path in [
            ("POST", "/admin/season/rollover"),
            ("POST", "/leagues"),
            ("POST", "/bracket/create"),
            ("GET", "/leaderboard?league_id=arbitrary"),
        ]:
            with self.assertRaises(SafetyError):
                c._check_path(method, path)

    def test_helpers_need_lease(self):
        c = object.__new__(GuardedHarness)
        c._closed = True
        with self.assertRaises(SafetyError):
            c.install_scoring_read_state()

    def test_jobs_not_overridden(self):
        import job_safety

        with patch.object(
            job_safety,
            "runtime_safety_settings",
            return_value={"NBA_CORNER_ENV": "test"},
        ), self.assertRaises(SafetyError):
            job_safety.guard_runtime_job("score-recompute")

    def test_unknown_scope_before_config(self):
        with patch("environment_safety.load_test_config") as load, self.assertRaises(
            SafetyError
        ):
            GuardedHarness("unread", characterization_scope="NC-UNAPPROVED")
        load.assert_not_called()
