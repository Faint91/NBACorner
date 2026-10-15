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


class AutomaticScoringAdmissionTests(unittest.TestCase):
    def test_only_context_bound_registered_auto_mutations_admitted(self):
        import integration_harness as harness
        from flask import Flask
        from unittest.mock import Mock

        permit = object.__new__(GuardedHarness)
        permit._ready = True
        permit._require_lease = Mock()
        permit._admission = "synthetic-scoring-context"
        permit.characterization_scope = "NC-02D1"
        permit._scoring_active = False
        permit._matches = {("bracket", "match")}
        app = Flask("offline-scoring-admission")
        with patch.object(harness, "_ACTIVE", permit):
            for method, path, expected in [
                ("POST", "/bracket/create", True),
                ("PATCH", "/bracket/bracket/match/match", True),
                ("PATCH", "/bracket/match/match/games", True),
                ("PATCH", "/bracket/other/match/match", False),
                ("POST", "/admin/score/recompute", False),
                ("POST", "/admin/season/rollover", False),
                ("GET", "/bracket/create", False),
            ]:
                with self.subTest(path=path, method=method), app.test_request_context(
                    path,
                    method=method,
                    headers={"X-NBA-Test-Context": permit._admission},
                ):
                    self.assertEqual(
                        harness.authorize_scoring_test_job("score-recompute"), expected
                    )
                    self.assertFalse(
                        harness.authorize_scoring_test_job("standings-refresh")
                    )
            with app.test_request_context("/bracket/create", method="POST"):
                self.assertFalse(harness.authorize_scoring_test_job("score-recompute"))
            self.assertFalse(harness.authorize_scoring_test_job("score-recompute"))

    def test_no_active_harness_refuses_automatic_job(self):
        import integration_harness as harness

        with patch.object(harness, "_ACTIVE", None):
            self.assertFalse(harness.authorize_scoring_test_job("score-recompute"))
