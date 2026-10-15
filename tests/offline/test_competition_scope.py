"""NC-02A2 scope boundary checks; no app imports, network or DB mutations."""

import unittest
from integration_harness import GuardedHarness
from environment_safety import SafetyError
from synthetic_fixtures import identity


class CompetitionScopeSafety(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness.__new__(GuardedHarness)
        self.c.characterization_scope = "NC-02A2"
        self.c._leagues = {identity("league-public"), identity("league-private")}
        self.c._brackets = {identity("score-user-a")}
        self.c._matches = {(identity("score-user-a"), identity("known-match"))}

    def test_only_registered_competition_subjects(self):
        self.c._check_path("GET", f"/leaderboard?league_id={identity('league-public')}")
        self.c._check_path(
            "PATCH",
            f"/bracket/{identity('score-user-a')}/match/{identity('known-match')}",
        )
        for method, path in [
            ("GET", f"/leaderboard?league_id={identity('unregistered')}"),
            (
                "PATCH",
                f"/bracket/{identity('score-user-a')}/match/{identity('unregistered')}",
            ),
            ("GET", "/leaderboard?league_id=invalid"),
            (
                "GET",
                "/leaderboard?league_id="
                + identity("league-public")
                + "&extra=unreviewed",
            ),
        ]:
            with self.assertRaises(SafetyError):
                self.c._check_path(method, path)

    def test_jobs_lifecycle_and_arbitrary_routes_refused(self):
        for method, path in [
            ("POST", "/admin/leaderboard/snapshot"),
            ("POST", "/admin/season/rollover"),
            ("POST", f"/admin/score/master/{identity('score-user-a')}/recompute"),
            ("POST", "/internal/standings/refresh"),
            ("POST", "/leagues"),
            ("DELETE", f"/bracket/{identity('score-user-a')}"),
            ("GET", "/unreviewed"),
        ]:
            with self.assertRaises(SafetyError):
                self.c._check_path(method, path)

    def test_identity_admission_not_unconditionally_public(self):
        with self.assertRaises(SafetyError):
            self.c._check_path("GET", "/__test__/identity")
        self.c._check_path("GET", "/__test__/identity", identity_bootstrap=True)
