"""NC-01B cannot broaden other harness scopes or bypass a verified lease."""

import unittest
from integration_harness import GuardedHarness
from environment_safety import SafetyError
from synthetic_fixtures import identity


class BracketScopeSafetyTests(unittest.TestCase):
    def context(self, scope):
        c = object.__new__(GuardedHarness)
        c.characterization_scope = scope
        c._brackets = {identity("bracket-draft")}
        c._matches = {(identity("bracket-draft"), identity("match"))}
        return c

    def test_bracket_scope_denies_other_features_and_query_escape(self):
        c = self.context("NC-01B")
        for method, path in [
            ("POST", "/auth/register"),
            ("POST", "/leagues"),
            ("POST", "/admin/season/rollover"),
            ("POST", "/internal/standings/refresh"),
            ("GET", "/brackets?league_id=anything"),
            ("GET", "/bracket/arbitrary"),
        ]:
            with self.assertRaises(SafetyError):
                c._check_path(method, path)
        c._check_path("GET", "/brackets")

    def test_helpers_require_active_context(self):
        c = self.context("NC-01B")
        c._closed = True
        for call in [
            lambda: c.bracket_timing("open"),
            lambda: c.install_bracket_scenario("draft"),
            lambda: c.bracket_snapshot(),
            lambda: c.bracket_request("DELETE", "/bracket/invalid"),
        ]:
            with self.assertRaises(SafetyError):
                call()

    def test_other_scopes_stay_narrow(self):
        for scope in [None, "NC-01A"]:
            c = self.context(scope)
            for path in [
                f'/bracket/{identity("bracket-draft")}/save',
                f'/bracket/match/{identity("match")}/games',
            ]:
                with self.assertRaises(SafetyError):
                    c._check_path("PATCH", path)

    def test_unknown_scope_still_rejected(self):
        with self.assertRaises(SafetyError):
            GuardedHarness("unread", characterization_scope="NC-01C")
