"""NC-01C exact query/route safety, no local DB access."""

import unittest
from unittest.mock import patch
from integration_harness import GuardedHarness
from environment_safety import SafetyError
from synthetic_fixtures import identity


class LeagueScopeSafetyTests(unittest.TestCase):
    def context(self, scope):
        c = object.__new__(GuardedHarness)
        c.characterization_scope = scope
        c._leagues = {identity("league-private")}
        c._brackets = set()
        c._matches = set()
        return c

    def test_other_features_and_query_escape_denied(self):
        c = self.context("NC-01C")
        for method, path in [
            ("POST", "/auth/register"),
            ("POST", "/bracket/create"),
            ("POST", "/admin/season/rollover"),
            ("GET", "/brackets?league_id=" + identity("league-private") + "&escape=1"),
            ("GET", "/leagues/unknown/members"),
            ("PATCH", "/leagues/" + identity("league-private")),
        ]:
            with self.assertRaises(SafetyError):
                c._check_path(method, path)
        c._check_path("GET", "/brackets?league_id=" + identity("league-private"))

    def test_helpers_without_lease_refused(self):
        c = self.context("NC-01C")
        c._closed = True
        for call in [
            lambda: c.league_request("POST", "/leagues"),
            lambda: c.install_league_scenario(),
            lambda: c.league_snapshot(),
            lambda: c.install_league_score_surface(),
        ]:
            with self.assertRaises(SafetyError):
                call()

    def test_older_scopes_do_not_gain_writes_or_queries(self):
        for scope in [None, "NC-01A", "NC-01B"]:
            c = self.context(scope)
            for method, path in [
                ("POST", "/leagues"),
                ("GET", "/brackets?league_id=" + identity("league-private")),
            ]:
                with self.assertRaises(SafetyError):
                    c._check_path(method, path)

    def test_next_scope_not_implicitly_allowed(self):
        with patch("environment_safety.load_test_config") as load, self.assertRaises(
            SafetyError
        ):
            GuardedHarness("unread", characterization_scope="NC-UNAPPROVED")
        load.assert_not_called()
