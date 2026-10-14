"""NC-01A route/fixture scope cannot bypass the existing harness."""

import unittest
from unittest.mock import patch
import environment_safety as safety
from integration_harness import GuardedHarness


class AuthScopeSafetyTests(unittest.TestCase):
    def test_unknown_scope_refuses_before_config(self):
        with patch.object(safety, "load_test_config") as load, self.assertRaises(
            safety.SafetyError
        ):
            GuardedHarness("synthetic", characterization_scope="all-features")
        load.assert_not_called()

    def test_default_scope_still_denies_registration(self):
        context = object.__new__(GuardedHarness)
        context._brackets = set()
        context._matches = set()
        with self.assertRaises(safety.SafetyError):
            context._check_path("POST", "/auth/register")

    def test_auth_scope_limits_feature_routes(self):
        context = object.__new__(GuardedHarness)
        context.characterization_scope = "NC-01A"
        context._brackets = set()
        for method, path in (
            ("POST", "/bracket/create"),
            ("GET", "/leagues"),
            ("POST", "/internal/standings/refresh"),
        ):
            with self.assertRaises(safety.SafetyError):
                context._check_path(method, path)
        context._check_path("POST", "/auth/register")
        context._check_path("GET", "/__test__/identity", identity_bootstrap=True)

    def test_auth_helper_without_lease_refuses(self):
        context = object.__new__(GuardedHarness)
        context._closed = True
        with self.assertRaises(safety.SafetyError):
            context.auth_request("POST", "/auth/register", payload={})


if __name__ == "__main__":
    unittest.main()
