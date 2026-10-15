"""NC-01E does not enable jobs or broaden existing scopes."""

import unittest
from unittest.mock import patch
from integration_harness import GuardedHarness
from environment_safety import SafetyError


class OperationScopeSafetyTests(unittest.TestCase):
    def test_unapproved_scope(self):
        with patch("environment_safety.load_test_config") as load, self.assertRaises(
            SafetyError
        ):
            GuardedHarness("unread", characterization_scope="NC-UNAPPROVED")
        load.assert_not_called()

    def test_scope_denies_product_writes(self):
        c = object.__new__(GuardedHarness)
        c.characterization_scope = "NC-01E"
        for method, path in [
            ("POST", "/bracket/create"),
            ("POST", "/leagues"),
            ("GET", "/internal/standings/refresh?token=synthetic"),
        ]:
            with self.assertRaises(SafetyError):
                c._check_path(method, path)

    def test_helper_requires_lease(self):
        c = object.__new__(GuardedHarness)
        c._closed = True
        with self.assertRaises(SafetyError):
            c.operational_request("POST", "/admin/season/rollover")
