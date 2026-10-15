"""NC-02B2 fixed fault injection cannot bypass the existing lease/scope guards."""

import unittest
from unittest.mock import Mock
import environment_safety as safety
from integration_harness import GuardedHarness


class BracketValidityScope(unittest.TestCase):
    def test_fault_requires_live_bracket_lease(self):
        context = object.__new__(GuardedHarness)
        context._require_bracket_scope = Mock(
            side_effect=safety.SafetyError("Lease required")
        )
        with self.assertRaises(safety.SafetyError):
            with context.bracket_validity_fault("count_3"):
                pass

    def test_fault_requires_b2_and_fixed_reviewed_case(self):
        context = object.__new__(GuardedHarness)
        context._require_bracket_scope = Mock()
        for scope, kind in [("NC-02B1", "count_3"), ("NC-02B2", "arbitrary_sql")]:
            context.characterization_scope = scope
            with self.assertRaises(safety.SafetyError):
                with context.bracket_validity_fault(kind):
                    pass

    def test_b2_route_scope_refuses_jobs_and_unregistered_mutations(self):
        context = object.__new__(GuardedHarness)
        context.characterization_scope = "NC-02B2"
        context._brackets = set()
        context._matches = set()
        context._leagues = set()
        for method, path in [
            ("POST", "/admin/season/rollover"),
            ("PATCH", "/bracket/unknown/save"),
            ("DELETE", "/bracket/unknown"),
            ("POST", "https://example.invalid"),
        ]:
            with self.assertRaises(safety.SafetyError):
                context._check_path(method, path)
