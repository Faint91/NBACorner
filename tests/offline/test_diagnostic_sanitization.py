"""NC-03R2 route-only security regression; no DB/network/application import."""

import unittest
from scripts.verify_nc03r2_diagnostic import run


class DiagnosticSanitizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = run()

    def test_unauthenticated_all_fault_scenarios_denied_without_diagnostic_reads(self):
        cases = [r for r in self.proof["outcomes"] if r["role"] == "anonymous"]
        self.assertEqual(len(cases), 8)
        self.assertTrue(
            all(r["status"] == 401 and r["diagnostic_reads"] == 0 for r in cases)
        )

    def test_ordinary_and_admin_claim_without_database_role_denied(self):
        cases = [
            r
            for r in self.proof["outcomes"]
            if r["role"] in {"ordinary", "forged_admin_claim"}
        ]
        self.assertEqual(len(cases), 6)
        self.assertTrue(
            all(r["status"] == 403 and r["diagnostic_reads"] == 0 for r in cases)
        )

    def test_authorized_health_missing_master_and_faults_sanitized(self):
        cases = [r for r in self.proof["outcomes"] if r["role"] == "admin"]
        self.assertEqual(len(cases), 32)
        self.assertTrue(all(r["sanitized"] for r in cases))

    def test_production_and_guarded_route_logic_same_authorization(self):
        for mode in ("production", "test"):
            self.assertEqual(
                len([r for r in self.proof["outcomes"] if r["environment"] == mode]), 23
            )

    def test_no_logs_provider_messages_sql_or_identifiers_exposed(self):
        self.assertTrue(self.proof["logs_empty"])
        self.assertFalse(self.proof["provider_markers_exposed"])
        self.assertFalse(self.proof["repair_SQL_exposed"])
        self.assertFalse(self.proof["identifiers_exposed"])
