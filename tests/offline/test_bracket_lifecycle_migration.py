"""Offline forward migration/security and local-only lifecycle tooling checks."""

from pathlib import Path
import hashlib, re, unittest
from unittest.mock import Mock
from environment_safety import SafetyError
from integration_harness import GuardedHarness
from scripts.reset_local_fixtures import VERIFIER_SHA

ROOT = Path(__file__).resolve().parents[2]


class LifecycleMigrationSafety(unittest.TestCase):
    def test_evolved_verifier_preserves_every_unrelated_baseline_assertion(self):
        baseline = (ROOT / "db/baseline/verify_current_schema.sql").read_text(
            encoding="utf-8"
        )
        expected = baseline.replace(",unique_active_bracket_per_user", "")
        parts = re.split(r"(?=  IF )", expected)
        removed = [
            p
            for p in parts
            if "RAISE EXCEPTION 'Baseline mismatch: index unique_active_bracket_per_user'"
            in p
            or "RAISE EXCEPTION 'Baseline mismatch: index ready unique_active_bracket_per_user'"
            in p
        ]
        self.assertEqual(len(removed), 2)
        expected = (
            "".join(p for p in parts if p not in removed)
            .replace(
                "atomic_update_match,fix_season_master",
                "atomic_update_match,create_master_bracket_atomic,fix_season_master",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        evolved = (ROOT / "db/post-baseline/verify_nc_02b3_schema.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            evolved.split("DO $forward_verify$", 1)[0].rstrip(), expected.rstrip()
        )
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_nc_02b3_schema.sql").read_bytes()
            ).hexdigest(),
            "7ff200f3d75b5697c68587942a78f30d36b357c4f086ac5792e973dbec91606e",
        )

    def test_migration_is_portable_and_seals_new_rpc_in_same_transaction(self):
        sql = (ROOT / "db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("GROUP BY user_id,season_id HAVING count(*)>1", sql)
        self.assertIn("DROP INDEX public.unique_active_bracket_per_user;", sql)
        self.assertIn("FOR UPDATE", sql)
        self.assertIn("p_replace IS DISTINCT FROM TRUE", sql)
        self.assertIn("SECURITY INVOKER", sql)
        self.assertIn("FROM PUBLIC,anon,authenticated", sql)
        self.assertIn("TO postgres,service_role", sql)
        self.assertLess(sql.index("REVOKE ALL"), sql.index("COMMIT;"))
        self.assertNotIn("CREATE ROLE", sql)
        self.assertNotIn("supabase.co", sql)
        self.assertNotIn("DROP TABLE", sql)

    def test_rollback_refuses_cross_season_data_loss(self):
        sql = (ROOT / "db/post-baseline/rollback_nc_02b3.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("GROUP BY user_id HAVING count(*)>1", sql)
        self.assertNotIn("DELETE FROM", sql)
        self.assertNotIn("TRUNCATE", sql)

    def test_lifecycle_fixture_and_rpc_proof_require_live_scope(self):
        context = object.__new__(GuardedHarness)
        context._require_bracket_scope = Mock(side_effect=SafetyError("Lease required"))
        with self.assertRaises(SafetyError):
            context.install_lifecycle_history("draft")
        with self.assertRaises(SafetyError):
            context.master_failure_rollback_proof()

    def test_other_scopes_cannot_use_lifecycle_mutations(self):
        context = object.__new__(GuardedHarness)
        context._require_bracket_scope = Mock()
        context.characterization_scope = "NC-02B2"
        with self.assertRaises(SafetyError):
            context.install_lifecycle_history("master")
        with self.assertRaises(SafetyError):
            context.master_failure_rollback_proof()

    def test_lifecycle_routes_are_registered_id_only(self):
        context = object.__new__(GuardedHarness)
        context.characterization_scope = "NC-02B3"
        context._brackets = {"fixture"}
        context._matches = set()
        context._leagues = set()
        context._check_path("GET", "/history/bracket/fixture")
        context._check_path("DELETE", "/bracket/fixture")
        for method, path in [
            ("GET", "/history/bracket/unknown"),
            ("DELETE", "/bracket/unknown"),
            ("POST", "/admin/season/rollover"),
        ]:
            with self.assertRaises(SafetyError):
                context._check_path(method, path)
