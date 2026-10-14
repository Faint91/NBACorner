"""Network-free seed/reset safety and raw synthetic-state integrity tests."""

import copy
import hashlib
import json
import os
import socket
import unittest
from unittest.mock import patch, Mock
import bcrypt
import environment_safety as safety
import synthetic_fixtures as fixtures
from scripts import reset_local_fixtures as reset

TARGET = safety.load_enrollments()[0]


def settings():
    return {
        "NBA_CORNER_ENV": "test",
        "NBA_CORNER_TEST_TARGET": TARGET.name,
        "NBA_CORNER_EXPECTED_PROJECT_REF": TARGET.project_ref,
        "SUPABASE_URL": TARGET.supabase_origin,
        "NBACORNER_BASE_URL": TARGET.backend_origin,
        "NBA_CORNER_EMAIL_MODE": "capture",
        "NBA_CORNER_RESET_LINK_ORIGIN": TARGET.backend_origin,
        "NBA_CORNER_PROVIDER_MODE": "fixtures",
        "NBA_CORNER_JOBS_ENABLED": "false",
    }


def marker(**changes):
    row = {
        "environment": "test",
        "project_ref": TARGET.project_ref,
        "marker_id": TARGET.marker_id,
        "marker_version": "2",
        "baseline_version": "nc-env-02-current-secured-v1",
        "baseline_checkpoint": "da8c6695be0726ef3893ffefe605f6fa6e368f9c",
        "baseline_commit": "2e9d6752ce0a5f559673b99221d88c7f51c9d8ea",
        "fixture_state": "UNSEEDED",
        "fixture_version": None,
        "fixture_checksum": None,
    }
    row.update(changes)
    return row


class Offline(unittest.TestCase):
    def setUp(self):
        for obj, name in (
            (socket, "create_connection"),
            (socket.socket, "connect"),
            (socket.socket, "connect_ex"),
        ):
            p = patch.object(obj, name, side_effect=AssertionError("Network forbidden"))
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(os.environ, {}, clear=True)
        p.start()
        self.addCleanup(p.stop)


class ResetSafetyTests(Offline):
    def reject_config(self, **changes):
        with patch.object(
            reset,
            "verify_live_local_identity",
            side_effect=AssertionError("Identity network must not run"),
        ), self.assertRaises(safety.SafetyError):
            reset.preflight(dict(settings(), **changes), True)

    def test_production_ref(self):
        self.reject_config(NBA_CORNER_EXPECTED_PROJECT_REF="rpwesmvzmgoctrokrbhy")

    def test_production_host(self):
        self.reject_config(SUPABASE_URL="https://rpwesmvzmgoctrokrbhy.supabase.co")

    def test_unknown_remote(self):
        self.reject_config(SUPABASE_URL="https://example.invalid")

    def test_missing_environment(self):
        self.reject_config(NBA_CORNER_ENV=None)

    def test_missing_enrollment(self):
        self.reject_config(NBA_CORNER_TEST_TARGET="unknown")

    def test_marker_mismatch(self):
        with patch.object(
            reset,
            "verify_live_local_identity",
            side_effect=safety.SafetyError("Marker mismatch"),
        ), self.assertRaises(safety.SafetyError):
            reset.preflight(settings(), True)

    def test_old_marker(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_local_marker(TARGET, marker(marker_version="1"))

    def test_baseline_mismatch(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_local_marker(TARGET, marker(baseline_version="wrong"))

    def test_missing_optin(self):
        with patch.object(
            reset, "verify_live_local_identity"
        ) as live, self.assertRaises(safety.SafetyError):
            reset.preflight(settings(), False)
        live.assert_not_called()

    def test_invalid_lifecycle(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_local_marker(TARGET, marker(fixture_state="SEEDED"))

    def test_unknown_fixture_version(self):
        with patch.object(
            reset,
            "verify_live_local_identity",
            return_value={
                "marker": marker(
                    fixture_state="SEEDED",
                    fixture_version="other",
                    fixture_checksum="a" * 64,
                )
            },
        ), self.assertRaises(safety.SafetyError):
            reset.preflight(settings(), True)

    def test_unexpected_tables(self):
        for tables in (
            fixtures.TABLES + ("auth.users",),
            fixtures.TABLES[:-1],
            fixtures.TABLES + ("users",),
        ):
            with self.assertRaises(safety.SafetyError):
                reset.validate_inventory(tables, fixtures.SEQUENCES)

    def test_unexpected_destructive_target(self):
        with self.assertRaises(safety.SafetyError):
            reset.validate_inventory(
                fixtures.TABLES, fixtures.SEQUENCES + ("platform",)
            )

    def test_dependency_drift(self):
        with self.assertRaises(safety.SafetyError):
            reset.validate_inventory(fixtures.TABLES, fixtures.SEQUENCES, ("auth",))

    def test_unmet_email(self):
        self.reject_config(NBA_CORNER_EMAIL_MODE="brevo")

    def test_unmet_provider(self):
        self.reject_config(NBA_CORNER_PROVIDER_MODE="live")

    def test_jobs_enabled(self):
        self.reject_config(NBA_CORNER_JOBS_ENABLED="true")

    def test_sql_lock_identity_and_transaction(self):
        sql = reset.reset_sql(marker()).decode()
        self.assertIn("pg_try_advisory_xact_lock(50405,1)", sql)
        self.assertIn(
            "LOCK TABLE nba_corner_test_control.test_environment_identity", sql
        )
        self.assertLess(
            sql.index("Local marker changed before reset"), sql.index("TRUNCATE TABLE")
        )
        self.assertIn("RESTART IDENTITY RESTRICT", sql)
        truncate = next(
            line for line in sql.splitlines() if line.startswith("TRUNCATE TABLE")
        )
        self.assertTrue(" CASCADE" not in truncate)
        self.assertTrue(sql.startswith("BEGIN;"))
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))

    def test_identity_change_prevents_execution(self):
        with patch.object(
            reset, "preflight", side_effect=[marker(), marker(marker_id="wrong")]
        ), patch.object(reset, "check_configuration"), patch.object(
            reset, "container_identity"
        ), patch.object(
            reset.subprocess, "run"
        ) as run, self.assertRaises(
            safety.SafetyError
        ):
            reset.run_reset(settings(), True)
        run.assert_not_called()

    def test_failed_sql_never_reports_success(self):
        with patch.object(reset, "preflight", return_value=marker()), patch.object(
            reset, "check_configuration"
        ), patch.object(reset, "container_identity"), patch.object(
            reset.subprocess, "run", return_value=Mock(returncode=1)
        ), self.assertRaises(
            safety.SafetyError
        ):
            reset.run_reset(settings(), True)

    def test_seed_does_not_open_global_gate(self):
        with self.assertRaises(safety.SafetyError):
            safety.require_live_identity(TARGET)

    def test_seeded_readiness_requires_independent_fixture_proof(self):
        seeded = marker(
            fixture_state="SEEDED",
            fixture_version=fixtures.VERSION,
            fixture_checksum="a" * 64,
        )
        with patch.object(
            safety,
            "verify_live_local_identity",
            return_value={"identity_verified": True, "marker": seeded},
        ), patch.object(
            reset,
            "verify_fixture_readiness",
            return_value={"mutation_permitted": False},
        ) as proof:
            result = safety.verify_provider_job_readiness(settings())
        proof.assert_called_once_with(settings())
        self.assertEqual(result["fixtures_reset"], "PASS")
        self.assertFalse(result["mutation_permitted"])

    def test_seeded_readiness_refuses_drift(self):
        seeded = marker(
            fixture_state="SEEDED",
            fixture_version=fixtures.VERSION,
            fixture_checksum="a" * 64,
        )
        with patch.object(
            safety,
            "verify_live_local_identity",
            return_value={"identity_verified": True, "marker": seeded},
        ), patch.object(
            reset, "verify_fixture_readiness", side_effect=safety.SafetyError("drift")
        ), self.assertRaises(
            safety.SafetyError
        ):
            safety.verify_provider_job_readiness(settings())

    def test_seeded_startup_remains_blocked(self):
        config = dict(settings(), NBA_CORNER_ALLOW_MUTATING_TESTS="1")
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "test", "NBA_CORNER_TEST_CONFIG": "synthetic"},
            clear=True,
        ), patch.object(
            safety, "load_test_config", return_value=config
        ), self.assertRaisesRegex(
            safety.SafetyError, "Mutation/startup remains blocked"
        ):
            safety.prepare_runtime_environment(
                Mock(side_effect=AssertionError("Production dotenv prohibited"))
            )


class FixtureTests(Offline):
    def test_foundation_integrity(self):
        self.assertTrue(fixtures.validate_state(fixtures.foundation()))

    def test_30_teams(self):
        self.assertEqual(len(fixtures.foundation()["teams"]), 30)

    def test_two_seasons(self):
        self.assertEqual(
            {r["code"] for r in fixtures.foundation()["seasons"]},
            {"2025-26", "2024-25"},
        )

    def test_standings(self):
        rows = fixtures.foundation()["standings"]
        self.assertEqual(len({r["code"] for r in rows}), 30)
        self.assertTrue(all(r["wins"] + r["losses"] == 82 for r in rows))

    def test_roles_reserved_accounts(self):
        rows = fixtures.foundation()["users"]
        self.assertEqual(sum(r["is_admin"] for r in rows), 1)
        self.assertTrue(all(r["email"].endswith(".example") for r in rows))

    def test_locally_generated_bcrypt_compatible(self):
        for role, value in fixtures.hashes().items():
            self.assertTrue(
                bcrypt.checkpw(("NCFixture!2026-" + role).encode(), value.encode())
            )
            self.assertEqual(value.split("$")[2], "12")

    def test_bracket_variants_and_graph(self):
        for kind in ("draft", "saved", "master", "deleted", "historical"):
            with self.subTest(kind=kind):
                state = fixtures.bracket_scenario(kind)
                self.assertTrue(fixtures.validate_state(state))
                self.assertEqual(len(state["matches"]), 21)
                self.assertEqual(
                    {r["round"] for r in state["matches"]}, {0, 1, 2, 3, 4}
                )

    def test_circular_master_pointer(self):
        data = fixtures.bracket_scenario("master")
        self.assertEqual(
            data["seasons"][0]["master_bracket_id"], data["brackets"][0]["id"]
        )

    def test_league_roles(self):
        data = fixtures.league_scenario()
        self.assertTrue(fixtures.validate_state(data))
        self.assertEqual(len(data["leagues"]), 2)
        self.assertEqual(len(data["league_members"]), 4)
        self.assertNotIn(
            fixtures.identity("user-b"), {r["user_id"] for r in data["league_members"]}
        )

    def test_history_ties(self):
        data = fixtures.score_history_scenario()
        self.assertTrue(fixtures.validate_state(data))
        self.assertEqual([r["total_points"] for r in data["bracket_scores"]], [3, 3])
        self.assertEqual(len(data["leaderboard_history_rows"]), 2)

    def test_no_default_resets(self):
        self.assertEqual(fixtures.foundation()["password_resets"], [])

    def test_reset_synthetic_helper(self):
        for used in (True, False):
            self.assertTrue(fixtures.validate_state(fixtures.reset_scenario(used=used)))

    def test_deterministic_all_states(self):
        for build in (
            fixtures.foundation,
            lambda: fixtures.bracket_scenario("saved"),
            fixtures.league_scenario,
            fixtures.score_history_scenario,
            fixtures.reset_scenario,
        ):
            self.assertEqual(build(), build())

    def test_version_and_manifest(self):
        manifest = json.loads(
            (reset.ROOT / "tests/fixtures/application/manifest.json").read_text()
        )
        self.assertEqual(manifest["fixture_version"], fixtures.VERSION)
        self.assertEqual(
            manifest["foundation_counts"],
            {t: len(rows) for t, rows in fixtures.foundation().items()},
        )

    def test_checksum_uses_complete_typed_db_state(self):
        sql = reset.state_sql()
        self.assertTrue(all("public." + t in sql for t in fixtures.TABLES))
        self.assertIn("to_jsonb(r)", sql)
        self.assertIn("last_value,is_called", sql)
        self.assertIn("sha256", reset.digest_sql(sql))

    def test_bad_graph_rejected(self):
        data = fixtures.bracket_scenario("draft")
        data["matches"][0]["next_match_id"] = data["matches"][0]["id"]
        with self.assertRaises(ValueError):
            fixtures.validate_state(data)

    def test_cross_season_uniqueness_preserved(self):
        data = fixtures.bracket_scenario("saved")
        extra = copy.deepcopy(fixtures.bracket_scenario("historical")["brackets"][0])
        data["brackets"].append(extra)
        with self.assertRaises(ValueError):
            fixtures.validate_state(data)


if __name__ == "__main__":
    unittest.main()
