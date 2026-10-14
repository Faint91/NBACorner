"""Offline local marker lifecycle contract tests; no app import or mutation."""

import json
import socket
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch
import environment_safety as safety

ROOT = Path(__file__).resolve().parents[2]
TARGET = safety.load_enrollments()[0]


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


class MarkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        for obj, name in (
            (socket, "create_connection"),
            (socket.socket, "connect"),
            (socket.socket, "connect_ex"),
        ):
            guard = patch.object(
                obj, name, side_effect=AssertionError("Network forbidden")
            )
            guard.start()
            self.addCleanup(guard.stop)

    def reject(self, **changes):
        with self.assertRaises(safety.SafetyError):
            safety.validate_local_marker(TARGET, marker(**changes))

    def test_v2_accepted(self):
        self.assertEqual(TARGET.marker_version, "2")
        self.assertEqual(safety.validate_local_marker(TARGET, marker()), marker())

    def test_v1_refused(self):
        self.reject(marker_version="1")

    def test_old_enrollment_cannot_authorize_old_marker(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_local_marker(
                replace(TARGET, marker_version="1"), marker(marker_version="1")
            )

    def test_unseeded_null_metadata_accepted(self):
        safety.validate_fixture_marker_metadata(marker())

    def test_unseeded_populated_metadata_rejected(self):
        for changes in (
            {"fixture_version": "nc-fixtures-v1"},
            {"fixture_checksum": "a" * 64},
            {"fixture_version": "nc-fixtures-v1", "fixture_checksum": "a" * 64},
        ):
            self.reject(**changes)

    def test_seeded_missing_version_rejected(self):
        self.reject(fixture_state="SEEDED", fixture_checksum="a" * 64)

    def test_seeded_missing_checksum_rejected(self):
        self.reject(fixture_state="SEEDED", fixture_version="nc-fixtures-v1")

    def test_seeded_complete_metadata_accepted_without_permit(self):
        row = marker(
            fixture_state="SEEDED",
            fixture_version="nc-fixtures-v1",
            fixture_checksum="a" * 64,
        )
        self.assertEqual(safety.validate_local_marker(TARGET, row), row)
        with self.assertRaises(safety.SafetyError):
            safety.require_live_identity(TARGET)

    def test_unknown_state_rejected(self):
        self.reject(fixture_state="OTHER")

    def test_missing_metadata_fields_rejected(self):
        for field in ("fixture_version", "fixture_checksum"):
            row = marker()
            del row[field]
            with self.assertRaises(safety.SafetyError):
                safety.validate_local_marker(TARGET, row)

    def test_malformed_seed_metadata_rejected(self):
        for version, checksum in (
            ("", "a" * 64),
            ("nc fixtures", "a" * 64),
            ("x" * 81, "a" * 64),
            ("nc-fixtures-v1", "bad"),
            ("nc-fixtures-v1", "A" * 64),
            (123, "a" * 64),
            ("nc-fixtures-v1", 123),
        ):
            self.reject(
                fixture_state="SEEDED",
                fixture_version=version,
                fixture_checksum=checksum,
            )

    def test_project_mismatch_refused(self):
        self.reject(project_ref="local:other")

    def test_marker_mismatch_refused(self):
        self.reject(marker_id="other")

    def test_baseline_mismatch_refused(self):
        for field in ("baseline_version", "baseline_checkpoint", "baseline_commit"):
            self.reject(**{field: "other"})

    def test_migration_scope_and_acl_contract(self):
        sql = (
            ROOT / "test-infrastructure/local-supabase/fixture-marker-v2.sql"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            sql.count("ALTER TABLE nba_corner_test_control.test_environment_identity"),
            1,
        )
        self.assertEqual(
            sql.count("UPDATE nba_corner_test_control.test_environment_identity"), 1
        )
        for forbidden in (
            "DROP SCHEMA",
            "TRUNCATE",
            "INSERT INTO",
            "ALTER FUNCTION",
            "public.",
            "GRANT ",
            "REVOKE ",
            "OWNER TO",
        ):
            self.assertNotIn(forbidden, sql)
        self.assertIn("{postgres=arwdDxtm/postgres,service_role=r/postgres}", sql)
        self.assertIn("{postgres=UC/postgres,service_role=U/postgres}", sql)
        self.assertIn("pg_try_advisory_xact_lock", sql)
        self.assertIn("fixture_version IS NULL AND fixture_checksum IS NULL", sql)
        self.assertIn(
            "fixture_version IS NOT NULL AND fixture_checksum IS NOT NULL", sql
        )

    def test_original_setup_denies_ordinary_roles(self):
        sql = (
            ROOT / "test-infrastructure/local-supabase/identity-marker.sql"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "REVOKE ALL ON SCHEMA nba_corner_test_control FROM PUBLIC, anon, authenticated",
            sql,
        )
        self.assertIn(
            "REVOKE ALL ON TABLE nba_corner_test_control.test_environment_identity FROM PUBLIC, anon, authenticated, service_role",
            sql,
        )
        self.assertIn(
            "GRANT SELECT ON TABLE nba_corner_test_control.test_environment_identity TO service_role",
            sql,
        )

    def test_live_query_requests_metadata_and_never_enables_mutation(self):
        response = Mock(status=200)
        response.read.return_value = json.dumps(
            [
                marker(
                    fixture_state="SEEDED",
                    fixture_version="nc-fixtures-v1",
                    fixture_checksum="a" * 64,
                )
            ]
        ).encode()
        connection = Mock()
        connection.getresponse.return_value = response
        settings = {
            "NBA_CORNER_ENV": "test",
            "NBA_CORNER_TEST_TARGET": TARGET.name,
            "NBA_CORNER_EXPECTED_PROJECT_REF": TARGET.project_ref,
            "SUPABASE_URL": TARGET.supabase_origin,
            "NBACORNER_BASE_URL": TARGET.backend_origin,
            "SUPABASE_KEY": "sb_secret_offline_fixture",
        }
        with patch("http.client.HTTPConnection", return_value=connection):
            result = safety.verify_live_local_identity(settings)
        self.assertIn(
            "fixture_version,fixture_checksum", connection.request.call_args.args[1]
        )
        self.assertFalse(result["mutation_permitted"])


if __name__ == "__main__":
    unittest.main()
