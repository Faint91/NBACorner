"""Offline harness refusals/bypass tests. No app import or actual socket connection."""

import contextlib
import io
import os
import socket
import unittest
from unittest.mock import Mock, patch
import environment_safety as safety
import integration_harness as harness
from scripts import reset_local_fixtures as reset

TARGET = safety.load_enrollments()[0]


def settings():
    return {
        "NBA_CORNER_ENV": "test",
        "NBA_CORNER_ALLOW_MUTATING_TESTS": "1",
        "NBA_CORNER_TEST_TARGET": TARGET.name,
        "NBA_CORNER_EXPECTED_PROJECT_REF": TARGET.project_ref,
        "SUPABASE_URL": TARGET.supabase_origin,
        "NBACORNER_BASE_URL": TARGET.backend_origin,
        "NBA_CORNER_EMAIL_MODE": "capture",
        "NBA_CORNER_RESET_LINK_ORIGIN": TARGET.backend_origin,
        "NBA_CORNER_PROVIDER_MODE": "fixtures",
        "NBA_CORNER_JOBS_ENABLED": "false",
    }


def marker():
    return {
        "environment": "test",
        "project_ref": TARGET.project_ref,
        "marker_id": TARGET.marker_id,
        "marker_version": "2",
        "baseline_version": "nc-env-02-current-secured-v1",
        "baseline_checkpoint": "da8c6695be0726ef3893ffefe605f6fa6e368f9c",
        "baseline_commit": "2e9d6752ce0a5f559673b99221d88c7f51c9d8ea",
        "fixture_state": "SEEDED",
        "fixture_version": "nc-fixtures-v1",
        "fixture_checksum": harness.CANONICAL_CHECKSUM,
    }


class HarnessSafetyTests(unittest.TestCase):
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
        self.assertIsNone(harness._ACTIVE)

    def reject_config(self, **changes):
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_settings(dict(settings(), **changes), True)

    def test_prod_project(self):
        self.reject_config(NBA_CORNER_EXPECTED_PROJECT_REF="rpwesmvzmgoctrokrbhy")

    def test_prod_api(self):
        self.reject_config(SUPABASE_URL="https://rpwesmvzmgoctrokrbhy.supabase.co")

    def test_prod_render(self):
        self.reject_config(NBACORNER_BASE_URL="https://nbacorner.onrender.com")

    def test_loopback_backed_by_prod(self):
        self.reject_config(
            SUPABASE_URL="https://rpwesmvzmgoctrokrbhy.supabase.co",
            NBACORNER_BASE_URL=TARGET.backend_origin,
        )

    def test_unknown_remote(self):
        self.reject_config(SUPABASE_URL="https://example.invalid")

    def test_missing_enrollment(self):
        self.reject_config(NBA_CORNER_TEST_TARGET="unknown")

    def test_marker_mismatch(self):
        row = marker()
        row["marker_id"] = "wrong"
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_identity(TARGET, row)

    def test_baseline_mismatch(self):
        row = marker()
        row["baseline_version"] = "wrong"
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_identity(TARGET, row)

    def test_fixture_version(self):
        row = marker()
        row["fixture_version"] = "other"
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_identity(TARGET, row)

    def test_fixture_checksum(self):
        row = marker()
        row["fixture_checksum"] = "a" * 64
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_identity(TARGET, row)

    def test_unseeded(self):
        row = marker()
        row.update(
            fixture_state="UNSEEDED", fixture_version=None, fixture_checksum=None
        )
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_identity(TARGET, row)

    def test_email_unsafe(self):
        self.reject_config(NBA_CORNER_EMAIL_MODE="brevo")

    def test_provider_live(self):
        self.reject_config(NBA_CORNER_PROVIDER_MODE="live")

    def test_provider_credentials(self):
        with patch.dict(os.environ, {"BALLDONTLIE_API_KEY": "synthetic"}):
            self.reject_config()

    def test_jobs_enabled(self):
        self.reject_config(NBA_CORNER_JOBS_ENABLED="true")

    def test_missing_optin(self):
        self.reject_config(NBA_CORNER_ALLOW_MUTATING_TESTS="0")

    def test_missing_invocation(self):
        with self.assertRaises(safety.SafetyError):
            harness.validate_harness_settings(settings(), False)

    def test_missing_lease(self):
        # Even the fixed-target maintenance lease requires explicit opt-in.
        with self.assertRaises(safety.SafetyError):
            reset.LocalFixtureLease(settings()).__enter__()
        context = object.__new__(harness.GuardedHarness)
        context._closed = False
        with self.assertRaises(safety.SafetyError):
            context._require_lease()

    def test_backend_identity_mismatch(self):
        body = dict(
            marker(),
            backend_origin=TARGET.backend_origin,
            email_mode="capture",
            provider_mode="fixtures",
            jobs_enabled=False,
        )
        harness.validate_backend_identity(TARGET, body)
        for key, value in (
            ("project_ref", "local:wrong"),
            ("backend_origin", "http://127.0.0.1:1"),
            ("jobs_enabled", True),
            ("fixture_checksum", "a" * 64),
        ):
            with self.assertRaises(safety.SafetyError):
                harness.validate_backend_identity(TARGET, dict(body, **{key: value}))

    def test_raw_helper_refuses(self):
        with self.assertRaises(safety.SafetyError):
            safety.get_test_client()

    def test_existing_integration_helper_refuses(self):
        import ast

        tree = ast.parse(
            (reset.ROOT / "tests/test_bracket_fill_and_save.py").read_text(
                encoding="utf-8"
            )
        )
        node = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_post"
        )
        node.returns = None
        for arg in node.args.args:
            arg.annotation = None
        namespace = {"get_test_client": safety.get_test_client}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                "offline-helper",
                "exec",
            ),
            namespace,
        )
        with self.assertRaises(safety.SafetyError):
            namespace["_post"]("/bracket/create", {})

    def test_standings_job_refuses(self):
        from job_safety import guard_runtime_job

        with patch.object(
            safety, "load_test_config", return_value=settings()
        ), patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "test", "NBA_CORNER_TEST_CONFIG": "synthetic"},
        ), self.assertRaises(
            safety.SafetyError
        ):
            guard_runtime_job("standings-refresh")

    def test_reset_unknown_target_refuses(self):
        with self.assertRaises(safety.SafetyError):
            reset.preflight(
                dict(settings(), SUPABASE_URL="https://example.invalid"), True
            )

    def test_environment_manipulation_cannot_start(self):
        with patch.dict(
            os.environ,
            {
                "NBA_CORNER_ENV": "test",
                "NBA_CORNER_TEST_CONFIG": "synthetic",
                "ALLOW_MUTATIONS": "true",
            },
            clear=True,
        ), patch.object(
            safety, "load_test_config", return_value=settings()
        ), self.assertRaises(
            safety.SafetyError
        ):
            safety.prepare_runtime_environment()

    def test_contextless_startup_refuses(self):
        with self.assertRaises(safety.SafetyError):
            harness.require_harness_startup(TARGET)

    def test_unapproved_route_refuses(self):
        context = object.__new__(harness.GuardedHarness)
        context._brackets = set()
        context._matches = set()
        for method, path in (
            ("POST", "/admin/standings/refresh"),
            ("POST", "/auth/register"),
            ("POST", "https://example.invalid"),
            ("GET", "/health?token=synthetic"),
            ("GET", "/__test__/identity"),
        ):
            with self.assertRaises(safety.SafetyError):
                context._check_path(method, path)

    def test_log_sink_retains_no_values(self):
        sink = harness.QuietSink()
        sink.write("synthetic-password-token-key")
        sink.flush()
        self.assertEqual(vars(sink), {})

    def test_inactive_client_refuses_before_connection(self):
        context = object.__new__(harness.GuardedHarness)
        context._closed = True
        with self.assertRaises(safety.SafetyError):
            context.request("POST", "/bracket/create", payload={}, role="admin")

    def test_valid_pure_checks_are_not_permits(self):
        harness.validate_harness_settings(settings(), True)
        harness.validate_harness_identity(TARGET, marker())
        with self.assertRaises(safety.SafetyError):
            safety.require_live_identity(TARGET)

    def test_lease_post_commit_proof_preserves_formatting(self):
        lease = object.__new__(reset.LocalFixtureLease)
        lease.active = True
        lease._exchange = Mock(return_value={"verified": True})
        lease.reset_foundation(marker())
        sql = lease._exchange.call_args.args[0].decode()
        commit = sql.index("COMMIT;")
        self.assertTrue(sql.index("BEGIN READ ONLY;", commit) > commit)
        self.assertTrue(sql.index("extra_float_digits=3", commit) > commit)

    def test_readiness_is_not_a_permit(self):
        with patch.object(
            safety, "verify_live_local_identity", return_value={"marker": marker()}
        ), patch.object(
            safety,
            "verify_provider_job_readiness",
            return_value={"mutation_permitted": False},
        ):
            report = harness.readiness_report(settings())
        self.assertEqual(report["integration_harness"], "PASS")
        self.assertFalse(report["harness_scoped_mutation_permitted"])
        self.assertFalse(report["mutation_permitted"])
        self.assertIsNone(harness._ACTIVE)


if __name__ == "__main__":
    unittest.main()
