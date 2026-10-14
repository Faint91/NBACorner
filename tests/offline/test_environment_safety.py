"""Offline guards only: never imports/runs the live bracket test or application."""

import ast
import base64
import json
import io
import sys
from types import SimpleNamespace
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import environment_safety as safety

ROOT = Path(__file__).resolve().parents[2]
REF = "abcdefghijklmnopqrst"
TARGET = safety.TestTarget(
    "synthetic",
    REF,
    f"https://{REF}.supabase.co",
    "http://127.0.0.1:5000",
    "fixture-marker",
    "1",
)


def settings():
    return {
        "NBA_CORNER_ENV": "test",
        "NBA_CORNER_ALLOW_MUTATING_TESTS": "1",
        "NBA_CORNER_TEST_TARGET": "synthetic",
        "NBA_CORNER_EXPECTED_PROJECT_REF": REF,
        "SUPABASE_URL": TARGET.supabase_origin,
        "NBACORNER_BASE_URL": TARGET.backend_origin,
    }


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.network_patches = [
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("Network forbidden"),
            ),
            patch.object(
                socket.socket,
                "connect",
                side_effect=AssertionError("Network forbidden"),
            ),
            patch.object(
                socket.socket,
                "connect_ex",
                side_effect=AssertionError("Network forbidden"),
            ),
        ]
        for guard in self.network_patches:
            guard.start()
            self.addCleanup(guard.stop)

    def rejected(self, **changes):
        config = settings()
        config.update(changes)
        with self.assertRaises(safety.SafetyError):
            safety.validate_test_target(config, (TARGET,))

    def test_enrollment_alone_cannot_authorize_client(self):
        with patch.object(
            safety, "load_test_config", return_value=settings()
        ), patch.object(safety, "load_enrollments", return_value=(TARGET,)):
            with self.assertRaises(safety.SafetyError):
                safety.GuardedTestClient()

    def test_empty_port_is_malformed(self):
        with self.assertRaises(safety.SafetyError):
            safety.normalize_origin("https://example.invalid:")

    def test_launcher_refuses_before_child_process(self):
        filename = ROOT / "scripts/run_test_environment.py"
        tree = ast.parse(filename.read_text(encoding="utf-8"))
        main = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"
        )
        parser = Mock()
        parser.parse_args.return_value = SimpleNamespace(
            config="synthetic", entry="integration"
        )
        process = Mock(side_effect=AssertionError("Child process prohibited"))
        namespace = {
            "__doc__": "offline",
            "__file__": str(filename),
            "argparse": SimpleNamespace(ArgumentParser=Mock(return_value=parser)),
            "subprocess": SimpleNamespace(run=process),
            "sys": sys,
            "Path": Path,
            "SafetyError": safety.SafetyError,
            "load_test_config": Mock(return_value=settings()),
            "load_enrollments": Mock(return_value=(TARGET,)),
            "validate_test_target": safety.validate_test_target,
            "require_live_identity": safety.require_live_identity,
        }
        exec(
            compile(
                ast.Module(body=[main], type_ignores=[]), "offline_launcher", "exec"
            ),
            namespace,
        )
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(namespace["main"](), 2)
        process.assert_not_called()

    def test_pytest_collection_refuses_except_exact_offline_file(self):
        filename = ROOT / "conftest.py"
        tree = ast.parse(filename.read_text(encoding="utf-8"))
        hook = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
        guard = Mock(side_effect=safety.SafetyError("No enrollment"))
        namespace = {
            "__file__": str(filename),
            "Path": Path,
            "get_test_client": guard,
            "SafetyError": safety.SafetyError,
            "pytest": SimpleNamespace(UsageError=RuntimeError),
        }
        exec(
            compile(
                ast.Module(body=[hook], type_ignores=[]), "offline_conftest", "exec"
            ),
            namespace,
        )
        for selection in [
            ["tests"],
            ["tests/test_bracket_fill_and_save.py"],
            ["tests/offline"],
            ["tests/offline/test_environment_safety.py", "tests"],
        ]:
            session = SimpleNamespace(
                config=SimpleNamespace(
                    args=selection, invocation_params=SimpleNamespace(dir=ROOT)
                )
            )
            with self.subTest(selection=selection), self.assertRaises(RuntimeError):
                namespace["pytest_sessionstart"](session)
        session = SimpleNamespace(
            config=SimpleNamespace(
                args=["tests/offline/test_environment_safety.py"],
                invocation_params=SimpleNamespace(dir=ROOT),
            )
        )
        guard.reset_mock()
        namespace["pytest_sessionstart"](session)
        guard.assert_not_called()

    def test_missing_identity(self):
        self.rejected(NBA_CORNER_ENV=None)

    def test_unknown_identity(self):
        self.rejected(NBA_CORNER_ENV="staging")

    def test_malformed_identity(self):
        self.rejected(NBA_CORNER_ENV=" test ")

    def test_production_identity(self):
        self.rejected(NBA_CORNER_ENV="production")

    def test_production_project(self):
        self.rejected(NBA_CORNER_EXPECTED_PROJECT_REF="rpwesmvzmgoctrokrbhy")

    def test_production_api_host(self):
        self.rejected(SUPABASE_URL="https://rpwesmvzmgoctrokrbhy.supabase.co")

    def test_production_database_host(self):
        self.rejected(SUPABASE_URL="https://db.rpwesmvzmgoctrokrbhy.supabase.co")

    def test_production_render_backend(self):
        self.rejected(NBACORNER_BASE_URL="https://nbacorner.onrender.com")

    def test_localhost_cannot_hide_production_database(self):
        self.rejected(SUPABASE_URL="https://rpwesmvzmgoctrokrbhy.supabase.co")

    def test_unenrolled_target(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_test_target(settings(), ())

    def test_registry_has_no_enrolled_target(self):
        self.assertEqual(safety.load_enrollments(), ())

    def test_unknown_enrollment_name(self):
        self.rejected(NBA_CORNER_TEST_TARGET="other")

    def test_project_host_mismatch(self):
        self.rejected(SUPABASE_URL="https://bcdefghijklmnopqrstu.supabase.co")

    def test_backend_origin_mismatch(self):
        self.rejected(NBACORNER_BASE_URL="http://127.0.0.1:5001")

    def test_missing_opt_in(self):
        self.rejected(NBA_CORNER_ALLOW_MUTATING_TESTS=None)

    def test_opt_in_is_exact(self):
        self.rejected(NBA_CORNER_ALLOW_MUTATING_TESTS="true")

    def test_missing_target(self):
        self.rejected(NBACORNER_BASE_URL=None)

    def test_bad_origins(self):
        for value in [
            "",
            "http://",
            "ftp://example.invalid",
            "https://x.invalid:bad",
            " https://x.invalid",
            "https://x.invalid/?secret=x",
            "https://x.invalid/#fragment",
            "https://x.invalid/api",
            "https://x.invalid\\path",
            "https://x.invalid:99999",
        ]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                safety.normalize_origin(value)

    def test_credentials_in_urls(self):
        for value in ["https://user:synthetic@x.invalid", "https://user@x.invalid"]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                safety.normalize_origin(value)

    def test_remote_plain_http(self):
        with self.assertRaises(safety.SafetyError):
            safety.normalize_origin("http://example.invalid")

    def test_production_normalization_variants(self):
        for value in [
            "HTTPS://NBACORNER.ONRENDER.COM:443/",
            "https://nbacorner.onrender.com./path",
            "https://www.nbacorner.com/",
            "https://NBACORNER.COM:8443/",
            "https://db.rpwesmvzmgoctrokrbhy.supabase.co/",
            "https://%72pwesmvzmgoctrokrbhy.supabase.co/",
        ]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                safety.normalize_origin(value)

    def test_synthetic_pure_validation(self):
        config = settings()
        config["SUPABASE_URL"] = TARGET.supabase_origin.upper() + ":443/"
        self.assertEqual(safety.validate_test_target(config, (TARGET,)), TARGET)

    def test_redirects_are_rejected(self):
        for value in [
            "https://nbacorner.onrender.com/",
            "/next",
            TARGET.backend_origin,
        ]:
            with self.subTest(value=value), self.assertRaises(safety.SafetyError):
                safety.refuse_redirect(TARGET, value)

    def test_live_identity_cannot_be_bypassed_by_pure_target(self):
        with self.assertRaises(safety.SafetyError):
            safety.require_live_identity(TARGET)

    def test_mutating_client_refuses_without_configuration(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(
            safety.SafetyError
        ):
            safety.GuardedTestClient()

    def test_transport_is_unconditionally_disabled(self):
        client = object.__new__(safety.GuardedTestClient)
        with self.assertRaises(safety.SafetyError):
            client.request("POST", "/auth/register")

    def test_production_credential_metadata(self):
        config = settings()
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {"role": "service_role", "ref": "rpwesmvzmgoctrokrbhy"}
                ).encode()
            )
            .decode()
            .rstrip("=")
        )
        config["SUPABASE_KEY"] = "offline." + payload + ".fixture"
        with self.assertRaises(safety.SafetyError):
            safety.validate_test_target(config, (TARGET,))

    def test_malformed_credential_payload_has_safe_error(self):
        config = settings()
        config["SUPABASE_KEY"] = "offline.W10.fixture"  # JSON list, not claims.
        with self.assertRaisesRegex(safety.SafetyError, "Malformed server credential"):
            safety.validate_test_target(config, (TARGET,))

    def test_wrong_credential_role(self):
        config = settings()
        payload = (
            base64.urlsafe_b64encode(json.dumps({"role": "anon", "ref": REF}).encode())
            .decode()
            .rstrip("=")
        )
        config["SUPABASE_KEY"] = "offline." + payload + ".fixture"
        with self.assertRaises(safety.SafetyError):
            safety.validate_test_target(config, (TARGET,))

    def test_marker_and_backend_evidence(self):
        marker = {
            "environment": "test",
            "project_ref": REF,
            "marker_id": TARGET.marker_id,
            "marker_version": "1",
        }
        backend = dict(
            marker,
            backend_origin=TARGET.backend_origin,
            email_mode="capture",
            provider_mode="fixtures",
            jobs_enabled=False,
        )
        safety.validate_identity_evidence(TARGET, marker, backend)
        for database, server in [
            ({}, backend),
            (dict(marker, project_ref="other"), backend),
            (marker, {}),
            (marker, dict(backend, jobs_enabled=True)),
            (marker, dict(backend, email_mode="live")),
            (marker, dict(backend, provider_mode="live")),
        ]:
            with self.subTest(database=database, server=server), self.assertRaises(
                safety.SafetyError
            ):
                safety.validate_identity_evidence(TARGET, database, server)

    def test_missing_explicit_config(self):
        with self.assertRaises(safety.SafetyError):
            safety.load_test_config(None)

    def test_ordinary_env_cannot_be_selected(self):
        with self.assertRaises(safety.SafetyError):
            safety.load_test_config(str(ROOT / ".env"))

    def test_controlled_file_does_not_merge_ambient_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / ".env.test.local"
            filename.write_text("NBA_CORNER_ENV=test\n", encoding="utf-8")
            with patch.dict(os.environ, {"SUPABASE_KEY": "ambient-synthetic-value"}):
                self.assertEqual(
                    safety.load_test_config(str(filename)), {"NBA_CORNER_ENV": "test"}
                )

    def test_config_duplicate_unknown_and_interpolation_rejected(self):
        for text in [
            "NBA_CORNER_ENV=test\nNBA_CORNER_ENV=test\n",
            "BREVO_API_KEY=placeholder\n",
            "SUPABASE_KEY=${AMBIENT}\n",
        ]:
            with tempfile.TemporaryDirectory() as directory:
                filename = Path(directory) / ".env.test.local"
                filename.write_text(text, encoding="utf-8")
                with self.assertRaises(safety.SafetyError):
                    safety.load_test_config(str(filename))

    def test_child_environment_drops_production_and_proxy_variables(self):
        parent = {
            "SUPABASE_KEY": "ambient",
            "BREVO_API_KEY": "ambient",
            "HTTP_PROXY": "ambient",
            "PYTHONPATH": "ambient",
            "PATH": "platform",
        }
        child = safety.controlled_child_environment(
            settings(), str(ROOT / ".env.test.local"), parent
        )
        for name in ["SUPABASE_KEY", "BREVO_API_KEY", "HTTP_PROXY", "PYTHONPATH"]:
            self.assertNotIn(name, child)
        self.assertEqual(child["PATH"], "platform")
        self.assertEqual(child["NBA_CORNER_ENV"], "test")

    def test_unset_identity_preserves_normal_startup(self):
        loader = Mock()
        with patch.dict(os.environ, {}, clear=True):
            safety.prepare_runtime_environment(loader)
        loader.assert_called_once_with()

    def test_explicit_production_preserves_normal_startup(self):
        loader = Mock()
        with patch.dict(os.environ, {"NBA_CORNER_ENV": "production"}, clear=True):
            safety.prepare_runtime_environment(loader)
        loader.assert_called_once_with()

    def test_test_startup_never_loads_ordinary_env(self):
        loader = Mock()
        with patch.dict(
            os.environ,
            {
                "NBA_CORNER_ENV": "test",
                "SUPABASE_URL": "https://rpwesmvzmgoctrokrbhy.supabase.co",
            },
            clear=True,
        ):
            with self.assertRaises(safety.SafetyError):
                safety.prepare_runtime_environment(loader)
        loader.assert_not_called()

    def test_unknown_startup_identity(self):
        loader = Mock()
        with patch.dict(os.environ, {"NBA_CORNER_ENV": "unknown"}, clear=True):
            with self.assertRaises(safety.SafetyError):
                safety.prepare_runtime_environment(loader)
        loader.assert_not_called()

    def test_hidden_test_identity_in_ordinary_env_refuses(self):
        def loader():
            os.environ["NBA_CORNER_ENV"] = "test"

        with patch.dict(os.environ, {}, clear=True), self.assertRaises(
            safety.SafetyError
        ):
            safety.prepare_runtime_environment(loader)

    def test_production_identity_cannot_mix_test_config(self):
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "production", "NBA_CORNER_TEST_CONFIG": "ignored"},
            clear=True,
        ), self.assertRaises(safety.SafetyError):
            safety.prepare_runtime_environment(Mock())

    def test_app_and_job_guard_precedes_client_construction(self):
        for filename in ["app.py", "scripts/update_standings.py"]:
            tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
            start = next(
                i
                for i, n in enumerate(tree.body)
                if isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Name)
                and n.value.func.id == "prepare_runtime_environment"
            )
            end = next(
                i
                for i, n in enumerate(tree.body)
                if isinstance(n, (ast.Assign, ast.AnnAssign))
                and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Name)
                and n.value.func.id == "create_client"
            )
            self.assertLess(start, end)
            client_factory = Mock(
                side_effect=AssertionError("Client must not initialize")
            )
            prefix = ast.Module(body=tree.body[start : end + 1], type_ignores=[])
            with patch.dict(
                os.environ, {"NBA_CORNER_ENV": "test"}, clear=True
            ), self.assertRaises(safety.SafetyError):
                exec(
                    compile(prefix, filename, "exec"),
                    {
                        "os": os,
                        "prepare_runtime_environment": safety.prepare_runtime_environment,
                        "create_client": client_factory,
                    },
                )
            client_factory.assert_not_called()

    def test_extracted_http_helpers_cannot_bypass_guard(self):
        # Compile only four transport helpers, never import/run the integration module.
        tree = ast.parse(
            (ROOT / "tests/test_bracket_fill_and_save.py").read_text(encoding="utf-8")
        )
        helpers = [
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name in {"_post", "_get", "_patch", "_delete"}
        ]
        for node in helpers:
            node.returns = None
            for argument in node.args.args:
                argument.annotation = None
        namespace = {"get_test_client": safety.get_test_client}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=helpers, type_ignores=[])),
                "offline_helpers",
                "exec",
            ),
            namespace,
        )
        with patch.dict(os.environ, {}, clear=True):
            for name in ["_post", "_get", "_patch", "_delete"]:
                args = (
                    ("/fixture", {}) if name in {"_post", "_patch"} else ("/fixture",)
                )
                with self.subTest(helper=name), self.assertRaises(safety.SafetyError):
                    namespace[name](*args)


if __name__ == "__main__":
    unittest.main()
