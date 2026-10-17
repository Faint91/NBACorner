"""NC-03R1 explicit signing configuration and actual auth-code acceptance."""

import os
import unittest
from unittest.mock import patch

from environment_safety import SafetyError
from jwt_configuration import (
    JWTConfigurationError,
    runtime_jwt_secret,
    validate_jwt_secret,
)
from scripts.verify_nc03r1_jwt_config import run


class JWTConfigurationTests(unittest.TestCase):
    def test_missing_empty_whitespace_and_short_values(self):
        for value in (None, "", " ", "\t\n", "x" * 31, "secret", "changeme"):
            with self.subTest(case_type=type(value).__name__):
                with self.assertRaises(JWTConfigurationError) as result:
                    validate_jwt_secret(value)
                self.assertIn(
                    str(result.exception),
                    {
                        "JWT_SECRET is required",
                        "JWT_SECRET must contain at least 32 characters",
                    },
                )

    def test_exact_explicit_value_and_unicode_boundary(self):
        for value in ("s" * 32, "z" * 64, " " + "s" * 32 + " ", "\u00e9" * 32):
            self.assertEqual(validate_jwt_secret(value), value)

    def test_no_implicit_key_in_any_ordinary_mode(self):
        for settings in ({}, {"NBA_CORNER_ENV": "production"}):
            with patch.dict(os.environ, settings, clear=True):
                with self.assertRaises(JWTConfigurationError):
                    runtime_jwt_secret()

    def test_test_mode_requires_verified_harness_injection(self):
        for settings in (
            {"NBA_CORNER_ENV": "test", "JWT_SECRET": "s" * 48},
            {"NBA_CORNER_TEST_CONFIG": "unverified", "JWT_SECRET": "s" * 48},
        ):
            with patch.dict(os.environ, settings, clear=True):
                with self.assertRaises(SafetyError):
                    runtime_jwt_secret()

    def test_production_test_mix_and_unknown_identity_rejected(self):
        for settings in (
            {"NBA_CORNER_ENV": "production", "NBA_CORNER_TEST_CONFIG": "unverified"},
            {"NBA_CORNER_ENV": "unknown"},
        ):
            with patch.dict(os.environ, settings, clear=True):
                with self.assertRaises(JWTConfigurationError):
                    runtime_jwt_secret()

    def test_unguarded_harness_key_access_denied(self):
        from integration_harness import startup_jwt_secret

        with self.assertRaises(SafetyError):
            startup_jwt_secret()

    def test_actual_startup_and_forged_source_key_rejection(self):
        result = run()
        self.assertEqual(len(result["unsafe_startup_cases"]), 7)
        self.assertEqual(
            result["actual_current_route_statuses"]["forged_old_source_fallback"], 401
        )

    def test_actual_token_compatibility_and_validation_regressions(self):
        result = run()
        self.assertEqual(len(result["actual_current_route_statuses"]), 14)
        self.assertTrue(
            result["actual_generation_claims_and_seven_day_expiry_unchanged"]
        )
        self.assertTrue(result["explicit_config_preserved_exactly"])

    def test_harness_injection_rejects_wrong_thread_and_expired_lease(self):
        import threading
        from types import SimpleNamespace
        from unittest.mock import Mock
        import integration_harness as harness

        permit = SimpleNamespace(
            _starting=True,
            _owner=threading.get_ident() + 1,
            _require_lease=Mock(),
            _jwt_secret="nc03r1-explicit-synthetic-fixture-key-for-guard-test",
        )
        with patch.object(harness, "_ACTIVE", permit):
            with self.assertRaises(SafetyError):
                harness.startup_jwt_secret()
            permit._owner = threading.get_ident()
            permit._require_lease.side_effect = SafetyError("Verified lease required")
            with self.assertRaises(SafetyError):
                harness.startup_jwt_secret()

    def test_current_static_acceptance_supersedes_only_historical_fallback(self):
        import importlib.util
        from pathlib import Path
        from scripts.nc03r1_acceptance_metadata import mark_signing_config_acceptance

        path = Path("tests/characterization/auth_static.py")
        spec = importlib.util.spec_from_file_location("nc03r1_static_auth", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls = module.CurrentStaticAuthBehavior
        original = cls.current_behavior__auth__implementation_defaults
        mark_signing_config_acceptance(cls)
        case = cls("current_behavior__auth__implementation_defaults")
        case.current_behavior__auth__implementation_defaults()
        self.assertEqual(
            cls.current_behavior__auth__implementation_defaults.metadata[
                "previous_metadata"
            ],
            original.metadata,
        )
