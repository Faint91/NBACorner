"""NC-03R1 focused guarded G1/G2 and auth regressions; preserves old evidence."""

import argparse
import importlib.util
import json
import socket
import sys
import traceback
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from email_transport import test_mailbox
from environment_safety import load_test_config
from integration_harness import GuardedHarness, readiness_report
from scripts.reset_local_fixtures import verify_fixture_readiness
from scripts.verify_nc03r1_jwt_config import historical_source_fallback


class SanitizedResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        return (
            type(err[1]).__name__
            + ": sensitive details withheld; locations="
            + str(
                [
                    (Path(t.filename).name, t.lineno, t.name)
                    for t in traceback.extract_tb(err[2])
                ]
            )
        )


class RuntimeAcceptance(unittest.TestCase):
    config = None

    def test_actual_app_startup_login_and_signature_controls(self):
        import jwt

        with GuardedHarness(
            self.config, allow_local_mutations=True, characterization_scope="NC-01A"
        ) as context:
            self.assertGreaterEqual(len(context.module.JWT_SECRET), 32)
            self.assertEqual(context.module.JWT_SECRET, context._jwt_secret)
            context.login("user-a")
            self.assertEqual(
                context.auth_request("GET", "/auth/test-me", role="user-a")[0], 200
            )
            original = context._tokens["user-a"]
            claims = jwt.decode(
                original, context.module.JWT_SECRET, algorithms=["HS256"]
            )
            self.assertEqual(
                set(claims), {"user_id", "username", "is_admin", "av", "exp"}
            )
            try:
                for key in (
                    historical_source_fallback(),
                    "nc03r1-wrong-explicit-synthetic-signing-key",
                ):
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        context._tokens["user-a"] = jwt.encode(
                            claims, key, algorithm="HS256"
                        )
                    self.assertEqual(
                        context.auth_request("GET", "/auth/test-me", role="user-a")[0],
                        401,
                    )
            finally:
                context._tokens["user-a"] = original
            self.assertEqual(
                context.auth_request("GET", "/auth/test-me", role="user-a")[0], 200
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    args = parser.parse_args()
    if not args.allow_local_mutations:
        print("REFUSED: explicit guarded local opt-in required.")
        return 2
    suite = unittest.TestSuite()
    RuntimeAcceptance.config = args.config
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeAcceptance))
    for filename, classname in (
        ("identity_auth_g2", "IdentityAuthAcceptance"),
        ("password_reset", "PasswordResetAcceptance"),
        ("auth_access", "CurrentAuthBehavior"),
    ):
        spec = importlib.util.spec_from_file_location(
            "nc03r1_" + filename, ROOT / "tests/characterization" / (filename + ".py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CONFIG = args.config
        module.OPT_IN = True
        cls = getattr(module, classname)
        if filename == "auth_access":
            for name in (
                "valid_registration",
                "login_failures",
                "fixture_username_login",
                "required_identity_access",
                "admin_boundary",
                "admin_claim_db_recheck",
                "test_email_boundary",
                "public_health",
            ):
                suite.addTest(cls("current_behavior__auth__" + name))
        else:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    case_ids = [
        case.id()
        for group in suite
        for case in (list(group) if isinstance(group, unittest.TestSuite) else [group])
    ]
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        suite
    )
    fixture = verify_fixture_readiness(load_test_config(args.config))
    assert not test_mailbox().inspect_messages()
    assert "app" not in sys.modules
    with socket.socket() as connection:
        stopped = connection.connect_ex(("127.0.0.1", 55410)) != 0
    assert stopped
    evidence = dict(
        phase="NC-03R1",
        passed=result.wasSuccessful(),
        tests_run=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        case_ids=case_ids,
        failed_case_ids=[case.id() for case, _ in [*result.failures, *result.errors]],
        fixture=fixture,
        readiness=readiness_report(load_test_config(args.config)),
        flask_stopped=stopped,
        email_capture_empty=True,
        production_contact=False,
        prior_evidence_rewritten=False,
    )
    (ROOT / "db/records/nc_03r1_auth_validation.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {k: evidence[k] for k in ("passed", "tests_run", "failures", "errors")}
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(
            "NC-03R1 guarded validation unavailable; sensitive details withheld",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
