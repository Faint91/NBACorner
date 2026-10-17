"""Fixed R3/G2 focused acceptance on the existing guarded local harness only."""

import argparse
import importlib.util
import json
import socket
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_password_reset_acceptance import SanitizedResult
from scripts.reset_local_fixtures import verify_fixture_readiness
from environment_safety import load_test_config
from integration_harness import readiness_report
from email_transport import test_mailbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    args = parser.parse_args()
    if not args.allow_local_mutations:
        parser.error("Explicit guarded local mutation opt-in required")
    suite = unittest.TestSuite()
    modules = []
    ids = []
    for file, cls in [
        ("password_reset", "PasswordResetAcceptance"),
        ("identity_auth_g2", "IdentityAuthAcceptance"),
        ("reset_link_r3", "ResetRoutingAcceptance"),
    ]:
        spec = importlib.util.spec_from_file_location(
            "nc03r3_" + file, ROOT / ("tests/characterization/" + file + ".py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CONFIG = args.config
        module.OPT_IN = True
        selected = unittest.defaultTestLoader.loadTestsFromTestCase(
            getattr(module, cls)
        )
        ids.extend(test.id() for test in selected)
        suite.addTests(selected)
        modules.append(module)
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        suite
    )
    cleanup = verify_fixture_readiness(load_test_config(args.config))
    ready = readiness_report(load_test_config(args.config))
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", 55410)) != 0
    assert not test_mailbox().inspect_messages() and "app" not in sys.modules
    evidence = dict(
        phase="NC-03R3",
        passed=result.wasSuccessful(),
        tests_run=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        case_ids=ids,
        cleanup=cleanup,
        readiness=ready,
        flask_stopped=True,
        mailbox_empty=True,
        production_contact=False,
        configuration_injection="Explicit synthetic frontend origin for actual production-mode link helper; existing local capture transport and guards unchanged",
        no_raw_tokens_or_full_reset_URLs_recorded=True,
    )
    (ROOT / "db/records/nc_03r3_acceptance.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {k: evidence[k] for k in ["passed", "tests_run", "failures", "errors"]}
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
