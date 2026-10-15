"""Fixed NC-02D2 acceptance/regression suite; writes separate repair evidence only."""

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import socket
import unittest
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.local_supabase_environment import ROOT, sql_file
from integration_harness import readiness_report
from environment_safety import load_test_config
from scripts.reset_local_fixtures import verify_fixture_readiness
from email_transport import test_mailbox
from scripts.nc02c1_acceptance_metadata import mark_acceptance
from scripts.nc02c2_acceptance_metadata import mark_standings_acceptance
from scripts.nc02c3_acceptance_metadata import mark_transition_acceptance
from scripts.nc02d1_acceptance_metadata import mark_scoring_acceptance
from scripts.nc02d2_acceptance_metadata import mark_history_acceptance


class SanitizedResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        return (
            type(err[1]).__name__
            + ": acceptance failure; sensitive diagnostics withheld. Locations: "
            + str(
                [
                    (Path(t.filename).name, t.lineno, t.name)
                    for t in traceback.extract_tb(err[2])
                ]
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    parser.add_argument(
        "--lifecycle-only",
        action="store_true",
        help="Run fixed NC-02D2 live/offline acceptance only",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run affected bracket source checks without importing the app or accessing the DB",
    )
    args = parser.parse_args()
    if not args.allow_local_mutations:
        print("REFUSED: explicit guarded local mutation opt-in required.")
        return 2
    suites = []
    modules = []
    if args.static_only and args.lifecycle_only:
        parser.error("Choose either static-only or lifecycle-only")
    for file, cls in [
        ("history_snapshot", "HistoryAcceptance"),
        ("scoring_recompute", "ScoringAcceptance"),
        ("season_transition", "SeasonTransitionAcceptance"),
        ("standings_refresh", "StandingsAcceptance"),
        ("canonical_source", "CanonicalAcceptance"),
        ("bracket_lifecycle", "BracketLifecycleAcceptance"),
        ("bracket_validity", "BracketValidityAcceptance"),
        ("bracket_lock", "BracketLockAcceptance"),
        ("auth_access", "CurrentAuthBehavior"),
        ("auth_static", "CurrentStaticAuthBehavior"),
        ("bracket_access", "CurrentBracketBehavior"),
        ("bracket_static", "CurrentStaticBracketBehavior"),
        ("league_access", "CurrentLeagueBehavior"),
        ("league_static", "CurrentStaticLeagueBehavior"),
        ("scoring_live", "CurrentLiveScoring"),
        ("scoring_static", "CurrentStaticScoring"),
        ("scoring_offline", "CurrentOfflineScoring"),
        ("privacy_access", "PrivacyAccessAcceptance"),
        ("operations_live", "CurrentLiveOperations"),
        ("operations_static", "CurrentStaticOperations"),
        ("operations_offline", "CurrentOfflineOperations"),
        ("competitive_eligibility", "CompetitiveEligibilityAcceptance"),
        ("competitive_offline", "CompetitiveEligibilityOffline"),
    ]:
        if args.static_only and file != "bracket_static":
            continue
        if args.lifecycle_only and file != "history_snapshot":
            continue
        spec = importlib.util.spec_from_file_location(
            "nc02d2_" + file, ROOT / ("tests/characterization/" + file + ".py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CONFIG = args.config
        module.OPT_IN = True
        mark_acceptance(getattr(module, cls))
        mark_standings_acceptance(getattr(module, cls))
        mark_transition_acceptance(getattr(module, cls))
        mark_scoring_acceptance(getattr(module, cls))
        mark_history_acceptance(getattr(module, cls))
        loader = unittest.TestLoader()
        loader.testMethodPrefix = (
            "test_"
            if file
            in {
                "history_snapshot",
                "scoring_recompute",
                "season_transition",
                "standings_refresh",
                "canonical_source",
                "privacy_access",
                "competitive_eligibility",
                "competitive_offline",
                "bracket_lock",
                "bracket_validity",
                "bracket_lifecycle",
            }
            else "current_behavior__"
        )
        if file == "bracket_lifecycle":
            loader.testMethodPrefix = "test_b3_"
        if file == "bracket_validity":
            loader.testMethodPrefix = "test_b2_"
        suites.append(loader.loadTestsFromTestCase(getattr(module, cls)))
        modules.append(module)
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        unittest.TestSuite(suites)
    )
    if args.static_only:
        evidence = {
            "phase": "NC-02D2",
            "passed": result.wasSuccessful(),
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "findings": [r for m in modules for r in m.RESULTS],
            "read_only_static": True,
            "production_contact": False,
        }
        (ROOT / "db/records/nc_02d2_static_validation.json").write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(
            json.dumps(
                {k: evidence[k] for k in ("passed", "tests_run", "failures", "errors")}
            )
        )
        return 0 if result.wasSuccessful() else 1
    sql_file(ROOT / "db/post-baseline/verify_current_schema.sql")
    sql_file(ROOT / "test-infrastructure/local-supabase/verify-fixture-marker-v2.sql")
    settings = load_test_config(args.config)
    fixture_proof = verify_fixture_readiness(settings)
    with socket.socket() as probe:
        probe.settimeout(5)
        try:
            probe.connect(("127.0.0.1", 55410))
        except ConnectionRefusedError:
            flask_stopped = True
        else:
            raise AssertionError("Guarded Flask listener still active")
    assert not test_mailbox().inspect_messages(), "Email capture was not cleared"
    assert "app" not in sys.modules, "Guarded application import remains active"
    evidence = {
        "phase": "NC-02D2",
        "passed": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "findings": [r for m in modules for r in m.RESULTS],
        "readiness": readiness_report(load_test_config(args.config)),
        "canonical_cleanup": {
            "fixture_readiness": fixture_proof,
            "flask_stopped": flask_stopped,
            "email_capture_empty": True,
            "app_import_removed": True,
        },
        "production_contact": False,
        "historical_NC01_evidence_rewritten": False,
    }
    path = ROOT / (
        "db/records/nc_02d2_lifecycle_validation.json"
        if args.lifecycle_only
        else "db/records/nc_02d2_validation.json"
    )
    path.write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {k: evidence[k] for k in ("passed", "tests_run", "failures", "errors")}
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
