"""Fixed NC-02E acceptance/regression suite; writes separate repair evidence only."""

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
        "--recheck",
        action="store_true",
        help="Recheck the fixed registration regressions, snapshot-delegation contract and E routes after the local decorator/timing fixes",
    )
    parser.add_argument(
        "--lifecycle-only",
        action="store_true",
        help="Run fixed NC-02E live/offline acceptance only",
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
    superseded = []
    selected_case_ids = []
    recheck_auth = {
        "current_behavior__auth__duplicate_email",
        "current_behavior__auth__duplicate_username",
        "current_behavior__auth__password_whitespace",
        "current_behavior__auth__registration_invalid_fields",
        "current_behavior__auth__registration_password_policy",
    }
    suites = []
    modules = []
    if sum((args.static_only, args.lifecycle_only, args.recheck)) > 1:
        parser.error("Choose only one focused validation mode")
    for file, cls in [
        ("rollover_atomic", "AtomicRolloverAcceptance"),
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
        if args.recheck and file not in {
            "rollover_atomic",
            "auth_access",
            "scoring_static",
        }:
            continue
        if args.static_only and file != "bracket_static":
            continue
        if args.lifecycle_only and file != "rollover_atomic":
            continue
        spec = importlib.util.spec_from_file_location(
            "nc02e_" + file, ROOT / ("tests/characterization/" + file + ".py")
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
        if file == "scoring_static":
            original = (
                module.CurrentStaticScoring.current_behavior__history__snapshot_source
            )

            def atomic_snapshot_source(self):
                self.assertIn(
                    "create_final_leaderboard_snapshot",
                    self.fn("_snapshot_leaderboard_for_current_season"),
                )
                self.assertIn("run_rollover", self.fn("_rollover_current_season"))
                service = (ROOT / "rollover_service.py").read_text(encoding="utf-8")
                self.assertIn("calculation_only=True", service)
                sql = (
                    (ROOT / "db/post-baseline/0007_nc_02e_atomic_rollover.sql")
                    .read_text(encoding="utf-8")
                    .split("CREATE FUNCTION public.run_season_rollover", 1)[1]
                )
                self.assertLess(
                    sql.index("public.publish_leaderboard_snapshot"),
                    sql.index("public.execute_season_rollover_transition"),
                )

            atomic_snapshot_source.metadata = dict(
                original.metadata,
                phase="NC-02E",
                previous_metadata=dict(original.metadata),
                current_behavior="Standalone snapshot preserved; rollover performs read-only preparation then locked DB snapshot gate before atomic transition. Real SQL rollback acceptance is authoritative.",
            )
            module.CurrentStaticScoring.current_behavior__history__snapshot_source = (
                atomic_snapshot_source
            )
        loader = unittest.TestLoader()
        loader.testMethodPrefix = (
            "test_"
            if file
            in {
                "history_snapshot",
                "rollover_atomic",
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
        loaded = loader.loadTestsFromTestCase(getattr(module, cls))
        applicable = []
        for case in loaded:
            name = case._testMethodName
            if args.recheck and file == "auth_access" and name not in recheck_auth:
                continue
            if (
                args.recheck
                and file == "scoring_static"
                and name != "current_behavior__history__snapshot_source"
            ):
                continue
            obsolete = (
                file == "season_transition"
                or name.startswith("current_behavior__rollover__")
                or (
                    file == "history_snapshot"
                    and name
                    in {
                        "test_d2_zero_participation_verified_final_repeat_and_cleanup",
                        "test_d2_failure_is_never_zero_and_gate_stays_closed",
                        "test_d2_legacy_success_structured_failure_blocks_cleanup",
                        "test_d2_later_cleanup_failure_preserves_final_snapshot",
                    }
                )
            )
            if obsolete:
                superseded.append(
                    dict(
                        test=case.id(),
                        reason="Superseded NC-02E atomic RPC, completed-master and retention contract; replaced by E live/DB proof. Historical evidence unchanged.",
                    )
                )
            else:
                applicable.append(case)
                selected_case_ids.append(case.id())
        suites.append(unittest.TestSuite(applicable))
        modules.append(module)
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        unittest.TestSuite(suites)
    )
    if args.static_only:
        evidence = {
            "phase": "NC-02E",
            "passed": result.wasSuccessful(),
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "findings": [r for m in modules for r in m.RESULTS],
            "read_only_static": True,
            "production_contact": False,
        }
        (ROOT / "db/records/nc_02e_static_validation.json").write_text(
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
        "phase": "NC-02E",
        "superseded_assertions": superseded,
        "selected_case_ids": selected_case_ids,
        "failed_case_ids": [
            case.id() for case, _ in [*result.failures, *result.errors]
        ],
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
        "db/records/nc_02e_recheck_validation.json"
        if args.recheck
        else (
            "db/records/nc_02e_lifecycle_validation.json"
            if args.lifecycle_only
            else "db/records/nc_02e_validation.json"
        )
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
