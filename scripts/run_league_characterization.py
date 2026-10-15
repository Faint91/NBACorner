"""Fixed NC-01C current-behavior suite; no arbitrary test selection."""

import argparse, importlib.util, json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.local_supabase_environment import ROOT, sql_file
from integration_harness import readiness_report
from environment_safety import load_test_config


class SanitizedResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        return (
            type(err[1]).__name__
            + ": characterization failure; sensitive diagnostics withheld."
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    args = parser.parse_args()
    if not args.allow_local_mutations:
        print("REFUSED: explicit local characterization opt-in required.")
        return 2
    spec = importlib.util.spec_from_file_location(
        "nc01c_league", ROOT / "tests/characterization/league_access.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CONFIG = args.config
    module.OPT_IN = True
    loader = unittest.TestLoader()
    loader.testMethodPrefix = "current_behavior__league__"
    static_spec = importlib.util.spec_from_file_location(
        "nc01c_static", ROOT / "tests/characterization/league_static.py"
    )
    static_module = importlib.util.module_from_spec(static_spec)
    static_spec.loader.exec_module(static_module)
    suite = unittest.TestSuite(
        (
            loader.loadTestsFromTestCase(module.CurrentLeagueBehavior),
            loader.loadTestsFromTestCase(static_module.CurrentStaticLeagueBehavior),
        )
    )
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        suite
    )
    sql_file(ROOT / "db/baseline/verify_current_schema.sql")
    sql_file(ROOT / "test-infrastructure/local-supabase/verify-fixture-marker-v2.sql")
    report = {
        "phase": "NC-01C",
        "passed": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "findings": module.RESULTS + static_module.RESULTS,
        "readiness": readiness_report(load_test_config(args.config)),
        "business_behavior_changed": False,
        "production": {
            "contact": False,
            "mutation": False,
            "secrets_used": False,
            "deployment": False,
        },
    }
    (ROOT / "db/records/nc_01c_league.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {
                "phase": "NC-01C",
                "passed": result.wasSuccessful(),
                "tests": result.testsRun,
                "findings": len(module.RESULTS) + len(static_module.RESULTS),
                "canonical_cleanup": report["readiness"]["fixtures_reset"],
            },
            indent=2,
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
