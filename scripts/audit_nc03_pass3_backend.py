"""Fixed NC-02G2 acceptance/regression suite; writes separate repair evidence only."""

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
from scripts.nc03r1_acceptance_metadata import mark_signing_config_acceptance


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
        help="Recheck only cases that failed in the saved full F1 run, with the same guarded cleanup",
    )
    parser.add_argument(
        "--lifecycle-only",
        action="store_true",
        help="Run fixed NC-02G2 live/offline acceptance only",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run affected bracket source checks without importing the app or accessing the DB",
    )
    parser.add_argument(
        "--latest-recheck",
        action="store_true",
        help="Recheck only failed cases in the saved first recheck; preserves that evidence",
    )
    args = parser.parse_args()
    if args.latest_recheck:
        args.recheck = True
    if not args.allow_local_mutations:
        print("REFUSED: explicit guarded local mutation opt-in required.")
        return 2
    superseded = []
    selected_case_ids = []
    recheck_ids = set()
    if args.recheck:
        previous = json.loads(
            (
                ROOT
                / (
                    "db/records/nc_03_pass3_recheck_validation.json"
                    if args.latest_recheck
                    else "db/records/nc_03_pass3_initial_validation.json"
                )
            ).read_text(encoding="utf-8")
        )
        recheck_ids = set(previous["failed_case_ids"])
        if not recheck_ids:
            parser.error(
                "No failed cases in saved initial run; no recheck is necessary"
            )
    suites = []
    modules = []
    if sum((args.static_only, args.lifecycle_only, args.recheck)) > 1:
        parser.error("Choose only one focused validation mode")
    for file, cls in [
        ("password_reset", "PasswordResetAcceptance"),
        ("identity_auth_g2", "IdentityAuthAcceptance"),
        ("league_history", "LeagueHistoryAcceptance"),
        ("league_lifecycle", "LeagueLifecycleAcceptance"),
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
        if args.recheck and not any(
            case.startswith("nc02g2_" + file + ".") for case in recheck_ids
        ):
            continue
        if args.static_only and file != "bracket_static":
            continue
        if args.lifecycle_only and file not in {"identity_auth_g2", "password_reset"}:
            continue
        spec = importlib.util.spec_from_file_location(
            "nc02g2_" + file, ROOT / ("tests/characterization/" + file + ".py")
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
        if file == "auth_access":
            cls_auth = module.CurrentAuthBehavior
            for name in (
                "duplicate_email",
                "duplicate_username",
                "registration_nonobject",
                "password_whitespace",
            ):
                method_name = "current_behavior__auth__" + name
                original_auth = getattr(cls_auth, method_name)

                def approved_auth_contract(self, _original=original_auth, _name=name):
                    old_call = self.call

                    def approved_call(method, path, status, **kwargs):
                        if (
                            _name in {"duplicate_email", "duplicate_username"}
                            and path == "/auth/register"
                            and status == 400
                        ):
                            status = 409
                        if _name == "registration_nonobject":
                            status = 400
                        if _name == "password_whitespace" and path == "/auth/login":
                            status = 200
                        return old_call(method, path, status, **kwargs)

                    self.call = approved_call
                    return _original(self)

                approved_auth_contract.metadata = dict(
                    original_auth.metadata,
                    phase="NC-02G2",
                    previous_metadata=dict(original_auth.metadata),
                    current_behavior="Approved G1 controlled request/conflict/exact-password behavior; original evidence retained",
                )
                setattr(cls_auth, method_name, approved_auth_contract)
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
                phase="NC-02G2",
                previous_metadata=dict(original.metadata),
                current_behavior="Standalone snapshot preserved; rollover performs read-only preparation then locked DB snapshot gate before atomic transition. Real SQL rollback acceptance is authoritative.",
            )
            module.CurrentStaticScoring.current_behavior__history__snapshot_source = (
                atomic_snapshot_source
            )
        if file == "league_access":
            original_errors = (
                module.CurrentLeagueBehavior.current_behavior__league__errors
            )

            def f1_error_contract(self):
                original_call = self.call

                def contract_call(method, path, status, **kwargs):
                    if method == "POST" and isinstance(kwargs.get("payload"), list):
                        status = 400  # F1 sanitizes malformed objects instead of returning 500.
                    if (
                        method == "DELETE"
                        and status == 200
                        and not path.endswith("/membership")
                    ):
                        kwargs["payload"] = {"confirm_delete": True}
                    return original_call(method, path, status, **kwargs)

                self.call = contract_call
                original_errors(self)

            f1_error_contract.metadata = dict(
                original_errors.metadata,
                phase="NC-02G2",
                previous_metadata=dict(original_errors.metadata),
                current_behavior="Preserve ID/auth/missing/repeat-delete error matrix with approved F1 malformed-object 400 and explicit confirmed deletion.",
            )
            module.CurrentLeagueBehavior.current_behavior__league__errors = (
                f1_error_contract
            )
        if file == "auth_access":
            import ast
            import inspect
            import textwrap

            klass = module.CurrentAuthBehavior
            original = klass.current_behavior__auth__login_metadata
            tree = ast.parse(textwrap.dedent(inspect.getsource(original)))
            node = tree.body[0]
            node.decorator_list = []
            changed = 0
            for item in ast.walk(node):
                if isinstance(item, ast.Set) and {
                    v.value for v in item.elts if isinstance(v, ast.Constant)
                } == {"user_id", "username", "is_admin", "exp"}:
                    item.elts.append(ast.Constant(value="av"))
                    changed += 1
            assert changed == 1
            scope = dict(module.__dict__)
            exec(
                compile(
                    ast.fix_missing_locations(tree),
                    "G2 additional av claim adapter",
                    "exec",
                ),
                scope,
            )
            replacement = scope[node.name]
            replacement.metadata = dict(
                original.metadata,
                phase="NC-02G2",
                approved_requirement="A13/A14",
                current_behavior="Additional av claim; original identity, algorithm and seven-day expiry assertions preserved",
            )
            klass.current_behavior__auth__login_metadata = replacement
        if file == "auth_static":
            import ast
            import textwrap
            import inspect

            klass = module.CurrentStaticAuthBehavior
            old_defaults = klass.current_behavior__auth__implementation_defaults
            tree = ast.parse(textwrap.dedent(inspect.getsource(old_defaults)))
            node = tree.body[0]
            node.decorator_list = []
            for item in ast.walk(node):
                if (
                    isinstance(item, ast.Constant)
                    and item.value == "bcrypt.gensalt(rounds=BCRYPT_ROUNDS)"
                ):
                    item.value = "rounds=BCRYPT_ROUNDS"
            scope = dict(module.__dict__)
            exec(
                compile(
                    ast.fix_missing_locations(tree),
                    "G2 shared-hasher static adapter",
                    "exec",
                ),
                scope,
            )
            replacement = scope[node.name]
            replacement.metadata = dict(
                old_defaults.metadata,
                phase="NC-02G2",
                current_behavior="Original signing/expiry/default assertions preserved; password hashing now delegates to G1 shared hasher",
            )
            klass.current_behavior__auth__implementation_defaults = replacement
            mark_signing_config_acceptance(klass)
            old_reset_ui = klass.current_behavior__auth__frontend_reset_request_only

            def completion_ui(self):
                source = self.front("pages/ResetPasswordPage.tsx")
                self.assertIn('"/auth/forgot-password"', source)
                self.assertIn('"/auth/reset-password"', source)
                self.assertIn("new_password", source)
                self.assertIn("logout()", source)
                self.assertNotIn("localStorage", source)
                self.assertNotIn("sessionStorage", source)
                self.assertIn(
                    '"/auth/forgot-password"', self.front("pages/AccountPage.tsx")
                )

            completion_ui.metadata = dict(
                old_reset_ui.metadata,
                phase="NC-02G2",
                current_behavior="Approved G2 request and completion UI; historical request-only evidence retained",
            )
            klass.current_behavior__auth__frontend_reset_request_only = completion_ui
        loader = unittest.TestLoader()
        loader.testMethodPrefix = (
            "test_"
            if file
            in {
                "password_reset",
                "identity_auth_g2",
                "history_snapshot",
                "league_history",
                "league_lifecycle",
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
            if file == "auth_access" and case._testMethodName.startswith(
                "current_behavior__auth__reset_"
            ):
                superseded.append(
                    dict(
                        test=case.id(),
                        reason="Approved G2 replaces raw-storage/24h/reusable-session reset contracts; covered by password_reset acceptance. Historical evidence unchanged.",
                    )
                )
                continue
            if (
                file == "auth_access"
                and case._testMethodName
                == "current_behavior__auth__username_case_resolution"
            ):
                superseded.append(
                    dict(
                        test=case.id(),
                        reason="Approved A2/A6 normalized uniqueness replaces case-distinct accounts; covered by G1 live and DB race acceptance. Original evidence unchanged.",
                    )
                )
                continue
            name = case._testMethodName
            if args.recheck and case.id() not in recheck_ids:
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
            f1_obsolete = (
                (
                    file == "league_access"
                    and name
                    in {
                        "current_behavior__league__creation_validation",
                        "current_behavior__league__join",
                        "current_behavior__league__admin_join_delete",
                        "current_behavior__league__leave",
                        "current_behavior__league__empty_final_leave",
                        "current_behavior__league__delete",
                        "current_behavior__league__owner_not_member",
                        "current_behavior__league__timing",
                    }
                )
                or (
                    file == "league_static"
                    and name
                    in {
                        "current_behavior__league__route_absences",
                        "current_behavior__league__password_source",
                        "current_behavior__league__frontend_members",
                        "current_behavior__league__frontend_owner",
                        "current_behavior__league__failure_paths",
                    }
                )
                or (
                    file == "privacy_access"
                    and name == "test_owner_without_membership_all_private_surfaces"
                )
            )
            if f1_obsolete:
                superseded.append(
                    dict(
                        test=case.id(),
                        reason="Approved L1-L19 F1 contract replaces old timing, minimum length, already-member error, unconfirmed delete and invalid ownerless fixture assumptions; covered by league_lifecycle live acceptance. Original evidence unchanged.",
                    )
                )
                continue
            if obsolete:
                superseded.append(
                    dict(
                        test=case.id(),
                        reason="Superseded NC-02G2 atomic RPC, completed-master and retention contract; replaced by E live/DB proof. Historical evidence unchanged.",
                    )
                )
            else:
                applicable.append(case)
                selected_case_ids.append(case.id())
        suites.append(unittest.TestSuite(applicable))
        modules.append(module)
    if not selected_case_ids:
        raise RuntimeError("No applicable tests selected")
    result = unittest.TextTestRunner(verbosity=2, resultclass=SanitizedResult).run(
        unittest.TestSuite(suites)
    )
    if args.static_only:
        evidence = {
            "phase": "NC-02G2",
            "passed": result.wasSuccessful(),
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "findings": [r for m in modules for r in m.RESULTS],
            "read_only_static": True,
            "production_contact": False,
        }
        (ROOT / "db/records/nc_03_pass3_static_validation.json").write_text(
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
        "phase": "NC-02G2",
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
        "db/records/nc_03_pass3_final_recheck_validation.json"
        if args.latest_recheck
        else (
            "db/records/nc_03_pass3_recheck_validation.json"
            if args.recheck
            else (
                "db/records/nc_03_pass3_lifecycle_validation.json"
                if args.lifecycle_only
                else "db/records/nc_03_pass3_validation.json"
            )
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
