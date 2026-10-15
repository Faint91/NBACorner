"""Network-free fixture/job checks. Never imports app or executes a writer."""

import ast
import copy
import hashlib
import os
import socket
import unittest
from collections import defaultdict
from pathlib import Path
from unittest.mock import Mock, patch
import environment_safety as safety
import provider_transport as provider
import job_safety as jobs

ROOT = Path(__file__).resolve().parents[2]
TARGET = safety.load_enrollments()[0]


def config():
    return {
        "NBA_CORNER_ENV": "test",
        "NBA_CORNER_ALLOW_MUTATING_TESTS": "0",
        "NBA_CORNER_TEST_TARGET": TARGET.name,
        "NBA_CORNER_EXPECTED_PROJECT_REF": TARGET.project_ref,
        "SUPABASE_URL": TARGET.supabase_origin,
        "NBACORNER_BASE_URL": TARGET.backend_origin,
        "NBA_CORNER_EMAIL_MODE": "capture",
        "NBA_CORNER_RESET_LINK_ORIGIN": TARGET.backend_origin,
        "NBA_CORNER_PROVIDER_MODE": "fixtures",
        "NBA_CORNER_JOBS_ENABLED": "false",
    }


ESPN = (
    "https://site.web.api.espn.com/apis/v2/sports/basketball/nba/standings?season=2026"
)
BDL = "https://api.balldontlie.io/v1/games"


def function(path, name):
    return next(
        n
        for n in ast.parse((ROOT / path).read_text(encoding="utf-8")).body
        if isinstance(n, ast.FunctionDef) and n.name == name
    )


class ProviderJobTests(unittest.TestCase):
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
        self.live = Mock(side_effect=AssertionError("Provider forbidden"))

    def read(self, url=ESPN, **kwargs):
        return provider.provider_get(
            self.live, url, settings=config(), ambient={}, **kwargs
        )

    def test_mode_required(self):
        for value in (None, "live", "espn", "balldontlie", "unknown"):
            with self.subTest(mode=value), self.assertRaises(safety.SafetyError):
                provider.provider_get(
                    self.live,
                    ESPN,
                    settings=dict(config(), NBA_CORNER_PROVIDER_MODE=value),
                    ambient={},
                )
        self.live.assert_not_called()

    def test_live_espn_refused(self):
        with self.assertRaises(safety.SafetyError):
            provider.provider_get(
                self.live,
                ESPN,
                settings=dict(config(), NBA_CORNER_PROVIDER_MODE="live"),
                ambient={},
            )

    def test_live_balldontlie_refused(self):
        with self.assertRaises(safety.SafetyError):
            provider.provider_get(
                self.live,
                BDL,
                settings=dict(config(), NBA_CORNER_PROVIDER_MODE="live"),
                ambient={},
            )

    def test_credentials_rejected(self):
        for name in (
            "BALLDONTLIE_API_KEY",
            "ESPN_API_KEY",
            "NBA_STATS_TOKEN",
            "BREVO_API_KEY",
            "STANDINGS_CRON_TOKEN",
            "JWT_SECRET",
            "HEALTHCHECK_TOKEN",
        ):
            for source in ("settings", "ambient"):
                with self.subTest(name=name, source=source), self.assertRaises(
                    safety.SafetyError
                ):
                    safety.validate_test_provider_settings(
                        dict(
                            config(),
                            **({name: "synthetic"} if source == "settings" else {})
                        ),
                        TARGET,
                        ambient={name: "synthetic"} if source == "ambient" else {},
                    )

    def test_credentials_not_inherited(self):
        child = safety.controlled_child_environment(
            dict(config(), STANDINGS_CRON_TOKEN="synthetic"),
            "C:/fake/.env.test.local",
            parent={
                "BALLDONTLIE_API_KEY": "synthetic",
                "STANDINGS_CRON_TOKEN": "synthetic",
                "JWT_SECRET": "synthetic",
                "HTTPS_PROXY": "synthetic",
            },
        )
        for name in (
            "BALLDONTLIE_API_KEY",
            "STANDINGS_CRON_TOKEN",
            "JWT_SECRET",
            "HTTPS_PROXY",
        ):
            self.assertNotIn(name, child)

    def test_request_credentials_rejected(self):
        with self.assertRaises(safety.SafetyError):
            self.read(headers={"Authorization": "synthetic"})

    def test_espn_deterministic_fresh_json(self):
        a = self.read()
        b = self.read()
        self.assertEqual(a.text, b.text)
        a.json()["standings"]["entries"].clear()
        self.assertEqual(len(b.json()["standings"]["entries"]), 30)
        self.assertEqual(a.status_code, 200)
        a.raise_for_status()
        self.live.assert_not_called()

    def test_espn_actual_parser_statements(self):
        from standings_service import parse_espn
        from synthetic_fixtures import foundation

        rows = parse_espn(self.read().json(), foundation()["teams"])
        self.assertEqual(len(rows), 30)
        self.assertEqual(len({r["code"] for r in rows}), 30)
        self.live.assert_not_called()

    def test_balldontlie_pagination(self):
        a = self.read(BDL, params={"seasons[]": 2025, "per_page": 100})
        b = self.read(
            BDL,
            params={
                "seasons[]": 2025,
                "per_page": 100,
                "cursor": a.json()["meta"]["next_cursor"],
            },
        )
        self.assertIsNone(b.json()["meta"]["next_cursor"])
        self.assertEqual(len(a.json()["data"]), 3)
        self.assertEqual(len(b.json()["data"]), 3)

    def test_balldontlie_is_no_longer_standings_authority(self):
        fn = function("app.py", "fetch_and_sync_standings_from_nba")
        text = ast.unparse(fn)
        self.assertIn("refresh_current_standings", text)
        self.assertNotIn("balldontlie", text.lower())
        self.assertNotIn("provider_get", text)

    def test_unexpected_destinations_refused(self):
        for url in (
            "https://stats.nba.com/stats/leaguestandingsv3",
            "https://evil.invalid/",
            ESPN.replace("season=2026", "season=2028"),
            ESPN.replace("espn.com", "espn.com.evil.invalid"),
        ):
            with self.subTest(url=url), self.assertRaises(safety.SafetyError):
                self.read(url)

    def test_unknown_cursor_refused(self):
        with self.assertRaises(safety.SafetyError):
            self.read(BDL, params={"seasons[]": 2025, "per_page": 100, "cursor": 999})

    def test_production_callback_exact(self):
        callback = Mock(return_value="response")
        for identity in (None, "production"):
            self.assertEqual(
                provider.provider_get(
                    callback,
                    BDL,
                    settings={"NBA_CORNER_ENV": identity},
                    headers={"Authorization": "synthetic"},
                    timeout=10,
                ),
                "response",
            )
        callback.assert_called_with(
            BDL, headers={"Authorization": "synthetic"}, timeout=10
        )

    def test_mixed_identity_refused(self):
        with self.assertRaises(safety.SafetyError):
            provider.provider_mode(
                {"NBA_CORNER_ENV": "production", "NBA_CORNER_TEST_CONFIG": "synthetic"}
            )

    def test_jobs_disabled_default(self):
        self.assertFalse(safety.jobs_enabled({"NBA_CORNER_ENV": "test"}))
        with self.assertRaises(safety.SafetyError):
            safety.jobs_enabled(dict(config(), NBA_CORNER_JOBS_ENABLED="true"))

    def test_missing_jobs_blocks_readiness(self):
        with self.assertRaises(safety.SafetyError):
            safety.validate_test_job_settings(
                dict(config(), NBA_CORNER_JOBS_ENABLED=None)
            )

    def test_job_request_required(self):
        for requested in (None, "unknown", "season-rollover"):
            with self.assertRaises(safety.SafetyError):
                jobs.require_explicit_test_job(
                    config(), "standings-script", requested_job=requested
                )

    def test_mutation_optin_required(self):
        with self.assertRaises(safety.SafetyError):
            jobs.require_explicit_test_job(
                config(), "standings-script", requested_job="standings-script"
            )

    def test_live_identity_required(self):
        with patch.object(
            jobs,
            "verify_live_local_identity",
            side_effect=safety.SafetyError("Identity missing"),
        ) as live, self.assertRaises(safety.SafetyError):
            jobs.require_explicit_test_job(
                dict(config(), NBA_CORNER_ALLOW_MUTATING_TESTS="1"),
                "standings-script",
                requested_job="standings-script",
            )
        live.assert_called_once()

    def test_valid_identity_still_not_mutation_permission(self):
        with patch.object(
            jobs,
            "verify_live_local_identity",
            return_value={"marker": {"fixture_state": "UNSEEDED"}},
        ), self.assertRaisesRegex(
            safety.SafetyError, "Mutation/startup remains blocked"
        ):
            jobs.require_explicit_test_job(
                dict(config(), NBA_CORNER_ALLOW_MUTATING_TESTS="1"),
                "standings-script",
                requested_job="standings-script",
            )

    def test_production_jobs_noop(self):
        for identity in (None, "production"):
            with patch.dict(
                os.environ, {"NBA_CORNER_ENV": identity} if identity else {}, clear=True
            ), patch.object(
                jobs,
                "require_explicit_test_job",
                side_effect=AssertionError("test gate in production"),
            ):
                jobs.guard_runtime_job("standings-script")

    def test_readiness_no_mutation(self):
        with patch.object(
            safety,
            "verify_live_local_identity",
            return_value={
                "identity_verified": True,
                "marker": {"fixture_state": "UNSEEDED"},
            },
        ):
            result = safety.verify_provider_job_readiness(config())
        self.assertFalse(result["mutation_permitted"])
        self.assertEqual(result["fixtures_reset"], "UNMET")
        self.assertEqual(result["providers"], "PASS")

    def test_enrolled_loopback_only(self):
        self.assertEqual(
            safety.validate_test_destination(
                TARGET, TARGET.supabase_origin + "/rest/v1/teams"
            ),
            TARGET.supabase_origin,
        )
        for url in (
            "https://evil.invalid/path",
            "http://localhost:55421/",
            "http://127.0.0.1:1234/",
            "https://rpwesmvzmgoctrokrbhy.supabase.co/",
        ):
            with self.assertRaises(safety.SafetyError):
                safety.validate_test_destination(TARGET, url)

    def test_workflow_preserved_except_approved_legacy_season_retirement(self):
        self.assertEqual(
            hashlib.sha256(
                (ROOT / ".github/workflows/standings-cron.yml")
                .read_bytes()
                .replace(
                    b"        env:\n",
                    b"        env:\n          BALLDONTLIE_API_KEY: ${{ secrets.BALLDONTLIE_API_KEY }}\n          BACKEND_BASE_URL: ${{ secrets.BACKEND_BASE_URL }}\n          STANDINGS_CRON_TOKEN: ${{ secrets.STANDINGS_CRON_TOKEN }}\n",
                )
                .replace(
                    b"# Season selection comes from application_season; legacy NBA_SEASON_YEAR removed.",
                    b'NBA_SEASON_YEAR: "2025"  # adjust if needed',
                )
            ).hexdigest(),
            "0adbf07c1c28d3463a293f4656f2840c910f80f017cd14ffb912c1f3590ba6a2",
        )

    def test_script_guard_before_client(self):
        tree = ast.parse(
            (ROOT / "scripts/update_standings.py").read_text(encoding="utf-8")
        )
        calls = [
            n
            for n in tree.body
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
        ]
        self.assertLess(
            next(
                n.lineno
                for n in calls
                if getattr(n.value.func, "id", None) == "guard_runtime_job"
            ),
            next(
                n.lineno
                for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and getattr(n.func, "id", None) == "create_client"
            ),
        )

    def test_job_paths_guarded(self):
        for name in (
            "admin_snapshot_leaderboard",
            "admin_season_rollover",
            "fetch_and_sync_standings_from_nba",
            "admin_refresh_standings",
            "internal_cron_refresh_standings",
            "internal_overwrite_standings",
            "admin_insert_test_teams",
            "recompute_scores",
            "_snapshot_leaderboard_for_current_season",
            "_rollover_current_season",
        ):
            fn = function("app.py", name)
            i = (
                1
                if isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)
                else 0
            )
            self.assertEqual(fn.body[i].value.func.id, "guard_runtime_job")

    def test_startup_provider_gate_before_client(self):
        with patch.dict(
            os.environ,
            {"NBA_CORNER_ENV": "test", "NBA_CORNER_TEST_CONFIG": "fixture"},
            clear=True,
        ), patch.object(
            safety,
            "load_test_config",
            return_value=dict(
                config(),
                NBA_CORNER_ALLOW_MUTATING_TESTS="1",
                NBA_CORNER_PROVIDER_MODE="live",
            ),
        ), self.assertRaisesRegex(
            safety.SafetyError, "provider mode"
        ):
            safety.prepare_runtime_environment(
                Mock(side_effect=AssertionError("dotenv forbidden"))
            )

    def test_foreign_enrollment_refused(self):
        with self.assertRaises(safety.SafetyError):
            provider.provider_mode(
                dict(config(), NBA_CORNER_EXPECTED_PROJECT_REF="local:wrong"),
                ambient={},
            )


if __name__ == "__main__":
    unittest.main()
