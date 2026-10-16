"""Network-free F2 historical read/privacy and guarded-entry regression tests."""

import hashlib
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock
from types import SimpleNamespace
from league_history_service import read_history
from league_service import LeagueError
from integration_harness import GuardedHarness
from environment_safety import SafetyError
from synthetic_fixtures import identity

ROOT = Path(__file__).resolve().parents[2]
LEAGUE = dict(id="league", name="Current name", requires_password=False)


class HistoryReads(TestCase):
    def client(self, sequence):
        client = Mock()
        client.table.return_value = client
        for name in ("select", "eq", "in_", "order"):
            getattr(client, name).return_value = client
        client.execute.side_effect = [SimpleNamespace(data=value) for value in sequence]
        return client

    def test_only_actual_league_seasons_are_available_newest_first(self):
        client = self.client(
            [
                [
                    dict(
                        id="h1",
                        season_id="s1",
                        global_snapshot_id="g1",
                        expected_rows=1,
                        finalized_at="f1",
                    ),
                    dict(
                        id="h2",
                        season_id="s2",
                        global_snapshot_id="g2",
                        expected_rows=1,
                        finalized_at="f2",
                    ),
                ],
                [
                    dict(id="g1", season_id="s1", season_code="2024-25", is_final=True),
                    dict(id="g2", season_id="s2", season_code="2025-26", is_final=True),
                ],
            ]
        )
        value = read_history(client, LEAGUE)
        self.assertEqual(
            [s["season_code"] for s in value["seasons"]], ["2025-26", "2024-25"]
        )
        self.assertEqual(value["league"], LEAGUE)
        self.assertEqual(
            [c.args[0] for c in client.table.call_args_list],
            ["league_history_seasons", "leaderboard_history_snapshots"],
        )

    def test_no_history_is_empty_not_placeholder(self):
        self.assertEqual(read_history(self.client([[]]), LEAGUE)["seasons"], [])
        with self.assertRaises(LeagueError) as error:
            read_history(self.client([[]]), LEAGUE, "2024-25")
        self.assertEqual(error.exception.status, 404)

    def test_failed_query_is_not_empty_success(self):
        with self.assertRaises(LeagueError) as error:
            read_history(self.client([None]), LEAGUE)
        self.assertEqual(error.exception.status, 503)

    def sequence(self):
        return [
            [
                dict(
                    id="h",
                    season_id="season",
                    global_snapshot_id="global",
                    expected_rows=2,
                    finalized_at="final",
                )
            ],
            [
                dict(
                    id="global",
                    season_id="season",
                    season_code="2025-26",
                    is_final=True,
                    columns=[],
                )
            ],
            [
                dict(global_snapshot_row_id="r2", rank=1, display_order=1),
                dict(global_snapshot_row_id="r4", rank=2, display_order=2),
            ],
            [
                dict(
                    id="r4",
                    snapshot_id="global",
                    rank=4,
                    display_name="Frozen D",
                    total_points=0,
                    email="never-public",
                    user_id="secret-id",
                    bracket_id="live-private",
                    password_hash="never-public",
                ),
                dict(
                    id="r2",
                    snapshot_id="global",
                    rank=2,
                    display_name="Frozen B",
                    total_points=3,
                ),
            ],
        ]

    def test_stored_league_rank_order_overrides_global_rank_and_ids_never_escape(self):
        client = self.client(self.sequence())
        value = read_history(client, LEAGUE, "2025-26")
        self.assertEqual([r["rank"] for r in value["rows"]], [1, 2])
        self.assertEqual(
            [r["display_name"] for r in value["rows"]], ["Frozen B", "Frozen D"]
        )
        self.assertEqual(value["rows"][1]["total_points"], 0)
        for row in value["rows"]:
            self.assertFalse(
                set(row)
                & {
                    "id",
                    "user_id",
                    "bracket_id",
                    "snapshot_id",
                    "email",
                    "password_hash",
                }
            )
        self.assertFalse(
            {c.args[0] for c in client.table.call_args_list}
            & {"brackets", "bracket_scores", "league_members", "users"}
        )

    def test_missing_row_or_conflicting_source_refuses(self):
        for kind in ("missing", "conflict", "incomplete", "nonfinal"):
            data = self.sequence()
            if kind == "missing":
                data[3].pop()
            elif kind == "conflict":
                data[3][0]["snapshot_id"] = "other"
            elif kind == "incomplete":
                data[2].pop()
            else:
                data[1][0]["is_final"] = False
            with self.subTest(kind=kind):
                with self.assertRaises(LeagueError) as error:
                    read_history(self.client(data), LEAGUE, "2025-26")
                self.assertEqual(error.exception.status, 503)


class F2Safety(TestCase):
    def test_only_f2_scope_can_read_new_registered_history_routes(self):
        lid = identity("league-public")
        for scope in (None, "NC-01C", "NC-02D2", "NC-02F1", "NC-02F2"):
            c = object.__new__(GuardedHarness)
            c.characterization_scope = scope
            c._leagues = {lid}
            c._brackets = set()
            c._matches = set()
            c._auth_subjects = set()
            for path in (f"/leagues/{lid}/history", f"/leagues/{lid}/history/2025-26"):
                if scope == "NC-02F2":
                    c._check_path("GET", path)
                else:
                    with self.assertRaises(SafetyError):
                        c._check_path("GET", path)
            if scope == "NC-02F2":
                for method, path in (
                    ("POST", f"/leagues/{lid}/history"),
                    ("GET", f"/leagues/{identity('unregistered')}/history"),
                    ("GET", f"/leagues/{lid}/history/2025-26?escape=true"),
                ):
                    with self.assertRaises(SafetyError):
                        c._check_path(method, path)

    def test_fixed_fixture_requires_active_explicit_lease(self):
        c = object.__new__(GuardedHarness)
        with self.assertRaises((SafetyError, AttributeError)):
            c.install_league_history_scenario()

    def test_global_snapshot_and_transition_bodies_only_receive_approved_extensions(
        self,
    ):
        migration = (
            ROOT / "db/post-baseline/0009_nc_02f2_league_history.sql"
        ).read_text(encoding="utf-8")
        global_fn = migration.split(
            "CREATE OR REPLACE FUNCTION public.publish_leaderboard_snapshot", 1
        )[1].split("$body$;", 1)[0]
        original = (
            (ROOT / "db/post-baseline/0006_nc_02d2_final_snapshots.sql")
            .read_text(encoding="utf-8")
            .split("CREATE FUNCTION public.publish_leaderboard_snapshot", 1)[1]
            .split("$body$;", 1)[0]
        )
        start = global_fn.index(" INSERT INTO public.leaderboard_history_competitors")
        end = global_fn.index(
            " UPDATE public.leaderboard_history_snapshots SET is_final=true", start
        )
        self.assertEqual(global_fn[:start] + global_fn[end:], original)
        transition = migration.split(
            "CREATE OR REPLACE FUNCTION public.execute_season_rollover_transition", 1
        )[1].split("$body$;", 1)[0]
        original = (
            (ROOT / "db/post-baseline/0007_nc_02e_atomic_rollover.sql")
            .read_text(encoding="utf-8")
            .split("CREATE FUNCTION public.execute_season_rollover_transition", 1)[1]
            .split("$body$;", 1)[0]
        )
        self.assertEqual(
            transition.replace(
                " PERFORM public.verify_league_history_cutoff(p_source,p_snapshot);\n",
                "",
            ),
            original,
        )

    def test_f2_is_before_destructive_transition_and_global_failure_scope_unchanged(
        self,
    ):
        sql = (ROOT / "db/post-baseline/0009_nc_02f2_league_history.sql").read_text(
            encoding="utf-8"
        )
        rollover = sql.split(
            "CREATE OR REPLACE FUNCTION public.run_season_rollover", 1
        )[1]
        self.assertLess(
            rollover.index("publish_leaderboard_snapshot"),
            rollover.index("publish_league_history_cutoff"),
        )
        self.assertLess(
            rollover.index("publish_league_history_cutoff"),
            rollover.index("execute_season_rollover_transition"),
        )
        self.assertIn("LOCK TABLE public.leagues IN EXCLUSIVE MODE", sql)
        self.assertIn("WHERE id=OLD.league_id FOR UPDATE", sql)
        self.assertNotIn("UPDATE public.leaderboard_history_rows SET", sql)

    def test_verifier_pin_and_v1_checksum_inputs_remain_explicit(self):
        from scripts.reset_local_fixtures import VERIFIER_SHA, F2_TABLES
        from synthetic_fixtures import TABLES, VERSION

        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_current_schema.sql").read_bytes()
            ).hexdigest(),
            VERIFIER_SHA,
        )
        self.assertEqual(VERSION, "nc-fixtures-v1")
        self.assertFalse(set(F2_TABLES) & set(TABLES))
        self.assertEqual(len(F2_TABLES), 4)
        sql = (ROOT / "db/post-baseline/0009_nc_02f2_league_history.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("UNIQUE(league_id,season_id)", sql)
        self.assertIn("CHECK(expected_rows>0)", sql)
