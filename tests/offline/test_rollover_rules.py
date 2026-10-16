"""RR2/RR10 pure acceptance, no app import or IO."""

import copy
import unittest
from canonical_season import SeasonConfigurationError
from rollover_service import validate_target, completed_master_error
from synthetic_fixtures import bracket_scenario
from bracket_rules import apply_prediction


def complete_graph(graph):
    graph = copy.deepcopy(graph)
    # Root play-in, deciding play-in, series rounds, Finals.
    for rnd in range(5):
        for slot in sorted({m["slot"] for m in graph if m["round"] == rnd}):
            for row in [m for m in graph if m["round"] == rnd and m["slot"] == slot]:
                if not row["team_a"] or not row["team_b"]:
                    raise AssertionError("Invalid synthetic graph")
                changed = {
                    m["id"]: m
                    for m in apply_prediction(
                        graph, row["id"], row["team_a"], 1 if rnd == 0 else 4
                    )
                }
                graph = [changed.get(m["id"], m) for m in graph]
    return graph


class RolloverRules(unittest.TestCase):
    def test_completed_results_ignore_master_saved_flag(self):
        self.assertIsNone(
            completed_master_error(
                complete_graph(bracket_scenario("master")["matches"])
            )
        )

    def test_partial_champion_counts_and_graph_refuse(self):
        original = complete_graph(bracket_scenario("master")["matches"])
        for change in [
            "champion",
            "count",
            "edge",
            "missing",
            "coordinate",
            "participant",
        ]:
            with self.subTest(change=change):
                rows = copy.deepcopy(original)
                final = next(m for m in rows if m["round"] == 4)
                if change == "champion":
                    final["predicted_winner"] = None
                if change == "count":
                    final["predicted_winner_games"] = None
                if change == "edge":
                    rows[0]["next_match_id"] = None
                if change == "missing":
                    rows.pop()
                if change == "coordinate":
                    rows[0]["slot"] = 88
                if change == "participant":
                    final["team_b"] = final["team_a"]
                self.assertIsNotNone(completed_master_error(rows))

    def test_immediate_target_and_century(self):
        for source, target in [
            ("2025-26", "2026-27"),
            ("1999-00", "2000-01"),
            ("2098-99", "2099-00"),
        ]:
            self.assertEqual(
                validate_target(
                    source, target, "2027-04-01T00:00:00Z", "2027-04-02T00:00:00Z"
                ),
                target,
            )

    def test_invalid_skipped_target_or_timing(self):
        for code in ("2025-26", "2024-25", "2027-28", "2026-28", "bad"):
            with self.assertRaises((ValueError, SeasonConfigurationError)):
                validate_target(
                    "2025-26", code, "2027-04-01T00:00:00Z", "2027-04-02T00:00:00Z"
                )
        for opening, lock in [
            (None, None),
            ("2027-04-01T00:00:00Z", "2027-04-01T00:00:00Z"),
            ("2027-04-03T00:00:00Z", "2027-04-02T00:00:00Z"),
            ("2027-04-01", "2027-04-02"),
        ]:
            with self.assertRaises((ValueError, SeasonConfigurationError)):
                validate_target("2025-26", "2026-27", opening, lock)


class RolloverPreparationSafety(unittest.TestCase):
    def test_calculation_only_does_not_publish_or_request_job_admission(self):
        from unittest.mock import Mock, patch
        from types import SimpleNamespace
        import scoring_service as service
        from synthetic_fixtures import identity

        client = Mock()
        data = bracket_scenario("master")
        season = SimpleNamespace(id=identity("current"))
        master = data["brackets"][0]

        def table(name):
            q = Mock()
            q.select.return_value = q
            q.eq.return_value = q
            q.execute.return_value.data = data[name]
            return q

        client.table.side_effect = table
        with patch.object(service, "guard_runtime_job") as guard, patch.object(
            service, "get_current_scoring_master", return_value=(season, master)
        ):
            prepared = service.recompute_current_scores(client, calculation_only=True)
        self.assertEqual(prepared["scoring_rows"], [])
        self.assertEqual(len(prepared["scoring_source"]["matches"]), 21)
        client.rpc.assert_not_called()
        guard.assert_not_called()

    def test_frozen_d2_verifier_assertions_are_preserved(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "db/post-baseline"
        frozen = (root / "verify_nc_02d2_schema.sql").read_text(encoding="utf-8")
        expected = (
            frozen.replace(
                "password_resets_id_seq,seasons,standings",
                "password_resets_id_seq,season_rollover_audits,seasons,standings",
            )
            .replace(
                "create_master_bracket_atomic,finalize_season_transition",
                "create_master_bracket_atomic,execute_season_rollover_transition,finalize_season_transition",
            )
            .replace(
                "publish_leaderboard_snapshot,set_master_bracket",
                "publish_leaderboard_snapshot,require_completed_rollover_master,run_season_rollover,set_master_bracket",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        actual = (
            (root / "verify_nc_02e_schema.sql")
            .read_text(encoding="utf-8")
            .split("DO $rollover_verify$", 1)[0]
        )
        self.assertEqual(actual, expected)


class RolloverRoutePreservation(unittest.TestCase):
    def test_existing_http_route_inventory_preserved(self):
        import ast
        import hashlib
        import json
        from pathlib import Path

        source = (Path(__file__).resolve().parents[2] / "app.py").read_text(
            encoding="utf-8"
        )
        inventory = []
        for node in ast.parse(source).body:
            if isinstance(node, ast.FunctionDef):
                for deco in node.decorator_list:
                    if (
                        isinstance(deco, ast.Call)
                        and isinstance(deco.func, ast.Attribute)
                        and isinstance(deco.func.value, ast.Name)
                        and deco.func.value.id == "app"
                        and deco.func.attr == "route"
                    ):
                        inventory.append([node.name, ast.dump(deco)])
        additions = {"update_league", "transfer_league_owner", "remove_league_member"}
        self.assertEqual({n for n, _ in inventory} & additions, additions)
        actual = hashlib.sha256(
            json.dumps(
                sorted(item for item in inventory if item[0] not in additions),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        # Reviewed complete pre-E Flask route contract, including registration.
        self.assertEqual(
            actual, "353db33d063d627c55bbae67880697b08be41bab843d1e5fe0860fb50d22be7d"
        )
