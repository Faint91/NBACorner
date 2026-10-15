"""Network-free D2 contracts, rank freezing, safe serialization and guard refusals."""

import copy
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import history_service as service


class HistoryTests(unittest.TestCase):
    def test_frozen_rank_matrix_preserves_saved_time_and_true_ties(self):
        scores = []
        brackets = []
        users = []
        for bid, pts, hits, stamp, name in [
            ("top", 8, 1, "2026-01-03T00:00:00Z", "Z"),
            ("hits", 7, 2, "2026-01-03T00:00:00Z", "Z"),
            ("early-z", 7, 1, "2026-01-01T00:00:00Z", "Zulu"),
            ("early-a", 7, 1, "2026-01-01T00:00:00Z", "Alpha"),
            ("late", 7, 1, "2026-01-02T00:00:00Z", "A"),
        ]:
            scores.append(
                dict(
                    bracket_id=bid,
                    total_points=pts,
                    full_hits=hits,
                    partial_hits=0,
                    misses=0,
                    bonus_finalists=0,
                    bonus_champion=0,
                    points_by_round={"1": pts},
                    points_by_match={"east-1-4": {"points": pts}},
                )
            )
            brackets.append(dict(id=bid, user_id=bid, name="Bracket", saved_at=stamp))
            users.append(
                dict(
                    id=bid,
                    username=name,
                    email="must-not-escape",
                    password_hash="must-not-escape",
                )
            )
        before = copy.deepcopy((scores, brackets, users))
        frozen, _ = service.snapshot_rows(scores, brackets, users)
        self.assertEqual([r["rank"] for r in frozen], [1, 2, 3, 3, 5])
        self.assertEqual(
            [r["bracket_id"] for r in frozen],
            ["top", "hits", "early-a", "early-z", "late"],
        )
        self.assertEqual(before, (scores, brackets, users))
        self.assertNotIn("must-not-escape", str(frozen))

    def test_zero_only_confirmed_complete_final_snapshot(self):
        value = dict(
            state="created",
            snapshot_id="id",
            season_id="s",
            season_code="2025-26",
            expected_rows=0,
            actual_rows=0,
            is_final=True,
        )
        self.assertTrue(
            service.confirmed_snapshot(value, "s", 0)["structured_complete"]
        )
        for changes in (
            {"actual_rows": 1},
            {"actual_rows": False},
            {"snapshot_id": True},
            {"is_final": False},
            {"snapshot_id": None},
            {"expected_rows": None},
            {"state": "unknown"},
            {"season_id": "other"},
        ):
            with self.assertRaises(service.SnapshotError):
                service.confirmed_snapshot(dict(value, **changes), "s", 0)
        with self.assertRaises(service.SnapshotError):
            service.confirmed_snapshot(value, "s", 1)

    def test_frozen_existing_result_does_not_use_changed_current_count(self):
        value = dict(
            state="existing",
            snapshot_id="id",
            season_id="s",
            season_code="2025-26",
            expected_rows=2,
            actual_rows=2,
            is_final=True,
        )
        self.assertEqual(service.confirmed_snapshot(value, "s", 0)["expected_rows"], 2)

    def test_failed_recompute_never_queries_or_publishes_empty(self):
        from scoring_service import ScoringError

        client = Mock()
        with patch.object(service, "guard_runtime_job"), patch.object(
            service,
            "get_current_scoring_master",
            return_value=(SimpleNamespace(id="s"), {"id": "m"}),
        ), patch.object(
            service,
            "recompute_current_scores",
            side_effect=ScoringError("calculation_failure"),
        ):
            with self.assertRaises(service.SnapshotError) as caught:
                service.create_final_leaderboard_snapshot(client)
        self.assertEqual(caught.exception.stage, "canonical_recompute_failure")
        client.table.assert_not_called()
        client.rpc.assert_not_called()

    def test_query_failure_is_not_zero_even_after_successful_empty_evaluation(self):
        client = Mock()
        client.table.side_effect = RuntimeError("SECRET_SOURCE_FAILURE")
        with patch.object(service, "guard_runtime_job"), patch.object(
            service,
            "get_current_scoring_master",
            return_value=(SimpleNamespace(id="s"), {"id": "m"}),
        ), patch.object(
            service,
            "recompute_current_scores",
            return_value=dict(updated_brackets=0, scoring_rows=[], scoring_source={}),
        ):
            with self.assertRaises(service.SnapshotError) as caught:
                service.create_final_leaderboard_snapshot(client)
        self.assertNotIn("SECRET", str(caught.exception))
        client.rpc.assert_not_called()

    def test_unknown_read_result_is_not_zero(self):
        client = Mock()
        client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = (
            None
        )
        with patch.object(service, "guard_runtime_job"), patch.object(
            service,
            "get_current_scoring_master",
            return_value=(SimpleNamespace(id="s"), {"id": "m"}),
        ), patch.object(
            service,
            "recompute_current_scores",
            return_value=dict(updated_brackets=0, scoring_rows=[], scoring_source={}),
        ):
            with self.assertRaises(service.SnapshotError):
                service.create_final_leaderboard_snapshot(client)
        client.rpc.assert_not_called()

    def test_public_allowlists_drop_security_and_private_json(self):
        raw = [
            dict(
                id="row",
                rank=1,
                email="secret",
                user_id="private",
                bracket_id="private",
                per_match_points={
                    "east-1-4": 3,
                    "email": "secret",
                    "west-1-4": {"token": "secret"},
                },
                points_by_round={"1": 3, "token": "secret"},
            )
        ]
        result = service.public_snapshot_rows(raw)
        self.assertEqual(result[0]["per_match_points"], {"east-1-4": 3})
        self.assertEqual(result[0]["points_by_round"], {"1": 3})
        self.assertNotIn("secret", str(result))
        self.assertNotIn("private", str(result))
        columns = service.public_columns(
            [
                dict(key="east-1-4", label="E R1-4", type="matchup", email="secret"),
                dict(key="email", label="secret", type="summary"),
            ]
        )
        self.assertEqual(
            columns, [dict(key="east-1-4", label="E R1-4", type="matchup")]
        )

    def test_no_unguarded_job_or_global_permission(self):
        from integration_harness import authorize_transition_test_job, GuardedHarness

        self.assertFalse(authorize_transition_test_job("leaderboard-snapshot"))
        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02D1"
        with self.assertRaises(Exception):
            c.snapshot_request()
