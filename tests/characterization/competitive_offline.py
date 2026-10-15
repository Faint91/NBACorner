"""Offline eligibility, new-snapshot and recomputation-selection acceptance; no app/network."""

import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
RESULTS = []
spec = importlib.util.spec_from_file_location(
    "nc02a2_scoring_fixture", ROOT / "tests/characterization/scoring_offline.py"
)
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)


def acceptance(fn):
    fn.metadata = {
        "scenario": fn.__name__,
        "phase": "NC-02A2",
        "classification": "APPROVED REQUIREMENT",
        "requirements": ["P4", "P5", "P9"],
        "evidence_source": "OFFLINE AST functions and synthetic fake DB; no live jobs",
    }
    return fn


class CompetitiveEligibilityOffline(unittest.TestCase):
    def setUp(self):
        self.db, self.ns, self.jobs = prior.environment()

    def tearDown(self):
        RESULTS.append(dict(getattr(self, self._testMethodName).metadata))

    @acceptance
    def test_predicate_submission_deleted_season_and_legacy_metadata(self):
        check = self.ns["competitive_bracket_eligible"]
        saved = {
            "is_done": True,
            "deleted_at": None,
            "season_id": "current",
            "saved_at": None,
        }
        self.assertTrue(check(saved))
        for changed in (
            {"is_done": False},
            {"is_done": False, "saved_at": "old-save-time"},
            {"is_done": None},
            {"deleted_at": "deleted"},
            {"season_id": "past"},
        ):
            self.assertFalse(check({**saved, **changed}))
        self.assertTrue(check({**saved, "season_id": "past"}, season_id="past"))
        self.assertFalse(check(saved, season_id="past"))
        from canonical_season import SeasonConfigurationError

        def missing():
            raise SeasonConfigurationError()

        self.ns["current_season"] = missing
        with self.assertRaises(SeasonConfigurationError):
            check({**saved, "season_id": None})

    @acceptance
    def test_new_snapshot_uses_saved_only_old_history_unchanged(self):
        self.db.rows["bracket_scores"] = [
            dict(
                bracket_id=i,
                season_id="current",
                total_points=3,
                full_hits=1,
                points_by_match={},
            )
            for i in ("a", "b")
        ]
        self.db.rows["brackets"][1]["is_done"] = False
        old = {
            "season_code": "2024-25",
            "display_name": "Retained history",
            "total_points": 3,
        }
        self.db.rows["leaderboard_history"] = [old.copy()]
        rows = self.ns["_build_leaderboard_rows_for_current_season"]()
        self.assertEqual([r["bracket_id"] for r in rows], ["b"])
        result = self.ns["_snapshot_leaderboard_for_current_season"]()
        self.assertTrue(result["ok"])
        self.assertEqual(self.db.rows["leaderboard_history"][0], old)
        self.assertEqual(result["rows_snapshot"], 1)
        self.assertEqual(len(self.db.rows["bracket_scores"]), 2)

    @acceptance
    def test_recompute_selection_skips_unsaved_without_deleting_stale_score(self):
        # Route delegates once to canonical complete-set orchestration; no row loop.
        self.db.rows["users"].append(dict(id="admin", is_admin=True))
        delegated = []

        def recompute(client, **kwargs):
            self.assertIs(client, self.db)
            delegated.append(kwargs)
            return dict(updated_brackets=1, state="unchanged")

        from scoring_service import ScoringError

        self.ns.update(
            request=SimpleNamespace(user={"user_id": "admin", "is_admin": True}),
            jsonify=lambda value: value,
            recompute_current_scores=recompute,
            ScoringError=ScoringError,
        )
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        node = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "recompute_scores"
        )
        node.decorator_list = []
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]),
                "recompute_canonical_delegation",
                "exec",
            ),
            self.ns,
        )
        body, status = self.ns["recompute_scores"]("master")
        self.assertEqual(status, 200)
        self.assertEqual(body["updated_brackets"], 1)
        self.assertEqual(
            delegated, [dict(expected_season_id="current", expected_master_id="master")]
        )
        self.facts = {
            "prior_reference": "NC-01C draft_scored_leaderboard",
            "complete_publication_verified_by": "NC-02D1 live/RPC tests",
        }
