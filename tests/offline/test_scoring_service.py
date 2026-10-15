"""Canonical-only master resolution, sanitized failures and verifier preservation."""

import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import scoring_service as service

ROOT = Path(__file__).resolve().parents[2]


class ScoringServiceTests(unittest.TestCase):
    def client(self, pointer="master", master=None):
        client = Mock()
        valid = dict(id="master", season_id="current", is_master=True, deleted_at=None)

        def table(name):
            q = Mock()
            q.select.return_value = q
            q.eq.return_value = q
            q.limit.return_value = q
            q.execute.return_value.data = (
                [dict(id="current", master_bracket_id=pointer)]
                if name == "seasons"
                else [valid if master is None else master]
            )
            return q

        client.table.side_effect = table
        return client

    def resolve(self, client, **kwargs):
        with patch.object(
            service,
            "get_current_season",
            return_value=SimpleNamespace(id="current", code="2025-26"),
        ):
            return service.get_current_scoring_master(client, **kwargs)

    def test_current_active_master_only(self):
        season, master = self.resolve(self.client())
        self.assertEqual((season.id, master["id"]), ("current", "master"))
        for changed in [
            dict(id="master", season_id="historical", is_master=True),
            dict(id="master", season_id="current", is_master=False),
            dict(
                id="master", season_id="current", is_master=True, deleted_at="deleted"
            ),
        ]:
            with self.assertRaises(service.ScoringError):
                self.resolve(self.client(master=changed))

    def test_missing_pointer_and_caller_spoof_fail_closed(self):
        with self.assertRaises(service.ScoringError):
            self.resolve(self.client(pointer=None))
        for supplied in ["ordinary-user", "historical-master", "arbitrary"]:
            with self.assertRaises(service.ScoringError) as caught:
                self.resolve(self.client(), expected_master_id=supplied)
            self.assertEqual(caught.exception.stage, "caller_master_mismatch")
        with self.assertRaises(service.ScoringError):
            self.resolve(self.client(), expected_season_id="wrong")

    def test_missing_canonical_and_db_errors_are_sanitized(self):
        with patch.object(
            service, "get_current_season", side_effect=RuntimeError("SECRET_DIAGNOSTIC")
        ), self.assertRaises(service.ScoringError) as caught:
            service.get_current_scoring_master(self.client())
        self.assertNotIn("SECRET", str(caught.exception))

    def test_eligibility_saved_active_current_and_valid_time(self):
        b = dict(
            id="user",
            season_id="current",
            is_done=True,
            deleted_at=None,
            saved_at="2026-01-01T00:00:00Z",
        )
        self.assertTrue(service.eligible(b, "current", "master"))
        for change in [
            dict(id="master"),
            dict(season_id="historical"),
            dict(is_done=False),
            dict(deleted_at="removed"),
            dict(saved_at=None),
            dict(saved_at="bad"),
        ]:
            self.assertFalse(service.eligible(dict(b, **change), "current", "master"))

    def test_unscoped_scoring_admission_is_closed(self):
        from integration_harness import GuardedHarness, authorize_scoring_test_job

        for job in ["score-recompute", "season-rollover", "leaderboard-snapshot"]:
            self.assertFalse(authorize_scoring_test_job(job))
        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock(side_effect=RuntimeError("Lease"))
        with self.assertRaises(RuntimeError):
            c.recompute_request()
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02C3"
        with self.assertRaises(Exception):
            c.recompute_request()

    def test_late_calculation_failure_never_publishes_a_partial_set(self):
        from synthetic_fixtures import bracket_scenario, identity, STAMP
        from scoring_engine import score_bracket

        client = Mock()
        season = SimpleNamespace(id=identity("current"))
        master = dict(id=identity("bracket-master"))
        brackets = [
            dict(
                id=identity("score-" + role),
                season_id=season.id,
                is_done=True,
                deleted_at=None,
                saved_at=STAMP,
            )
            for role in ("user-a", "user-b")
        ]
        matches = bracket_scenario("master")["matches"]

        def table(name):
            q = Mock()
            q.select.return_value = q
            q.eq.return_value = q
            q.execute.return_value.data = brackets if name == "brackets" else matches
            return q

        client.table.side_effect = table
        count = 0

        def calculate(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise ValueError("SECRET_CALCULATION_DIAGNOSTIC")
            return score_bracket(*args)

        with patch.object(service, "guard_runtime_job"), patch.object(
            service, "get_current_scoring_master", return_value=(season, master)
        ), patch.object(
            service, "score_bracket", side_effect=calculate
        ), self.assertRaises(
            service.ScoringError
        ) as caught:
            service.recompute_current_scores(client)
        self.assertEqual(caught.exception.stage, "calculation_failure")
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertEqual(count, 2)
        client.rpc.assert_not_called()

    def test_verifier_preserves_c3_assertions_and_immutable_pin(self):
        old = (ROOT / "db/post-baseline/verify_nc_02c3_schema.sql").read_bytes()
        self.assertEqual(
            hashlib.sha256(old).hexdigest(),
            "a1046275846a14625808be9151cb3035f6fc7030128753f261ff2eeed42702a7",
        )
        prefix = (
            old.decode()
            .replace(
                "fix_season_master_on_bracket_soft_delete,publish_current_standings",
                "fix_season_master_on_bracket_soft_delete,publish_current_bracket_scores,publish_current_standings",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        current = (ROOT / "db/post-baseline/verify_nc_02d1_schema.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(current.split("DO $scores_verify$", 1)[0], prefix)
        from scripts.reset_local_fixtures import VERIFIER_SHA

        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_current_schema.sql").read_bytes()
            ).hexdigest(),
            VERIFIER_SHA,
        )
