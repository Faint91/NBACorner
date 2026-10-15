"""Offline transition safety contracts, verifier preservation, and timing validation."""

import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock
from canonical_season import validate_season_row, SeasonConfigurationError
from integration_harness import GuardedHarness, authorize_transition_test_job

ROOT = Path(__file__).resolve().parents[2]


class TransitionSafety(unittest.TestCase):
    def test_target_configuration_matches_canonical_requirements(self):
        row = {
            "id": "target",
            "code": "2026-27",
            "regular_season_end_utc": "2027-04-12T07:00:00Z",
            "playoffs_start_utc": "2027-04-18T07:00:00Z",
        }
        self.assertEqual(validate_season_row(row).code, "2026-27")
        for changes in [
            {"code": "arbitrary"},
            {"code": "2026-28"},
            {"regular_season_end_utc": None},
            {"playoffs_start_utc": None},
            {"regular_season_end_utc": "2027-04-12T07:00:00"},
            {"regular_season_end_utc": "2027-05-01T07:00:00Z"},
        ]:
            with self.assertRaises(SeasonConfigurationError):
                validate_season_row(dict(row, **changes))

    def test_finalization_admission_is_not_a_general_job_bypass(self):
        for job in [
            "season-rollover",
            "leaderboard-snapshot",
            "score-recompute",
            "standings-overwrite",
        ]:
            self.assertFalse(authorize_transition_test_job(job))
        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock(side_effect=RuntimeError("Lease"))
        with self.assertRaises(RuntimeError):
            c.transition_request(payload={"new_season_code": "2026-27"})
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02C2"
        with self.assertRaises(Exception):
            c.transition_request(payload={"new_season_code": "2026-27"})
        c.characterization_scope = "NC-02C3"
        for data in [
            {"new_season_code": "2027-28"},
            {"new_season_code": "2026-27", "force": True},
        ]:
            with self.assertRaises(Exception):
                c.transition_request(payload=data)

    def test_verifier_extends_frozen_c2_without_dropping_assertions(self):
        old = (ROOT / "db/post-baseline/verify_nc_02c2_schema.sql").read_bytes()
        self.assertEqual(
            hashlib.sha256(old).hexdigest(),
            "640bcb901709f310fa27018e83fdf62de7be4aec427415781f346ada5ee812d4",
        )
        prefix = (
            old.decode()
            .replace(
                "create_master_bracket_atomic,fix_season_master_on_bracket_soft_delete",
                "create_master_bracket_atomic,finalize_season_transition,fix_season_master_on_bracket_soft_delete",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        current = (ROOT / "db/post-baseline/verify_current_schema.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(current.split("DO $transition_verify$", 1)[0], prefix)
        from scripts.reset_local_fixtures import VERIFIER_SHA

        self.assertEqual(hashlib.sha256(current.encode()).hexdigest(), VERIFIER_SHA)
