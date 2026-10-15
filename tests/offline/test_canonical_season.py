"""Canonical production lookup is pure DB authority; no application import/network."""

import ast
import os
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from canonical_season import (
    get_current_season,
    espn_season_year,
    SeasonConfigurationError,
)
from scripts.reset_local_fixtures import VERIFIER_SHA, reset_sql
import hashlib

ROOT = Path(__file__).resolve().parents[2]


class CanonicalSeasonTests(unittest.TestCase):
    def client(self, pointers=None, rows=None):
        client = Mock()

        def table(name):
            query = Mock()
            query.select.return_value = query
            query.eq.return_value = query
            query.limit.return_value = query
            query.execute.return_value.data = (
                (
                    pointers
                    if pointers is not None
                    else [{"singleton": True, "season_id": "canonical"}]
                )
                if name == "application_season"
                else (
                    rows
                    if rows is not None
                    else [
                        {
                            "id": "canonical",
                            "code": "2025-26",
                            "regular_season_end_utc": "2026-04-12T07:00:00Z",
                            "playoffs_start_utc": "2026-04-18T07:00:00Z",
                        }
                    ]
                )
            )
            return query

        client.table.side_effect = table
        return client

    def test_conflicting_production_env_cannot_select_season(self):
        with patch.dict(
            os.environ,
            {
                "NBA_CORNER_ENV": "production",
                "CURRENT_SEASON_CODE": "2099-00",
                "NBA_SEASON_YEAR": "1900",
                "NBA_STANDINGS_SEASON": "1901",
                "REGULAR_SEASON_END_UTC": "invalid",
                "PLAYOFFS_START_UTC": "invalid",
            },
            clear=True,
        ):
            self.assertEqual(get_current_season(self.client()).code, "2025-26")

    def test_missing_or_duplicate_pointer_fails_closed(self):
        for rows in [
            [],
            [{"singleton": False, "season_id": "canonical"}],
            [{"singleton": True, "season_id": "canonical"}] * 2,
        ]:
            with self.subTest(rows=len(rows)), self.assertRaises(
                SeasonConfigurationError
            ):
                get_current_season(self.client(pointers=rows))

    def test_missing_season_and_provider_error_sanitized(self):
        with self.assertRaises(SeasonConfigurationError):
            get_current_season(self.client(rows=[]))
        c = self.client()
        c.table.side_effect = RuntimeError("Sensitive fixture diagnostic")
        with self.assertRaises(SeasonConfigurationError) as e:
            get_current_season(c)
        self.assertNotIn("Sensitive", str(e.exception))

    def test_invalid_timing_fails_closed(self):
        for value in [None, "bad", "2026-04-12T07:00:00", "2027-01-01T00:00:00Z"]:
            with self.assertRaises(SeasonConfigurationError):
                get_current_season(
                    self.client(
                        rows=[
                            {
                                "id": "canonical",
                                "code": "2025-26",
                                "regular_season_end_utc": value,
                                "playoffs_start_utc": "2026-04-18T07:00:00Z",
                            }
                        ]
                    )
                )

    def test_espn_ending_year_and_century(self):
        for code, year in [
            ("2024-25", 2025),
            ("2025-26", 2026),
            ("1999-00", 2000),
            ("2099-00", 2100),
        ]:
            self.assertEqual(espn_season_year(code), year)
        for code in [None, "2025", "2025-27", "bad"]:
            with self.assertRaises(SeasonConfigurationError):
                espn_season_year(code)

    def test_distinct_timing_boundaries(self):
        season = get_current_season(self.client())
        opening = season.bracket_creation_opens_at
        lock = season.playoff_lock_at
        self.assertFalse(
            season.status(opening - timedelta(microseconds=1))[
                "standings_freeze_reached"
            ]
        )
        middle = season.status(opening)
        self.assertTrue(middle["standings_freeze_reached"])
        self.assertFalse(middle["playoffs_locked"])
        self.assertTrue(middle["bracket_creation_open"])
        self.assertFalse(
            season.status(lock - timedelta(microseconds=1))["playoffs_locked"]
        )
        self.assertTrue(season.status(lock)["playoffs_locked"])
        self.assertFalse(season.status(lock)["bracket_creation_open"])

    def test_date_independence(self):
        season = get_current_season(self.client())
        for now in [
            datetime(2025, 12, 31, tzinfo=timezone.utc),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 8, 1, tzinfo=timezone.utc),
        ]:
            self.assertEqual(season.status(now)["season_code"], "2025-26")
            self.assertEqual(get_current_season(self.client()).id, season.id)

    def test_verifier_retains_previous_assertions(self):
        old = (
            (ROOT / "db/post-baseline/verify_nc_02b3_schema.sql")
            .read_text(encoding="utf-8")
            .replace(
                "'bracket_scores,bracket_view,brackets,leaderboard_history",
                "'application_season,bracket_scores,bracket_view,brackets,leaderboard_history",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        current = (ROOT / "db/post-baseline/verify_nc_02c1_schema.sql").read_text(
            encoding="utf-8"
        )
        self.assertEqual(current.split("DO $canonical_verify$", 1)[0], old)
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_nc_02c1_schema.sql").read_bytes()
            ).hexdigest(),
            "d4135d3da53bcf81acb2cee8c378296faf6e5b01477049112c5458ce979c1c5b",
        )

    def test_migration_has_no_designation_or_public_writes(self):
        sql = (ROOT / "db/post-baseline/0002_nc_02c1_canonical_season.sql").read_text()
        for text in [
            "PRIMARY KEY(singleton)",
            "CHECK(singleton)",
            "REFERENCES public.seasons(id) ON DELETE RESTRICT",
            "ENABLE ROW LEVEL SECURITY",
            "FROM PUBLIC,anon,authenticated",
            "TO postgres,service_role",
        ]:
            self.assertIn(text, sql)
        self.assertNotIn("INSERT INTO", sql)
        self.assertNotIn("CREATE FUNCTION", sql)

    def test_scoped_switch_refuses_without_lease_or_wrong_scope(self):
        from integration_harness import GuardedHarness

        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock(side_effect=RuntimeError("Lease"))
        with self.assertRaises(RuntimeError):
            c.canonical_fixture_season("current")
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02B3"
        with self.assertRaises(Exception):
            c.canonical_fixture_season("current")
