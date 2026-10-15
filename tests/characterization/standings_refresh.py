"""C2 live acceptance: selected local fixture-only refresh, no unrelated jobs."""

import unittest, copy, json
from unittest.mock import patch
from pathlib import Path
from datetime import timedelta
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
import standings_service as service

CONFIG = None
OPT_IN = False
RESULTS = []


class StandingsAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02C2"
        )
        self.c.__enter__()

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            {
                "phase": "NC-02C2",
                "scenario": self._testMethodName,
                "passed": True,
                "requirements": ["S3", "S4", "S5", "S6", "S7", "S8", "S9", "S13"],
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def snapshot(self):
        return sorted(
            self.c.module.supabase.table("standings").select("*").execute().data,
            key=lambda row: row["code"],
        )

    def semantic(self):
        return [
            {k: v for k, v in row.items() if k not in {"id", "updated_at"}}
            for row in self.snapshot()
        ]

    def test_c2_success_scheduled_admin_cron_equivalent(self):
        self.c.bracket_timing("early")
        self.c.login("admin")
        old = self.snapshot()
        states = []
        for kind in ["scheduled", "admin", "cron"]:
            status, body = self.c.standings_request(
                kind, role="admin" if kind == "admin" else None
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], "refreshed")
            self.assertEqual(body["team_count"], 30)
            states.append(self.semantic())
        self.assertEqual(states[0], states[1])
        self.assertEqual(states[1], states[2])
        self.assertNotEqual(old, self.snapshot())

    def test_c2_freeze_at_after_all_paths_no_fetch(self):
        self.c.bracket_timing("early")
        self.c.login("admin")
        opening = self.c.module.current_season().bracket_creation_opens_at
        for delta in [0, 1]:
            instant = opening + timedelta(seconds=delta)
            with patch.object(service, "utc_now", lambda: instant), patch.object(
                self.c.module, "now_utc", lambda: instant
            ), patch.object(
                service, "fetch_espn", side_effect=AssertionError("Fetch after freeze")
            ) as fetch:
                before = self.snapshot()
                for kind in ["scheduled", "admin", "cron"]:
                    status, body = self.c.standings_request(
                        kind,
                        role="admin" if kind == "admin" else None,
                        payload={"force": True},
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(body["state"], "frozen")
                    self.assertEqual(before, self.snapshot())
                fetch.assert_not_called()

    def test_c2_freeze_distinct_from_bracket_lock(self):
        self.c.bracket_timing("open")
        before = self.snapshot()
        self.assertFalse(self.c.module.playoffs_locked())
        self.assertTrue(self.c.module.bracket_creation_open())
        with patch.object(
            service, "fetch_espn", side_effect=AssertionError("Frozen provider")
        ):
            self.assertEqual(
                self.c.standings_request("scheduled")[1]["state"], "frozen"
            )
        self.assertEqual(before, self.snapshot())

    def test_c2_invalid_data_and_provider_failures_preserve_rows(self):
        self.c.bracket_timing("early")
        self.c.login("admin")
        before = self.snapshot()
        data = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures/providers/espn-standings-complete-2026.json"
            ).read_text()
        )
        invalid = []
        for kind in [
            "missing",
            "extra",
            "duplicate",
            "unknown",
            "conference",
            "rank",
            "rank16",
            "missing_rank",
            "fraction_rank",
            "duplicate_rank",
            "wins",
            "losses",
            "identity",
            "league",
        ]:
            value = copy.deepcopy(data)
            rows = value["standings"]["entries"]
            if kind == "missing":
                rows.pop()
            if kind == "extra":
                rows.append(copy.deepcopy(rows[0]))
            if kind == "duplicate":
                rows[1] = copy.deepcopy(rows[0])
            if kind == "unknown":
                rows[0]["team"]["abbreviation"] = "UNKNOWN"
            if kind == "conference":
                rows[0]["team"]["conference"] = "west"
            if kind == "rank":
                rows[0]["stats"][3]["value"] = 0
            if kind == "rank16":
                rows[0]["stats"][3]["value"] = 16
            if kind == "missing_rank":
                rows[0]["stats"].pop()
            if kind == "fraction_rank":
                rows[0]["stats"][3]["value"] = 1.5
            if kind == "duplicate_rank":
                rows[1]["stats"][3]["value"] = 1
            if kind == "wins":
                rows[0]["stats"][0]["value"] = None
            if kind == "losses":
                rows[0]["stats"][1]["value"] = -1
            if kind == "identity":
                rows[0]["team"]["id"] = "999"
            if kind == "league":
                value["league"]["slug"] = "wnba"
            invalid.append(value)
        for value in invalid + [{"bad": []}]:
            with patch.object(service, "fetch_espn", return_value=value):
                self.assertEqual(
                    self.c.standings_request("admin", role="admin")[0], 502
                )
            self.assertEqual(before, self.snapshot())
        with patch.object(
            service,
            "fetch_espn",
            side_effect=service.StandingsRefreshError("provider_failure"),
        ):
            self.assertEqual(self.c.standings_request("cron")[0], 502)
        self.assertEqual(before, self.snapshot())

    def test_c2_authorization_and_retired_bypasses(self):
        self.c.bracket_timing("early")
        self.c.login("admin")
        self.c.login("user-a")
        before = self.snapshot()
        self.assertEqual(self.c.standings_request("admin")[0], 401)
        self.assertEqual(self.c.standings_request("admin", role="user-a")[0], 403)
        for token in ["missing", "invalid"]:
            self.assertEqual(self.c.standings_request("cron", token=token)[0], 403)
        self.assertEqual(self.c.standings_request("overwrite", payload=[{}])[0], 410)
        self.assertEqual(
            self.c.standings_request(
                "seed", role="admin", payload={"seed_standings": True}
            )[0],
            409,
        )
        self.assertEqual(before, self.snapshot())
