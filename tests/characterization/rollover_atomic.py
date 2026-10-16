"""NC-02E real guarded Flask/PostgREST acceptance; canonical reset after each test."""

import importlib.util
from pathlib import Path
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity, STAMP
from canonical_season import get_current_season
import rollover_service
import scoring_service
import standings_service

CONFIG = None
OPT_IN = False
RESULTS = []


class AtomicRolloverAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02D2"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.c.bracket_timing("locked")
        self.ids = self.c.prepare_transition_competition()
        for role in ("admin", "user-a", "user-b"):
            self.c.login(role)
        opening = datetime.now(timezone.utc) + timedelta(days=2)
        self.opening = opening
        self.target = dict(
            new_season_code="2026-27",
            regular_season_end_utc=opening.isoformat(),
            playoffs_start_utc=(opening + timedelta(days=6)).isoformat(),
        )

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            dict(
                phase="NC-02E",
                scenario=self._testMethodName,
                passed=True,
                cleanup_checksum=CANONICAL_CHECKSUM,
                production_contact=False,
            )
        )

    def rows(self, table):
        return sorted(
            self.db.table(table).select("*").execute().data,
            key=lambda r: str(r.get("id", r.get("bracket_id"))),
        )

    def preserved(self):
        return {
            t: self.rows(t)
            for t in (
                "application_season",
                "seasons",
                "brackets",
                "matches",
                "bracket_scores",
                "standings",
            )
        }

    def complete(self, bid):
        spec = importlib.util.spec_from_file_location(
            "e_complete_fixture",
            Path(__file__).resolve().parents[1] / "offline/test_rollover_rules.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        graph = module.complete_graph(
            self.db.table("matches").select("*").eq("bracket_id", bid).execute().data
        )
        for row in graph:
            self.db.table("matches").update(
                {
                    k: row[k]
                    for k in (
                        "team_a",
                        "team_b",
                        "predicted_winner",
                        "predicted_winner_games",
                    )
                }
            ).eq("id", row["id"]).execute()

    def rollover(self, expected=200, payload=None, role="admin"):
        status, body = self.c.transition_request(
            payload=payload or self.target, role=role
        )
        self.assertEqual(status, expected)
        return body

    def safe(self, value):
        if isinstance(value, dict):
            self.assertFalse(
                set(value)
                & {
                    "email",
                    "password",
                    "password_hash",
                    "reset_token",
                    "token",
                    "jwt",
                    "service_role_key",
                }
            )
            for item in value.values():
                self.safe(item)
        elif isinstance(value, list):
            for item in value:
                self.safe(item)

    def test_e_full_success_history_readonly_new_refresh_and_repeat(self):
        self.complete(self.ids["master"])
        self.complete(self.ids["b"])
        # An edited-unsaved bracket with a stale timestamp is still a draft.
        self.db.table("brackets").update(dict(is_done=False, saved_at=STAMP)).eq(
            "id", self.ids["a"]
        ).execute()
        saved = [r for r in self.rows("brackets") if r["id"] == self.ids["b"]]
        graph = [r for r in self.rows("matches") if r["bracket_id"] == self.ids["b"]]
        result = self.rollover()
        self.assertEqual(result["state"], "completed")
        self.assertEqual(
            [r for r in self.rows("brackets") if r["id"] == self.ids["b"]], saved
        )
        self.assertEqual(
            [r for r in self.rows("matches") if r["bracket_id"] == self.ids["b"]], graph
        )
        self.assertFalse(
            self.db.table("brackets")
            .select("id")
            .eq("id", self.ids["a"])
            .execute()
            .data
        )
        self.assertFalse(self.rows("bracket_scores"))
        self.assertFalse(self.rows("standings"))
        for role in (None, "user-a", "user-b", "admin"):
            status, body = self.c.bracket_request(
                "GET", "/history/bracket/" + self.ids["b"], role=role
            )
            self.assertEqual(status, 200)
            self.safe(body)
            self.assertTrue(body["bracket"]["is_historical"])
            self.assertTrue(body["bracket"]["read_only"])
        match = graph[0]
        for method, path, payload, expected in [
            ("PATCH", "/bracket/" + self.ids["b"] + "/save", {}, 400),
            ("PATCH", "/bracket/match/" + match["id"] + "/games", {"games": 4}, 403),
        ]:
            status, _ = self.c.bracket_request(
                method, path, role="user-b", payload=payload
            )
            self.assertEqual(status, expected)
        original = standings_service.fetch_espn
        with patch.object(standings_service, "fetch_espn", wraps=original) as fetch:
            status, body = self.c.standings_request("scheduled")
            self.assertEqual(status, 200)
            self.assertEqual(body["team_count"], 30)
            fetch.assert_called_once_with(2027)
        before = self.preserved()
        history = self.rows("leaderboard_history_rows")
        audits = self.rows("season_rollover_audits")
        self.assertEqual(self.rollover()["state"], "already_completed")
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.rows("leaderboard_history_rows"), history)
        self.assertEqual(self.rows("season_rollover_audits"), audits)
        self.assertEqual(get_current_season(self.db).code, "2026-27")

    def test_e_preconditions_authorization_and_complete_master_gate(self):
        before = self.preserved()
        self.rollover(401, role=None)
        self.rollover(403, role="user-a")
        r = self.rollover(409)
        self.assertEqual(r["stage"], "prerequisite")
        self.assertTrue(r["audit_id"])
        self.assertEqual(before, self.preserved())
        self.assertFalse(
            self.db.table("leaderboard_history_snapshots")
            .select("id")
            .eq("season_id", identity("current"))
            .execute()
            .data
        )
        self.complete(self.ids["master"])
        before = self.preserved()
        for payload in (
            dict(new_season_code="2026-27"),
            dict(self.target, playoffs_start_utc=self.target["regular_season_end_utc"]),
        ):
            self.rollover(409, payload=payload)
            self.rollover(
                400,
                payload=dict(self.target, regular_season_end_utc="2027-04-12T00:00:00"),
            )
        self.assertEqual(before, self.preserved())

    def test_e_calculation_failure_is_not_zero_and_rpc_failure_sanitized(self):
        self.complete(self.ids["master"])
        before = self.preserved()
        with patch.object(
            rollover_service,
            "recompute_current_scores",
            side_effect=scoring_service.ScoringError("calculation_failure"),
        ):
            result = self.rollover(409)
        self.assertEqual(result["stage"], "recompute")
        self.assertEqual(before, self.preserved())
        original = self.db.rpc

        def fail(name, params):
            if name == "run_season_rollover":
                raise RuntimeError("Synthetic private transport detail")
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=fail):
            result = self.rollover(503)
        self.assertNotIn("private", str(result))
        self.assertEqual(result["stage"], "database_unavailable")
        self.assertEqual(before, self.preserved())

    def test_e_zero_competitors_requires_complete_master_and_reuses_snapshot(self):
        self.db.table("brackets").update(dict(is_done=False, saved_at=None)).eq(
            "season_id", identity("current")
        ).eq("is_master", False).execute()
        self.rollover(409)
        self.complete(self.ids["master"])
        status, snapshot = self.c.snapshot_request()
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["expected_rows"], 0)
        result = self.rollover()
        self.assertEqual(result["snapshot_id"], snapshot["history_snapshot_id"])
        headers = (
            self.db.table("leaderboard_history_snapshots")
            .select("*")
            .eq("season_id", identity("current"))
            .execute()
            .data
        )
        self.assertEqual(len(headers), 1)
        self.assertTrue(headers[0]["is_final"])
        self.assertEqual(headers[0]["expected_rows"], 0)
