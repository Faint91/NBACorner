"""Real guarded local snapshot/freshness/privacy/immutability and rollover-gate proof."""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity, STAMP
import history_service
import scoring_service

CONFIG = None
OPT_IN = False
RESULTS = []


class HistoryAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02D2"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.c.bracket_timing("locked")
        self.ids = self.c.prepare_transition_competition()
        self.c.login("admin")
        opening = datetime.now(timezone.utc) + timedelta(days=2)
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
                phase="NC-02D2",
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

    def snapshot(self, status=200):
        code, body = self.c.snapshot_request()
        self.assertEqual(code, status)
        return body

    def rollover(self, status=200):
        code, body = self.c.transition_request(payload=self.target)
        self.assertEqual(code, status)
        return body

    def current_history(self):
        return (
            self.db.table("leaderboard_history_snapshots")
            .select("*")
            .eq("season_id", identity("current"))
            .execute()
            .data
        )

    def public(self, code="2025-26"):
        status, body = self.c.bracket_request("GET", "/leaderboard/history/" + code)
        self.assertEqual(status, 200)
        return body

    def zero(self):
        self.db.table("brackets").update(dict(is_done=False, saved_at=None)).eq(
            "season_id", identity("current")
        ).eq("is_master", False).execute()

    def preserve(self):
        return {
            t: self.rows(t)
            for t in (
                "brackets",
                "matches",
                "standings",
                "seasons",
                "application_season",
            )
        }

    def test_d2_fresh_scores_stored_ties_public_privacy_and_repeat(self):
        # a and b have identical play-in predictions in the original scenario after copying b.
        a = self.ids["a"]
        b = self.ids["b"]
        a_matches = (
            self.db.table("matches").select("*").eq("bracket_id", a).execute().data
        )
        b_matches = (
            self.db.table("matches").select("*").eq("bracket_id", b).execute().data
        )
        by = {(m["conference"], m["round"], m["slot"]): m for m in b_matches}
        for m in a_matches:
            source = by.get((m["conference"], m["round"], m["slot"]), m)
            self.db.table("matches").update(
                {
                    k: source[k]
                    for k in (
                        "team_a",
                        "team_b",
                        "predicted_winner",
                        "predicted_winner_games",
                    )
                }
            ).eq("id", m["id"]).execute()
        self.db.table("brackets").update(dict(is_done=True, saved_at=STAMP)).eq(
            "id", a
        ).execute()
        self.db.table("brackets").update(dict(saved_at=STAMP)).eq("id", b).execute()
        # Deliberately stale live scores must not become history.
        self.db.table("bracket_scores").update(dict(total_points=999)).eq(
            "season_id", identity("current")
        ).execute()
        result = self.snapshot()
        self.assertTrue(result["structured_complete"])
        history = self.public()
        self.assertEqual([r["rank"] for r in history["rows"]], [1, 1])
        self.assertTrue(all(r["total_points"] != 999 for r in history["rows"]))
        self.assertTrue(
            all(r["saved_at"] and r["base_points"] is not None for r in history["rows"])
        )
        forbidden = {
            "email",
            "password",
            "password_hash",
            "token",
            "reset_token",
            "is_admin",
            "user_id",
            "bracket_id",
            "league_id",
        }

        def audit(value):
            if isinstance(value, dict):
                self.assertFalse(forbidden & set(value))
                for v in value.values():
                    audit(v)
            elif isinstance(value, list):
                for v in value:
                    audit(v)

        audit(history)
        before = (
            self.rows("leaderboard_history_snapshots"),
            self.rows("leaderboard_history_rows"),
        )
        repeat = self.snapshot()
        self.assertEqual(repeat["state"], "existing")
        self.assertEqual(repeat["history_snapshot_id"], result["history_snapshot_id"])
        self.assertEqual(
            before,
            (
                self.rows("leaderboard_history_snapshots"),
                self.rows("leaderboard_history_rows"),
            ),
        )

    def test_d2_zero_participation_verified_final_repeat_and_cleanup(self):
        self.zero()
        result = self.snapshot()
        self.assertEqual((result["expected_rows"], result["actual_rows"]), (0, 0))
        self.assertTrue(result["is_final"])
        self.assertEqual(self.public()["rows"], [])
        before = self.current_history()
        self.assertEqual(
            self.snapshot()["history_snapshot_id"], result["history_snapshot_id"]
        )
        self.assertEqual(self.current_history(), before)
        result = self.rollover()
        self.assertTrue(result["ok"])
        self.assertEqual(
            self.db.table("application_season")
            .select("season_id")
            .execute()
            .data[0]["season_id"],
            result["new_season"]["id"],
        )
        self.assertEqual(self.rows("standings"), [])
        self.assertEqual(self.public()["rows"], [])

    def test_d2_failure_is_never_zero_and_gate_stays_closed(self):
        self.zero()
        before = self.preserve()
        for failure in ("recompute", "query", "source"):
            if failure == "recompute":
                context = patch.object(
                    history_service,
                    "recompute_current_scores",
                    side_effect=scoring_service.ScoringError("calculation_failure"),
                )
            elif failure == "query":
                context = patch.object(
                    history_service,
                    "snapshot_rows",
                    side_effect=RuntimeError("Synthetic source query failure"),
                )
            else:
                context = patch.object(
                    history_service,
                    "get_current_scoring_master",
                    side_effect=scoring_service.ScoringError(
                        "canonical_master_invalid"
                    ),
                )
            with context:
                self.rollover(503)
            self.assertEqual(self.current_history(), [])
            self.assertEqual(self.preserve(), before)
            self.assertTrue(self.rows("matches"))

    def test_d2_legacy_success_structured_failure_blocks_cleanup(self):
        before = self.preserve()
        scores_before = self.rows("bracket_scores")
        original = self.db.rpc

        def fail(name, params):
            if name == "publish_leaderboard_snapshot":
                raise RuntimeError("Synthetic structured failure")
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=fail):
            self.rollover(503)
        self.assertTrue(
            self.db.table("leaderboard_history")
            .select("id")
            .eq("season_id", identity("current"))
            .execute()
            .data
        )
        self.assertEqual(self.current_history(), [])
        self.assertEqual(self.preserve(), before)
        self.assertTrue(self.rows("bracket_scores"))
        self.assertTrue(scores_before)

    def test_d2_later_cleanup_failure_preserves_final_snapshot(self):
        original = self.db.table

        class Query:
            def __init__(self, q):
                self.q = q

            def __getattr__(self, name):
                return getattr(self.q, name)

            def delete(self):
                raise RuntimeError("Synthetic cleanup failure")

        def table(name):
            return Query(original(name)) if name == "matches" else original(name)

        with patch.object(self.db, "table", side_effect=table):
            self.rollover(500)
        saved = self.public()
        self.assertTrue(self.current_history()[0]["is_final"])
        self.assertTrue(saved["rows"])
        self.assertTrue(self.rows("matches"))

    def test_d2_history_survives_live_mutation_and_canonical_change(self):
        result = self.snapshot()
        before = self.public()
        self.db.table("bracket_scores").update(dict(total_points=123)).eq(
            "season_id", identity("current")
        ).execute()
        status, _ = self.c.recompute_request()
        self.assertEqual(status, 200)
        self.assertEqual(self.public(), before)
        self.db.table("brackets").update(
            dict(deleted_at=datetime.now(timezone.utc).isoformat())
        ).eq("id", self.ids["b"]).execute()
        self.db.table("application_season").update(
            dict(season_id=identity("historical"))
        ).eq("singleton", True).execute()
        self.assertEqual(self.public(), before)
        self.assertTrue(result["history_snapshot_id"])

    def test_d2_changed_source_during_snapshot_is_refused(self):
        original = self.db.rpc

        def change(name, params):
            if name == "publish_leaderboard_snapshot":
                self.db.table("brackets").update(
                    dict(saved_at="2026-01-01T00:00:00Z")
                ).eq("id", self.ids["b"]).execute()
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=change):
            self.snapshot(503)
        self.assertEqual(self.current_history(), [])

    def test_d2_admin_only_snapshot_and_legacy_structure_requires_review(self):
        self.c.login("user-a")
        status, _ = self.c.snapshot_request(role="user-a")
        self.assertEqual(status, 403)
        self.db.table("leaderboard_history_snapshots").insert(
            dict(season_id=identity("current"), season_code="2025-26")
        ).execute()
        before = self.current_history()
        self.snapshot(503)
        self.assertEqual(self.current_history(), before)
