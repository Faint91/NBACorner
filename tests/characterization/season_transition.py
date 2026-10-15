"""S10/S11 real local HTTP/DB transition acceptance; canonical reset per test."""

import copy
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity
from canonical_season import get_current_season, espn_season_year
import standings_service

CONFIG = None
OPT_IN = False
RESULTS = []


class SeasonTransitionAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02C3"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.opening = datetime.now(timezone.utc) + timedelta(days=2)
        self.payload = {
            "new_season_code": "2026-27",
            "regular_season_end_utc": self.opening.isoformat(),
            "playoffs_start_utc": (self.opening + timedelta(days=6)).isoformat(),
        }
        self.c.login("admin")

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            {
                "phase": "NC-02C3",
                "scenario": self._testMethodName,
                "requirements": ["S10", "S11"],
                "passed": True,
                "cleanup_checksum": CANONICAL_CHECKSUM,
                "production_contact": False,
            }
        )

    def standings(self):
        return sorted(
            self.db.table("standings").select("*").execute().data,
            key=lambda r: r["code"],
        )

    def current(self):
        return get_current_season(self.db)

    def call(self, method, path, *, role=None, payload=None, expected=200):
        status, body = self.c.bracket_request(method, path, role=role, payload=payload)
        self.assertEqual(status, expected)
        return body

    def transition(self, expected=200, payload=None, role="admin"):
        status, body = self.c.transition_request(
            payload=self.payload if payload is None else payload, role=role
        )
        self.assertEqual(status, expected)
        return body

    def prepare(self):
        self.c.bracket_timing("locked")
        return self.c.prepare_transition_competition()

    def test_c3_success_consumers_history_refresh_freeze_and_repeat(self):
        ids = self.prepare()
        history = self.call("GET", "/leaderboard/history/2024-25", role="admin")
        old = self.current()
        self.assertTrue(self.c.module.playoffs_locked())
        result = self.transition()
        new = self.current()
        self.assertNotEqual(old.id, new.id)
        self.assertEqual(result["current_season"]["id"], old.id)
        self.assertEqual(result["new_season"]["id"], new.id)
        self.assertEqual(new.code, "2026-27")
        self.assertEqual(self.standings(), [])
        self.assertEqual(self.call("GET", "/season")["season_code"], new.code)
        self.assertEqual(self.c.module.current_season(), new)
        self.assertEqual(espn_season_year(new.code), 2027)
        self.assertEqual(self.call("GET", "/leaderboard")["rows"], [])
        self.assertEqual(self.c.module._build_leaderboard_rows_for_current_season(), [])

        # Both bracket and scoring query filters use the new canonical id.
        class Filter:
            def eq(this, key, value):
                self.assertEqual((key, value), ("season_id", new.id))
                return this

        self.c.module.with_current_season(Filter())
        self.assertEqual(
            history, self.call("GET", "/leaderboard/history/2024-25", role="admin")
        )
        self.assertTrue(self.call("GET", "/leaderboard/history/2025-26", role="admin"))
        retired = (
            self.db.table("brackets").select("*").eq("season_id", old.id).execute().data
        )
        self.assertTrue(all(r["deleted_at"] for r in retired))
        self.assertFalse(self.c.module.active_current_master_exists())
        self.assertIsNone(
            self.db.table("seasons")
            .select("master_bracket_id")
            .eq("id", new.id)
            .execute()
            .data[0]["master_bracket_id"]
        )
        self.c.login("user-a")
        self.call("POST", "/bracket/create", role="user-a", payload={}, expected=403)
        # Empty standings are expected, not old rows masquerading as new season.
        self.call("POST", "/bracket/create", role="admin", payload={}, expected=400)
        # Real provider fixture seam accepts explicit new ESPN year only.
        original = standings_service.fetch_espn
        with patch.object(standings_service, "fetch_espn", wraps=original) as fetch:
            status, refreshed = self.c.standings_request("scheduled")
            self.assertEqual(
                (status, refreshed["season_code"], refreshed["team_count"]),
                (200, new.code, 30),
            )
            fetch.assert_called_once_with(2027)
        self.assertEqual(len(self.standings()), 30)
        # Final lock stays distinct; new season timing controls both consumers.
        with patch.object(self.c.module, "now_utc", lambda: self.opening):
            self.assertTrue(self.c.module.bracket_creation_open())
            self.assertFalse(self.c.module.playoffs_locked())
            self.call("POST", "/bracket/create", role="admin", payload={})
            created = self.call("POST", "/bracket/create", role="user-a", payload={})
            self.assertEqual(created["bracket"]["season_id"], new.id)
            self.call(
                "POST", "/bracket/create", role="user-a", payload={}, expected=400
            )
            before = self.standings()
            with patch.object(
                standings_service,
                "fetch_espn",
                side_effect=AssertionError("Frozen fetch"),
            ):
                self.assertEqual(
                    self.c.standings_request("admin", role="admin")[1]["state"],
                    "frozen",
                )
            self.assertEqual(self.standings(), before)
        # Second invocation is rejected before cleanup; no retry/resume policy.
        state = self.c.competitive_snapshot()
        self.transition(expected=400)
        self.assertEqual(self.c.competitive_snapshot(), state)
        self.assertEqual(self.standings(), before)
        self.assertEqual(self.current(), new)

    def test_c3_invalid_target_and_auth_fail_before_mutation(self):
        before = self.standings()
        old = self.current()
        for payload in [
            {"new_season_code": "2026-27"},
            dict(
                self.payload,
                regular_season_end_utc=(self.opening + timedelta(days=9)).isoformat(),
            ),
        ]:
            self.transition(expected=400, payload=payload)
        self.transition(expected=401, role=None)
        self.c.login("user-a")
        self.transition(expected=403, role="user-a")
        self.assertEqual(self.standings(), before)
        self.assertEqual(self.current(), old)
        self.assertEqual(
            self.db.table("seasons").select("id").eq("code", "2026-27").execute().data,
            [],
        )

    def test_c3_existing_target_refused_before_snapshot(self):
        self.db.table("seasons").insert(
            dict(
                code="2026-27",
                regular_season_end_utc=self.payload["regular_season_end_utc"],
                playoffs_start_utc=self.payload["playoffs_start_utc"],
            )
        ).execute()
        before = self.standings()
        old = self.current()
        result = self.transition(expected=400)
        self.assertEqual(result["steps"], [])
        self.assertEqual(self.standings(), before)
        self.assertEqual(self.current(), old)

    def test_c3_snapshot_failure_preserves_pointer_and_standings(self):
        before = self.standings()
        old = self.current()
        # Canonical foundation intentionally contains no leaderboard prerequisites.
        result = self.transition(expected=400)
        self.assertIn("Snapshot step failed", result["error"])
        self.assertEqual(self.standings(), before)
        self.assertEqual(self.current(), old)

    def test_c3_finalization_failure_exposes_earlier_commits_without_split(self):
        self.prepare()
        before = self.standings()
        old = self.current()
        original = self.db.rpc

        def fail(name, params):
            if name == "finalize_season_transition":
                raise RuntimeError("Synthetic finalization transport failure")
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=fail):
            result = self.transition(expected=500)
        self.assertIn("previous rollover steps already applied", result["error"])
        self.assertEqual(self.current(), old)
        self.assertEqual(self.standings(), before)
        self.assertEqual(
            len(
                self.db.table("seasons")
                .select("id")
                .eq("code", "2026-27")
                .execute()
                .data
            ),
            1,
        )
        self.assertEqual(
            self.db.table("matches")
            .select("id")
            .eq("season_id", old.id)
            .execute()
            .data,
            [],
        )
        self.assertTrue(
            self.db.table("leaderboard_history")
            .select("id")
            .eq("season_id", old.id)
            .execute()
            .data
        )
        # Existing-target refusal preserves partial effects rather than auto-resuming.
        self.transition(expected=400)
        self.assertEqual(self.standings(), before)
        self.assertEqual(self.current(), old)

    def test_c3_season_insert_failure_preserves_pointer_and_standings(self):
        self.prepare()
        before = self.standings()
        old = self.current()
        original = self.db.table

        class TargetTable:
            def __init__(this, query):
                this.query = query

            def __getattr__(this, name):
                return getattr(this.query, name)

            def insert(this, payload):
                raise RuntimeError("Synthetic target insert failure")

        def table(name):
            query = original(name)
            return TargetTable(query) if name == "seasons" else query

        with patch.object(self.db, "table", side_effect=table):
            result = self.transition(expected=500)
        self.assertIn("previous steps already applied", result["error"])
        self.assertEqual(self.current(), old)
        self.assertEqual(self.standings(), before)
        self.assertEqual(
            self.db.table("seasons").select("id").eq("code", "2026-27").execute().data,
            [],
        )
        self.assertEqual(
            self.db.table("matches")
            .select("id")
            .eq("season_id", old.id)
            .execute()
            .data,
            [],
        )
        self.assertTrue(
            self.db.table("leaderboard_history")
            .select("id")
            .eq("season_id", old.id)
            .execute()
            .data
        )

    def test_c3_source_conflict_fails_closed_before_snapshot(self):
        old = self.current()
        other = copy.copy(old)
        object.__setattr__(other, "id", identity("historical"))
        calls = iter([old, other])
        before = self.standings()
        with patch.object(
            self.c.module, "get_current_season", side_effect=lambda _: next(calls)
        ):
            result = self.transition(expected=409)
        self.assertEqual(result["steps"], [])
        self.assertEqual(self.current(), old)
        self.assertEqual(self.standings(), before)
