"""F2 real guarded local API, current privacy, frozen membership and rollover gates."""

import unittest
from datetime import datetime, timezone, timedelta
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class LeagueHistoryAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02F2"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.ids = self.c.install_league_history_scenario()
        for role in ("admin", "owner", "user-a", "user-b"):
            self.c.login(role)

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            dict(
                phase="NC-02F2",
                scenario=self._testMethodName,
                cleanup_checksum=CANONICAL_CHECKSUM,
            )
        )

    def call(self, method, path, expected=200, role=None, payload=None):
        status, body = self.c.league_request(method, path, role=role, payload=payload)
        self.assertEqual(status, expected)

        def safe(v):
            if isinstance(v, dict):
                self.assertFalse(
                    set(v)
                    & {
                        "email",
                        "password_hash",
                        "user_id",
                        "bracket_id",
                        "snapshot_id",
                        "global_snapshot_id",
                        "global_snapshot_row_id",
                        "snapshot_row_id",
                        "reset_token",
                        "owner_user_id",
                    }
                )
                for item in v.values():
                    safe(item)
            elif isinstance(v, list):
                for item in v:
                    safe(item)

        if method == "GET" and "/history" in path:
            safe(body)
        return body

    def finalize(self):
        header = (
            self.db.table("leaderboard_history_snapshots")
            .select("id")
            .eq("season_id", self.ids["source"])
            .eq("is_final", True)
            .execute()
            .data[0]
        )
        return (
            self.db.rpc(
                "publish_league_history_cutoff",
                dict(p_source=self.ids["source"], p_snapshot=header["id"]),
            )
            .execute()
            .data
        )

    def path(self, detail=True, lid=None):
        return f"/leagues/{lid or self.ids['mixed']}/history" + (
            "/2025-26" if detail else ""
        )

    def rows(self, table):
        return sorted(
            self.db.table(table).select("*").execute().data, key=lambda r: str(r)
        )

    def frozen(self):
        return {
            t: self.rows(t)
            for t in (
                "league_history_cutoffs",
                "league_history_seasons",
                "league_history_rows",
            )
        }

    def test_f2_eligible_only_A_D_no_placeholder_and_empty_season_omission(self):
        self.finalize()
        body = self.call("GET", self.path())
        self.assertEqual(len(body["rows"]), 2)
        self.assertTrue(
            any("fixture-user-a" in r["display_name"] for r in body["rows"])
        )
        self.assertTrue(any("fixture-d" in r["display_name"] for r in body["rows"]))
        self.assertFalse(
            any(
                "fixture-user-b" in r["display_name"]
                or "fixture-owner" in r["display_name"]
                or "fixture-admin" in r["display_name"]
                for r in body["rows"]
            )
        )
        self.assertEqual(
            self.call("GET", self.path(False))["seasons"][0]["season_code"], "2025-26"
        )
        self.assertEqual(
            self.call("GET", self.path(False, self.ids["empty"]))["seasons"], []
        )
        self.call("GET", self.path(True, self.ids["empty"]), 404)
        self.call("GET", self.path().replace("2025-26", "2024-25"), 404)

    def test_f2_leave_before_cutoff_excluded(self):
        self.call("DELETE", f"/leagues/{self.ids['mixed']}/membership", role="user-a")
        self.finalize()
        body = self.call("GET", self.path())
        self.assertEqual(len(body["rows"]), 1)
        self.assertIn("fixture-d", body["rows"][0]["display_name"])
        self.assertEqual(body["rows"][0]["rank"], 1)

    def test_f2_leave_join_kick_transfer_rename_after_cutoff_never_rewrite(self):
        self.finalize()
        before = self.frozen()
        initial = self.call("GET", self.path())["rows"]
        self.call("DELETE", f"/leagues/{self.ids['mixed']}/membership", role="user-a")
        self.call(
            "POST", f"/leagues/{self.ids['empty']}/join", 201, role="user-a", payload={}
        )
        self.call(
            "DELETE",
            f"/leagues/{self.ids['mixed']}/members/{identity('user-b')}",
            role="admin",
        )
        self.call(
            "POST",
            f"/leagues/{self.ids['mixed']}/ownership",
            role="admin",
            payload={"target_user_id": identity("owner")},
        )
        self.call(
            "PATCH",
            f"/leagues/{self.ids['mixed']}",
            role="owner",
            payload={"name": "Current Renamed League"},
        )
        self.assertEqual(self.finalize()["state"], "existing")
        self.assertEqual(before, self.frozen())
        body = self.call("GET", self.path())
        self.assertEqual(body["rows"], initial)
        self.assertEqual(body["league"]["name"], "Current Renamed League")
        self.assertEqual(
            self.call("GET", self.path(False, self.ids["empty"]))["seasons"], []
        )

    def test_f2_current_private_membership_and_privacy_switch(self):
        self.finalize()
        lid = self.ids["mixed"]
        initial = self.call("GET", self.path())["rows"]
        for role in (None, "owner", "user-a"):
            self.assertEqual(self.call("GET", self.path(), role=role)["rows"], initial)
            self.assertEqual(
                len(self.call("GET", self.path(False), role=role)["seasons"]), 1
            )
        before = self.frozen()
        self.call(
            "POST",
            f"/leagues/{lid}/ownership",
            role="admin",
            payload={"target_user_id": identity("owner")},
        )
        self.call("DELETE", f"/leagues/{lid}/membership", role="admin")
        self.call("DELETE", f"/leagues/{lid}/membership", role="user-a")
        self.call(
            "PATCH",
            f"/leagues/{lid}",
            role="owner",
            payload={"is_private": True, "password": "private"},
        )
        for role in (None, "admin", "user-a"):
            self.call("GET", self.path(), 403, role=role)
            self.call("GET", self.path(False), 403, role=role)
        for role in ("owner", "user-b"):
            self.assertEqual(self.call("GET", self.path(), role=role)["rows"], initial)
            self.assertEqual(
                len(self.call("GET", self.path(False), role=role)["seasons"]), 1
            )
        self.call(
            "PATCH", f"/leagues/{lid}", role="owner", payload={"is_private": False}
        )
        self.assertEqual(self.call("GET", self.path())["rows"], initial)
        self.assertEqual(before, self.frozen())

    def test_f2_delete_cascade_preserves_global_and_brackets(self):
        self.finalize()
        protected = {
            t: self.rows(t)
            for t in (
                "users",
                "brackets",
                "matches",
                "bracket_scores",
                "leaderboard_history_snapshots",
                "leaderboard_history_rows",
                "leaderboard_history_competitors",
            )
        }
        lid = self.ids["mixed"]
        self.call(
            "DELETE",
            f"/leagues/{lid}",
            400,
            role="admin",
            payload={"confirm_delete": "true"},
        )
        self.call(
            "DELETE", f"/leagues/{lid}", role="admin", payload={"confirm_delete": True}
        )
        self.assertEqual(self.rows("league_history_rows"), [])
        self.assertEqual(self.rows("league_history_seasons"), [])
        self.call("GET", self.path(), 404)
        self.call("GET", self.path(False), 404)
        self.assertEqual(protected, {t: self.rows(t) for t in protected})
        self.call(
            "POST",
            "/leagues",
            201,
            role="admin",
            payload={"name": " synthetic f2 league "},
        )

    def test_f2_transition_failure_retains_global_and_league_cutoff_retry_reuses(self):
        # Canonical complete master and two eligible rows were installed by the fixture.
        self.c.bracket_timing("locked")
        target = dict(
            new_season_code="2026-27",
            regular_season_end_utc=(
                datetime.now(timezone.utc) + timedelta(days=2)
            ).isoformat(),
            playoffs_start_utc=(
                datetime.now(timezone.utc) + timedelta(days=5)
            ).isoformat(),
        )
        # A real SQL failure after transition starts; use the lease's fixed local session.
        self.c.lease._exchange(
            b"CREATE FUNCTION public.f2_transition_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic F2 target failure'; END $$; CREATE TRIGGER f2_transition_fault AFTER INSERT ON public.seasons FOR EACH ROW EXECUTE FUNCTION public.f2_transition_fault(); SELECT '{\"fault\":true}'::jsonb;\n"
        )
        try:
            status, body = self.c.transition_request(payload=target)
            self.assertEqual(status, 503)
            self.assertEqual(body["stage"], "transition")
            before = self.frozen()
            self.assertEqual(len(self.rows("league_history_seasons")), 1)
        finally:
            self.c.lease._exchange(
                b"DROP TRIGGER f2_transition_fault ON public.seasons; DROP FUNCTION public.f2_transition_fault(); SELECT '{\"fault_removed\":true}'::jsonb;\n"
            )
        self.call("DELETE", f"/leagues/{self.ids['mixed']}/membership", role="user-a")
        status, body = self.c.transition_request(payload=target)
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "completed")
        self.assertEqual(before, self.frozen())
        self.assertEqual(len(self.call("GET", self.path())["rows"]), 2)

    def test_f2_partial_publication_blocks_transition_and_retains_global(self):
        self.c.bracket_timing("locked")
        before = {
            t: self.rows(t)
            for t in (
                "leagues",
                "league_members",
                "brackets",
                "matches",
                "application_season",
                "standings",
            )
        }
        self.c.lease._exchange(
            b"CREATE FUNCTION public.f2_history_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.display_order=2 THEN RAISE EXCEPTION 'Synthetic F2 row failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER f2_history_fault BEFORE INSERT ON public.league_history_rows FOR EACH ROW EXECUTE FUNCTION public.f2_history_fault(); SELECT '{\"fault\":true}'::jsonb;\n"
        )
        target = dict(
            new_season_code="2026-27",
            regular_season_end_utc=(
                datetime.now(timezone.utc) + timedelta(days=2)
            ).isoformat(),
            playoffs_start_utc=(
                datetime.now(timezone.utc) + timedelta(days=5)
            ).isoformat(),
        )
        try:
            status, body = self.c.transition_request(payload=target)
            self.assertEqual(status, 409)
            self.assertEqual(body["stage"], "league_history")
            self.assertEqual(self.rows("league_history_rows"), [])
            self.assertEqual(self.rows("league_history_seasons"), [])
            self.assertEqual(self.rows("league_history_cutoffs"), [])
            self.assertEqual(before, {t: self.rows(t) for t in before})
            self.assertTrue(self.rows("leaderboard_history_snapshots")[0]["is_final"])
        finally:
            self.c.lease._exchange(
                b"DROP TRIGGER f2_history_fault ON public.league_history_rows; DROP FUNCTION public.f2_history_fault(); SELECT '{\"fault_removed\":true}'::jsonb;\n"
            )
        status, _ = self.c.transition_request(payload=target)
        self.assertEqual(status, 200)
