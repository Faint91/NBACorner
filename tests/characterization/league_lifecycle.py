"""NC-02F1 real local Flask/PostgREST lifecycle acceptance; no production IO."""

import unittest
from datetime import datetime, timezone, timedelta
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity
from league_service import verify_password

CONFIG = None
OPT_IN = False
RESULTS = []


class LeagueLifecycleAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02F1"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.ids = self.c.install_league_scenario()
        for role in ("user-a", "user-b", "owner", "admin"):
            self.c.login(role)

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            dict(
                phase="NC-02F1",
                scenario=self._testMethodName,
                cleanup_checksum=CANONICAL_CHECKSUM,
            )
        )

    def call(self, method, path, expected=200, role="owner", payload=None):
        status, body = self.c.league_request(method, path, role=role, payload=payload)
        self.assertEqual(status, expected)

        # Every response must exclude security and private hash fields recursively.
        def safe(value):
            if isinstance(value, dict):
                self.assertFalse(set(value) & {"password_hash", "email", "reset_token"})
                for item in value.values():
                    safe(item)
            elif isinstance(value, list):
                for item in value:
                    safe(item)

        safe(body)
        return body

    def create(self, name="F1 created", **settings):
        return self.call("POST", "/leagues", 201, payload=dict(name=name, **settings))[
            "league"
        ]["id"]

    def rows(self, table):
        return sorted(
            self.db.table(table).select("*").execute().data,
            key=lambda row: str(row.get("id", row.get("bracket_id"))),
        )

    def invariant(self):
        leagues = self.rows("leagues")
        members = self.rows("league_members")
        for league in leagues:
            self.assertEqual(
                sum(
                    m["league_id"] == league["id"]
                    and m["user_id"] == league["owner_user_id"]
                    for m in members
                ),
                1,
            )
        self.assertEqual(
            len({(m["league_id"], m["user_id"]) for m in members}), len(members)
        )

    def test_f1_names_uniqueness_normalization_reuse_and_validation(self):
        lid = self.create("  NBA Friends  ")
        for name in (
            "nba friends",
            "NBA Friends",
            "  NbA FrIeNdS  ",
            "\u2003NBA Friends\u00a0",
        ):
            self.call("POST", "/leagues", 409, payload={"name": name})
            self.call(
                "PATCH", f"/leagues/{self.ids['private']}", 409, payload={"name": name}
            )
        self.call("PATCH", f"/leagues/{lid}", payload={"name": " NBA FRIENDS "})
        self.assertEqual(
            next(row for row in self.rows("leagues") if row["id"] == lid)["name"],
            "NBA FRIENDS",
        )
        self.create("x")
        self.create("z" * 80)
        for name in (None, 1, True, [], {}, "", " ", "z" * 81, "\x00"):
            self.call("POST", "/leagues", 400, payload={"name": name})
        self.call("DELETE", f"/leagues/{lid}", payload={"confirm_delete": True})
        self.create("nba friends")
        self.invariant()

    def test_f1_create_join_all_timing_windows_and_idempotency(self):
        for timing in ("early", "open", "boundary", "locked"):
            self.c.bracket_timing(timing)
            before = {
                table: self.rows(table)
                for table in ("brackets", "matches", "bracket_scores", "users")
            }
            lid = self.create("F1 timing " + timing)
            self.call("POST", f"/leagues/{lid}/join", 201, role="user-b", payload={})
            repeated = self.call(
                "POST",
                f"/leagues/{lid}/join",
                role="user-b",
                payload={"password": None},
            )
            self.assertEqual(repeated["state"], "already_member")
            self.assertEqual(before, {table: self.rows(table) for table in before})
            self.invariant()
        self.call(
            "POST", "/leagues", 401, role=None, payload={"name": "unauthenticated"}
        )
        self.call("POST", f"/leagues/{lid}/join", 401, role=None, payload={})

    def test_f1_owner_transfer_leave_and_rejections(self):
        lid = self.ids["public"]
        refused = self.call("DELETE", f"/leagues/{lid}/membership", 409)
        self.assertIn("Transfer ownership", refused["error"])
        for target in (identity("owner"), identity("user-b"), identity("missing-user")):
            self.call(
                "POST",
                f"/leagues/{lid}/ownership",
                400,
                payload={"target_user_id": target},
            )
        self.call(
            "POST",
            f"/leagues/{lid}/ownership",
            payload={"target_user_id": identity("user-a")},
        )
        self.invariant()
        self.assertEqual(
            len([m for m in self.rows("league_members") if m["league_id"] == lid]), 2
        )
        self.call("DELETE", f"/leagues/{lid}/membership")
        self.call("DELETE", f"/leagues/{lid}/membership", 409, role="user-a")
        self.call("DELETE", f"/leagues/{lid}/membership", 400)
        self.invariant()

    def test_f1_admin_and_nonowner_no_owner_capabilities(self):
        lid = self.ids["private"]
        before = self.c.league_snapshot()
        for role in ("user-a", "user-b", "admin"):
            for method, path, payload in (
                ("PATCH", f"/leagues/{lid}", {"name": "stolen"}),
                ("PATCH", f"/leagues/{lid}", {"is_private": False}),
                (
                    "POST",
                    f"/leagues/{lid}/ownership",
                    {"target_user_id": identity("user-a")},
                ),
                ("DELETE", f"/leagues/{lid}/members/{identity('user-a')}", None),
                ("DELETE", f"/leagues/{lid}", {"confirm_delete": True}),
            ):
                self.call(method, path, 403, role=role, payload=payload)
        self.assertEqual(before, self.c.league_snapshot())
        self.call(
            "POST",
            f"/leagues/{lid}/join",
            400,
            role="admin",
            payload={"password": "wrong"},
        )
        for route in ("members",):
            self.call("GET", f"/leagues/{lid}/{route}", 403, role="admin")
        for route in ("leaderboard", "brackets", "stats/champion-picks"):
            self.call("GET", f"/{route}?league_id={lid}", 403, role="admin")

    def test_f1_password_privacy_switches_members_and_long_passwords(self):
        lid = self.ids["public"]
        members = self.rows("league_members")
        self.call("PATCH", f"/leagues/{lid}", 400, payload={"is_private": True})
        self.call(
            "PATCH", f"/leagues/{lid}", payload={"is_private": True, "password": " x "}
        )
        self.call(
            "POST",
            f"/leagues/{lid}/join",
            400,
            role="user-b",
            payload={"password": "wrong"},
        )
        self.call("PATCH", f"/leagues/{lid}", payload={"password": " y "})
        self.call(
            "POST",
            f"/leagues/{lid}/join",
            400,
            role="user-b",
            payload={"password": "x"},
        )
        self.assertEqual(members, self.rows("league_members"))
        self.call(
            "POST",
            f"/leagues/{lid}/join",
            201,
            role="user-b",
            payload={"password": " y "},
        )
        self.call("POST", f"/leagues/{lid}/join", role="user-b", payload={})
        after = self.rows("league_members")
        self.call("PATCH", f"/leagues/{lid}", payload={"is_private": False})
        self.assertEqual(after, self.rows("league_members"))
        self.assertIsNone(
            next(l for l in self.rows("leagues") if l["id"] == lid)["password_hash"]
        )
        self.call("POST", f"/leagues/{lid}/join", 201, role="admin", payload={})
        for password in (None, 123, False, [], "", " ", "a" * 129):
            self.call(
                "PATCH",
                f"/leagues/{lid}",
                400,
                payload={"is_private": True, "password": password},
            )
        long = "\u00e9" * 128
        long_id = self.create("F1 long password", is_private=True, password=long)
        self.call(
            "POST",
            f"/leagues/{long_id}/join",
            400,
            role="user-b",
            payload={"password": "\u00e9" * 127 + "a"},
        )
        self.call(
            "POST",
            f"/leagues/{long_id}/join",
            201,
            role="user-b",
            payload={"password": long},
        )
        stored = next(l for l in self.rows("leagues") if l["id"] == long_id)[
            "password_hash"
        ]
        self.assertNotEqual(stored, long)
        self.assertTrue(verify_password(long, stored))
        self.invariant()

    def test_f1_discovery_minimal_and_private_member_access(self):
        lid = self.ids["private"]
        for role in ("admin", "user-b"):
            found = next(
                l
                for l in self.call("GET", "/leagues", role=role)["leagues"]
                if l["id"] == lid
            )
            self.assertTrue(found["requires_password"])
            self.assertFalse(
                set(found)
                & {"owner_user_id", "user_id", "members", "brackets", "scores", "ranks"}
            )
            self.call("GET", f"/leagues/{lid}/members", 403, role=role)
        self.call("GET", f"/leagues/{lid}/members")
        self.call("GET", f"/leagues/{lid}/members", role="user-a")
        self.call("GET", "/leagues", 401, role=None)

    def test_f1_leave_kick_delete_keep_competition_and_scope_live(self):
        self.c.install_league_score_surface()
        lid = self.ids["public"]
        before = {
            t: self.rows(t)
            for t in (
                "users",
                "brackets",
                "matches",
                "bracket_scores",
                "leaderboard_history",
                "leaderboard_history_snapshots",
                "leaderboard_history_rows",
            )
        }

        def leaderboard(path):
            body = self.call("GET", path, role="user-a")
            return body if isinstance(body, list) else body["rows"]

        first = leaderboard(f"/leaderboard?league_id={lid}")
        self.assertIn(identity("user-a"), str(first))
        self.call("DELETE", f"/leagues/{lid}/members/{identity('owner')}", 400)
        self.call("DELETE", f"/leagues/{lid}/members/{identity('user-b')}", 400)
        self.call("DELETE", f"/leagues/{lid}/members/{identity('user-a')}")
        self.assertNotIn(
            identity("user-a"), str(leaderboard(f"/leaderboard?league_id={lid}"))
        )
        self.assertIn(identity("user-a"), str(leaderboard("/leaderboard")))
        self.call("POST", f"/leagues/{lid}/join", 201, role="user-a", payload={})
        self.call("DELETE", f"/leagues/{lid}/membership", role="user-a")
        self.assertNotIn(
            identity("user-a"), str(leaderboard(f"/leaderboard?league_id={lid}"))
        )
        other = next(l for l in self.rows("leagues") if l["id"] == self.ids["private"])
        for confirmation in (
            {},
            {"confirm_delete": False},
            {"confirm_delete": "true"},
            {"confirm_delete": 1},
        ):
            self.call("DELETE", f"/leagues/{lid}", 400, payload=confirmation)
        self.call("DELETE", f"/leagues/{lid}", payload={"confirm_delete": True})
        self.assertFalse(
            any(m["league_id"] == lid for m in self.rows("league_members"))
        )
        self.assertEqual(before, {t: self.rows(t) for t in before})
        self.assertEqual(
            other, next(l for l in self.rows("leagues") if l["id"] == other["id"])
        )
        self.invariant()

    def test_f1_real_rollover_league_owner_membership_persistence(self):
        # Reuse E's completed master fixture and real guarded atomic rollover route.
        from canonical_season import get_current_season

        ids = self.c.prepare_transition_competition()
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "f1_complete",
            Path(__file__).resolve().parents[1] / "offline/test_rollover_rules.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        graph = module.complete_graph(
            self.db.table("matches")
            .select("*")
            .eq("bracket_id", ids["master"])
            .execute()
            .data
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
        self.c.bracket_timing("locked")
        before = self.c.league_snapshot()
        opening = datetime.now(timezone.utc) + timedelta(days=2)
        status, body = self.c.transition_request(
            payload=dict(
                new_season_code="2026-27",
                regular_season_end_utc=opening.isoformat(),
                playoffs_start_utc=(opening + timedelta(days=6)).isoformat(),
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(before, self.c.league_snapshot())
        self.assertEqual(get_current_season(self.db).code, "2026-27")
        self.invariant()
        self.call(
            "POST",
            f"/leagues/{self.ids['public']}/join",
            201,
            role="user-b",
            payload={},
        )
        refresh_status, _ = self.c.standings_request("admin", role="admin")
        self.assertEqual(refresh_status, 200)
        # Move only the new synthetic season into its normal bracket window.
        # Joining is always allowed; bracket creation still obeys its own timing.
        now = datetime.now(timezone.utc)
        self.db.table("seasons").update(
            {
                "regular_season_end_utc": (now - timedelta(days=1)).isoformat(),
                "playoffs_start_utc": (now + timedelta(days=2)).isoformat(),
            }
        ).eq("id", get_current_season(self.db).id).execute()
        status, body = self.c.bracket_request(
            "POST", "/bracket/create", role="user-a", payload={}
        )
        self.assertEqual(status, 200)
        self.assertTrue(
            any(
                m["user_id"] == identity("user-a")
                and m["league_id"] == self.ids["public"]
                for m in self.rows("league_members")
            )
        )
