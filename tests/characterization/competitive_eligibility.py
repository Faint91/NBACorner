"""NC-02A2 guarded current competition lifecycles; no production/job execution."""

import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


def acceptance(fn):
    fn.metadata = {
        "scenario": fn.__name__,
        "phase": "NC-02A2",
        "classification": "APPROVED REQUIREMENT",
        "requirements": ["P4", "P5", "P9"],
    }
    return fn


class CompetitiveEligibilityAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02A2"
        )
        self.c.__enter__()
        self.facts = {}

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            {
                **getattr(self, self._testMethodName).metadata,
                "evidence": self.c.summary,
                "facts": self.facts,
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def call(self, method, path, status=200, role=None, payload=None):
        actual, body = self.c.bracket_request(method, path, role=role, payload=payload)
        self.assertEqual(actual, status)
        self.safe(body)
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
            for v in value.values():
                self.safe(v)
        elif isinstance(value, list):
            for v in value:
                self.safe(v)

    def setup_competition(self, saved=True):
        self.c.bracket_timing("open")
        for role in ("user-a", "user-b", "owner", "admin"):
            self.c.login(role)
        self.leagues = self.c.install_league_scenario()
        self.ids = self.c.install_competitive_scenario()
        if saved:
            self.fill()
            self.save()
        self.before = self.c.competitive_snapshot()
        self.history = self.call("GET", "/leaderboard/history/2024-25", role="owner")
        self.league_before = self.c.league_snapshot()

    def state(self):
        snapshot = self.c.bracket_snapshot()
        return next(b for b in snapshot["brackets"] if b["id"] == self.ids["a"]), [
            m for m in snapshot["matches"] if m["bracket_id"] == self.ids["a"]
        ]

    def at(self, slot=6, conf="east"):
        return next(
            m for m in self.state()[1] if m["slot"] == slot and m["conference"] == conf
        )

    def pick(self, slot, conf="east", *, role="user-a", games=4):
        m = self.at(slot, conf)
        return self.call(
            "PATCH",
            f"/bracket/{self.ids['a']}/match/{m['id']}",
            role=role,
            payload={"action": "set_winner", "team": m["team_a"], "games": games},
        )

    def fill(self):
        for slot in range(1, 12):
            for conf in (["nba"] if slot == 11 else ["east", "west"]):
                self.pick(slot, conf)

    def save(self, status=200):
        return self.call(
            "PATCH",
            f"/bracket/{self.ids['a']}/save",
            status,
            role="user-a",
            payload={"name": "Fixture competition submitted"},
        )

    def assert_surfaces(self, eligible):
        a, b = self.ids["a"], self.ids["b"]
        row = self.state()[0]
        self.assertEqual(row["is_done"], eligible)
        if not eligible:
            self.assertIsNone(row["saved_at"])
        global_rows = self.call("GET", "/leaderboard")["rows"]
        self.assertEqual(
            [r["bracket_id"] for r in global_rows], [b, a] if eligible else [b]
        )
        self.assertTrue(
            all(r["total_points"] == 3 and r["full_hits"] == 1 for r in global_rows)
        )
        global_stats = self.call("GET", "/stats/champion-picks", role="owner")
        self.assertEqual(global_stats["total_brackets"], 2 if eligible else 1)
        self.assertEqual(
            global_stats.get("least_predicted_matchup") is not None, eligible
        )
        for kind, lid in self.leagues.items():
            # Public nonmember may use the authenticated public competition scope;
            # private requests must use a member. This is independent of frontend filtering.
            role = "user-b" if kind == "public" else "owner"
            scoped = self.call("GET", f"/leaderboard?league_id={lid}", role=role)[
                "rows"
            ]
            self.assertEqual([r["bracket_id"] for r in scoped], [a] if eligible else [])
            listed = self.call("GET", f"/brackets?league_id={lid}", role="owner")
            self.assertEqual([r["bracket_id"] for r in listed], [a] if eligible else [])
            stats = self.call(
                "GET", f"/stats/champion-picks?league_id={lid}", role="owner"
            )
            self.assertEqual(stats["total_brackets"], 1 if eligible else 0)
            member = next(
                m
                for m in self.call("GET", f"/leagues/{lid}/members", role="owner")[
                    "members"
                ]
                if m["user_id"] == identity("user-a")
            )
            self.assertEqual(member["has_bracket"], eligible)
            self.assertEqual(member["bracket_id"], a if eligible else None)
        listed = self.call("GET", "/brackets", role="owner")
        self.assertEqual({r["bracket_id"] for r in listed}, {a, b} if eligible else {b})
        self.call("GET", f"/bracket/{a}", 200 if eligible else 403, role="owner")
        self.call("GET", f"/bracket/{a}", role="user-a")
        for role in ("user-b", "admin"):
            self.call(
                "GET",
                f"/leaderboard?league_id={self.leagues['private']}",
                403,
                role=role,
            )
        self.call("GET", f"/leaderboard?league_id={self.leagues['public']}", 401)
        self.call("GET", f"/leaderboard?league_id={self.leagues['private']}", 401)

    def unchanged_internal(self):
        after = self.c.competitive_snapshot()
        self.assertTrue(self.before["bracket_scores"] == after["bracket_scores"])
        for table in (
            "leaderboard_history_snapshots",
            "leaderboard_history_rows",
            "leaderboard_history",
        ):
            self.assertTrue(self.before[table] == after[table])
        self.assertEqual(
            self.history, self.call("GET", "/leaderboard/history/2024-25", role="owner")
        )
        self.assertTrue(self.league_before == self.c.league_snapshot())
        self.facts.update(
            stored_scores_preserved=True,
            historical_snapshots_preserved=True,
            membership_preserved=True,
            formulas_executed=False,
        )

    def lifecycle(self, action):
        self.setup_competition()
        self.assert_surfaces(True)
        m = self.at(slot=11, conf="nba")
        if action == "winner":
            self.call(
                "PATCH",
                f"/bracket/{self.ids['a']}/match/{m['id']}",
                role="user-a",
                payload={"action": "set_winner", "team": m["team_b"], "games": 5},
            )
        elif action == "games":
            self.call(
                "PATCH",
                f"/bracket/match/{m['id']}/games",
                role="user-a",
                payload={"games": 7},
            )
        else:
            self.call(
                "PATCH",
                f"/bracket/{self.ids['a']}/match/{m['id']}",
                role="user-a",
                payload={"action": "undo"},
            )
        self.assert_surfaces(False)
        if action == "undo":
            self.pick(11, "nba")
        self.save()
        self.assert_surfaces(True)
        self.unchanged_internal()
        self.facts.update(
            edit=action,
            saved_visible=True,
            edit_hidden=True,
            resave_visible=True,
            scopes=["global", "public", "private-member"],
        )

    @acceptance
    def test_winner_edit_resave_all_surfaces(self):
        self.lifecycle("winner")

    @acceptance
    def test_games_only_edit_resave_all_surfaces(self):
        self.lifecycle("games")

    @acceptance
    def test_undo_resave_all_surfaces(self):
        self.lifecycle("undo")

    @acceptance
    def test_stored_draft_score_hidden_without_deletion(self):
        self.setup_competition(saved=False)
        self.assert_surfaces(False)
        self.unchanged_internal()
        self.facts.update(
            draft_score_physically_retained=True, draft_score_visible=False
        )

    @acceptance
    def test_postlock_edits_still_allowed_but_all_invalidate(self):
        self.setup_competition()
        self.c.bracket_timing("locked")
        m = self.at(11, "nba")
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            role="user-a",
            payload={"games": 7},
        )
        self.assert_surfaces(False)
        self.pick(11, "nba", games=5)
        self.call(
            "PATCH",
            f"/bracket/{self.ids['a']}/match/{m['id']}",
            role="user-a",
            payload={"action": "undo"},
        )
        self.assert_surfaces(False)
        self.save(status=403)
        self.unchanged_internal()
        self.facts.update(
            postlock_mutations_unchanged=True, postlock_resave_still_denied=True
        )

    @acceptance
    def test_admin_mutation_authorization_unchanged_invalidation_shared(self):
        self.setup_competition()
        self.pick(11, "nba", role="admin", games=5)
        self.assert_surfaces(False)
        self.call("GET", f"/bracket/{self.ids['a']}", 403, role="admin")
        self.save()
        self.assert_surfaces(True)
        self.unchanged_internal()
        self.facts.update(
            admin_mutation_gap_retained=True, no_admin_draft_read_bypass=True
        )
