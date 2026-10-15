"""Guarded local D1 scoring publication, canonical authority and automatic flows."""

import unittest
from unittest.mock import patch
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity, STAMP
import scoring_service

CONFIG = None
OPT_IN = False
RESULTS = []


class ScoringAcceptance(unittest.TestCase):
    def setUp(self):
        self.c = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02D1"
        )
        self.c.__enter__()
        self.db = self.c.module.supabase
        self.c.bracket_timing("open")
        self.ids = self.c.install_competitive_scenario()
        self.c.login("admin")
        self.c.login("user-a")

    def tearDown(self):
        self.c.__exit__(None, None, None)
        self.assertEqual(self.c.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM)
        RESULTS.append(
            dict(
                phase="NC-02D1",
                scenario=self._testMethodName,
                requirements=["SC1", "SC2", "SC3", "SC4", "SC6", "SC7", "SC8", "SC9"],
                passed=True,
                cleanup_checksum=CANONICAL_CHECKSUM,
                production_contact=False,
            )
        )

    def rows(self):
        return sorted(
            self.db.table("bracket_scores").select("*").execute().data,
            key=lambda r: r["bracket_id"],
        )

    def recompute(self, expected=200, **kwargs):
        status, body = self.c.recompute_request(**kwargs)
        self.assertEqual(status, expected)
        return body

    def match(self, bid, rnd=0, slot=1, conf="east"):
        return next(
            m
            for m in self.db.table("matches")
            .select("*")
            .eq("bracket_id", bid)
            .execute()
            .data
            if (m["conference"], m["round"], m["slot"]) == (conf, rnd, slot)
        )

    def save_a(self):
        m = self.match(self.ids["a"])
        self.db.table("matches").update(
            dict(predicted_winner=m["team_a"], predicted_winner_games=1)
        ).eq("id", m["id"]).execute()
        self.db.table("brackets").update(dict(is_done=True, saved_at=STAMP)).eq(
            "id", self.ids["a"]
        ).execute()

    def mutate(self, m, payload, expected=200, *, bid=None):
        status, body = self.c.bracket_request(
            "PATCH",
            f"/bracket/{bid or self.ids['master']}/match/{m['id']}",
            payload=payload,
            role="admin" if bid is None else "user-a",
        )
        self.assertEqual(status, expected)
        return body

    def test_d1_manual_complete_set_idempotence_and_eligibility(self):
        self.assertEqual(len(self.rows()), 2)
        self.recompute()
        first = self.rows()
        self.assertEqual([r["bracket_id"] for r in first], [self.ids["b"]])
        second = self.recompute()
        self.assertEqual(second["state"], "unchanged")
        self.assertEqual(second["written_rows"], 0)
        self.assertEqual(self.rows(), first)
        self.recompute(expected=401, role=None)
        self.recompute(expected=403, role="user-a")
        self.assertEqual(self.rows(), first)

    def test_d1_auto_winner_undo_count_and_failed_ordinary_no_recompute(self):
        self.save_a()
        self.recompute()
        master = self.match(self.ids["master"])
        a = lambda: next(r for r in self.rows() if r["bracket_id"] == self.ids["a"])
        self.assertEqual(a()["total_points"], 1)
        self.mutate(master, dict(action="set_winner", team=master["team_b"], games=1))
        self.assertEqual(a()["total_points"], 0)
        self.mutate(master, dict(action="undo"))
        self.assertEqual(a()["misses"], 0)
        series = self.match(self.ids["master"], 1, 6)
        user = self.match(self.ids["a"], 1, 6)
        self.db.table("matches").update(
            dict(predicted_winner=user["team_a"], predicted_winner_games=6)
        ).eq("id", user["id"]).execute()
        self.mutate(series, dict(action="set_winner", team=series["team_a"], games=6))
        self.assertEqual(a()["total_points"], 3)
        status, _ = self.c.bracket_request(
            "PATCH",
            f"/bracket/match/{series['id']}/games",
            role="admin",
            payload={"games": 5},
        )
        self.assertEqual(status, 200)
        self.assertEqual(a()["total_points"], 1)
        before = self.rows()
        with patch.object(
            self.c.module,
            "recompute_current_scores",
            side_effect=AssertionError("Unwanted recompute"),
        ):
            self.mutate(
                series, dict(action="set_winner", team="INVALID", games=6), expected=400
            )
            self.mutate(
                user,
                dict(action="set_winner", team=user["team_a"], games=6),
                bid=self.ids["a"],
            )
        self.assertEqual(self.rows(), before)

    def test_d1_canonical_master_spoofs_and_invalid_pointers_preserve_scores(self):
        self.recompute()
        before = self.rows()
        self.recompute(expected=400, master_id=self.ids["a"])
        past = self.c.install_bracket_scenario("historical", role="admin")
        self.recompute(expected=400, master_id=past)
        self.db.table("seasons").update({"master_bracket_id": None}).eq(
            "id", identity("current")
        ).execute()
        self.recompute(expected=503)
        self.assertEqual(self.rows(), before)
        self.db.table("seasons").update({"master_bracket_id": self.ids["master"]}).eq(
            "id", identity("current")
        ).execute()
        self.db.table("brackets").update({"is_master": False}).eq(
            "id", self.ids["master"]
        ).execute()
        self.recompute(expected=503)
        self.assertEqual(self.rows(), before)

    def test_d1_committed_master_recompute_failure_last_good_then_manual_recovery(self):
        self.save_a()
        self.recompute()
        before = self.rows()
        m = self.match(self.ids["master"])
        original = self.db.rpc

        def fail(name, params):
            if name == "publish_current_bracket_scores":
                raise RuntimeError("Synthetic score publication failure")
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=fail):
            body = self.mutate(
                m, dict(action="set_winner", team=m["team_b"], games=1), expected=503
            )
        self.assertTrue(body["master_mutation_committed"])
        self.assertEqual(self.rows(), before)
        self.assertEqual(
            self.match(self.ids["master"])["predicted_winner"], m["team_b"]
        )
        self.recompute()
        self.assertEqual(
            next(r for r in self.rows() if r["bracket_id"] == self.ids["a"])[
                "total_points"
            ],
            0,
        )

    def test_d1_live_ranks_and_stored_bonus_components(self):
        self.save_a()
        owner = self.c.install_bracket_scenario("saved", role="owner")
        self.recompute()
        status, body = self.c.bracket_request("GET", "/leaderboard")
        self.assertEqual(status, 200)
        self.assertEqual([r["rank"] for r in body["rows"]], [1, 1, 3])
        self.assertEqual(body["master_bracket_id"], self.ids["master"])
        final = self.match(self.ids["master"], 4, 11, "nba")
        predicted = self.match(self.ids["a"], 4, 11, "nba")
        for m in [final, predicted]:
            self.db.table("matches").update(
                dict(
                    team_a="BOS",
                    team_b="LAL",
                    predicted_winner="BOS",
                    predicted_winner_games=6,
                )
            ).eq("id", m["id"]).execute()
        self.recompute()
        row = next(r for r in self.rows() if r["bracket_id"] == self.ids["a"])
        self.assertEqual((row["bonus_finalists"], row["bonus_champion"]), (1, 3))
        self.assertEqual(row["total_points"], sum(row["points_by_round"].values()) + 4)
        self.assertEqual(row["full_hits"], 2)

    def test_d1_master_replacement_recomputes_new_truth_and_failure_recovers(self):
        self.save_a()
        self.recompute()
        self.assertEqual(
            next(r for r in self.rows() if r["bracket_id"] == self.ids["a"])[
                "total_points"
            ],
            1,
        )
        status, body = self.c.bracket_request(
            "POST",
            "/bracket/create",
            payload={"replace_existing_master": True},
            role="admin",
        )
        self.assertEqual(status, 200)
        new_id = body["bracket"]["id"]
        self.assertTrue(
            all(
                r["master_bracket_id"] == new_id and r["total_points"] == 0
                for r in self.rows()
            )
        )
        before = self.rows()
        original = self.db.rpc

        def fail(name, params):
            if name == "publish_current_bracket_scores":
                raise RuntimeError("Synthetic replacement publication failure")
            return original(name, params)

        with patch.object(self.db, "rpc", side_effect=fail):
            status, body = self.c.bracket_request(
                "POST",
                "/bracket/create",
                payload={"replace_existing_master": True},
                role="admin",
            )
        self.assertEqual(status, 503)
        self.assertTrue(body["master_mutation_committed"])
        self.assertEqual(self.rows(), before)
        current = (
            self.db.table("seasons")
            .select("master_bracket_id")
            .eq("id", identity("current"))
            .execute()
            .data[0]["master_bracket_id"]
        )
        self.assertNotEqual(current, new_id)
        self.recompute()
        self.assertTrue(all(r["master_bracket_id"] == current for r in self.rows()))

    def test_d1_changed_source_rejects_entire_publication(self):
        self.recompute()
        before = self.rows()
        original = scoring_service.score_bracket
        changed = False

        def calculate(*args):
            nonlocal changed
            result = original(*args)
            if not changed:
                changed = True
                self.db.table("brackets").update(
                    {"saved_at": "2026-01-01T00:00:00Z"}
                ).eq("id", self.ids["b"]).execute()
            return result

        with patch.object(scoring_service, "score_bracket", side_effect=calculate):
            self.recompute(expected=503)
        self.assertEqual(self.rows(), before)
