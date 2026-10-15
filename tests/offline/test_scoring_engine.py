"""SC1-SC4/SC6 pure scoring acceptance, including clarified wrong-opponent rule."""

import copy
import unittest
from scoring_engine import score_bracket, rank_live_rows


def match(conf="east", rnd=1, slot=4, a="BOS", b="LAL", winner="BOS", games=6):
    return {
        "conference": conf,
        "round": rnd,
        "slot": slot,
        "team_a": a,
        "team_b": b,
        "predicted_winner": winner,
        "predicted_winner_games": games,
    }


def score(actual, user):
    key = f"{actual['conference']}-{actual['round']}-{actual['slot']}"
    return score_bracket({key: user}, {key: actual})


class ScoringEngineTests(unittest.TestCase):
    def test_base_series_matrix_and_opponent_clarification(self):
        actual = match()
        for changes, points, full in [
            ({}, 3, 1),
            ({"games": 5}, 1, 0),
            ({"games": None}, 1, 0),
            ({"winner": "LAL"}, 0, 0),
            ({"b": "DEN"}, 1, 0),
            ({"winner": None}, 0, 0),
        ]:
            user = match(**changes)
            r = score(actual, user)
            self.assertEqual((r["base_points"], r["full_hits"]), (points, full))
            self.assertEqual(r["total_points"], points)

    def test_play_in_winner_hit_miss_and_opponent(self):
        actual = match(rnd=0, slot=1, games=1)
        for user, points, full in [
            (match(rnd=0, slot=1, games=1), 1, 1),
            (match(rnd=0, slot=1, games=99), 1, 1),
            (match(rnd=0, slot=1, games=1, b="DEN"), 1, 0),
            (match(rnd=0, slot=1, games=1, winner="LAL"), 0, 0),
        ]:
            r = score(actual, user)
            self.assertEqual((r["base_points"], r["full_hits"]), (points, full))

    def test_bonus_combinations_and_separation(self):
        actual = match(conf="nba", rnd=4, slot=11)
        cases = [
            (match(conf="nba", rnd=4, slot=11, a="MIL", b="DEN", winner="MIL"), 0, 0),
            (match(conf="nba", rnd=4, slot=11, b="DEN", winner="DEN"), 0, 0),
            (match(conf="nba", rnd=4, slot=11, winner="LAL"), 1, 0),
            (match(conf="nba", rnd=4, slot=11, b="DEN"), 0, 3),
            (match(conf="nba", rnd=4, slot=11), 1, 3),
        ]
        for user, finalists, champion in cases:
            r = score(actual, user)
            self.assertEqual(
                (r["bonus_finalists"], r["bonus_champion"]), (finalists, champion)
            )
            self.assertEqual(r["total_points"], r["base_points"] + finalists + champion)
            self.assertEqual(sum(r["points_by_round"].values()), r["base_points"])
        r = score(actual, match(conf="nba", rnd=4, slot=11))
        self.assertEqual((r["total_points"], r["full_hits"]), (7, 1))

    def test_finalist_order_is_pair_identity_not_champion(self):
        actual = match(conf="nba", rnd=4, slot=11)
        user = match(conf="nba", rnd=4, slot=11, a="LAL", b="BOS", winner="LAL")
        self.assertEqual(score(actual, user)["bonus_finalists"], 1)

    def test_partial_master_no_future_bonus_earlier_round_scores(self):
        master = {
            "east-1-4": match(),
            "nba-4-11": match(
                conf="nba", rnd=4, slot=11, a=None, b=None, winner=None, games=None
            ),
        }
        user = copy.deepcopy(master)
        user["nba-4-11"] = match(conf="nba", rnd=4, slot=11)
        r = score_bracket(user, master)
        self.assertEqual(
            (r["base_points"], r["bonus_champion"], r["bonus_finalists"]), (3, 0, 0)
        )
        self.assertEqual(r["points_by_match"]["nba-4-11"]["status"], "pending")
        actual = match(conf="nba", rnd=4, slot=11, winner=None, games=None)
        self.assertEqual(score(actual, user["nba-4-11"])["bonus_finalists"], 1)
        self.assertEqual(score(actual, user["nba-4-11"])["bonus_champion"], 0)

    def test_missing_prediction_and_missing_actual_count(self):
        self.assertEqual(score_bracket({}, {"east-1-4": match()})["misses"], 1)
        r = score(match(games=None), match())
        self.assertEqual(r["base_points"], 0)
        for games in [True, 0, 8]:
            with self.assertRaises(ValueError):
                score(match(games=games), match())

    def test_pure_engine_is_deterministic_and_does_not_mutate(self):
        actual = match()
        user = match()
        before = copy.deepcopy((actual, user))
        self.assertEqual(score(actual, user), score(actual, user))
        self.assertEqual((actual, user), before)

    def test_competition_ranks_and_stable_names_do_not_break_ties(self):
        def row(bid, pts, hits=1, stamp="2026-01-01T00:00:00Z", username="Name"):
            return dict(
                bracket_id=bid,
                user_id=bid,
                total_points=pts,
                full_hits=hits,
                saved_at=stamp,
                username=username,
            )

        rows = [
            row("c", 7, username="Zulu"),
            row("d", 6),
            row("b", 7, username="Alpha"),
            row("a", 8),
        ]
        ranked = rank_live_rows(rows)
        self.assertEqual([r["bracket_id"] for r in ranked], ["a", "b", "c", "d"])
        self.assertEqual([r["rank"] for r in ranked], [1, 2, 2, 4])
        self.assertNotIn("rank", rows[0])

    def test_hits_then_saved_instant_with_timezone_equivalence(self):
        rows = [
            dict(
                bracket_id="late",
                total_points=5,
                full_hits=1,
                saved_at="2026-01-02T00:00:00Z",
            ),
            dict(
                bracket_id="early",
                total_points=5,
                full_hits=1,
                saved_at="2026-01-01T00:00:00Z",
            ),
            dict(
                bracket_id="hits",
                total_points=5,
                full_hits=2,
                saved_at="2026-01-03T00:00:00Z",
            ),
            dict(
                bracket_id="same",
                total_points=5,
                full_hits=1,
                saved_at="2025-12-31T16:00:00-08:00",
            ),
        ]
        r = rank_live_rows(rows)
        self.assertEqual([x["rank"] for x in r], [1, 2, 2, 4])
        self.assertEqual(r[0]["bracket_id"], "hits")
        self.assertEqual(r[-1]["bracket_id"], "late")

    def test_invalid_saved_time_has_no_competitive_advantage(self):
        for stamp in [None, "bad", "2026-01-01T00:00:00"]:
            self.assertEqual(
                rank_live_rows([dict(total_points=99, full_hits=21, saved_at=stamp)]),
                [],
            )
