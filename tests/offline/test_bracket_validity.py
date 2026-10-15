"""Pure NC-02B2 graph/count/submission acceptance; no app, DB or network."""

from copy import deepcopy
import unittest
from bracket_rules import game_count_error, apply_prediction, submission_error
from synthetic_fixtures import bracket_scenario


def complete():
    matches = bracket_scenario("draft")["matches"]
    for m in sorted(matches, key=lambda row: (row["slot"], row["conference"])):
        m = next(row for row in matches if row["id"] == m["id"])
        changed = apply_prediction(
            matches, m["id"], m["team_a"], 1 if m["round"] == 0 else 4
        )
        by_id = {r["id"]: r for r in changed}
        matches[:] = [by_id.get(r["id"], r) for r in matches]
    return matches


class BracketValidityRules(unittest.TestCase):
    def at(self, rows, slot, conf="east"):
        return next(m for m in rows if m["slot"] == slot and m["conference"] == conf)

    def test_complete_graph_accepts_and_draft_fails(self):
        self.assertIsNone(submission_error(complete()))
        self.assertIsNotNone(submission_error(bracket_scenario("draft")["matches"]))

    def test_count_domain_strict_including_bool_float_and_string(self):
        for invalid in [
            None,
            0,
            -1,
            1,
            2,
            3,
            8,
            99,
            True,
            False,
            4.0,
            "4",
            "bad",
            [],
            {},
        ]:
            self.assertIsNotNone(game_count_error({"round": 1}, invalid))
        for good in [4, 5, 6, 7]:
            self.assertIsNone(game_count_error({"round": 1}, good))
        self.assertIsNone(game_count_error({"round": 1}, None, allow_missing=True))

    def test_playin_count_canonical_never_editable(self):
        for value in [1, None, 4, "1", True]:
            self.assertIsNotNone(game_count_error({"round": 0}, value, count_edit=True))
        self.assertIsNone(game_count_error({"round": 0}, 1))
        for value in [None, 0, 4, "1", True]:
            self.assertIsNotNone(
                game_count_error({"round": 0}, value, allow_missing=True)
            )

    def test_every_submission_field_rejected_when_invalid(self):
        for field, bad in [
            ("predicted_winner", None),
            ("predicted_winner", "foreign"),
            ("team_a", None),
            ("team_b", None),
            ("predicted_winner_games", None),
            *[("predicted_winner_games", v) for v in [0, -1, 3, 8, "bad", 4.0, True]],
        ]:
            with self.subTest(field=field, value=bad):
                rows = complete()
                self.at(rows, 11, "nba")[field] = bad
                self.assertIsNotNone(submission_error(rows))

    def test_missing_duplicate_extra_or_broken_matches_rejected(self):
        for change in (
            "missing",
            "duplicate",
            "extra",
            "link",
            "cycle",
            "slot",
            "round",
            "stale",
        ):
            rows = complete()
            if change == "missing":
                rows.pop()
            elif change == "duplicate":
                rows.append(deepcopy(rows[0]))
            elif change == "extra":
                rows.append({**rows[0], "id": "extra"})
            elif change == "link":
                rows[0]["next_match_id"] = None
            elif change == "cycle":
                rows[0]["next_match_id"] = rows[0]["id"]
            elif change == "slot":
                rows[0]["next_slot"] = "invalid"
            elif change == "round":
                rows[0]["round"] = 8
            else:
                self.at(rows, 11, "nba")["team_a"] = "stale"
            with self.subTest(change=change):
                self.assertIsNotNone(submission_error(rows))

    def test_master_empty_and_partial_persistable_invalid_completed_result_not(self):
        rows = bracket_scenario("draft")["matches"]
        self.assertIsNone(submission_error(rows, master=True))
        m = self.at(rows, 6)
        updates = apply_prediction(rows, m["id"], m["team_a"], 4)
        rows = [{r["id"]: r for r in updates}.get(m["id"], m) for m in rows]
        self.assertIsNone(submission_error(rows, master=True))
        self.at(rows, 6)["predicted_winner_games"] = 8
        self.assertIsNotNone(submission_error(rows, master=True))

    def graph_case(self, action, slot):
        rows = complete()
        before = deepcopy(rows)
        source = self.at(rows, slot)
        updates = apply_prediction(
            rows,
            source["id"],
            None if action == "undo" else source["team_b"],
            None if action == "undo" else 6,
        )
        after = {r["id"]: r for r in rows}
        after.update({r["id"]: r for r in updates})
        rows = list(after.values())
        for round_slot in {7: [9, 10], 6: [8, 10], 10: []}[slot] + [11]:
            m = self.at(rows, round_slot, "nba" if round_slot == 11 else "east")
            self.assertIsNone(m["predicted_winner"])
            self.assertIsNone(m["predicted_winner_games"])
        self.assertEqual(
            [r for r in rows if r["conference"] == "west"],
            [r for r in before if r["conference"] == "west"],
        )
        if slot == 7:
            self.assertEqual(self.at(rows, 8), self.at(before, 8))
        self.assertEqual(
            self.at(rows, 11, "nba")["team_b"], self.at(before, 11, "nba")["team_b"]
        )

    def test_change_clears_recursive_opponent_dependency(self):
        self.graph_case("change", 7)

    def test_undo_clears_recursive_opponent_dependency(self):
        self.graph_case("undo", 7)

    def test_finals_dependency_change(self):
        self.graph_case("change", 10)

    def test_finals_dependency_undo(self):
        self.graph_case("undo", 10)

    def test_playin_dual_outputs_clear_both_branches(self):
        for action in ["change", "undo"]:
            rows = complete()
            old = deepcopy(rows)
            source = self.at(rows, 2)
            updates = apply_prediction(
                rows,
                source["id"],
                source["team_b"] if action == "change" else None,
                1 if action == "change" else None,
            )
            by_id = {r["id"]: r for r in updates}
            rows = [by_id.get(r["id"], r) for r in rows]
            for slot in [3, 4, 5, 8, 9, 10]:
                self.assertIsNone(self.at(rows, slot)["predicted_winner"])
                self.assertIsNone(self.at(rows, slot)["predicted_winner_games"])
            self.assertEqual(self.at(rows, 6), self.at(old, 6))
            self.assertEqual(self.at(rows, 7), self.at(old, 7))
            self.assertEqual(
                [r for r in rows if r["conference"] == "west"],
                [r for r in old if r["conference"] == "west"],
            )

    def test_current_winner_count_not_inherited_if_omitted_no_input_mutation(self):
        rows = complete()
        old = deepcopy(rows)
        m = self.at(rows, 6)
        changed = apply_prediction(rows, m["id"], m["team_b"], None)
        self.assertIsNone(
            next(r for r in changed if r["id"] == m["id"])["predicted_winner_games"]
        )
        self.assertEqual(rows, old)
