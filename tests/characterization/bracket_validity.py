"""NC-02B2 guarded synthetic live acceptance; no production/job execution."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bracket_lock import BracketLockAcceptance
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM

CONFIG = None
OPT_IN = False
RESULTS = []


class BracketValidityAcceptance(BracketLockAcceptance):
    # Only this class's B2 methods are selected by its runner; B1 remains separate.
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02B2"
        )
        self.context.__enter__()
        self.facts = {}

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.assertEqual(
            self.context.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM
        )
        RESULTS.append(
            {
                "scenario": self._testMethodName,
                "phase": "NC-02B2",
                "requirements": ["B6", "B7", "B8", "B9"],
                "facts": self.facts,
                "evidence": self.context.summary,
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def test_b2_counts_both_routes_and_playin(self):
        bid = self.setup_bracket()
        m = self.at(bid, 6)
        before = self.state(bid)
        for bad in [0, -1, 1, 2, 3, 8, 99, True, 4.0, "4", "bad", [4], {}]:
            self.pick(bid, 6, games=bad, status=400)
            self.call(
                "PATCH",
                f"/bracket/match/{m['id']}/games",
                400,
                role="user-a",
                payload={"games": bad},
            )
        self.assertEqual(before, self.state(bid))
        for value in [4, 5, 6, 7]:
            self.pick(bid, 6, games=value)
            self.call(
                "PATCH",
                f"/bracket/match/{m['id']}/games",
                200,
                role="user-a",
                payload={"games": value},
            )
        play = self.at(bid, 1)
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{play['id']}",
            200,
            role="user-a",
            payload={"action": "set_winner", "team": play["team_a"]},
        )
        self.assertEqual(self.at(bid, 1)["predicted_winner_games"], 1)
        for bad in [None, 0, 4, True, "1"]:
            (
                self.pick(bid, 1, games=bad, status=400)
                if bad is not None
                else self.call(
                    "PATCH",
                    f"/bracket/{bid}/match/{play['id']}",
                    400,
                    role="user-a",
                    payload={
                        "action": "set_winner",
                        "team": play["team_a"],
                        "games": None,
                    },
                )
            )
        for bad in [1, 4, True, "1"]:
            self.call(
                "PATCH",
                f"/bracket/match/{play['id']}/games",
                400,
                role="user-a",
                payload={"games": bad},
            )
        # A changed winner without a simultaneous replacement count must not
        # inherit the old series count; it remains an incomplete draft.
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            200,
            role="user-a",
            payload={"action": "set_winner", "team": m["team_b"]},
        )
        self.assertIsNone(self.at(bid, 6)["predicted_winner_games"])
        self.facts.update(strict_counts=True, playin_fixed=True)

    def participant_case(self, master=False):
        role = "admin" if master else "user-a"
        bid = self.setup_bracket(
            "master" if master else "draft",
            role=role,
            timing="locked" if master else "open",
        )
        before = self.state(bid)
        self.pick(bid, 4, role=role, status=400)
        self.assertEqual(before, self.state(bid))
        if master:
            self.save(bid, role=role)
        else:
            self.save(bid, status=400)
        for slot in [1, 2, 3]:
            self.pick(bid, slot, role=role)
        self.pick(bid, 4, role=role)
        self.assertIsNotNone(self.at(bid, 4)["predicted_winner"])
        if master:
            self.save(bid, role=role)
        self.facts.update(
            one_sided_refused=True,
            natural_progression=True,
            partial_master_persisted=master,
        )

    def test_b2_ordinary_participants_and_draft_progression(self):
        self.participant_case()

    def test_b2_master_participants_and_incremental_save(self):
        self.participant_case(True)

    def test_b2_submission_rejects_faults_and_accepts_only_complete(self):
        bid = self.setup_bracket()
        self.save(bid, status=400)
        self.fill(bid)
        for fault in [
            "missing_winner",
            "missing_count",
            "count_3",
            "count_8",
            "count_negative",
            "count_zero",
            "one_sided",
            "wrong_winner",
            "stale_participant",
        ]:
            with self.context.bracket_validity_fault(fault):
                before = self.state(bid)
                self.save(bid, status=400)
                self.assertEqual(before, self.state(bid))
        self.assertFalse(self.state(bid)[0]["is_done"])
        self.save(bid)
        self.assertTrue(self.state(bid)[0]["is_done"])
        self.facts.update(
            submission_faults_rejected=9,
            explicit_complete_submission=True,
            no_autofill=True,
        )

    def graph(self, action, slot=7, master=False):
        role = "admin" if master else "user-a"
        bid = self.setup_bracket(
            "master" if master else "draft",
            role=role,
            timing="locked" if master else "open",
        )
        self.fill(bid, role=role)
        self.save(bid, role=role)
        before = self.state(bid)[1]
        m = self.at(bid, slot)
        if action == "undo":
            self.undo(bid, slot, role=role)
        else:
            self.pick(
                bid,
                slot,
                role=role,
                team=m["team_b"],
                games=1 if m["round"] == 0 else 6,
            )
        expected = {7: [9, 10], 10: [], 2: [3, 4, 5, 8, 9, 10]}[slot]
        for downstream in expected + [11]:
            row = self.at(bid, downstream, "nba" if downstream == 11 else "east")
            self.assertIsNone(row["predicted_winner"])
            self.assertIsNone(row["predicted_winner_games"])
        after = self.state(bid)[1]
        self.assertEqual(
            [r for r in before if r["conference"] == "west"],
            [r for r in after if r["conference"] == "west"],
        )
        if slot == 7:
            self.assertEqual(
                next(r for r in before if r["slot"] == 8 and r["conference"] == "east"),
                self.at(bid, 8),
            )
        self.assertFalse(self.state(bid)[0]["is_done"])
        self.assertIsNone(self.state(bid)[0]["saved_at"])
        self.save(bid, role=role, status=200 if master else 400)
        self.facts.update(
            action=action,
            upstream_slot=slot,
            recursive_clear=True,
            unrelated_branch_preserved=True,
            master=master,
        )

    def test_b2_winner_change_recursive_opponent_dependency(self):
        self.graph("change")

    def test_b2_undo_recursive_opponent_dependency(self):
        self.graph("undo")

    def test_b2_finals_dependency(self):
        self.graph("change", 10)

    def test_b2_playin_dual_feed(self):
        self.graph("change", 2)

    def test_b2_master_recursive_change(self):
        self.graph("change", master=True)

    def test_b2_master_recursive_undo(self):
        self.graph("undo", master=True)
