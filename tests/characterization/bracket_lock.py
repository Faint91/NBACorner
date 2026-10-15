"""NC-02B1 acceptance via existing loopback-only, lease/reset guarded harness."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bracket_access import CurrentBracketBehavior
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM

CONFIG = None
OPT_IN = False
RESULTS = []


class BracketLockAcceptance(CurrentBracketBehavior):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02B1"
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
                "phase": "NC-02B1",
                "requirements": ["B1", "B2", "B3", "B4", "B5", "B16"],
                "evidence": self.context.summary,
                "facts": self.facts,
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def refusal(self, bid, role="user-a", locked=True):
        before = self.state(bid)
        m = self.at(bid, 6)
        paths = [
            (
                f"/bracket/{bid}/match/{m['id']}",
                {"action": "set_winner", "team": m["team_a"], "games": 5},
            ),
            (f"/bracket/{bid}/match/{m['id']}", {"action": "undo"}),
            (f"/bracket/match/{m['id']}/games", {"games": 7}),
            (f"/bracket/{bid}/save", {"name": "Denied content"}),
        ]
        for path, payload in paths:
            body = self.call("PATCH", path, 403, role=role, payload=payload)
            if locked:
                self.assertEqual(
                    body,
                    {"error": "Bracket content is locked once the playoffs start."},
                )
        self.assertEqual(before, self.state(bid))

    def test_ordinary_before_boundary_all_content_and_resave(self):
        bid = self.setup_bracket()
        flags = self.context.bracket_deadline_boundary("before")
        self.assertFalse(flags["locked"])
        self.pick(bid, 6)
        self.undo(bid, 6)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            200,
            role="user-a",
            payload={"games": 5},
        )
        self.fill(bid)
        self.save(bid)
        self.assertTrue(self.state(bid)[0]["is_done"])
        self.facts.update(boundary="one microsecond before", all_content_permitted=True)

    def frozen(self, relative, saved=False):
        bid = self.setup_bracket()
        self.pick(bid, 6)
        if saved:
            self.fill(bid)
            self.save(bid)
        flags = self.context.bracket_deadline_boundary(relative)
        self.assertTrue(flags["locked"])
        self.refusal(bid)
        body = self.call("POST", "/bracket/create", 403, role="user-a", payload={})
        self.assertEqual(
            body, {"error": "Bracket content is locked once the playoffs start."}
        )
        self.call("GET", f"/bracket/{bid}", 200, role="user-a")
        row = self.state(bid)[0]
        self.assertEqual(row["is_done"], saved)
        self.assertEqual(self.context.module.competitive_bracket_eligible(row), saved)
        listed = self.call("GET", "/brackets", 200, role="user-a")
        self.assertEqual(any(r["bracket_id"] == bid for r in listed), saved)
        # League/history reads are not subject to the content deadline.
        self.call("GET", "/leaderboard/history", 200, role="user-a")
        self.facts.update(
            boundary=relative, frozen=True, submitted=saved, reads_allowed=True
        )

    def test_draft_at_boundary_frozen_readable_ineligible(self):
        self.frozen("at")

    def test_draft_after_boundary_frozen_readable_ineligible(self):
        self.frozen("after")

    def test_saved_at_boundary_no_mutation_or_invalidation(self):
        self.frozen("at", saved=True)

    def test_create_hard_lock_overrides_inconsistent_open_window(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        self.context.bracket_deadline_boundary("at")
        before = self.context.bracket_snapshot()
        with patch.object(
            self.context.module, "bracket_creation_open", return_value=True
        ):
            self.call("POST", "/bracket/create", 403, role="user-a", payload={})
        self.assertEqual(before, self.context.bracket_snapshot())
        self.facts.update(hard_lock_independent_of_opening=True)

    def test_nonowner_and_admin_ordinary_content_denied(self):
        bid = self.setup_bracket()
        for role in ("user-b", "admin"):
            self.context.login(role)
            self.refusal(bid, role, locked=False)
        self.facts.update(nonowner_denied=True, arbitrary_admin_denied=True)

    def test_admin_own_ordinary_denied(self):
        bid = self.setup_bracket(role="admin")
        self.refusal(bid, "admin", locked=False)
        self.facts.update(admin_ordinary_owner_denied=True)

    def test_nonadmin_master_owner_denied_admin_postlock_permitted(self):
        bid = self.setup_bracket("master", role="user-a", timing="locked")
        self.refusal(bid, locked=False)
        self.context.login("admin")
        self.pick(bid, 6, role="admin")
        self.undo(bid, 6, role="admin")
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            200,
            role="admin",
            payload={"games": 5},
        )
        self.fill(bid, role="admin")
        self.save(bid, role="admin")
        self.facts.update(
            nonadmin_master_owner_denied=True,
            admin_master_different_owner_postlock=True,
        )
