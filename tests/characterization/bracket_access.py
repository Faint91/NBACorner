"""NC-01B live characterization; existing guarded local context only."""

import unittest
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []
MATCH = "MATCHES REQUIREMENT"
GAP = "KNOWN GAP"
NR = "REQUIREMENT NOT YET REVIEWED"
REQ = {
    "visibility": "Other users may see another user's bracket only if it is saved.",
    "email": "Emails must never be exposed in bracket responses.",
    "edit": "A saved/submitted bracket may be edited before final lock; editing requires saving/submitting again.",
    "undo": "Ordinary bracket owners may undo predictions before lock.",
    "lock": "At playoff start ordinary users may not select/change winners, undo, change series counts or save/resubmit.",
    "admin": "Admins should edit only the master bracket, not arbitrary user brackets.",
    "create": "Admin bracket creation may bypass the normal creation window.",
    "history": "Past-season bracket/history information may be public.",
}


def behavior(group, current, classification=NR, requirement=None, question=None):
    def decorate(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            classification=classification,
            approved_requirement=REQ.get(requirement),
            future_business_question=question,
            evidence_source="LIVE guarded local Flask; canonical reset before/after sequence",
        )
        return fn

    return decorate


class CurrentBracketBehavior(unittest.TestCase):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01B"
        )
        self.context.__enter__()
        self.facts = {}

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.assertEqual(
            self.context.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM
        )
        row = dict(getattr(self, self._testMethodName).metadata)
        row.update(
            evidence=self.context.summary,
            facts=self.facts,
            cleanup_checksum=CANONICAL_CHECKSUM,
        )
        RESULTS.append(row)

    def call(self, method, path, status, **kwargs):
        actual, body = self.context.bracket_request(method, path, **kwargs)
        self.assertEqual(actual, status)
        return body

    def setup_bracket(self, kind="draft", role="user-a", timing="open"):
        self.context.bracket_timing(timing)
        self.context.login(role)
        return self.context.install_bracket_scenario(kind, role=role)

    def state(self, bid):
        s = self.context.bracket_snapshot()
        return next(b for b in s["brackets"] if b["id"] == bid), [
            m for m in s["matches"] if m["bracket_id"] == bid
        ]

    def at(self, bid, slot, conf="east"):
        return next(
            m
            for m in self.state(bid)[1]
            if m["slot"] == slot and m["conference"] == conf
        )

    def pick(
        self, bid, slot, role="user-a", games=None, team=None, status=200, conf="east"
    ):
        m = self.at(bid, slot, conf)
        return self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            status,
            role=role,
            payload={
                "action": "set_winner",
                "team": team or m["team_a"],
                "games": (1 if m["round"] == 0 else 4) if games is None else games,
            },
        )

    def undo(self, bid, slot, role="user-a", status=200):
        m = self.at(bid, slot)
        return self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            status,
            role=role,
            payload={"action": "undo"},
        )

    def fill(self, bid, role="user-a"):
        for slot in range(1, 12):
            for conf in (["nba"] if slot == 11 else ["east", "west"]):
                m = self.at(bid, slot, conf)
                self.assertTrue(m["team_a"] and m["team_b"])
                self.pick(bid, slot, role=role, conf=conf)
        self.assertEqual(len(self.state(bid)[1]), 21)

    def save(self, bid, role="user-a", status=200, payload=None):
        return self.call(
            "PATCH",
            f"/bracket/{bid}/save",
            status,
            role=role,
            payload={"name": "Fixture submitted"} if payload is None else payload,
        )

    @behavior(
        "creation",
        "Open-window ordinary creation produces 21 current-season matches, draft state and active-user duplicate rejection.",
        question="Approve initial graph and duplicate response contract?",
    )
    def current_behavior__bracket__ordinary_creation(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        before = self.call("GET", "/brackets/me", 200, role="user-a")
        self.assertIsNone(before["bracket"])
        body = self.call("POST", "/bracket/create", 200, role="user-a", payload={})
        bid = body["bracket"]["id"]
        b, ms = self.state(bid)
        self.assertTrue(
            not b["is_done"] and b["season_id"] == identity("current") and len(ms) == 21
        )
        self.assertEqual(
            sorted(m["round"] for m in ms), [0] * 6 + [1] * 8 + [2] * 4 + [3] * 2 + [4]
        )
        self.call("POST", "/bracket/create", 400, role="user-a", payload={})
        self.facts = {
            "initial_matches": 21,
            "initial_saved": False,
            "current_season": True,
            "duplicate_created": False,
        }

    @behavior(
        "creation",
        "Ordinary creation rejected before regular-season end and after playoff start; unauthenticated creation rejected.",
        question="Approve normal creation window and missing-date policies?",
    )
    def current_behavior__bracket__creation_windows(self):
        self.context.login("user-a")
        self.call("POST", "/bracket/create", 401, payload={})
        for mode in ("early", "locked"):
            self.context.bracket_timing(mode)
            self.call("POST", "/bracket/create", 403, role="user-a", payload={})
        self.assertFalse(self.context.bracket_snapshot()["brackets"])

    @behavior(
        "creation",
        "Create ignores request fields/non-object body; authenticated open-window request still creates draft.",
        question="Approve ignored creation payload behavior?",
    )
    def current_behavior__bracket__creation_payload(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        self.call("POST", "/bracket/create", 200, role="user-a", payload=["synthetic"])

    @behavior(
        "schema/timing quirks",
        "Historical active bracket blocks new current-season creation through global user uniqueness despite per-season Flask lookup.",
        question="Approve cross-season active-bracket policy? PRESERVED CURRENT BEHAVIOR / CHARACTERIZATION LIMITATION.",
    )
    def current_behavior__bracket__historical_creation_constraint(self):
        self.setup_bracket("historical")
        self.call("POST", "/bracket/create", 200, role="user-a", payload={})
        self.assertEqual(len(self.context.bracket_snapshot()["brackets"]), 2)

    @behavior(
        "admin/master behavior",
        "Admin creation bypasses early/locked windows and promotes new bracket with season master linkage.",
        MATCH,
        "create",
    )
    def current_behavior__bracket__admin_creation_bypass(self):
        self.context.login("admin")
        self.context.bracket_timing("early")
        body = self.call("POST", "/bracket/create", 200, role="admin", payload={})
        bid = body["bracket"]["id"]
        self.assertTrue(self.state(bid)[0]["is_master"])
        self.call("DELETE", f"/bracket/{bid}", 403, role="admin")
        self.context.bracket_timing("locked")
        body = self.call(
            "POST",
            "/bracket/create",
            200,
            role="admin",
            payload={"replace_existing_master": True},
        )
        b = self.state(body["bracket"]["id"])[0]
        s = self.context.bracket_snapshot()
        self.assertTrue(
            b["is_master"]
            and any(x["master_bracket_id"] == b["id"] for x in s["seasons"])
        )

    @behavior(
        "admin/master behavior",
        "New admin creation demotes existing other-owner master, updates pointer; ordinary payload cannot request master status.",
        question="Approve automatic master replacement policy?",
    )
    def current_behavior__bracket__master_replacement(self):
        old = self.setup_bracket("master", role="user-b")
        self.context.login("admin")
        self.call("POST", "/bracket/create", 409, role="admin", payload={})
        new = self.call(
            "POST",
            "/bracket/create",
            200,
            role="admin",
            payload={"replace_existing_master": True},
        )["bracket"]["id"]
        self.assertFalse(self.state(old)[0]["is_master"])
        self.assertTrue(self.state(new)[0]["is_master"])
        self.context.login("user-a")
        ordinary = self.call(
            "POST", "/bracket/create", 200, role="user-a", payload={"is_master": True}
        )["bracket"]["id"]
        self.assertFalse(self.state(ordinary)[0]["is_master"])

    @behavior(
        "predictions",
        "Valid winner advances to existing child; play-in games forced to one; unsupported actions/invalid winner fail; one-sided not-ready match can accept its populated team.",
        question="Approve readiness, action and winner-input contract?",
    )
    def current_behavior__bracket__prediction_validation(self):
        bid = self.setup_bracket()
        self.pick(bid, 1, games=99, status=400)
        self.pick(bid, 1)
        self.assertEqual(self.at(bid, 1)["predicted_winner_games"], 1)
        self.assertEqual(self.at(bid, 3)["team_a"], self.at(bid, 1)["team_a"])
        self.pick(bid, 6, team="BOS", status=400)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            400,
            role="user-a",
            payload={"action": "unsupported"},
        )
        self.pick(bid, 4, status=400)
        self.assertIsNone(self.at(bid, 4)["predicted_winner"])
        self.facts = {
            "match_count_remains": len(self.state(bid)[1]),
            "one_sided_match_rejected": True,
        }

    @behavior(
        "match propagation",
        "Full graph progresses through 21 matches to Finals; changing earlier winner clears propagated old team and downstream picks/counts.",
        question="Approve exact downstream clearing rules?",
    )
    def current_behavior__bracket__winner_change_graph(self):
        bid = self.setup_bracket()
        self.fill(bid)
        self.assertIsNotNone(self.at(bid, 11, "nba")["predicted_winner"])
        m = self.at(bid, 6)
        old = m["team_a"]
        self.pick(bid, 6, team=m["team_b"], games=6)
        self.assertEqual(self.at(bid, 8)["team_a"], m["team_b"])
        self.assertIsNone(self.at(bid, 8)["predicted_winner"])
        self.assertIsNone(self.at(bid, 8)["predicted_winner_games"])
        self.assertTrue(
            all(
                x["predicted_winner"] != old
                for x in self.state(bid)[1]
                if x["round"] > 1
            )
        )
        self.facts = {
            "matches": 21,
            "finals_populated_before_change": True,
            "earlier_losing_team_removed": True,
        }

    @behavior(
        "undo",
        "Owner undo succeeds before lock; repeated/no-prior undo succeeds and clears prediction/count.",
        MATCH,
        "undo",
    )
    def current_behavior__bracket__owner_undo(self):
        bid = self.setup_bracket()
        self.pick(bid, 6)
        self.undo(bid, 6)
        self.undo(bid, 6)
        self.undo(bid, 7)
        self.assertIsNone(self.at(bid, 6)["predicted_winner"])
        self.assertIsNone(self.at(bid, 6)["predicted_winner_games"])

    @behavior(
        "match propagation",
        "Undo with downstream selections clears advanced slots/predictions/counts; 7-8 play-in winner/loser feeds two branches.",
        question="Approve play-in loser branches and deep undo clearing semantics?",
    )
    def current_behavior__bracket__undo_graph(self):
        bid = self.setup_bracket()
        self.fill(bid)
        self.save(bid)
        self.undo(bid, 6)
        self.assertIsNone(self.at(bid, 8)["team_a"])
        self.assertIsNone(self.at(bid, 8)["predicted_winner"])
        self.undo(bid, 2)
        self.assertIsNone(self.at(bid, 3)["team_b"])
        self.assertIsNone(self.at(bid, 5)["team_b"])
        bracket, _ = self.state(bid)
        self.assertFalse(bracket["is_done"])
        self.assertIsNone(bracket["saved_at"])

    @behavior(
        "cross-user authorization",
        "Other ordinary user cannot predict, undo, change games, save or delete an owner's current bracket.",
        question="Approve non-owner mutation policy for all routes?",
    )
    def current_behavior__bracket__nonowner_mutations(self):
        bid = self.setup_bracket()
        self.context.login("user-b")
        self.pick(bid, 6, role="user-b", status=403)
        self.undo(bid, 6, role="user-b", status=403)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="user-b",
            payload={"games": 4},
        )
        self.save(bid, role="user-b", status=403)
        self.call("DELETE", f"/bracket/{bid}", 403, role="user-b")
        self.assertIsNone(self.at(bid, 6)["predicted_winner"])

    @behavior(
        "admin/master behavior",
        "Admin predicts, undoes, saves and deletes another ordinary user's bracket; games-only route still requires owner.",
        GAP,
        "admin",
    )
    def current_behavior__bracket__admin_arbitrary_mutations(self):
        bid = self.setup_bracket()
        self.context.login("admin")
        before = self.state(bid)
        self.pick(bid, 6, role="admin", status=403)
        self.undo(bid, 6, role="admin", status=403)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="admin",
            payload={"games": 4},
        )
        self.save(bid, role="admin", status=403)
        self.assertEqual(before, self.state(bid))
        # B3 now deliberately denies arbitrary admin deletion as well.
        self.call("DELETE", f"/bracket/{bid}", 403, role="admin")
        self.assertIsNone(self.state(bid)[0]["deleted_at"])

    @behavior(
        "admin/master behavior",
        "Admin-owned master supports prediction, undo, games-only and save after playoff start.",
        MATCH,
        "admin",
    )
    def current_behavior__bracket__master_mutations(self):
        bid = self.setup_bracket("master", role="admin", timing="locked")
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

    @behavior(
        "game counts",
        "Games-only accepts negative/zero/large counts, requires field, leaves saved state unchanged; absent set-winner count persists NULL outside play-in.",
        question="Approve range/required count and games-only unsave semantics?",
    )
    def current_behavior__bracket__game_count_values(self):
        bid = self.setup_bracket("saved")
        m = self.at(bid, 6)
        for value in (4, 5, 6, 7):
            self.call(
                "PATCH",
                f"/bracket/match/{m['id']}/games",
                200,
                role="user-a",
                payload={"games": value},
            )
            self.assertEqual(self.at(bid, 6)["predicted_winner_games"], value)
            self.assertFalse(self.state(bid)[0]["is_done"])
        before = self.state(bid)
        for invalid in (0, -1, 1, 2, 3, 8, 99, 4.0, True, "4", "bad", [4]):
            self.call(
                "PATCH",
                f"/bracket/match/{m['id']}/games",
                400,
                role="user-a",
                payload={"games": invalid},
            )
        self.assertEqual(before, self.state(bid))
        self.call(
            "PATCH", f"/bracket/match/{m['id']}/games", 400, role="user-a", payload={}
        )
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            200,
            role="user-a",
            payload={"action": "set_winner", "team": m["team_a"]},
        )
        self.assertIsNone(self.at(bid, 6)["predicted_winner_games"])

    @behavior(
        "save/resubmit",
        "Complete bracket saves repeatedly; pre-lock winner/count edits through set_winner clear is_done/saved_at and require explicit resave.",
        MATCH,
        "edit",
    )
    def current_behavior__bracket__save_edit_resubmit(self):
        bid = self.setup_bracket()
        self.save(bid, status=400)
        self.fill(bid)
        self.save(bid)
        self.save(bid)
        self.pick(bid, 6, games=5)
        b, _ = self.state(bid)
        self.assertTrue(not b["is_done"] and b["saved_at"] is None)
        self.save(bid)
        self.assertTrue(self.state(bid)[0]["is_done"])

    @behavior(
        "save/resubmit",
        "Games-only edits to a saved bracket do not clear is_done/saved_at, bypassing required resubmission state.",
        GAP,
        "edit",
    )
    def current_behavior__bracket__games_only_saved_edit(self):
        bid = self.setup_bracket()
        self.fill(bid)
        self.save(bid)
        b, _ = self.state(bid)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            200,
            role="user-a",
            payload={"games": 7},
        )
        after, _ = self.state(bid)
        self.assertTrue(not after["is_done"] and after["saved_at"] is None)

    @behavior(
        "save/resubmit",
        "Partial graph with ready but unpredicted pairs is rejected at save; missing-pair skip is separately static evidence.",
        question="Approve what completion means for unpopulated downstream matches?",
    )
    def current_behavior__bracket__partial_graph_save(self):
        bid = self.setup_bracket()
        for slot in (1, 2, 3, 6, 7):
            for conf in ("east", "west"):
                self.pick(bid, slot, conf=conf)
        self.save(bid, status=400)
        self.facts = {
            "incomplete_ready_pairs_rejected": True,
            "static_skip_missing_pairs": True,
        }

    @behavior(
        "visibility/privacy",
        "Saved bracket detail/list expose owner email; same issue previously established in NC-01A1, now confirmed for listing too.",
        GAP,
        "email",
    )
    def current_behavior__bracket__email_serialization(self):
        bid = self.setup_bracket("saved", role="user-b")
        self.context.login("user-a")
        body = self.call("GET", f"/bracket/{bid}", 200, role="user-a")
        self.assertEqual(set(body["bracket"]["owner"]), {"id", "username"})
        rows = self.call("GET", "/brackets", 200, role="user-a")
        self.assertEqual(set(rows[0]["user"]), {"id", "username"})
        self.facts = {
            "owner_fields": sorted(body["bracket"]["owner"]),
            "list_user_fields": sorted(rows[0]["user"]),
            "previously_established": "NC-01A1",
            "same_requirement_issue": True,
        }

    @behavior(
        "visibility/privacy",
        "Ordinary other-user draft detail is denied; saved detail is readable; anonymous detail/list denied; owners can read draft/saved.",
        MATCH,
        "visibility",
    )
    def current_behavior__bracket__visibility_boundary(self):
        bid = self.setup_bracket()
        self.context.login("user-b")
        self.call("GET", f"/bracket/{bid}", 200, role="user-a")
        self.call("GET", f"/bracket/{bid}", 403, role="user-b")
        self.call("GET", f"/bracket/{bid}", 401)
        self.call("GET", "/brackets", 401)
        self.fill(bid)
        self.save(bid)
        self.call("GET", f"/bracket/{bid}", 200, role="user-b")
        self.call("GET", f"/bracket/{bid}", 200, role="user-a")

    @behavior(
        "visibility/privacy",
        "Admin can read another ordinary user's unsaved draft.",
        GAP,
        "visibility",
    )
    def current_behavior__bracket__admin_draft_visibility(self):
        bid = self.setup_bracket()
        self.context.login("admin")
        self.call("GET", f"/bracket/{bid}", 403, role="admin")

    @behavior(
        "playoff lock",
        "Ordinary predictions, undo and both series-count paths still mutate after playoff lock.",
        GAP,
        "lock",
    )
    def current_behavior__bracket__postlock_content(self):
        bid = self.setup_bracket(timing="locked")
        before = self.state(bid)
        self.pick(bid, 6, status=403)
        self.pick(bid, 6, games=6, status=403)
        self.undo(bid, 6, status=403)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="user-a",
            payload={"games": 7},
        )
        self.assertEqual(before, self.state(bid))
        self.facts = {
            "playoffs_locked": True,
            "all_content_refused_without_writes": True,
        }

    @behavior(
        "playoff lock",
        "Ordinary save/resubmit rejected after playoff start even when complete.",
        MATCH,
        "lock",
    )
    def current_behavior__bracket__postlock_save(self):
        bid = self.setup_bracket()
        self.fill(bid)
        self.save(bid)
        self.context.bracket_timing("locked")
        self.save(bid, status=403)
        self.call("GET", f"/bracket/{bid}", 200, role="user-a")
        self.call("GET", "/auth/test-me", 200, role="user-a")
        self.facts = {
            "identity_read_not_blanket_blocked": True,
            "bracket_read_not_locked": True,
        }

    @behavior(
        "deletion",
        "Owner can soft-delete draft/saved after lock; matches retained, detail hidden and same-season recreation possible in open window.",
        question="Is deletion content-changing or unrelated? Approve deletion/recreation/history retention policy?",
    )
    def current_behavior__bracket__delete_recreate(self):
        bid = self.setup_bracket("saved", timing="locked")
        before = self.state(bid)
        self.call("DELETE", f"/bracket/{bid}", 403, role="user-a")
        self.assertEqual(before, self.state(bid))
        self.context.bracket_timing("open")
        self.call("DELETE", f"/bracket/{bid}", 200, role="user-a")
        b, ms = self.state(bid)
        self.assertTrue(
            b["deleted_at"]
            and b["deleted_by_user_id"] == identity("user-a")
            and len(ms) == 21
        )
        self.call("GET", f"/bracket/{bid}", 404, role="user-a")
        self.call("DELETE", f"/bracket/{bid}", 404, role="user-a")
        self.context.bracket_timing("open")
        self.call("POST", "/bracket/create", 200, role="user-a", payload={})

    @behavior(
        "deletion",
        "Master soft-delete demotes flag and clears season pointer; admin can recreate master afterward.",
        question="Approve master deletion/replacement lifecycle?",
    )
    def current_behavior__bracket__master_delete(self):
        bid = self.setup_bracket("master", role="admin")
        before = self.context.bracket_snapshot()
        self.call("DELETE", f"/bracket/{bid}", 403, role="admin")
        self.call("POST", "/bracket/create", 409, role="admin", payload={})
        self.assertEqual(before, self.context.bracket_snapshot())
        self.call(
            "POST",
            "/bracket/create",
            200,
            role="admin",
            payload={"replace_existing_master": True},
        )

    @behavior(
        "historical brackets",
        "Historical saved/draft detail returns 404 even to owner/admin due current-season filter; historical writes rejected; history routes require auth and read snapshots.",
        question="Should public historical visibility be implemented? Requirement permits public history but does not mandate anonymous routes.",
    )
    def current_behavior__bracket__historical_boundaries(self):
        bid = self.setup_bracket("historical")
        self.context.login("user-b")
        self.context.login("admin")
        for role in ("user-a", "user-b", "admin"):
            self.call("GET", f"/bracket/{bid}", 404, role=role)
        self.save(bid, status=400)
        self.pick(bid, 6, status=403)
        self.undo(bid, 6, status=403)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="user-a",
            payload={"games": 4},
        )
        self.call("DELETE", f"/bracket/{bid}", 403, role="user-a")
        self.call("GET", "/leaderboard/history", 200)
        self.call("GET", "/leaderboard/history", 200, role="user-a")
        self.call("GET", "/leaderboard/history/2024-25", 404, role="user-a")

    @behavior(
        "edge/errors",
        "Invalid IDs/actions/fields return 400, missing IDs 404, non-object save/prediction/game payloads 500, missing auth 401.",
        question="Approve edge-error status and payload contract?",
    )
    def current_behavior__bracket__edge_errors(self):
        bid = self.setup_bracket()
        m = self.at(bid, 6)
        self.call("GET", "/bracket/invalid", 400, role="user-a")
        self.call("GET", f"/bracket/{identity('missing-bracket')}", 404, role="user-a")
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{identity('missing-match')}",
            404,
            role="user-a",
            payload={"action": "undo"},
        )
        self.call(
            "PATCH", f"/bracket/{bid}/match/invalid", 400, role="user-a", payload={}
        )
        self.save(bid, status=400, payload={})
        self.save(bid, status=500, payload=["synthetic"])
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            500,
            role="user-a",
            payload=["synthetic"],
        )
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            500,
            role="user-a",
            payload=["synthetic"],
        )
        self.call("PATCH", f"/bracket/{bid}/save", 401, payload={})
        self.call("DELETE", f"/bracket/{bid}", 401)

    @behavior(
        "edge/errors",
        "Match from another bracket returns 400; deleted bracket predictions/games denied; drafts omitted from saved listing.",
        question="Approve error precedence and deleted-record visibility?",
    )
    def current_behavior__bracket__wrong_bracket_deleted(self):
        bid = self.setup_bracket()
        other = self.context.install_bracket_scenario("saved", role="user-b")
        m = self.at(other, 6)
        self.call(
            "PATCH",
            f"/bracket/{bid}/match/{m['id']}",
            400,
            role="user-a",
            payload={"action": "undo"},
        )
        self.assertEqual(len(self.call("GET", "/brackets", 200, role="user-a")), 1)
        self.call("DELETE", f"/bracket/{bid}", 200, role="user-a")
        self.pick(bid, 6, status=404)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="user-a",
            payload={"games": 4},
        )


# Preserve NC-01 provenance while explicitly marking approved repair acceptance.
from scripts.nc02a1_acceptance_metadata import mark_acceptance

mark_acceptance(CurrentBracketBehavior)


from scripts.nc02a2_acceptance_metadata import mark_acceptance as mark_nc02a2_acceptance

mark_nc02a2_acceptance(CurrentBracketBehavior)

from scripts.nc02b1_acceptance_metadata import mark_acceptance as mark_nc02b1

mark_nc02b1(CurrentBracketBehavior)

from scripts.nc02b2_acceptance_metadata import mark_acceptance as mark_nc02b2

mark_nc02b2(CurrentBracketBehavior)

from scripts.nc02b3_acceptance_metadata import mark_acceptance as mark_nc02b3

mark_nc02b3(CurrentBracketBehavior)
