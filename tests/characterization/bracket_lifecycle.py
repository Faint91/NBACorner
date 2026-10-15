"""Guarded B10–B15 acceptance; fixed enrolled local synthetic fixtures only."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bracket_validity import BracketValidityAcceptance
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []


class BracketLifecycleAcceptance(BracketValidityAcceptance):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-02B3"
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
                "phase": "NC-02B3",
                "scenario": self._testMethodName,
                "requirements": ["B10", "B11", "B12", "B13", "B14", "B15"],
                "facts": self.facts,
                "evidence": self.context.summary,
                "cleanup_checksum": CANONICAL_CHECKSUM,
            }
        )

    def create(self, role="user-a", status=200, replace=False):
        return self.call(
            "POST",
            "/bracket/create",
            status,
            role=role,
            payload={"replace_existing_master": True} if replace else {},
        )

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
            for item in value.values():
                self.safe(item)
        elif isinstance(value, list):
            for item in value:
                self.safe(item)

    def test_b3_cross_season_and_same_season_uniqueness(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        historical = self.context.install_lifecycle_history("submitted")
        current = self.create()["bracket"]["id"]
        self.create(status=400)
        self.assertIsNone(self.state(historical)[0]["deleted_at"])
        self.assertNotEqual(current, historical)
        self.context.login("user-b")
        self.create(role="user-b")
        self.assertEqual(len(self.context.bracket_snapshot()["brackets"]), 3)
        self.facts.update(
            cross_season_allowed=True,
            same_season_duplicate_denied=True,
            different_users_allowed=True,
        )

    def test_b3_predeadline_delete_recreate_and_closed_window(self):
        bid = self.setup_bracket("saved")
        self.call("DELETE", f"/bracket/{bid}", 200, role="user-a")
        self.assertEqual(len(self.state(bid)[1]), 21)
        new = self.create()["bracket"]["id"]
        self.context.bracket_timing("early")
        self.call("DELETE", f"/bracket/{new}", 200, role="user-a")
        self.create(status=403)
        self.facts.update(
            soft_delete_retains_matches=True,
            open_recreate=True,
            early_recreate_denied=True,
        )

    def test_b3_submitted_delete_at_and_after_deadline_preserves_all_data(self):
        self.context.bracket_timing("open")
        for role in ["user-a", "user-b", "owner", "admin"]:
            self.context.login(role)
        ids = self.context.install_competitive_scenario()
        bid = ids["a"]
        self.fill(bid)
        self.save(bid)
        for boundary in ["at", "after"]:
            self.context.bracket_deadline_boundary(boundary)
            before = self.context.competitive_snapshot()
            self.call("DELETE", f"/bracket/{bid}", 403, role="user-a")
            self.assertEqual(before, self.context.competitive_snapshot())
        self.facts.update(
            submitted_delete_denied_at_and_after=True,
            competitive_history_and_rows_preserved=True,
        )

    def test_b3_postlock_draft_delete_and_no_recreation(self):
        bid = self.setup_bracket(timing="locked")
        self.call("DELETE", f"/bracket/{bid}", 200, role="user-a")
        self.assertFalse(self.state(bid)[0]["is_done"])
        self.assertEqual(len(self.state(bid)[1]), 21)
        self.create(status=403)
        self.facts.update(postlock_draft_delete=True, postlock_recreation_denied=True)

    def test_b3_nonowner_and_admin_arbitrary_delete_denied(self):
        bid = self.setup_bracket()
        before = self.state(bid)
        for role in ["user-b", "admin"]:
            self.context.login(role)
            self.call("DELETE", f"/bracket/{bid}", 403, role=role)
        self.assertEqual(before, self.state(bid))
        self.facts.update(
            nonowner_delete_denied=True, admin_arbitrary_delete_denied=True
        )

    def master(self, timing="open"):
        self.context.bracket_timing(timing)
        self.context.login("admin")
        return self.create(role="admin")["bracket"]["id"]

    def test_b3_master_create_explicit_replace_and_delete_protection(self):
        old = self.master("early")
        before = self.context.bracket_snapshot()
        self.create(role="admin", status=409)
        self.call("DELETE", f"/bracket/{old}", 403, role="admin")
        self.assertEqual(before, self.context.bracket_snapshot())
        new = self.create(role="admin", replace=True)["bracket"]["id"]
        self.assertIsNotNone(self.state(old)[0]["deleted_at"])
        self.assertFalse(self.state(old)[0]["is_master"])
        self.assertTrue(self.state(new)[0]["is_master"])
        active = [
            b
            for b in self.context.bracket_snapshot()["brackets"]
            if b["is_master"] and b["deleted_at"] is None
        ]
        self.assertEqual([b["id"] for b in active], [new])
        self.assertEqual(
            next(
                s["master_bracket_id"]
                for s in self.context.bracket_snapshot()["seasons"]
                if s["id"] == identity("current")
            ),
            new,
        )
        self.facts.update(
            explicit_replace=True,
            one_active_master=True,
            old_retired_records_retained=True,
        )

    def test_b3_postlock_master_replace_other_season_preserved(self):
        self.context.bracket_timing("locked")
        self.context.login("admin")
        historical = self.context.install_lifecycle_history("master")
        old = self.create(role="admin")["bracket"]["id"]
        before = self.state(historical)
        new = self.create(role="admin", replace=True)["bracket"]["id"]
        self.assertEqual(before, self.state(historical))
        self.assertNotEqual(new, old)
        self.assertEqual(
            next(
                s["master_bracket_id"]
                for s in self.context.bracket_snapshot()["seasons"]
                if s["id"] == identity("historical")
            ),
            historical,
        )
        self.facts.update(
            postlock_master_replace=True, other_season_master_unchanged=True
        )

    def test_b3_replacement_failure_rolls_back_retirement_pointer_and_graph(self):
        self.master()
        self.assertTrue(self.context.master_failure_rollback_proof())
        self.facts.update(forced_fk_failure=True, whole_replacement_rolled_back=True)

    def test_b3_ordinary_replacement_and_malformed_intent_refused(self):
        self.master()
        self.context.login("user-a")
        before = self.context.bracket_snapshot()
        self.create(replace=True, status=403)
        self.call(
            "POST",
            "/bracket/create",
            400,
            role="admin",
            payload={"replace_existing_master": "true"},
        )
        self.assertEqual(before, self.context.bracket_snapshot())
        self.facts.update(ordinary_replace_denied=True, explicit_boolean_required=True)

    def test_b3_historical_submitted_public_safe_and_immutable(self):
        self.context.bracket_timing("open")
        for role in ["user-a", "user-b", "admin"]:
            self.context.login(role)
        bid = self.context.install_lifecycle_history("submitted")
        before = self.state(bid)
        for role in [None, "user-a", "user-b", "admin"]:
            body = self.call("GET", f"/history/bracket/{bid}", 200, role=role)
            self.safe(body)
            self.assertTrue(body["bracket"]["read_only"])
            self.assertTrue(body["bracket"]["is_historical"])
        self.pick(bid, 6, status=403)
        self.undo(bid, 6, status=403)
        self.save(bid, status=400)
        m = self.at(bid, 6)
        self.call(
            "PATCH",
            f"/bracket/match/{m['id']}/games",
            403,
            role="user-a",
            payload={"games": 4},
        )
        self.call("GET", f"/bracket/{bid}", 404, role="user-a")
        self.assertEqual(before, self.state(bid))
        self.facts.update(
            public_submitted_history=True,
            safe_serialization=True,
            historical_writes_denied=True,
        )

    def test_b3_historical_draft_owner_private_no_public_leak(self):
        self.context.bracket_timing("open")
        for role in ["user-a", "user-b", "admin"]:
            self.context.login(role)
        bid = self.context.install_lifecycle_history("draft")
        self.safe(self.call("GET", f"/history/bracket/{bid}", 200, role="user-a"))
        for role in [None, "user-b", "admin"]:
            self.call("GET", f"/history/bracket/{bid}", 403, role=role)
        self.assertFalse(self.state(bid)[0]["is_done"])
        self.facts.update(
            historical_draft_owner_read=True,
            anonymous_other_admin_denied=True,
            no_autopromotion=True,
        )

    def test_b3_current_ids_not_exposed_through_public_history(self):
        bid = self.setup_bracket("saved")
        self.call("GET", f"/history/bracket/{bid}", 404)
        self.call("GET", f"/history/bracket/{bid}", 404, role="user-a")
        self.call("GET", f"/bracket/{bid}", 401)
        self.call("GET", f"/bracket/{bid}", 200, role="user-a")
        self.facts.update(
            current_auth_contract_preserved=True,
            historical_surface_not_current_bypass=True,
        )
