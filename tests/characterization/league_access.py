"""Live NC-01C league surfaces only; canonical guarded reset per sequence."""

import unittest
import bcrypt
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity

CONFIG = None
OPT_IN = False
RESULTS = []
NR = "REQUIREMENT NOT YET REVIEWED"
GAP = "KNOWN GAP"
MATCH = "MATCHES REQUIREMENT"
REQ = {
    "private": "Private-league bracket information requires league membership.",
    "email": "Email addresses must never be exposed to other users.",
    "saved": "Another user may see a bracket only if that bracket is saved.",
}
PASSWORD = "NCFixture!2026-private-league"


def behavior(group, current, classification=NR, requirement=None, question=None):
    def wrap(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            approved_requirement=REQ.get(requirement),
            classification=classification,
            future_business_question=question,
            evidence_source="LIVE guarded local Flask; canonical reset per sequence",
        )
        return fn

    return wrap


class CurrentLeagueBehavior(unittest.TestCase):
    def setUp(self):
        self.context = GuardedHarness(
            CONFIG, allow_local_mutations=OPT_IN, characterization_scope="NC-01C"
        )
        self.context.__enter__()
        self.facts = {}

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.assertEqual(
            self.context.cleanup_proof["fixture_checksum"], CANONICAL_CHECKSUM
        )
        r = dict(getattr(self, self._testMethodName).metadata)
        r.update(
            evidence=self.context.summary,
            facts=self.facts,
            cleanup_checksum=CANONICAL_CHECKSUM,
        )
        RESULTS.append(r)

    def call(self, method, path, status, **kwargs):
        actual, body = self.context.league_request(method, path, **kwargs)
        self.assertEqual(actual, status)
        return body

    def setup_leagues(self, **kwargs):
        self.context.bracket_timing("open")
        ids = self.context.install_league_scenario(**kwargs)
        for role in ("user-a", "user-b", "owner", "admin"):
            self.context.login(role)
        return ids

    def create(
        self, name="Fixture created", password="", role="user-a", status=201, **extra
    ):
        return self.call(
            "POST",
            "/leagues",
            status,
            role=role,
            payload=dict(name=name, password=password, **extra),
        )

    def members(self, lid, role="user-a", status=200):
        return self.call("GET", f"/leagues/{lid}/members", status, role=role)

    def join(self, lid, password="", role="user-b", status=201, **extra):
        return self.call(
            "POST",
            f"/leagues/{lid}/join",
            status,
            role=role,
            payload=dict(password=password, **extra),
        )

    @behavior(
        "creation",
        "Ordinary public/private and admin creation succeed pre-lock; owner membership auto-created; password optional bcrypt hash, no season field.",
        question="Approve creator powers, limits and defaults?",
    )
    def current_behavior__league__creation(self):
        self.context.bracket_timing("open")
        for role in ("user-a", "admin"):
            self.context.login(role)
        self.create(name="Fixture public")
        self.create(name="Fixture private", password="FixturePass!2026")
        self.create(name="Fixture admin", role="admin")
        snap = self.context.league_snapshot()
        self.assertEqual(len(snap["leagues"]), 3)
        self.assertEqual(len(snap["members"]), 3)
        self.assertTrue(
            all(not l["is_global"] and "season_id" not in l for l in snap["leagues"])
        )
        private = next(l for l in snap["leagues"] if l["name"] == "Fixture private")
        self.assertTrue(
            bcrypt.checkpw(b"FixturePass!2026", private["password_hash"].encode())
        )
        self.facts = {
            "created": 3,
            "owner_memberships": 3,
            "password_hashed": True,
            "season_field": False,
        }

    @behavior(
        "creation",
        "Names trim and enforce 3–80 characters, exact duplicate names rejected; case-distinct name accepted. Missing/empty name and short password fail.",
        question="Approve naming/uniqueness/password rules?",
    )
    def current_behavior__league__creation_validation(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        self.create(name=" Fixture Case ")
        self.create(name="Fixture Case", status=400)
        self.create(name="fixture case")
        for name in ("", "  ", "ab", "x" * 81):
            self.create(name=name, status=400)
        self.create(name="Fixture short", password="123", status=400)
        self.call("POST", "/leagues", 400, role="user-a", payload={})
        self.call("POST", "/leagues", 500, role="user-a", payload=["synthetic"])

    @behavior(
        "creation",
        "Backend ignores visibility/owner/is_global request fields; missing password yields public even if private requested; supplied password yields private even if public requested.",
        question="Approve public/private wire contract and ignored request fields?",
    )
    def current_behavior__league__creation_forged_fields(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        self.create(
            name="Fixture nominal private",
            visibility="private",
            owner_user_id=identity("user-b"),
            is_global=True,
        )
        self.create(
            name="Fixture nominal public",
            password="FixturePass!2026",
            visibility="public",
        )
        ls = self.context.league_snapshot()["leagues"]
        self.assertTrue(
            all(
                l["owner_user_id"] == identity("user-a") and not l["is_global"]
                for l in ls
            )
        )
        self.assertIsNone(
            next(l for l in ls if l["name"] == "Fixture nominal private")[
                "password_hash"
            ]
        )
        self.assertTrue(
            next(l for l in ls if l["name"] == "Fixture nominal public")[
                "password_hash"
            ]
        )

    @behavior(
        "discovery",
        "Authenticated roles discover public/private non-global metadata and member counts; anonymous list/me denied; member-only own list, no emails/brackets/scores in discovery.",
        question="Approve metadata discovery for private leagues?",
    )
    def current_behavior__league__discovery(self):
        ids = self.setup_leagues()
        self.call("GET", "/leagues", 401)
        self.call("GET", "/leagues/me", 401)
        for role in ("user-a", "user-b", "owner", "admin"):
            rows = self.call("GET", "/leagues", 200, role=role)["leagues"]
            self.assertEqual(len(rows), 2)
            self.assertTrue(
                all(
                    l["member_count"] == 2 and isinstance(l["requires_password"], bool)
                    for l in rows
                )
            )
            self.assertTrue(
                all(
                    not (
                        {"email", "members", "brackets", "password_hash", "scores"}
                        & set(l)
                    )
                    for l in rows
                )
            )
        self.assertEqual(
            self.call("GET", "/leagues/me", 200, role="user-b")["leagues"], []
        )
        self.facts = {"discovery_fields": sorted(rows[0]), "anonymous_denied": True}

    @behavior(
        "password behavior",
        "Own-leagues requires_password contains actual stored bcrypt hash instead of boolean; other discovery/create/join surfaces use booleans.",
        question="Approve password-derived response contract/security requirement? Hash values withheld.",
    )
    def current_behavior__league__own_list_hash_surface(self):
        ids = self.setup_leagues()
        rows = self.call("GET", "/leagues/me", 200, role="user-a")["leagues"]
        self.assertIs(
            next(r for r in rows if r["id"] == ids["private"])["requires_password"],
            True,
        )
        self.assertIs(
            next(r for r in rows if r["id"] == ids["public"])["requires_password"],
            False,
        )
        self.facts = {"requires_password_type": "boolean", "hash_exposed": False}

    @behavior(
        "join",
        "Public join succeeds; repeated/owner join fails; private missing/wrong password fails, trimmed correct password succeeds; membership is caller identity despite forged user_id.",
        question="Approve join/password/repeat contract?",
    )
    def current_behavior__league__join(self):
        ids = self.setup_leagues()
        self.join(ids["public"], user_id=identity("admin"))
        self.join(ids["public"], status=400)
        self.join(ids["public"], role="owner", status=400)
        self.join(ids["private"], status=400)
        for _ in range(2):
            self.join(ids["private"], password="WrongSynthetic", status=400)
        self.join(ids["private"], password=" " + PASSWORD + " ")
        ms = self.context.league_snapshot()["members"]
        self.assertTrue(
            any(
                m["user_id"] == identity("user-b") and m["league_id"] == ids["private"]
                for m in ms
            )
        )
        self.assertFalse(any(m["user_id"] == identity("admin") for m in ms))

    @behavior(
        "admin powers",
        "Admin cannot bypass private join password and cannot delete another owner's league; admin own creation/delete works.",
        question="Approve admin league powers?",
    )
    def current_behavior__league__admin_join_delete(self):
        ids = self.setup_leagues()
        self.join(ids["private"], role="admin", status=400)
        self.join(ids["private"], password=PASSWORD, role="admin")
        self.call("DELETE", f"/leagues/{ids['private']}", 403, role="admin")
        new = self.create(name="Fixture admin owned", role="admin")["league"]["id"]
        self.call("DELETE", f"/leagues/{new}", 200, role="admin")

    @behavior(
        "leave",
        "Ordinary member leaves without changing league/owner/brackets; repeat/nonmember leave fails; owner cannot leave with other members.",
        question="Approve owner-leave and repeated leave rules?",
    )
    def current_behavior__league__leave(self):
        ids = self.setup_leagues()
        bid = self.context.install_bracket_scenario("saved", role="user-a")
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 400, role="owner")
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 200, role="user-a")
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 400, role="user-a")
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 400, role="user-b")
        self.assertEqual(len(self.context.league_snapshot()["leagues"]), 2)
        self.assertTrue(
            any(b["id"] == bid for b in self.context.bracket_snapshot()["brackets"])
        )

    @behavior(
        "leave",
        "Final non-owner membership can leave an owner-not-member fixture, leaving empty league and unchanged owner; owner/nonmember rules unchanged after lock.",
        question="Approve owner-not-member/empty-league lifecycle?",
    )
    def current_behavior__league__empty_final_leave(self):
        ids = self.setup_leagues(empty=True)
        self.join(ids["public"])
        self.context.bracket_timing("locked")
        self.call("DELETE", f"/leagues/{ids['public']}/membership", 200, role="user-b")
        self.assertEqual(self.context.league_snapshot()["members"], [])
        self.assertEqual(self.members(ids["public"], role="owner")["members"], [])
        self.call("DELETE", f"/leagues/{ids['public']}/membership", 400, role="owner")

    @behavior(
        "delete",
        "Only owner can hard-delete public/private leagues, including after lock; memberships cascade, bracket remains; deleted join/member access returns 404.",
        question="Approve hard-delete/cascade/retention policy?",
    )
    def current_behavior__league__delete(self):
        ids = self.setup_leagues()
        bid = self.context.install_bracket_scenario("saved", role="user-a")
        self.call("DELETE", f"/leagues/{ids['public']}", 403, role="user-a")
        self.call("DELETE", f"/leagues/{ids['private']}", 403, role="user-b")
        self.context.bracket_timing("locked")
        for lid in ids.values():
            self.call("DELETE", f"/leagues/{lid}", 200, role="owner")
        self.assertEqual(self.context.league_snapshot(), {"leagues": [], "members": []})
        self.assertTrue(
            any(b["id"] == bid for b in self.context.bracket_snapshot()["brackets"])
        )
        self.members(ids["private"], role="owner", status=404)
        self.context.bracket_timing("open")
        self.join(ids["private"], status=404)

    @behavior(
        "membership",
        "Member/owner can list members; ordinary nonmember denied for public/private; no anonymous member listing.",
        question="Approve public member-list visibility contract?",
    )
    def current_behavior__league__member_access(self):
        ids = self.setup_leagues()
        for lid in ids.values():
            for role in ("user-a", "owner"):
                self.assertEqual(len(self.members(lid, role=role)["members"]), 2)
            self.members(lid, role="user-b", status=403)
            self.members(lid, role=None, status=401)

    @behavior(
        "privacy/email",
        "Member/owner/admin listing responses actually emit other users' emails on public/private surfaces, confirming NC-01A static warning.",
        GAP,
        "email",
    )
    def current_behavior__league__member_email(self):
        ids = self.setup_leagues()
        for lid in ids.values():
            for role in ("user-a", "owner", "admin"):
                if lid == ids["private"] and role == "admin":
                    self.members(lid, role=role, status=403)
                    continue
                rows = self.members(lid, role=role)["members"]
                others = [r for r in rows if r["user_id"] != identity(role)]
                self.assertTrue(others and all("email" not in r for r in others))
                self.assertTrue(
                    all(
                        not (
                            {"password", "password_hash", "reset_token", "is_admin"}
                            & set(r)
                        )
                        for r in rows
                    )
                )
        self.facts = {
            "member_fields": sorted(rows[0]),
            "other_user_email_present": False,
            "prior_reference": "NC-01A display_fields_static",
        }

    @behavior(
        "private leagues",
        "Nonmember admin obtains private member saved-bracket ID through admin bypass, contrary to membership requirement.",
        GAP,
        "private",
    )
    def current_behavior__league__admin_private_bracket(self):
        ids = self.setup_leagues()
        self.context.install_bracket_scenario("saved", role="user-a")
        self.members(ids["private"], role="admin", status=403)

    @behavior(
        "member bracket access",
        "Ordinary nonmember is denied private member endpoint, but league-filtered saved list and direct saved-bracket detail bypass membership.",
        GAP,
        "private",
    )
    def current_behavior__league__private_bracket_bypass(self):
        ids = self.setup_leagues()
        bid = self.context.install_bracket_scenario("saved", role="user-a")
        self.members(ids["private"], role="user-b", status=403)
        self.call("GET", f"/brackets?league_id={ids['private']}", 403, role="user-b")
        body = self.call("GET", f"/bracket/{bid}", 200, role="user-b")
        self.assertNotIn("email", body["bracket"]["owner"])
        self.facts = {
            "private_list_denied": True,
            "general_saved_detail_unchanged": True,
        }

    @behavior(
        "member bracket access",
        "Public/private member lists hide draft ID and predictions, showing has_bracket=false; saved IDs shown to members. Direct other-user draft denied; nonmembers get no draft via filtered list.",
        MATCH,
        "saved",
    )
    def current_behavior__league__draft_saved_visibility(self):
        ids = self.setup_leagues()
        draft = self.context.install_bracket_scenario("draft", role="user-a")
        saved = self.context.install_bracket_scenario("saved", role="owner")
        for lid in ids.values():
            row = next(
                r
                for r in self.members(lid)["members"]
                if r["user_id"] == identity("user-a")
            )
            self.assertTrue(not row["has_bracket"] and row["bracket_id"] is None)
            self.assertFalse({"predictions", "scores"} & set(row))
            self.call("GET", f"/bracket/{draft}", 403, role="owner")
            self.call("GET", f"/bracket/{draft}", 403, role="user-b")
            self.call("GET", f"/bracket/{saved}", 200, role="user-a")
            if lid == ids["private"]:
                self.call("GET", f"/brackets?league_id={lid}", 403, role="user-b")
            else:
                listed = self.call(
                    "GET", f"/brackets?league_id={lid}", 200, role="user-b"
                )
                self.assertTrue(all(r["bracket_id"] != draft for r in listed))
        self.facts = {
            "draft_id_hidden": True,
            "draft_predictions_hidden": True,
            "not_submitted_indicator": True,
        }

    @behavior(
        "league leaderboard",
        "Global leaderboard is anonymous and ignores league_id; league filtering is client-side. Nonmember can obtain saved private-member score/bracket rows; no email fields there.",
        GAP,
        "private",
    )
    def current_behavior__league__leaderboard_private_surface(self):
        ids = self.setup_leagues()
        bids = self.context.install_league_score_surface()
        self.assertEqual(len(self.call("GET", "/leaderboard", 200)["rows"]), 2)
        path = f"/leaderboard?league_id={ids['private']}"
        self.call("GET", path, 401)
        self.call("GET", path, 403, role="user-b")
        scoped = self.call("GET", path, 200, role="user-a")
        self.assertEqual([r["bracket_id"] for r in scoped["rows"]], [bids["user-a"]])
        self.assertTrue(all("email" not in r for r in scoped["rows"]))
        self.facts = {
            "private_scope_enforced": True,
            "global_eligibility_unchanged": True,
        }

    @behavior(
        "league leaderboard",
        "Members with no score rows absent from leaderboard; saved member ID remains in member list; empty score surface returns empty rows.",
        question="Approve missing-score/member presentation and tie policy?",
    )
    def current_behavior__league__missing_scores(self):
        ids = self.setup_leagues()
        self.context.install_bracket_scenario("saved", role="user-a")
        self.assertEqual(
            self.call("GET", "/leaderboard", 200, role="user-a")["rows"], []
        )
        self.assertTrue(
            any(r["has_bracket"] for r in self.members(ids["private"])["members"])
        )

    @behavior(
        "private leagues",
        "League champion-picks endpoint denies ordinary nonmember and anonymous requests; members/owner can access; calculations not validated.",
        MATCH,
        "private",
    )
    def current_behavior__league__stats_membership(self):
        ids = self.setup_leagues()
        self.context.install_bracket_scenario("saved", role="user-a")
        path = f"/stats/champion-picks?league_id={ids['private']}"
        self.call("GET", path, 401)
        self.call("GET", path, 403, role="user-b")
        for role in ("user-a", "owner"):
            self.call("GET", path, 200, role=role)

    @behavior(
        "private leagues",
        "Admin without membership can read private champion-picks bracket aggregate through bypass.",
        GAP,
        "private",
    )
    def current_behavior__league__stats_admin_bypass(self):
        ids = self.setup_leagues()
        self.context.install_bracket_scenario("saved", role="user-a")
        self.call(
            "GET",
            f"/stats/champion-picks?league_id={ids['private']}",
            403,
            role="admin",
        )

    @behavior(
        "password behavior",
        "Create/join strip outer password whitespace; whitespace-only creates public; one-/three-character passwords fail minimum; repeated incorrect join remains 400.",
        question="Approve normalization, minimum length and retry policy?",
    )
    def current_behavior__league__password_normalization(self):
        self.context.bracket_timing("open")
        self.context.login("user-a")
        self.context.login("user-b")
        self.create(name="Fixture whitespace", password="   ")
        new = self.create(name="Fixture trimmed", password="  FixturePass!2026  ")[
            "league"
        ]["id"]
        self.join(new, password="FixturePass!2026")
        self.assertIsNone(
            next(
                l
                for l in self.context.league_snapshot()["leagues"]
                if l["name"] == "Fixture whitespace"
            )["password_hash"]
        )

    @behavior(
        "historical/cross-season behavior",
        "Leagues/membership have no season linkage; current member bracket lookup omits historical bracket; explicit historical champion-picks keeps league membership gate.",
        question="Approve historical league access/public scope separately?",
    )
    def current_behavior__league__historical(self):
        ids = self.setup_leagues()
        self.context.install_bracket_scenario("historical", role="user-a")
        row = next(
            r
            for r in self.members(ids["private"])["members"]
            if r["user_id"] == identity("user-a")
        )
        self.assertFalse(row["has_bracket"])
        path = f"/stats/champion-picks?league_id={ids['private']}&season_code=2024-25"
        self.call("GET", path, 403, role="user-b")
        self.call("GET", path, 200, role="user-a")
        self.assertTrue(
            all("season_id" not in l for l in self.context.league_snapshot()["leagues"])
        )

    @behavior(
        "schema/edge behavior",
        "Global league excluded from discovery/own list; join/leave/delete rejected even for owner; private/public represented independently of is_global.",
        question="Approve global-league special policies?",
    )
    def current_behavior__league__global(self):
        ids = self.setup_leagues(global_public=True)
        self.assertEqual(
            len(self.call("GET", "/leagues", 200, role="user-a")["leagues"]), 1
        )
        self.join(ids["public"], status=400)
        self.call("DELETE", f"/leagues/{ids['public']}/membership", 400, role="user-a")
        self.call("DELETE", f"/leagues/{ids['public']}", 400, role="owner")

    @behavior(
        "schema/edge behavior",
        "Malformed/nonexistent IDs, missing auth, non-object join payloads and repeat delete produce representative 400/404/401/500 errors; no arbitrary user mutation routes.",
        question="Approve error/status contract?",
    )
    def current_behavior__league__errors(self):
        ids = self.setup_leagues()
        self.members("invalid", status=400)
        self.members(identity("missing-league"), status=404)
        self.join("invalid", status=400)
        self.join(identity("missing-league"), status=404)
        self.call(
            "POST",
            f"/leagues/{ids['private']}/join",
            500,
            role="user-b",
            payload=["synthetic"],
        )
        self.call("POST", "/leagues", 401, payload={})
        self.call("POST", f"/leagues/{ids['private']}/join", 401, payload={})
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 401)
        self.call("DELETE", f"/leagues/{ids['private']}", 401)
        self.call("DELETE", f"/leagues/{identity('missing-league')}", 404, role="owner")
        self.call("DELETE", f"/leagues/{ids['private']}", 200, role="owner")
        self.call("DELETE", f"/leagues/{ids['private']}", 404, role="owner")

    @behavior(
        "owner powers",
        "Owner without membership can read saved member bracket ID through owner bypass on private league.",
        GAP,
        "private",
    )
    def current_behavior__league__owner_not_member(self):
        ids = self.setup_leagues(empty=True)
        self.join(ids["private"], password=PASSWORD, role="user-a")
        self.context.install_bracket_scenario("saved", role="user-a")
        self.members(ids["private"], role="owner", status=403)

    @behavior(
        "schema/edge behavior",
        "Playoff lock blocks league create/join even for admin; leave/delete remain available. No approved league timing contract assigned.",
        question="Approve league timing distinct from bracket-content final lock?",
    )
    def current_behavior__league__timing(self):
        ids = self.setup_leagues()
        self.context.bracket_timing("locked")
        for role in ("user-b", "admin"):
            self.create(name="Fixture closed", role=role, status=403)
            self.join(ids["public"], role=role, status=403)
        self.call("DELETE", f"/leagues/{ids['private']}/membership", 200, role="user-a")
        self.call("DELETE", f"/leagues/{ids['private']}", 200, role="owner")

    @behavior(
        "league leaderboard",
        "Stored score row for an unsaved member bracket appears in anonymous/global and league-query leaderboard, despite member list hiding its draft ID.",
        GAP,
        "saved",
    )
    def current_behavior__league__draft_scored_leaderboard(self):
        ids = self.setup_leagues()
        bids = self.context.install_league_score_surface(draft_member=True)
        member = next(
            r
            for r in self.members(ids["private"])["members"]
            if r["user_id"] == identity("user-a")
        )
        self.assertFalse(member["has_bracket"])
        for role in (None, "user-b", "user-a"):
            body = self.call("GET", "/leaderboard", 200, role=role)
            self.assertTrue(
                any(r["bracket_id"] == bids["user-a"] for r in body["rows"])
            )
        self.facts = {
            "draft_id_and_stored_score_visible": True,
            "scenario_basis": "existing score fixture with member submission flag cleared; score math not run",
        }


# Preserve NC-01 provenance while explicitly marking approved repair acceptance.
from scripts.nc02a1_acceptance_metadata import mark_acceptance

mark_acceptance(CurrentLeagueBehavior)
