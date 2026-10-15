"""Static-only league code/schema/frontend baseline, no application import."""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FRONT = ROOT.parent / "frontend/src"
RESULTS = []


def behavior(group, current, question):
    def wrap(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            approved_requirement=None,
            classification="REQUIREMENT NOT YET REVIEWED",
            future_business_question=question,
            evidence_source="STATIC source/schema/frontend; no browser claim",
        )
        return fn

    return wrap


class CurrentStaticLeagueBehavior(unittest.TestCase):
    def setUp(self):
        self.app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.app)
        self.schema = (ROOT / "db/baseline/000_current_schema.sql").read_text(
            encoding="utf-8"
        )

    def tearDown(self):
        RESULTS.append(dict(getattr(self, self._testMethodName).metadata))

    def fn(self, name):
        return ast.get_source_segment(
            self.app,
            next(
                n
                for n in self.tree.body
                if isinstance(n, ast.FunctionDef) and n.name == name
            ),
        )

    def front(self, name):
        return (FRONT / name).read_text(encoding="utf-8")

    @behavior(
        "schema/edge behavior",
        "DB enforces exact league-name and league/user membership uniqueness; owner FK no cascade, membership FKs cascade; nullable hash, no league/member season or soft-delete fields.",
        "Approve case/uniqueness/owner deletion and season policies?",
    )
    def current_behavior__league__schema(self):
        for x in [
            '"league_members_league_user_unique" UNIQUE ("league_id", "user_id")',
            '"leagues_name_unique" UNIQUE ("name")',
            '"league_members_league_id_fkey"',
            '"league_members_user_id_fkey"',
        ]:
            self.assertIn(x, self.schema)
        segment = self.schema[
            self.schema.index(
                'CREATE TABLE "public"."league_members"'
            ) : self.schema.index('CREATE TABLE "public"."password_resets"')
        ]
        self.assertNotIn("season_id", segment)
        self.assertNotIn("deleted_at", segment)
        self.assertIn('"password_hash" "text",', segment)

    @behavior(
        "membership",
        "Membership writes always use JWT subject; no rename/update/transfer/kick/invite/detail GET/admin-specific league routes. Member GET doubles as detail.",
        "Which owner/admin management features are required?",
    )
    def current_behavior__league__route_absences(self):
        routes = []
        for n in self.tree.body:
            if isinstance(n, ast.FunctionDef):
                for d in n.decorator_list:
                    if (
                        isinstance(d, ast.Call)
                        and isinstance(d.func, ast.Attribute)
                        and d.func.attr == "route"
                        and "/leagues" in str(ast.literal_eval(d.args[0]))
                    ):
                        routes.append(
                            (
                                ast.literal_eval(d.args[0]),
                                next(
                                    ast.literal_eval(k.value)
                                    for k in d.keywords
                                    if k.arg == "methods"
                                ),
                            )
                        )
        self.assertEqual(len(routes), 7)
        self.assertFalse(any("PATCH" in m for _, m in routes))
        self.assertNotIn('data.get("user_id")', self.fn("join_league"))

    @behavior(
        "password behavior",
        "bcrypt hashing/comparison with configured rounds; optional password determines public/private; no join limiter in route; owner auto-membership insertion failure is nonfatal.",
        "Approve password/attempt throttling and partial-creation contract?",
    )
    def current_behavior__league__password_source(self):
        self.assertIn("bcrypt.hashpw", self.fn("create_league"))
        self.assertIn("bcrypt.checkpw", self.fn("join_league"))
        self.assertNotIn("is_rate_limited", self.fn("join_league"))
        self.assertIn("membership = None", self.fn("create_league"))

    @behavior(
        "frontend",
        "Create has public/private selection; private requires local password; API sends name/password, clears form. Join passwords held in local React state, cleared after success.",
        "Approve client validation and password-state lifetime?",
    )
    def current_behavior__league__frontend_forms(self):
        info = self.front("pages/LeagueInfoPage.tsx")
        find = self.front("pages/FindLeaguesPage.tsx")
        for x in [
            "newLeagueVisibility",
            "if (isPrivate && !password)",
            'password: isPrivate ? password : ""',
            'setNewLeaguePassword("")',
        ]:
            self.assertIn(x, info)
        for x in [
            "useState<Record<string, string>>({})",
            'requiresPassword ? password : ""',
            "setPasswords",
        ]:
            self.assertIn(x, find)

    @behavior(
        "frontend",
        "Member UI shows username/role/join date, links saved bracket ID, otherwise No bracket yet; API type includes email, UI member table does not render it.",
        "Approve member presentation and not-submitted wording?",
    )
    def current_behavior__league__frontend_members(self):
        info = self.front("pages/LeagueInfoPage.tsx")
        api = self.front("api/leagues.ts")
        self.assertIn("email: string | null;", api)
        self.assertIn("navigate(`/bracket/${m.bracket_id}`)", info)
        self.assertIn("m.has_bracket && m.bracket_id", info)
        self.assertIn('"No bracket yet"', info)
        self.assertNotIn("m.email", info)

    @behavior(
        "league leaderboard",
        "LeaderboardPage fetches global leaderboard then filters rows by IDs from member endpoint; points/full-hits/saved-time ordering and ties are presentation only here.",
        "Approve membership enforcement placement and league tie/display contract?",
    )
    def current_behavior__league__frontend_leaderboard(self):
        source = self.front("pages/LeaderboardPage.tsx")
        self.assertIn(
            "rows.filter((r) => selectedLeagueMemberIds.includes(r.user_id))", source
        )
        self.assertIn("getLeagueMembers(leagueId)", source)
        self.assertIn('request.args.get("league_id")', self.fn("leaderboard"))
        for x in ["total_points", "full_hits", "saved_at", "rows_out.sort"]:
            self.assertIn(x, self.fn("leaderboard"))

    @behavior(
        "historical/cross-season behavior",
        "No league history endpoint or season columns; LeagueStatsPage passes optional season_code and league_id to champion-picks; current memberships gate explicit past-season stats.",
        "Approve historical league privacy scope versus permitted public history?",
    )
    def current_behavior__league__history_source(self):
        source = self.front("pages/LeagueStatsPage.tsx")
        self.assertIn('params.set("league_id", leagueId)', source)
        self.assertIn("season_code", source)
        self.assertIn(
            'season_code = request.args.get("season_code")',
            self.fn("champion_pick_stats"),
        )

    @behavior(
        "owner powers",
        "UI offers owner deletion and non-owner leave confirmations; no member removal/ownership-transfer/password-change UI. Loading/error states and protected frontend routes are client presentation.",
        "Approve owner-leave/delete and missing management features?",
    )
    def current_behavior__league__frontend_owner(self):
        source = self.front("pages/LeagueInfoPage.tsx")
        for x in [
            "handleDeleteLeague",
            "handleLeaveLeague",
            "confirmDeleteOpen",
            "confirmLeaveOpen",
            "loadingMembers",
            "membersError",
        ]:
            self.assertIn(x, source)
        self.assertIn("owner_user_id", self.fn("delete_league"))

    @behavior(
        "schema/edge behavior",
        "Leave exception handler returns 200 empty-members fallback; create/join are separate writes with no transaction/RPC or encoded numeric league limit.",
        "Approve failure category, atomicity and limits?",
    )
    def current_behavior__league__failure_paths(self):
        self.assertIn("Fail-open", self.fn("leave_league"))
        self.assertIn("members", self.fn("leave_league"))
        for name in ["create_league", "join_league", "leave_league", "delete_league"]:
            self.assertNotIn(".rpc(", self.fn(name))


# Preserve NC-01 provenance while explicitly marking approved repair acceptance.
from scripts.nc02a1_acceptance_metadata import mark_acceptance

mark_acceptance(CurrentStaticLeagueBehavior)


from scripts.nc02a2_acceptance_metadata import mark_acceptance as mark_nc02a2_acceptance

mark_nc02a2_acceptance(CurrentStaticLeagueBehavior)
