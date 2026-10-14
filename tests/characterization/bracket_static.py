"""Static-only bracket source/schema/frontend characterization, no app import."""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FRONT = ROOT.parent / "frontend/src"
RESULTS = []


def behavior(
    group,
    current,
    classification="REQUIREMENT NOT YET REVIEWED",
    requirement=None,
    question=None,
):
    def wrap(fn):
        fn.metadata = dict(
            scenario=fn.__name__,
            group=group,
            current_behavior=current,
            approved_requirement=requirement,
            classification=classification,
            future_business_question=question,
            evidence_source="STATIC source inspection; no browser/runtime claim",
        )
        return fn

    return wrap


class CurrentStaticBracketBehavior(unittest.TestCase):
    def setUp(self):
        self.app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.schema = (ROOT / "db/baseline/000_current_schema.sql").read_text(
            encoding="utf-8"
        )
        self.front = (FRONT / "pages/BracketPage.tsx").read_text(encoding="utf-8")
        self.tree = ast.parse(self.app)

    def tearDown(self):
        RESULTS.append(dict(getattr(self, self._testMethodName).metadata))

    def fn(self, name):
        return ast.get_source_segment(
            self.app,
            next(
                n
                for n in self.tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name
            ),
        )

    @behavior(
        "frontend behavior",
        "Ordinary owner undo is suppressed by admin+master-only UI handler, although backend accepts pre-lock owner undo.",
        "KNOWN GAP",
        "Ordinary bracket owners may undo predictions before lock.",
    )
    def current_behavior__bracket__frontend_undo(self):
        self.assertIn("if (!(isAdmin && isMaster)) return;", self.front)
        self.assertIn('action: "undo"', self.front)

    @behavior(
        "frontend behavior",
        "Winner and game controls check ownership/admin-master and readiness, but not playoff lock; save alone checks savingLockedForUser.",
        "KNOWN GAP",
        "At playoff start ordinary users may not select/change winners, undo, change series counts or save/resubmit.",
    )
    def current_behavior__bracket__frontend_lock(self):
        for start, end in [
            ("const handleSetWinner", "const handleUndo"),
            ("const handleSelectGames", "const handleExport"),
        ]:
            begin = self.front.index(start)
            stop = self.front.find(end, begin + 1)
            part = self.front[begin : stop if stop != -1 else begin + 1800]
            self.assertNotIn("savingLockedForUser", part)
        self.assertIn(
            "canEdit && allDecided && !!trimmedName && !saving && !savingLockedForUser",
            self.front,
        )

    @behavior(
        "frontend behavior",
        "Frontend allows owner editing and admin-master editing; game options are 4–7, play-in one; pending games local until winner; edits reload backend state.",
        question="Approve UI count range, optimistic state and admin-owner overlap?",
    )
    def current_behavior__bracket__frontend_controls(self):
        for value in [
            "const canEdit = isOwner || (isAdmin && isMaster);",
            "[4, 5, 6, 7]",
            "setPendingGames",
            'action: "set_winner"',
            "await loadBracket({ silent: true })",
        ]:
            self.assertIn(value, self.front)

    @behavior(
        "frontend behavior",
        "Dashboard uses brackets/me and saved list, creates/deletes via backend; actual createDisabled lets admins bypass creation timing despite stale comment.",
        "MATCHES REQUIREMENT",
        "Admin bracket creation may bypass the normal creation window.",
    )
    def current_behavior__bracket__frontend_creation(self):
        source = (FRONT / "pages/DashboardPage.tsx").read_text(encoding="utf-8")
        for value in [
            'get("/brackets/me")',
            'post("/bracket/create", {})',
            "del(`/bracket/${deleteTargetId}`)",
            "(!isAdmin && (!creationOpen || playoffsLocked))",
        ]:
            self.assertIn(value, source)

    @behavior(
        "schema/timing quirks",
        "Two active-user unique indexes include a global user predicate; two master indexes differ on deleted_at; season/master foreign keys form cyclic linkage. No fixes.",
        question="Approve cross-season uniqueness and soft-deleted master constraints?",
    )
    def current_behavior__bracket__schema_constraints(self):
        for value in [
            '"unique_active_bracket_per_user"',
            '"uniq_active_bracket_per_user_per_season"',
            '"uq_master_per_season"',
            '"ux_brackets_one_master_per_season"',
            '"seasons_master_bracket_fk"',
            '"brackets_season_id_fkey"',
        ]:
            self.assertIn(value, self.schema)

    @behavior(
        "schema/timing quirks",
        "Match season IDs copied from bracket by trigger; soft-delete trigger demotes master and clears pointer. Flask graph updates are individual requests, not atomic RPC calls.",
        question="Approve partial-write/transaction contract and trigger behavior?",
    )
    def current_behavior__bracket__triggers_rpc(self):
        for value in [
            '"trg_matches_set_season"',
            '"trg_fix_season_master_on_bracket_soft_delete"',
            '"set_master_bracket"',
            '"set_winner_atomic"',
            '"undo_prediction_atomic"',
        ]:
            self.assertIn(value, self.schema)
        for name in [
            "create_bracket_for_user",
            "update_match",
            "save_bracket",
            "delete_bracket",
        ]:
            self.assertNotIn(".rpc(", self.fn(name))

    @behavior(
        "state/lifecycle",
        "is_done/saved_at encode submission; deleted_at/deleted_by encode soft deletion; is_master plus season pointer derive master. Historical/locked are contextual, not enum states.",
        question="Approve formal state transitions and derived-master precedence?",
    )
    def current_behavior__bracket__state_model(self):
        for value in [
            '"is_done" boolean DEFAULT false',
            '"saved_at" timestamp with time zone',
            '"deleted_at" timestamp with time zone',
            '"is_master" boolean DEFAULT false',
        ]:
            self.assertIn(value, self.schema)
        self.assertIn("derived_is_master", self.fn("get_bracket_by_id"))

    @behavior(
        "schema/timing quirks",
        "DB season timestamps resolve UTC globals at startup; env fallbacks, missing lock defaults 2099; lock is now>=start, creation requires end<=now<start. No shared blanket request lock.",
        question="Approve date defaults, refresh and timezone contract?",
    )
    def current_behavior__bracket__timing(self):
        self.assertIn("now_utc() >= PLAYOFFS_START_UTC", self.fn("playoffs_locked"))
        self.assertIn("now < REGULAR_SEASON_END_UTC", self.fn("bracket_creation_open"))
        self.assertIn("datetime(2099, 1, 1", self.fn("_resolve_season_globals"))
        self.assertNotIn("playoffs_locked", self.fn("_season_bootstrap"))
        self.assertNotIn("playoffs_locked", self.fn("update_match"))
        self.assertNotIn("playoffs_locked", self.fn("set_match_games"))
        self.assertNotIn("playoffs_locked", self.fn("delete_bracket"))

    @behavior(
        "save/resubmit",
        "Save requires name and predictions/counts only for matches with both teams; empty or missing-pair matches skipped. No exact 21-match completion requirement.",
        question="Approve completion validation for absent/unpopulated matches?",
    )
    def current_behavior__bracket__save_completeness_static(self):
        f = self.fn("save_bracket")
        self.assertIn('if not m.get("team_a") or not m.get("team_b"):', f)
        self.assertNotIn("len(matches)", f)

    @behavior(
        "historical brackets",
        "No archive/public bracket-display endpoint; current bracket routes filter current season; PastSeasonsPage reads leaderboard snapshot routes, not raw historical brackets.",
        question="Approve public history and historical bracket access scope?",
    )
    def current_behavior__bracket__history_source(self):
        source = (FRONT / "pages/PastSeasonsPage.tsx").read_text(encoding="utf-8")
        self.assertIn("/leaderboard/history", source)
        self.assertIn(
            "leaderboard_history_snapshots", self.fn("leaderboard_history_index")
        )
        self.assertIn("leaderboard_history_rows", self.fn("leaderboard_history_season"))
        self.assertIn("CURRENT_SEASON_ID", self.fn("get_bracket_by_id"))
