"""Static scoring/history/frontend inventory; no application import."""

import ast, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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
            evidence_source="STATIC source/schema/frontend; no browser or live job claim",
        )
        return fn

    return wrap


class CurrentStaticScoring(unittest.TestCase):
    def setUp(self):
        self.app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.app)

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

    @behavior(
        "scoring architecture",
        "Master predicted_winner/games keyed conference-round-slot are actual results; caller-supplied master ID need not match season pointer or is_master. Same master/user ID skips score.",
        question="Approve ground-truth identity and missing/replaced master policy?",
    )
    def current_behavior__scoring__master_source(self):
        f = self.fn("recompute_scores")
        self.assertNotIn('.eq("is_master"', f)
        self.assertNotIn('master_bracket_id")', f)
        self.assertIn("len(brs) < 2", self.fn("_compute_score_for_bracket"))

    @behavior(
        "recomputation",
        "Admin trigger selects saved/current/nondeleted brackets, upserts each separately; no automatic scoring on prediction/save; no independent scoring cron/script found.",
        question="Approve recalculation timing and transaction/failure behavior?",
    )
    def current_behavior__scoring__recompute_source(self):
        self.assertIn('.eq("is_done", True)', self.fn("recompute_scores"))
        for n in ["update_match", "save_bracket"]:
            self.assertNotIn("_compute_score", self.fn(n))

    @behavior(
        "league leaderboard",
        "No backend league filter; frontend filters global rows using member IDs. Existing NC-01C private-score exposure, not a newly counted surface.",
        "KNOWN GAP",
        "Private-league bracket information requires membership.",
    )
    def current_behavior__scoring__league_surface(self):
        self.assertIn("require_private_league_membership", self.fn("leaderboard"))
        s = (ROOT.parent / "frontend/src/pages/LeaderboardPage.tsx").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "rows.filter((r) => selectedLeagueMemberIds.includes(r.user_id))", s
        )

    @behavior(
        "historical reads",
        "Three history tables: legacy denormalized internal bracket/user references; structured season snapshots and snapshot rows power current API. Reads latest snapshot per season, no live user join.",
        question="Approve history retention/legacy purpose and duplicate selection?",
    )
    def current_behavior__history__storage(self):
        self.assertIn("leaderboard_history_rows", self.fn("leaderboard_history_season"))
        self.assertNotIn('.table("users")', self.fn("leaderboard_history_season"))
        self.assertIn(
            '.order("snapshot_at", desc=True)', self.fn("leaderboard_history_season")
        )

    @behavior(
        "snapshot creation",
        "Legacy write precedes structured snapshot; structured failure is nonfatal; duplicate guard only checks legacy rows. Rollover calls snapshot but is not executed here.",
        question="Approve atomicity/recovery/snapshot scheduling?",
    )
    def current_behavior__history__snapshot_source(self):
        self.assertIn(
            "except Exception", self.fn("_snapshot_leaderboard_for_current_season")
        )
        self.assertIn(
            "_snapshot_leaderboard_for_current_season",
            self.fn("_rollover_current_season"),
        )

    @behavior(
        "frontend",
        "Global frontend sorts points/full hits/earlier saved time, ranks displayed by array position; history uses stored rank or index fallback, dynamic numeric points and snapshot columns; no archived bracket links.",
        question="Approve rank style, snapshot display and historical navigation?",
    )
    def current_behavior__history__frontend(self):
        s = (ROOT.parent / "frontend/src/pages/PastSeasonsPage.tsx").read_text(
            encoding="utf-8"
        )
        self.assertIn("row.rank", s)
        self.assertNotIn("navigate(`/bracket/", s)
        f = (ROOT.parent / "frontend/src/pages/LeaderboardPage.tsx").read_text(
            encoding="utf-8"
        )
        self.assertIn("const sa = a.saved_at", f)
        self.assertIn("bonus_champion", f)

    @behavior(
        "edge behavior",
        "History read sorts total_points/full_hits without explicit rank or saved-time order; saved_at not stored. Equal score/time secondary order and historical retention remain unreviewed.",
        question="Approve rank/order consistency and retention?",
    )
    def current_behavior__history__sorting(self):
        f = self.fn("leaderboard_history_season")
        self.assertIn('.order("full_hits", desc=True)', f)
        self.assertNotIn('.order("rank"', f)

    @behavior(
        "privacy",
        "Structured history rows have no live user FK; legacy user/bracket references and schema deletion behavior differ; no account deletion performed.",
        question="Approve deleted-user/bracket retention?",
    )
    def current_behavior__history__retention(self):
        s = (ROOT / "db/baseline/000_current_schema.sql").read_text()
        segment = s[
            s.index('CREATE TABLE "public"."leaderboard_history_rows"') : s.index(
                'ALTER TABLE "public"."leaderboard_history_rows"'
            )
        ]
        self.assertNotIn("user_id", segment)
        self.assertIn("display_name", segment)


# Preserve NC-01 provenance while explicitly marking approved repair acceptance.
from scripts.nc02a1_acceptance_metadata import mark_acceptance

mark_acceptance(CurrentStaticScoring)


from scripts.nc02a2_acceptance_metadata import mark_acceptance as mark_nc02a2_acceptance

mark_nc02a2_acceptance(CurrentStaticScoring)
