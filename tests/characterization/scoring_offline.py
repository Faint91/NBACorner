"""Unchanged source helpers executed OFFLINE against in-memory transport doubles."""

import ast, copy, unittest
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
RESULTS = []
REQ = {
    "champion": "Correct NBA champion bonus: +3 points.",
    "finalists": "Correctly predicting both NBA Finals participants: +1 point.",
    "tie": "Exact leaderboard ties are ranked by earlier bracket saved_at.",
}


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
            approved_requirement=REQ.get(requirement),
            classification=classification,
            future_business_question=question,
            evidence_source="OFFLINE unchanged AST-extracted source helper with in-memory DB double; not live job execution",
        )
        return fn

    return wrap


class DB:
    def __init__(self):
        self.rows = {}
        self.calls = []

    def table(self, name):
        return Q(self, name)


class Q:
    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.filters = []
        self.sorts = []
        self.max = None
        self.op = "read"
        self.payload = None

    def select(self, *a):
        return self

    def eq(self, k, v):
        self.filters.append(lambda r: r.get(k) == v)
        return self

    def is_(self, k, v):
        return self.eq(k, v)

    def in_(self, k, v):
        self.filters.append(lambda r: r.get(k) in v)
        return self

    def order(self, k, desc=False):
        self.sorts.append((k, desc))
        return self

    def limit(self, n):
        self.max = n
        return self

    def insert(self, v):
        self.op = "insert"
        self.payload = v
        return self

    def upsert(self, v):
        self.op = "upsert"
        self.payload = v
        return self

    def execute(self):
        rows = self.db.rows.setdefault(self.name, [])
        if self.op != "read":
            data = self.payload if isinstance(self.payload, list) else [self.payload]
            for r in data:
                row = copy.deepcopy(r)
                row.setdefault("id", self.name + "-" + str(len(rows) + 1))
                if self.op == "upsert":
                    rows[:] = [
                        x for x in rows if x.get("bracket_id") != row.get("bracket_id")
                    ]
                rows.append(row)
            self.db.calls.append((self.name, self.op))
            return SimpleNamespace(
                data=copy.deepcopy(
                    data if self.name != "leaderboard_history_snapshots" else [rows[-1]]
                )
            )
        out = [copy.deepcopy(r) for r in rows if all(f(r) for f in self.filters)]
        for k, desc in reversed(self.sorts):
            out.sort(key=lambda r: r.get(k, 0), reverse=desc)
        return SimpleNamespace(data=out[: self.max] if self.max else out)


def environment():
    db = DB()
    db.rows["brackets"] = [
        dict(id=i, season_id="current", deleted_at=None, user_id=i, name=i)
        for i in ["master", "a", "b"]
    ]
    db.rows["users"] = [
        dict(id=i, username="Alpha" if i == "a" else "Zulu") for i in ["a", "b"]
    ]
    calls = []
    ns = dict(
        supabase=db,
        CURRENT_SEASON_ID="current",
        CURRENT_SEASON_CODE="2025-26",
        datetime=datetime,
        timezone=timezone,
        guard_runtime_job=lambda job: calls.append(job),
        ensure_season_globals=lambda: None,
        Optional=__import__("typing").Optional,
        Dict=__import__("typing").Dict,
        Any=__import__("typing").Any,
        request=SimpleNamespace(user={}),
        safe_print=lambda *a: None,
        APIError=RuntimeError,
    )
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {
        "_fetch_matches_for_bracket",
        "_compute_score_for_bracket",
        "with_current_season",
        "_build_leaderboard_rows_for_current_season",
        "_snapshot_leaderboard_for_current_season",
    }
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT / "app.py"), "exec"),
        ns,
    )
    return db, ns, calls


def match(bid, rnd, slot=1, winner="BOS", games=4, a="BOS", b="LAL"):
    return dict(
        id=f"{bid}-{rnd}-{slot}",
        bracket_id=bid,
        conference="nba" if rnd == 4 else "east",
        round=rnd,
        slot=slot,
        team_a=a,
        team_b=b,
        predicted_winner=winner,
        predicted_winner_games=games,
    )


class CurrentOfflineScoring(unittest.TestCase):
    def setUp(self):
        self.db, self.ns, self.jobs = environment()
        self.facts = {}

    def tearDown(self):
        r = dict(getattr(self, self._testMethodName).metadata)
        r["facts"] = self.facts
        RESULTS.append(r)

    def score(self, actual, user):
        self.db.rows["matches"] = actual + user
        master = {f"{m['conference']}-{m['round']}-{m['slot']}": m for m in actual}
        return self.ns["_compute_score_for_bracket"](master, "master", "a")

    @behavior(
        "base points",
        "Play-in full hit awards 1; rounds 1–4 full winner/participants/count hit awards 3 each; wrong winner zero; no round escalation.",
        question="Approve round base values?",
    )
    def current_behavior__scoring__base_points(self):
        for rnd in range(5):
            r = self.score([match("master", rnd)], [match("a", rnd)])
            self.assertEqual(r["total_points"], 1 if rnd == 0 else 3)
        self.facts = {"round_full_points": {"0": 1, "1": 3, "2": 3, "3": 3, "4": 3}}

    @behavior(
        "champion bonus",
        "Correct Finals champion earns base Finals 3 only; explicit bonus_champion remains 0 rather than approved +3.",
        "KNOWN GAP",
        "champion",
    )
    def current_behavior__scoring__champion_bonus(self):
        r = self.score([match("master", 4, 11)], [match("a", 4, 11)])
        self.assertEqual((r["total_points"], r["bonus_champion"]), (3, 0))
        self.facts = {
            "finals_base": 3,
            "explicit_champion_bonus": 0,
            "approved_bonus": 3,
        }

    @behavior(
        "finalist bonus",
        "Both/one/neither/swapped finalists and champion-correct different set all have bonus_finalists=0; approved both-finalists +1 absent.",
        "KNOWN GAP",
        "finalists",
    )
    def current_behavior__scoring__finalist_bonus(self):
        cases = [
            ("BOS", "LAL", "BOS"),
            ("BOS", "DEN", "BOS"),
            ("MIL", "DEN", "MIL"),
            ("LAL", "BOS", "BOS"),
        ]
        points = []
        for a, b, w in cases:
            r = self.score(
                [match("master", 4, 11)], [match("a", 4, 11, a=a, b=b, winner=w)]
            )
            self.assertEqual(r["bonus_finalists"], 0)
            points.append(r["total_points"])
        self.facts = {
            "explicit_finalist_bonus_each_case": [0] * 4,
            "base_points_cases": points,
            "approved_both_bonus": 1,
        }

    @behavior(
        "game-count scoring",
        "Rounds 1–4 exact count earns full 3 with matching participants; incorrect/null/zero/negative/large user count yields partial 1. Play-in count ignored; NULL actual count is pending.",
        question="Approve partial/count and historical availability rules?",
    )
    def current_behavior__scoring__counts(self):
        for n in [5, None, 0, -1, 99]:
            self.assertEqual(
                self.score([match("master", 1)], [match("a", 1, games=n)])[
                    "total_points"
                ],
                1,
            )
        self.assertEqual(
            self.score([match("master", 0, games=1)], [match("a", 0, games=99)])[
                "total_points"
            ],
            1,
        )
        r = self.score([match("master", 1, games=None)], [match("a", 1)])
        self.assertEqual(r["points_by_match"]["east-1-1"]["status"], "pending")

    @behavior(
        "edge behavior",
        "Missing user match/no pick are misses; incomplete actual winner/count is pending; no user matches skips persistence; deleted/historical/same-ID master skips helper.",
        question="Approve missing/incomplete/error contract?",
    )
    def current_behavior__scoring__edges(self):
        r = self.score(
            [match("master", 1), match("master", 2)], [match("a", 1, winner=None)]
        )
        self.assertEqual(r["misses"], 2)
        self.assertIsNone(self.score([match("master", 1)], []))
        self.db.rows["brackets"][1]["deleted_at"] = "synthetic"
        self.assertIsNone(self.score([match("master", 1)], [match("a", 1)]))
        self.db.rows["brackets"][1].update(deleted_at=None, season_id="historical")
        self.assertIsNone(self.score([match("master", 1)], [match("a", 1)]))

    @behavior(
        "recomputation",
        "Per-bracket upsert overwrites score rather than increments; same inputs repeat same numeric result, updated_at changes. Helper does not check submission flag; source job entry remains blocked live.",
        question="Approve recalculation timing/eligibility/atomicity?",
    )
    def current_behavior__scoring__upsert(self):
        self.db.rows["brackets"][1]["is_done"] = False
        for _ in range(2):
            r = self.score([match("master", 1)], [match("a", 1)])
        self.assertEqual(len(self.db.rows["bracket_scores"]), 1)
        self.assertEqual(r["total_points"], 3)
        r = self.score([match("master", 1, winner="LAL")], [match("a", 1)])
        self.assertEqual(r["total_points"], 0)

    def snapshot_rows(self):
        self.db.rows["bracket_scores"] = [
            dict(
                bracket_id=i,
                season_id="current",
                total_points=3,
                full_hits=1,
                points_by_match={"east-1-4": {"points": 3}},
            )
            for i in ["a", "b"]
        ]
        self.db.rows["brackets"][1]["saved_at"] = "2026-01-02T00:00:00Z"
        self.db.rows["brackets"][2]["saved_at"] = "2026-01-01T00:00:00Z"

    @behavior(
        "tie ordering",
        "Snapshot exact score/hit ties sort username instead of earlier saved_at; builder omits saved_at. Later-saved Alpha ranks ahead of earlier-saved Zulu.",
        "KNOWN GAP",
        "tie",
    )
    def current_behavior__history__snapshot_tie(self):
        self.snapshot_rows()
        r = self.ns["_snapshot_leaderboard_for_current_season"]()
        self.assertTrue(r["ok"])
        self.assertEqual(self.db.rows["leaderboard_history"][0]["user_id"], "a")
        self.facts = {
            "earlier_saved_rank": 2,
            "later_saved_rank": 1,
            "sort_uses_username": True,
        }

    @behavior(
        "snapshot creation",
        "Snapshot writes legacy rows plus structured snapshot/rows; repeat rejected by legacy season row; sequential ranks and numeric per-match flattening persisted, not one transaction.",
        question="Approve snapshot frequency/atomicity/rank format?",
    )
    def current_behavior__history__snapshot_repeat(self):
        self.snapshot_rows()
        r = self.ns["_snapshot_leaderboard_for_current_season"]()
        self.assertEqual((r["rows_snapshot"], r["history_rows_count"]), (2, 2))
        self.assertEqual(
            self.ns["_snapshot_leaderboard_for_current_season"]()["status"], 400
        )
        self.assertEqual(
            self.db.rows["leaderboard_history_rows"][0]["per_match_points"],
            {"east-1-4": 3},
        )
        self.assertNotIn("user_id", self.db.rows["leaderboard_history_rows"][0])

    @behavior(
        "snapshot creation",
        "Missing score rows refuses snapshot; existing structured snapshot alone does not trigger duplicate legacy guard.",
        question="Approve cross-model duplicate/failure policy?",
    )
    def current_behavior__history__snapshot_empty(self):
        self.assertEqual(
            self.ns["_snapshot_leaderboard_for_current_season"]()["status"], 400
        )
        self.snapshot_rows()
        self.db.rows["leaderboard_history_snapshots"] = [
            dict(id="old", season_code="2025-26")
        ]
        self.assertTrue(self.ns["_snapshot_leaderboard_for_current_season"]()["ok"])
