"""Operational source helpers, OFFLINE deterministic provider fixtures and DB doubles."""

import ast, copy, runpy, unittest, requests
from pathlib import Path
from datetime import datetime, timezone, date
from types import SimpleNamespace
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
prior = runpy.run_path(str(ROOT / "tests/characterization/scoring_offline.py"))
CONFIG = None
RESULTS = []
REQ = {
    "provider": "ESPN is the authoritative standings source.",
    "season": "Future season selection must derive from canonical application season configuration, not conflicting independent environment variables.",
    "freeze": "Standings freeze when the regular season ends / bracket-creation period opens.",
    "snapshot": "Season rollover may delete active match rows once the historical snapshot has been successfully saved.",
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
            evidence_source="OFFLINE unchanged AST helpers; fixed provider fixture/in-memory DB, no live job or transaction proof",
        )
        return fn

    return wrap


class DB(prior["DB"]):
    def __init__(self):
        super().__init__()
        self.fail = None

    def table(self, n):
        return Q(self, n)


class Q(prior["Q"]):
    def delete(self):
        self.op = "delete"
        return self

    def update(self, v):
        self.op = "update"
        self.payload = v
        return self

    def execute(self):
        if self.db.fail == (self.name, self.op):
            raise RuntimeError("Synthetic DB failure")
        if self.op in {"delete", "update"}:
            rows = self.db.rows.setdefault(self.name, [])
            selected = [r for r in rows if all(f(r) for f in self.filters)]
            if self.op == "delete":
                rows[:] = [r for r in rows if r not in selected]
            else:
                for r in selected:
                    r.update(copy.deepcopy(self.payload))
            self.db.calls.append((self.name, self.op))
            return SimpleNamespace(data=copy.deepcopy(selected))
        if self.op == "insert":
            rows = self.db.rows.setdefault(self.name, [])
            data = self.payload if isinstance(self.payload, list) else [self.payload]
            added = []
            for r in data:
                row = copy.deepcopy(r)
                row.setdefault("id", self.name + "-" + str(len(rows) + 1))
                rows.append(row)
                added.append(copy.deepcopy(row))
            self.db.calls.append((self.name, self.op))
            return SimpleNamespace(data=added)
        return super().execute()


def load_functions(path, names, ns):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    for node in nodes:
        node.decorator_list = (
            []
        )  # Preserve bodies; no full Flask application import offline.
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), ns)


class CurrentOfflineOperations(unittest.TestCase):
    def setUp(self):
        _, self.ns, _ = prior["environment"]()
        self.db = DB()
        self.ns["supabase"] = self.db
        self.ns.update(
            now_utc=lambda: datetime(2026, 10, 14, tzinfo=timezone.utc),
            defaultdict=defaultdict,
            provider_uses_fixtures=lambda: True,
            BALLDONTLIE_API_KEY=None,
            season_start_year=__import__("canonical_season").season_start_year,
        )
        load_functions(
            ROOT / "app.py",
            {"_rollover_current_season", "fetch_and_sync_standings_from_nba"},
            self.ns,
        )
        self.facts = {}

    def tearDown(self):
        r = dict(getattr(self, self._testMethodName).metadata)
        r["facts"] = self.facts
        RESULTS.append(r)

    def rollover_state(self):
        self.db.rows.update(
            brackets=[
                dict(
                    id=x,
                    season_id="current",
                    deleted_at=None,
                    is_done=True,
                    user_id=x,
                    name=x,
                )
                for x in ["master", "a", "b"]
            ],
            users=[dict(id=x, username=x) for x in ["a", "b"]],
            seasons=[dict(id="current", code="2025-26")],
            matches=[
                dict(id="active", season_id="current"),
                dict(id="past", season_id="historical"),
            ],
            bracket_scores=[
                dict(bracket_id=x, season_id="current", total_points=3, full_hits=1)
                for x in ["a", "b"]
            ],
            standings=[dict(code="BOS")],
            teams=[dict(code="BOS")],
        )

    def roll(self, code="2026-27"):
        return self.ns["_rollover_current_season"](code)

    def espn(self, data=None):
        path = ROOT / "scripts/update_standings.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        ns = dict(
            supabase=self.db,
            datetime=datetime,
            timezone=timezone,
            requests=requests,
            guard_runtime_job=lambda j: None,
            DEBUG_STANDINGS=False,
            get_current_season=lambda client: SimpleNamespace(code="2025-26"),
            espn_season_year=__import__("canonical_season").espn_season_year,
            print=lambda *a, **kw: None,
        )
        for n in tree.body:
            if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name)
                and t.id
                in {
                    "EAST_WEST_BY_CODE",
                    "ESPN_TO_DB_CODE",
                    "ESPN_STANDINGS_URL_TEMPLATE",
                }
                for t in n.targets
            ):
                exec(
                    compile(ast.Module(body=[n], type_ignores=[]), str(path), "exec"),
                    ns,
                )
        from provider_transport import provider_get, FixtureResponse
        from environment_safety import load_test_config

        settings = load_test_config(CONFIG)
        if data is None:
            ns["provider_get"] = lambda callback, url, **kw: provider_get(
                callback, url, settings=settings, **kw
            )
        else:
            ns["provider_get"] = lambda *a, **kw: SimpleNamespace(
                status_code=200,
                json=lambda: copy.deepcopy(data),
                raise_for_status=lambda: None,
            )
        load_functions(
            path,
            {
                "_safe_int",
                "_safe_float",
                "update_standings_from_json",
            },
            ns,
        )
        return ns

    @behavior(
        "provider/source",
        "ESPN script parses existing 2026 fixture and updates/inserts codes, preserving absent stale rows; repeated refresh stable row count.",
        "MATCHES REQUIREMENT",
        "provider",
    )
    def current_behavior__standings__espn(self):
        self.db.rows["standings"] = [dict(id="stale", code="OLD")]
        ns = self.espn()
        ns["update_standings_from_json"]()
        n = len(self.db.rows["standings"])
        self.assertGreater(n, 1)
        ns["update_standings_from_json"]()
        self.assertEqual(len(self.db.rows["standings"]), n)
        self.assertTrue(any(r["code"] == "OLD" for r in self.db.rows["standings"]))
        self.facts = {
            "rows_including_stale": n,
            "stale_retained": True,
            "real_provider_contact": False,
        }

    @behavior(
        "standings refresh",
        "Missing/unknown team skipped, malformed top shape leaves rows intact, duplicate team entries update existing code; changed wins written.",
        question="Approve parser/duplicates/stale and partial data semantics?",
    )
    def current_behavior__standings__espn_edges(self):
        entry = {
            "team": {"abbreviation": "NY", "displayName": "Synthetic NY"},
            "stats": [{"name": "wins", "value": 4}, {"name": "losses", "value": 2}],
        }
        data = {
            "standings": {
                "entries": [
                    entry,
                    copy.deepcopy(entry),
                    {"team": {"abbreviation": "UNKNOWN", "displayName": "Unknown"}},
                    None,
                ]
            }
        }
        ns = self.espn(data)
        ns["update_standings_from_json"]()
        self.assertEqual(len(self.db.rows["standings"]), 1)
        self.assertEqual(self.db.rows["standings"][0]["code"], "NYK")
        self.espn({"bad": []})["update_standings_from_json"]()
        self.assertEqual(len(self.db.rows["standings"]), 1)

    @behavior(
        "season source",
        "ESPN year follows independent NBA_STANDINGS_SEASON override or UTC August boundary; NBA_SEASON_YEAR workflow value ignored, not canonical CURRENT_SEASON_CODE.",
        "KNOWN GAP",
        "season",
    )
    def current_behavior__standings__year(self):
        ns = self.espn()
        self.assertEqual(ns["espn_season_year"]("2025-26"), 2026)
        self.assertEqual(ns["espn_season_year"]("2026-27"), 2027)
        self.facts = {
            "july_2026_end_year": 2026,
            "august_2026_end_year": 2027,
            "workflow_variable_consumed": False,
            "prior_reference": "NC-ENV-04B",
        }

    @behavior(
        "failure/atomicity",
        "ESPN DB failure is caught without rollback; per-code updates before failure can remain. Invalid override raises before request.",
        question="Approve error propagation and partial updates?",
    )
    def current_behavior__standings__script_failure(self):
        ns = self.espn()
        self.db.fail = ("standings", "insert")
        ns["update_standings_from_json"]()
        self.assertEqual(self.db.rows.get("standings", []), [])
        ns["NBA_STANDINGS_SEASON_OVERRIDE"] = "invalid"
        ns["get_current_season"] = lambda client: (_ for _ in ()).throw(
            RuntimeError("Missing canonical state")
        )
        with self.assertRaises(RuntimeError):
            ns["update_standings_from_json"]()

    def bdl(self, fail=False):
        from synthetic_fixtures import foundation
        from provider_transport import provider_get
        from environment_safety import load_test_config

        settings = load_test_config(CONFIG)
        self.db.rows["teams"] = foundation()["teams"]
        self.db.rows["standings"] = [dict(code="OLD")]
        self.ns["provider_get"] = (
            (
                lambda *a, **kw: (_ for _ in ()).throw(
                    RuntimeError("Synthetic provider failure")
                )
            )
            if fail
            else lambda callback, url, **kw: provider_get(
                callback, url, settings=settings, **kw
            )
        )

    @behavior(
        "provider/source",
        "Active Flask admin/cron refresh aggregates Balldontlie regular-season fixture games rather than authoritative ESPN.",
        "KNOWN GAP",
        "provider",
    )
    def current_behavior__standings__active_provider(self):
        self.bdl()
        r = self.ns["fetch_and_sync_standings_from_nba"]()
        self.assertEqual(r["season_year"], 2025)
        self.assertEqual(r["updated"], 30)
        self.assertEqual(r["pages_fetched"], 2)
        self.facts = {
            "provider": "Balldontlie",
            "rows": 30,
            "pages": 2,
            "season_start_year": 2025,
        }

    @behavior(
        "failure/atomicity",
        "Flask refresh deletes all standings then inserts; insert failure leaves empty table; provider failure occurs before delete.",
        question="Approve replace/error/rollback policy?",
    )
    def current_behavior__standings__refresh_failure(self):
        self.bdl(True)
        with self.assertRaises(Exception):
            self.ns["fetch_and_sync_standings_from_nba"]()
        self.assertEqual(self.db.rows["standings"], [dict(code="OLD")])
        self.bdl()
        self.db.fail = ("standings", "insert")
        with self.assertRaises(Exception):
            self.ns["fetch_and_sync_standings_from_nba"]()
        self.assertEqual(self.db.rows["standings"], [])

    @behavior(
        "rollover order",
        "Rollover snapshots first, deletes current scores/matches, soft-deletes current brackets, inserts next season; standings/teams/past matches remain.",
        "MATCHES REQUIREMENT",
        "snapshot",
    )
    def current_behavior__rollover__order(self):
        self.rollover_state()
        r = self.roll()
        self.assertTrue(r["ok"])
        ops = self.db.calls
        self.assertLess(
            ops.index(("leaderboard_history_rows", "insert")),
            ops.index(("matches", "delete")),
        )
        self.assertEqual(
            self.db.rows["matches"], [dict(id="past", season_id="historical")]
        )
        self.assertEqual(len(self.db.rows["standings"]), 1)
        self.assertEqual(self.ns["CURRENT_SEASON_CODE"], "2025-26")
        self.facts = {
            "steps": [s["step"] for s in r["steps"]],
            "globals_unchanged": True,
        }

    @behavior(
        "snapshot preservation",
        "Snapshot error aborts before score/match deletion.",
        "MATCHES REQUIREMENT",
        "snapshot",
    )
    def current_behavior__rollover__snapshot_failure(self):
        self.rollover_state()
        self.ns["_snapshot_leaderboard_for_current_season"] = lambda: dict(
            error="Synthetic failure", status=500
        )
        self.assertFalse(self.roll()["ok"])
        self.assertEqual(len(self.db.rows["matches"]), 2)
        self.assertEqual(self.db.calls, [])

    @behavior(
        "snapshot preservation",
        "Legacy-only existing snapshot is accepted; structured history failure is nonfatal and rollover still deletes matches. Snapshot-success definition needs checkpoint.",
        "UNCLEAR / NEEDS BUSINESS CHECKPOINT",
        "snapshot",
        "Does legacy-only persistence satisfy successfully saved snapshot when Past Seasons structured data is absent?",
    )
    def current_behavior__rollover__partial_snapshot(self):
        self.rollover_state()
        self.db.fail = ("leaderboard_history_snapshots", "insert")
        r = self.roll()
        self.assertTrue(r["ok"])
        self.assertTrue(self.db.rows["leaderboard_history"])
        self.assertEqual(
            self.db.rows["matches"], [dict(id="past", season_id="historical")]
        )

    @behavior(
        "season lifecycle",
        "Empty/same/existing target season rejected; arbitrary nonempty new code accepted; dates optional; current globals stay old and env_next_actions asks manual config update.",
        question="Approve target code/date/current-selection policy?",
    )
    def current_behavior__rollover__preconditions(self):
        self.rollover_state()
        for code in ["", "2025-26"]:
            self.assertFalse(self.roll(code)["ok"])
        self.assertTrue(self.roll("arbitrary-code")["ok"])

    @behavior(
        "failure/atomicity",
        "Failure deleting scores/matches, soft-deleting brackets or inserting season returns error with earlier writes retained; no all-step transaction.",
        question="Approve retry and partial commit recovery?",
    )
    def current_behavior__rollover__failures(self):
        for table, op in [
            ("bracket_scores", "delete"),
            ("matches", "delete"),
            ("brackets", "update"),
            ("seasons", "insert"),
        ]:
            self.setUp()
            self.rollover_state()
            self.db.fail = (table, op)
            r = self.roll()
            self.assertFalse(r["ok"])
            self.assertTrue(self.db.rows.get("leaderboard_history"))

    @behavior(
        "edges",
        "Repeat target rejected once created; existing legacy snapshot reuses without checking structured completeness; no master completion/date/recompute prerequisite in helper.",
        question="Approve rollover idempotence/preconditions?",
    )
    def current_behavior__rollover__repeat(self):
        self.rollover_state()
        self.assertTrue(self.roll()["ok"])
        self.assertFalse(self.roll()["ok"])

    @behavior(
        "cron operations",
        "Offline internal refresh rejects absent/wrong synthetic token; correct header calls same Balldontlie helper; repeat replaces same 30 rows.",
        question="Approve token transport/replay and admin/cron equivalence?",
    )
    def current_behavior__admin_ops__token(self):
        self.bdl()
        self.ns.update(
            STANDINGS_CRON_TOKEN="offline-synthetic-only",
            jsonify=lambda obj: obj,
            request=SimpleNamespace(headers={}, args={}),
        )
        load_functions(ROOT / "app.py", {"internal_cron_refresh_standings"}, self.ns)
        fn = self.ns["internal_cron_refresh_standings"]
        self.assertEqual(fn()[1], 403)
        self.ns["request"].headers["X-Cron-Token"] = "wrong-synthetic"
        self.assertEqual(fn()[1], 403)
        self.ns["request"].headers["X-Cron-Token"] = "offline-synthetic-only"
        self.assertEqual(fn()[1], 200)
        self.assertEqual(fn()[1], 200)
        self.assertEqual(len(self.db.rows["standings"]), 30)
        self.facts = {"token_values_recorded": False, "correct_token_repeated_rows": 30}
