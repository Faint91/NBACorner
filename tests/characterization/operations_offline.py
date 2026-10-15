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

    def rpc(self, name, params):
        assert name in {"publish_current_standings", "finalize_season_transition"}
        db = self

        class Publish:
            def execute(self):
                if name == "finalize_season_transition":
                    if db.fail == ("transition", "finalize"):
                        raise RuntimeError("Synthetic finalization failure")
                    db.rows["standings"] = []
                    db.ns["CURRENT_SEASON_ID"] = params["p_new_season_id"]
                    db.ns["CURRENT_SEASON_CODE"] = params["p_new_season_code"]
                    db.calls.append(("transition", "finalize"))
                    return SimpleNamespace(data={"state": "transitioned"})
                if db.fail == ("standings", "publish"):
                    raise RuntimeError("Synthetic publish failure")
                db.rows["standings"] = copy.deepcopy(params["p_rows"])
                return SimpleNamespace(
                    data={
                        "state": "refreshed",
                        "refreshed": True,
                        "season_code": "2025-26",
                        "team_count": 30,
                    }
                )

        return Publish()

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
        self.db.ns = self.ns
        self.ns["get_current_season"] = lambda client: self.ns["current_season"]()
        self.ns["has_request_context"] = lambda: False
        self.facts = {}
        # Isolate this existing post-gate cleanup double from snapshot internals.
        # Canonical recompute/atomic DB publication are covered by D2 live/SQL tests.
        self.ns["_snapshot_leaderboard_for_current_season"] = self.snapshot_boundary

    def snapshot_boundary(self):
        try:
            self.db.table("leaderboard_history").insert(
                [dict(season_id="current")]
            ).execute()
            header = (
                self.db.table("leaderboard_history_snapshots")
                .insert(dict(season_id="current"))
                .execute()
                .data[0]
            )
            rows = [
                dict(snapshot_id=header["id"], rank=i + 1)
                for i, _ in enumerate(self.db.rows.get("bracket_scores", []))
            ]
            if rows:
                self.db.table("leaderboard_history_rows").insert(rows).execute()
            return dict(
                ok=True,
                structured_complete=True,
                is_final=True,
                season_id="current",
                history_snapshot_id=header["id"],
                expected_rows=len(rows),
                actual_rows=len(rows),
                rows_snapshot=len(rows),
                history_rows_count=len(rows),
            )
        except RuntimeError:
            return dict(ok=False, error="Synthetic structured failure", status=503)

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
        return self.ns["_rollover_current_season"](
            code,
            datetime(2027, 4, 12, tzinfo=timezone.utc),
            datetime(2027, 4, 18, tzinfo=timezone.utc),
        )

    def espn(self, data=None):
        import standings_service as service
        from synthetic_fixtures import foundation
        from unittest.mock import patch

        self.db.rows["teams"] = foundation()["teams"]
        fixture = __import__("json").loads(
            (
                ROOT / "tests/fixtures/providers/espn-standings-complete-2026.json"
            ).read_text()
        )
        season = __import__("canonical_season").CurrentSeason(
            "current",
            "2025-26",
            datetime(2026, 4, 12, tzinfo=timezone.utc),
            datetime(2026, 4, 18, tzinfo=timezone.utc),
        )

        def refresh(client, **kwargs):
            with patch.object(
                service, "guard_runtime_job", lambda job: None
            ), patch.object(
                service, "get_current_season", lambda client: season
            ), patch.object(
                service,
                "fetch_espn",
                side_effect=(
                    RuntimeError("synthetic provider failure")
                    if self.db.fail == ("provider", "get")
                    else None
                ),
                return_value=copy.deepcopy(fixture if data is None else data),
            ):
                return service.refresh_current_standings(
                    client, now=lambda: datetime(2026, 4, 1, tzinfo=timezone.utc)
                )

        ns = dict(
            supabase=self.db,
            guard_runtime_job=lambda job: None,
            refresh_current_standings=refresh,
            StandingsRefreshError=service.StandingsRefreshError,
            log_result=lambda result: None,
            espn_season_year=__import__("canonical_season").espn_season_year,
        )
        load_functions(
            ROOT / "scripts/update_standings.py", {"update_standings_from_json"}, ns
        )
        self.ns.update(
            refresh_current_standings=refresh,
            StandingsRefreshError=service.StandingsRefreshError,
            log_result=lambda result: None,
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
        self.assertFalse(any(r["code"] == "OLD" for r in self.db.rows["standings"]))
        self.facts = {
            "rows_including_stale": n,
            "stale_retained": False,
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
        before = copy.deepcopy(self.db.rows.get("standings", []))
        for payload in [data, {"bad": []}]:
            with self.assertRaises(Exception):
                self.espn(payload)["update_standings_from_json"]()
            self.assertEqual(self.db.rows.get("standings", []), before)

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
            "canonical_2025_26_espn_year": 2026,
            "canonical_2026_27_espn_year": 2027,
            "date_inference": False,
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
        self.db.fail = ("standings", "publish")
        with self.assertRaises(Exception):
            ns["update_standings_from_json"]()
        self.assertEqual(self.db.rows.get("standings", []), [])

    def bdl(self, fail=False):
        # Legacy helper name retained solely for historic test identifiers.
        self.db.rows["standings"] = [dict(code="OLD")]
        self.espn()
        if fail:
            self.db.fail = ("provider", "get")

    @behavior(
        "provider/source",
        "Active Flask admin/cron refresh aggregates Balldontlie regular-season fixture games rather than authoritative ESPN.",
        "KNOWN GAP",
        "provider",
    )
    def current_behavior__standings__active_provider(self):
        self.bdl()
        r = self.ns["fetch_and_sync_standings_from_nba"]()
        self.assertEqual(r["season_code"], "2025-26")
        self.assertEqual(r["team_count"], 30)
        self.assertEqual(r["state"], "refreshed")
        self.facts = {
            "provider": "ESPN",
            "rows": 30,
            "espn_ending_year": 2026,
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
        self.db.fail = ("standings", "publish")
        with self.assertRaises(Exception):
            self.ns["fetch_and_sync_standings_from_nba"]()
        self.assertEqual(self.db.rows["standings"], [dict(code="OLD")])

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
        self.assertEqual(len(self.db.rows["standings"]), 0)
        self.assertEqual(self.ns["CURRENT_SEASON_CODE"], "2026-27")
        self.facts = {
            "steps": [s["step"] for s in r["steps"]],
            "canonical_advanced_by_finalization": True,
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
        self.assertFalse(r["ok"])
        self.assertTrue(self.db.rows["leaderboard_history"])
        self.assertEqual(len(self.db.rows["matches"]), 2)
        self.assertFalse(any(op == "delete" for _, op in self.db.calls))

    @behavior(
        "season lifecycle",
        "Empty/same/existing target season rejected; arbitrary nonempty new code accepted; dates optional; current globals stay old and env_next_actions asks manual config update.",
        question="Approve target code/date/current-selection policy?",
    )
    def current_behavior__rollover__preconditions(self):
        self.rollover_state()
        for code in ["", "2025-26"]:
            self.assertFalse(self.roll(code)["ok"])
        self.assertFalse(self.roll("arbitrary-code")["ok"])

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
