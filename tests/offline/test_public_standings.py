"""Offline public standings API regression tests using actual Flask route hooks."""
import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, g, has_request_context, jsonify, request

from canonical_season import SeasonConfigurationError, get_current_season
from public_standings_service import read_public_standings
from standings_service import EAST, WEST
from synthetic_fixtures import foundation

ROOT = Path(__file__).resolve().parents[2]
SEASON = {
    "id": "current-season",
    "code": "2026-27",
    "regular_season_end_utc": "2027-04-12T07:00:00Z",
    "playoffs_start_utc": "2027-04-18T07:00:00Z",
}


def stored_rows():
    names = {team["code"]: team["name"] for team in foundation()["teams"]}
    return [
        {
            "code": code,
            "name": names[code],
            "conference": conference,
            "seed": position,
            "wins": 20 - position,
            "losses": position,
            "win_pct": (20 - position) / 20,
        }
        for conference, codes in (("east", EAST), ("west", WEST))
        for position, code in enumerate(codes, 1)
    ][::-1]


class ReadOnlyDB:
    def __init__(self):
        self.rows = stored_rows()
        self.teams = foundation()["teams"]
        self.calls = []
        self.forbidden = []
        self.fail_table = None
        self.rollover = False
        self.season_reads = 0
        self.pointer_rows = [{"singleton": True, "season_id": SEASON["id"]}]

    def __getattr__(self, name):
        self.forbidden.append(name)
        raise AssertionError("Unexpected database operation: " + name)

    def table(self, name):
        if name not in {"application_season", "seasons", "standings", "teams"}:
            self.forbidden.append("table:" + name)
            raise AssertionError("Unexpected relation")
        db = self

        class Query:
            def __getattr__(self, operation):
                db.forbidden.append(name + ":" + operation)
                raise AssertionError("Read-only fixture")

            def select(self, columns):
                self.columns = [c.strip() for c in columns.split(",")]
                return self

            def eq(self, key, value):
                assert name == "seasons" and key == "id" and value == SEASON["id"]
                return self

            def limit(self, count):
                assert count == 2 and name in {"seasons", "application_season"}
                return self

            def execute(self):
                db.calls.append((name, self.columns))
                if db.fail_table == name:
                    raise RuntimeError("PRIVATE_DATABASE_DETAIL_NEVER_RETURNED")
                if name == "seasons":
                    db.season_reads += 1
                    rows = [dict(SEASON)]
                    if db.rollover and db.season_reads > 1:
                        rows[0]["code"] = "2027-28"
                elif name == "application_season":
                    rows = db.pointer_rows
                elif name == "standings":
                    rows = db.rows
                else:
                    rows = db.teams
                return SimpleNamespace(
                    data=None
                    if rows is None
                    else [
                        {key: value for key, value in row.items() if key in self.columns}
                        for row in copy.deepcopy(rows)
                    ]
                )

        return Query()


class PublicStandingsTests(unittest.TestCase):
    def setUp(self):
        network = patch("socket.socket.connect", side_effect=AssertionError("Offline"))
        network.start()
        self.addCleanup(network.stop)
        self.db = ReadOnlyDB()
        self.before = copy.deepcopy(self.db.rows)
        self.logs = []
        self.app = Flask("public_standings_offline")
        env = {
            "app": self.app,
            "supabase": self.db,
            "g": g,
            "has_request_context": has_request_context,
            "request": request,
            "jsonify": jsonify,
            "get_current_season": get_current_season,
            "SeasonConfigurationError": SeasonConfigurationError,
            "read_public_standings": read_public_standings,
            "safe_print": lambda *args: self.logs.append(args),
        }
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        wanted = {
            "current_season",
            "ensure_season_globals",
            "_season_bootstrap",
            "public_standings",
            "_public_standings_no_cache",
            "handle_any",
        }
        nodes = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in wanted
        ]
        self.assertEqual(len(nodes), len(wanted))
        # Execute only checked-in route ASTs, never application startup or env loading.
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "actual app hooks", "exec"), env)  # noqa: S102
        self.client = self.app.test_client()

    def tearDown(self):
        self.assertEqual(self.db.forbidden, [])

    def get(self, status=200):
        response = self.client.get("/standings")
        self.assertEqual(response.status_code, status)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertIn("no-cache", response.headers["Cache-Control"])
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertNotIn("PRIVATE_DATABASE_DETAIL", response.get_data(as_text=True))
        return response.json

    def test_anonymous_complete_response_and_authoritative_stats(self):
        body = self.get()
        self.assertEqual(set(body), {"season_code", "status", "east", "west"})
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["season_code"], "2026-27")
        by_code = {row["code"]: row for row in self.db.rows}
        for conference, codes in (("east", EAST), ("west", WEST)):
            self.assertEqual([row["code"] for row in body[conference]], codes)
            self.assertEqual([row["seed"] for row in body[conference]], list(range(1, 16)))
            for row in body[conference]:
                self.assertEqual(row, by_code[row["code"]])

    def test_no_master_or_private_account_queries(self):
        self.get()
        self.assertEqual(
            {name for name, _ in self.db.calls},
            {"application_season", "seasons", "standings", "teams"},
        )

    def test_observed_ties_and_gaps_are_preserved(self):
        for row in self.db.rows:
            if row["conference"] == "east" and row["seed"] not in (1, 15):
                row["seed"] = 2
            if row["conference"] == "west":
                row["seed"] = 1
        body = self.get()
        self.assertEqual([r["seed"] for r in body["east"]], [1] + [2] * 13 + [15])
        self.assertEqual([r["seed"] for r in body["west"]], [1] * 15)

    def test_rank_is_not_recalculated_from_wins(self):
        for row in self.db.rows:
            row["wins"] = row["seed"]
            row["losses"] = 20 - row["seed"]
            row["win_pct"] = row["wins"] / 20
        body = self.get()
        self.assertEqual([r["seed"] for r in body["east"]], list(range(1, 16)))
        self.assertEqual([r["wins"] for r in body["east"]], list(range(1, 16)))

    def test_empty_standings_are_explicit_and_read_only(self):
        self.db.rows = []
        self.assertEqual(
            self.get(),
            {"season_code": "2026-27", "status": "empty", "east": [], "west": []},
        )
        self.assertNotIn("teams", [name for name, _ in self.db.calls])

    def test_incomplete_rows_never_return_partial_standings(self):
        self.db.rows.pop()
        body = self.get(503)
        self.assertEqual(body["status"], "unavailable")
        self.assertNotIn("east", body)

    def test_null_rows_are_an_error_not_an_empty_season(self):
        self.db.rows = None
        self.assertEqual(self.get(503)["status"], "unavailable")

    def test_wrong_conference_and_duplicate_teams_rejected(self):
        for change in ("conference", "duplicate"):
            with self.subTest(change=change):
                self.db.rows = stored_rows()
                if change == "conference":
                    self.db.rows[0]["conference"] = "east"
                else:
                    self.db.rows[0] = copy.deepcopy(self.db.rows[1])
                self.get(503)

    def test_invalid_stored_values_are_rejected_without_fabrication(self):
        for field, value in (("seed", None), ("seed", 16), ("wins", -1), ("win_pct", 2)):
            with self.subTest(field=field, value=value):
                self.db.rows = stored_rows()
                self.db.rows[0][field] = value
                self.get(503)

    def test_failure_of_either_public_table_is_sanitized(self):
        for name in ("standings", "teams"):
            with self.subTest(table=name):
                self.db.fail_table = name
                body = self.get(503)
                self.assertEqual(
                    body,
                    {"status": "unavailable", "error": "Current standings unavailable"},
                )

    def test_canonical_bootstrap_failures_also_prevent_caching(self):
        for name in ("application_season", "seasons"):
            with self.subTest(table=name):
                self.db.fail_table = name
                self.get(503)
        self.db.fail_table = None
        self.db.pointer_rows = []
        self.get(503)

    def test_canonical_season_not_calendar_or_master_derived(self):
        with patch.dict("os.environ", {"CURRENT_SEASON_CODE": "1900-01"}):
            self.assertEqual(self.get()["season_code"], "2026-27")

    def test_rollover_during_reads_fails_closed(self):
        self.db.rollover = True
        self.assertEqual(self.get(503)["status"], "unavailable")

    def test_repeated_reads_do_not_initialize_or_refresh(self):
        self.get()
        self.get()
        self.assertEqual(self.db.rows, self.before)
        self.assertEqual(self.db.season_reads, 4)

    def test_projection_does_not_expose_additional_stored_fields(self):
        for row in self.db.rows:
            row["private_metadata"] = "DO_NOT_EXPOSE"
            row["id"] = 123
        body = self.get()
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(body))
        self.assertNotIn("id", body["east"][0])
        self.assertEqual(
            next(columns for name, columns in self.db.calls if name == "standings"),
            ["code", "name", "conference", "seed", "wins", "losses", "win_pct"],
        )

    def test_operational_routes_and_logic_unchanged(self):
        source = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        names = {
            "fetch_and_sync_standings_from_nba",
            "admin_refresh_standings",
            "internal_cron_refresh_standings",
            "internal_overwrite_standings",
        }
        selected = [
            node
            for node in source.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        self.assertEqual(len(selected), len(names))
        signature = hashlib.sha256(
            ast.dump(ast.Module(body=selected, type_ignores=[])).encode()
        ).hexdigest()
        self.assertEqual(signature, "fffeee44fd92ba8e7e34448cf0d44675788ef9d1413641cb3efba9fdef1e6670")


if __name__ == "__main__":
    unittest.main()
