"""Exercise the history routes with synthetic records and a SELECT-only adapter."""
import ast
import copy
import re
import unittest
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

from flask import Flask, jsonify, request
from history_service import historical_bracket_links, public_columns, public_snapshot_rows


class ReadQuery:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)

    def select(self, fields, **kwargs):
        self.fields = fields.replace(" ", "").split(",")
        return self

    def eq(self, key, value):
        self.rows = [r for r in self.rows if r.get(key) == value]
        return self

    def is_(self, key, value):
        assert value in ("null", None)
        return self.eq(key, None)

    def in_(self, key, values):
        self.rows = [r for r in self.rows if r[key] in values]
        return self

    def order(self, key, desc=False):
        return self

    def or_(self, expr):
        assert expr == "is_final.is.null,is_final.eq.true"
        return self

    def limit(self, n):
        self.rows = self.rows[:n]
        return self

    def execute(self):
        rows = self.rows if self.fields == ["*"] else [
            {k: r.get(k) for k in self.fields} for r in self.rows
        ]
        return SimpleNamespace(data=rows, count=len(rows))


def bid(i):
    return str(UUID(int=i + 1))


class HistoryLinks(unittest.TestCase):
    def setUp(self):
        self.snap = dict(id="snap", season_id="past", season_code="2025-26", columns=[])
        self.tables = {
            "seasons": [dict(id="past", code="2025-26")],
            "leaderboard_history_snapshots": [self.snap],
            "leaderboard_history_rows": [dict(id=i, snapshot_id="snap", display_name="Same name", rank=1)
                                         for i in range(13)],
            "leaderboard_history_competitors": [dict(snapshot_row_id=i, user_id=str(i)) for i in range(13)],
            "leaderboard_history": [dict(user_id=str(i), bracket_id=bid(i), season_id="past", season_code="2025-26")
                                    for i in range(13)],
            "brackets": [dict(id=bid(i), user_id=str(i), season_id="past", is_done=True,
                              deleted_at=None, **{"seasons.code": "2025-26"}) for i in range(13)],
            "matches": [dict(id=k, bracket_id=bid(i), conference="east", round=1)
                        for i in range(13) for k in range(21)],
            "users": [],
        }
        self.reads = []
        def table(name):
            self.reads.append(name)
            return ReadQuery(self.tables[name])

        app = Flask(__name__)
        env = dict(app=app, jsonify=jsonify, request=request, wraps=wraps, re=re,
                   historical_bracket_links=historical_bracket_links, public_columns=public_columns,
                   public_snapshot_rows=public_snapshot_rows, supabase=SimpleNamespace(table=table),
                   current_season=lambda: SimpleNamespace(id="now", code="2026-27"),
                   is_uuid=lambda v: bool(UUID(v)), decode_token=lambda v: {"user_id": "0"} if v == "fixture" else None,
                   public_user=lambda row: {}, safe_print=Mock())
        names = {"bracket_read_auth", "competitive_bracket_eligible", "leaderboard_history_season", "get_bracket_by_id"}
        source = Path(__file__).resolve().parents[2] / "app.py"
        nodes = [n for n in ast.parse(source.read_text(encoding="utf-8-sig")).body if getattr(n, "name", "") in names]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "production routes", "exec"), env)
        self.client = app.test_client()
        self.log = env["safe_print"]

    def links(self):
        response = self.client.get("/leaderboard/history/" + self.snap["season_code"])
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("user_id", response.get_data(as_text=True))
        return [r["historical_bracket_id"] for r in response.json["rows"]]

    def test_all_thirteen_exact_destinations_and_read_only_matches(self):
        before = copy.deepcopy(self.tables)
        self.assertEqual(self.links(), [bid(i) for i in range(13)])
        for relation in ("leaderboard_history_competitors", "leaderboard_history", "brackets"):
            self.assertEqual(self.reads.count(relation), 1)
        for i in range(13):
            detail = self.client.get("/history/bracket/" + bid(i))
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json["bracket"]["id"], bid(i))
            self.assertIs(detail.json["bracket"]["read_only"], True)
            self.assertEqual(len(detail.json["matches"]["east"]["1"]), 21)
        self.assertEqual(self.tables, before)

    def test_missing_conflicting_and_ineligible_refs(self):
        mapping = self.tables["leaderboard_history_competitors"]
        mapping.pop(0)
        mapping.append(dict(snapshot_row_id=1, user_id="other"))
        archive = self.tables["leaderboard_history"]
        archive.append(dict(archive[2], bracket_id=bid(12)))
        archive[3]["user_id"] = "unrelated"
        archive[4]["season_code"] = "2024-25"
        archive[5]["season_id"] = "other"
        brackets = self.tables["brackets"]
        brackets[6]["is_done"] = False
        brackets[7]["deleted_at"] = "deleted"
        brackets[8]["season_id"] = "other"
        brackets[9]["user_id"] = "other"
        brackets[10]["seasons.code"] = "2026-27"
        self.assertEqual(self.links(), [None] * 11 + [bid(11), bid(12)])

    def test_failed_optional_lookup_logs_and_returns_no_unverified_ids(self):
        del self.tables["leaderboard_history_competitors"]
        self.assertEqual(self.links(), [None] * 13)
        self.log.assert_called_once_with("Historical bracket links unavailable")

    def test_summary_only_and_nonhistorical(self):
        for code in ("2026-27", "2027-28"):
            self.snap["season_code"] = code
            self.assertEqual(self.links(), [None] * 13)
        self.tables["leaderboard_history_competitors"].clear()
        for code in ("2024-25", "2017-18"):
            self.snap["season_code"] = code
            self.assertEqual(self.links(), [None] * 13)
        self.assertNotIn("brackets", self.reads)

    def test_viewer_still_enforces_access(self):
        path = "/history/bracket/" + bid(0)
        bracket = self.tables["brackets"][0]
        bracket["is_done"] = False
        self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.client.get(path, headers={"Authorization": "Bearer invalid"}).status_code, 401)
        self.assertTrue(self.client.get(path, headers={"Authorization": "Bearer fixture"}).json["bracket"]["read_only"])
        bracket["deleted_at"] = "deleted"
        self.assertEqual(self.client.get(path).status_code, 404)
        bracket.update(deleted_at=None, is_done=True, season_id="now")
        self.assertEqual(self.client.get(path).status_code, 404)
