"""Actual bracket route in isolated Flask; no app startup, network or database."""

import ast
import copy
import json
from pathlib import Path
import random
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid
from flask import Flask, request, jsonify
from synthetic_fixtures import foundation
from standings_service import parse_espn
from playoff_seeding import required_playoff_teams, AmbiguousPlayoffSeeding

ROOT = Path(__file__).resolve().parents[2]


class PlayoffSeedingTests(unittest.TestCase):
    def setUp(self):
        self.network = patch(
            "socket.socket.connect", side_effect=AssertionError("Offline only")
        )
        self.network.start()
        self.addCleanup(self.network.stop)
        self.teams = foundation()["teams"]
        data = json.loads(
            (
                ROOT / "tests/fixtures/providers/espn-standings-complete-2027.json"
            ).read_text()
        )
        self.rows = parse_espn(data, self.teams, expected_year=2027)
        self.by_code = {t["code"]: t for t in self.teams}

    def route(self, rows):
        app = Flask(__name__)
        db = Mock()

        def table(name):
            query = Mock()
            query.select.return_value = query
            query.eq.return_value = query
            query.limit.return_value = query
            query.execute.return_value.data = {
                "users": [{"is_admin": True}],
                "teams": self.teams,
                "standings": rows,
            }[name]
            return query

        db.table.side_effect = table
        db.rpc.return_value.execute.return_value.data = {
            "id": "synthetic-master",
            "is_master": True,
        }

        def auth(fn):
            def call():
                request.user = {"user_id": "synthetic-admin"}
                return fn()

            call.__name__ = fn.__name__
            return call

        env = dict(
            app=app,
            request=request,
            jsonify=jsonify,
            supabase=db,
            require_auth=auth,
            active_current_master_exists=lambda: False,
            current_season=lambda: SimpleNamespace(id="synthetic-season"),
            required_playoff_teams=required_playoff_teams,
            AmbiguousPlayoffSeeding=AmbiguousPlayoffSeeding,
            uuid=uuid,
            recompute_after_master_change=Mock(return_value=None),
        )
        node = next(
            n
            for n in ast.parse((ROOT / "app.py").read_text(encoding="utf-8")).body
            if isinstance(n, ast.FunctionDef) and n.name == "create_bracket_for_user"
        )
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "actual_bracket_route", "exec"
            ),
            env,
        )
        with app.test_client() as client:
            response = client.post("/bracket/create", json={})
        return response, db

    def test_unique_seed_creation_builds_same_21_match_graph(self):
        response, db = self.route(self.rows)
        self.assertEqual(response.status_code, 200)
        db.rpc.assert_called_once()
        name, args = db.rpc.call_args.args
        self.assertEqual(name, "create_master_bracket_atomic")
        self.assertEqual(len(args["p_matches"]), 21)
        for conf in ["east", "west"]:
            seeds = {
                r["seed"]: self.by_code[r["code"]]["id"]
                for r in self.rows
                if r["conference"] == conf
            }
            games = {m["slot"]: m for m in args["p_matches"] if m["conference"] == conf}
            self.assertEqual(
                (games[1]["team_a"], games[1]["team_b"]), (seeds[9], seeds[10])
            )
            self.assertEqual(
                (games[2]["team_a"], games[2]["team_b"]), (seeds[7], seeds[8])
            )
            self.assertEqual(
                (games[6]["team_a"], games[6]["team_b"]), (seeds[3], seeds[6])
            )

    def test_ambiguity_rejected_before_rpc_or_table_writes(self):
        for kind in ["all", "required", "cutoff", "missing"]:
            rows = copy.deepcopy(self.rows)
            if kind == "all":
                for row in rows:
                    row["seed"] = 1
            if kind == "required":
                next(r for r in rows if r["conference"] == "east" and r["seed"] == 2)[
                    "seed"
                ] = 1
            if kind == "cutoff":
                next(r for r in rows if r["conference"] == "west" and r["seed"] == 11)[
                    "seed"
                ] = 10
            if kind == "missing":
                rows = [
                    r
                    for r in rows
                    if not (r["conference"] == "east" and r["seed"] == 7)
                ]
            with self.subTest(kind=kind):
                response, db = self.route(rows)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(
                    response.json["error"],
                    "Standings do not yet provide unambiguous playoff seeding.",
                )
                db.rpc.assert_not_called()
                self.assertTrue(
                    all(
                        call.args[0] in {"users", "teams", "standings"}
                        for call in db.table.call_args_list
                    )
                )
                for call in db.table.return_value.method_calls:
                    self.fail("Unexpected table mutation")

    def test_harmless_ties_below_qualification_allowed(self):
        for row in self.rows:
            if row["seed"] > 10:
                row["seed"] = 11
        response, db = self.route(self.rows)
        self.assertEqual(response.status_code, 200)
        db.rpc.assert_called_once()

    def test_retrieval_order_never_resolves_ambiguous_slots(self):
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row["seed"] = 1
        for i in range(6):
            random.Random(i).shuffle(rows)
            with self.assertRaises(AmbiguousPlayoffSeeding):
                required_playoff_teams(rows, self.by_code)

    def test_valid_slots_independent_of_input_order(self):
        expected = required_playoff_teams(self.rows, self.by_code)
        random.Random(7).shuffle(self.rows)
        self.assertEqual(required_playoff_teams(self.rows, self.by_code), expected)
