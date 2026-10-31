"""Offline STATS-02D boundary/ranking/auth tests. No app startup or network."""

import ast
from datetime import datetime, timedelta, timezone
from functools import wraps
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from flask import Flask, jsonify, request
import jwt
import requests
from daily_assertion_service import daily_assertion_private_response
from daily_stats_service import (
    CONTRACT,
    TIMEZONE,
    StatsUnavailable,
    StatsInvalidMonth,
    assemble_stats,
    fetch_inputs,
    get_daily_stats,
    validate_inputs,
    validated_month,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
CONFIG = {
    "DAILY_STATS_READ_URL": "https://www.nbacorner.com/1on1/api/internal/daily/monthly-ranking-inputs",
    "DAILY_STATS_READ_TOKEN": "x" * 43,
}


def row(subject=None, cp=10, hints=5, predictions=2, eligible=None):
    return dict(
        nbaUserId=subject or str(uuid.uuid4()),
        correctPlayers=cp,
        correctPredictions=predictions,
        hintNumerator=hints,
        hintDenominator=cp,
        rankingEligible=cp > 0 if eligible is None else eligible,
    )


def payload(rows=(), month="2026-11"):
    return dict(contract=CONTRACT, month=month, timezone=TIMEZONE, subjects=list(rows))


class DB:
    def __init__(self, users):
        self.users = users
        self.queries = []

    def table(self, name):
        assert name == "users"
        db = self

        class Query:
            def select(self, columns):
                self.columns = columns
                return self

            def eq(self, key, value):
                self.ids = [value]
                return self

            def in_(self, key, values):
                self.ids = values
                return self

            def limit(self, value):
                assert value == len(self.ids)
                return self

            def execute(self):
                db.queries.append((self.columns, self.ids))
                return SimpleNamespace(
                    data=[
                        {k: u[k] for k in self.columns.split(",") if k in u}
                        for u in db.users
                        if u["id"] in self.ids
                    ]
                )

        return Query()


class Response:
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, value):
        self.body = json.dumps(value).encode()
        self.failure = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size):
        if self.failure:
            raise self.failure
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i : i + chunk_size]


class Session:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.trust_env = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        assert self.trust_env is False
        return self.response


class DailyStatsTests(unittest.TestCase):
    def setUp(self):
        self.network = patch(
            "socket.socket.connect", side_effect=AssertionError("No network permitted")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def facade(self, rows, names=None, current=None, month="2026-11"):
        ids = [r["nbaUserId"] for r in rows]
        current = current or (ids[0] if ids else str(uuid.uuid4()))
        users = [
            {"id": k, "username": v, "auth_version": 3}
            for k, v in (
                names or {i: "User" + str(n) for n, i in enumerate(ids)}
            ).items()
        ]
        if current not in {u["id"] for u in users}:
            users.append({"id": current, "username": "Current", "auth_version": 3})
        db = DB(users)
        response = Response(payload(rows, month))
        session = Session(response)
        result = get_daily_stats(
            current, month, db, environ=CONFIG, now=NOW, session_factory=lambda: session
        )
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(len(db.queries), 1)
        self.assertEqual(db.queries[0][0], "id,username")
        self.assertEqual(
            set(session.calls[0][1]["headers"]), {"Accept", "X-Daily-Stats-Read-Token"}
        )
        self.assertEqual(session.calls[0][1]["timeout"], (2, 3))
        self.assertFalse(session.calls[0][1]["allow_redirects"])
        self.assertNotIn("Authorization", session.calls[0][1]["headers"])
        public = json.dumps(result)
        for subject in set(ids) | {current}:
            self.assertNotIn(subject, public)
        self.assertNotIn(CONFIG["DAILY_STATS_READ_TOKEN"], public)
        self.assertNotIn("hintNumerator", public)
        return result

    def test_primary_correct_players_beats_average(self):
        a, b = row(cp=20, hints=40), row(cp=19, hints=0)
        result = self.facade([b, a])
        self.assertEqual([r["correctPlayers"] for r in result["top3"]], [20, 19])

    def test_average_and_exact_fractions_not_display_rounding(self):
        a, b = row(cp=60, hints=7), row(cp=60, hints=8)
        self.assertEqual(format(7 / 60, ".1f"), format(8 / 60, ".1f"))
        result = self.facade([b, a])
        self.assertEqual([r["averageHints"] for r in result["top3"]], [7 / 60, 8 / 60])
        self.assertEqual(result["me"]["rank"], 2)

    def test_current_username_order_and_unicode_casefold(self):
        rows = [row() for _ in range(5)]
        names = dict(
            zip(
                [r["nbaUserId"] for r in rows],
                ["charlie", "Bob", "alice", "Straße", "strassf"],
            )
        )
        result = self.facade(rows, names)
        self.assertEqual(
            [r["username"] for r in result["top3"]], ["alice", "Bob", "charlie"]
        )
        # Unicode casefold compares Straße as strasse, preserving displayed spelling.
        result = self.facade(
            rows[3:], {r["nbaUserId"]: names[r["nbaUserId"]] for r in rows[3:]}
        )
        self.assertEqual([r["username"] for r in result["top3"]], ["Straße", "strassf"])

    def test_unicode_canonical_equivalents_use_hidden_fallback_without_mutating_names(
        self,
    ):
        a = row("00000000-0000-4000-8000-000000000001")
        b = row("00000000-0000-4000-8000-000000000002")
        names = {a["nbaUserId"]: "\u00c9clair", b["nbaUserId"]: "E\u0301CLAIR"}
        result = self.facade([b, a], names)
        self.assertEqual(result["me"]["rank"], 2)
        self.assertEqual(
            [r["username"] for r in result["top3"]],
            [names[a["nbaUserId"]], names[b["nbaUserId"]]],
        )

    def test_hidden_uuid_fallback_is_stable_and_never_public(self):
        a = row("00000000-0000-4000-8000-000000000001")
        b = row("00000000-0000-4000-8000-000000000002")
        result = self.facade([b, a], {a["nbaUserId"]: "ALICE", b["nbaUserId"]: "alice"})
        self.assertEqual(result["me"]["rank"], 2)
        self.assertEqual([r["rank"] for r in result["top3"]], [1, 2])
        self.assertEqual([r["username"] for r in result["top3"]], ["ALICE", "alice"])

    def test_rename_changes_next_read_and_missing_accounts_drop_before_rank(self):
        a, b, missing = row(), row(), row(cp=30, hints=0)
        names = {a["nbaUserId"]: "Zulu", b["nbaUserId"]: "Alpha"}
        result = self.facade([a, b, missing], names)
        self.assertEqual(result["participantCount"], 2)
        self.assertEqual(result["me"]["rank"], 2)
        names[a["nbaUserId"]] = "Aardvark"
        self.assertEqual(self.facade([a, b, missing], names)["me"]["rank"], 1)

    def test_zero_correct_predictions_only_unranked_and_absent_daily_subject_zero(self):
        a = row(cp=0, hints=0, predictions=12)
        result = self.facade([a])
        self.assertEqual(
            result["me"],
            {
                "username": "User0",
                "correctPlayers": 0,
                "correctPredictions": 12,
                "averageHints": None,
                "rank": None,
            },
        )
        self.assertEqual(result["top3"], [])
        self.assertEqual(result["neighborhood"], [])
        result = self.facade([])
        self.assertEqual(result["me"]["correctPlayers"], 0)
        self.assertEqual(result["me"]["correctPredictions"], 0)
        self.assertIsNone(result["me"]["averageHints"])
        self.assertIsNone(result["me"]["rank"])

    def test_disabled_ranking_flag_keeps_personal_stats(self):
        result = self.facade([row(cp=4, hints=6, eligible=False)])
        self.assertEqual(result["me"]["correctPlayers"], 4)
        self.assertEqual(result["me"]["averageHints"], 1.5)
        self.assertIsNone(result["me"]["rank"])
        self.assertEqual(result["participantCount"], 0)

    def test_top3_and_neighborhood_all_boundaries(self):
        for count in (0, 1, 2, 3, 4, 12):
            rows = [row(cp=24 - i, hints=0) for i in range(count)]
            names = {r["nbaUserId"]: "User" + str(i) for i, r in enumerate(rows)}
            for index in range(max(1, count)):
                with self.subTest(count=count, rank=index + 1):
                    result = self.facade(
                        rows, names, current=rows[index]["nbaUserId"] if rows else None
                    )
                    self.assertEqual(len(result["top3"]), min(3, count))
                    self.assertEqual(
                        [r["rank"] for r in result["top3"]],
                        list(range(1, min(3, count) + 1)),
                    )
                    expected = (
                        list(range(max(1, index - 1), min(count, index + 3) + 1))
                        if index >= 3
                        else []
                    )
                    self.assertEqual(
                        [r["rank"] for r in result["neighborhood"]], expected
                    )
                    self.assertEqual(
                        sum(
                            r.get("isCurrentUser", False)
                            for r in result["neighborhood"]
                        ),
                        1 if expected else 0,
                    )

    def test_non_displayable_users_and_missing_current_fail_closed(self):
        a, b = row(), row(cp=20)
        for bad in (None, "", "  ", "bad\nname", "x" * 81):
            with self.subTest(bad=repr(bad)):
                result = self.facade(
                    [a, b], {a["nbaUserId"]: "Valid", b["nbaUserId"]: bad}
                )
                self.assertEqual(result["participantCount"], 1)
        with self.assertRaises(StatsUnavailable):
            assemble_stats("2026-11", [a], [], a["nbaUserId"])

    def test_month_default_past_future_leap_and_vancouver_boundaries(self):
        for instant, month in [
            ("2026-11-01T06:59:59+00:00", "2026-10"),
            ("2026-11-01T07:00:00+00:00", "2026-11"),
            ("2027-01-01T07:59:59+00:00", "2026-12"),
            ("2027-01-01T08:00:00+00:00", "2027-01"),
        ]:
            self.assertEqual(
                validated_month(now=datetime.fromisoformat(instant)), month
            )
        self.assertEqual(validated_month("2024-02", now=NOW), "2024-02")
        for bad in ("2026-12", "2026-13", "0000-01", "26-11", "2026-1", "2026-11 ", ""):
            with self.subTest(month=bad), self.assertRaises(StatsInvalidMonth):
                validated_month(bad, now=NOW)

    def test_month_rollover_personal_rank_resets_without_changing_prior_response(self):
        subject = str(uuid.uuid4())
        october = self.facade(
            [row(subject, cp=4, hints=3, predictions=2)],
            current=subject,
            month="2026-10",
        )
        november = self.facade(
            [row(subject, cp=0, hints=0, predictions=0)], current=subject
        )
        self.assertEqual(october["me"]["rank"], 1)
        self.assertEqual(
            november["me"],
            {
                "username": "User0",
                "correctPlayers": 0,
                "correctPredictions": 0,
                "averageHints": None,
                "rank": None,
            },
        )
        self.assertEqual(
            october,
            self.facade(
                [row(subject, cp=4, hints=3, predictions=2)],
                current=subject,
                month="2026-10",
            ),
        )

    def test_complete_upstream_validation_rejects_all_malformed_rows(self):
        good = row()
        variants = [
            {"contract": "wrong"},
            {"timezone": "UTC"},
            {"month": "2026-10"},
            {"extra": 1},
            {"subjects": {}},
            {"subjects": [good, good]},
            {"subjects": [good, {**good, "nbaUserId": good["nbaUserId"].upper()}]},
        ]
        for field, value in [
            ("nbaUserId", "arbitrary"),
            ("correctPlayers", -1),
            ("correctPlayers", True),
            ("correctPlayers", 1.5),
            ("correctPredictions", 31),
            ("hintDenominator", 9),
            ("hintNumerator", 31),
            ("rankingEligible", 1),
        ]:
            variants.append({"subjects": [{**good, field: value}]})
        variants.extend(
            [
                {"subjects": [{**good, "email": "private"}]},
                {"subjects": [row(cp=0, hints=0, eligible=True)]},
                {"subjects": [row() for _ in range(501)]},
            ]
        )
        for change in variants:
            with self.subTest(change=str(change)[:80]), self.assertRaises(
                StatsUnavailable
            ):
                validate_inputs({**payload([good]), **change}, "2026-11")

    def test_transport_failures_timeout_redirect_size_json_and_duplicates_fail_closed(
        self,
    ):
        variants = []
        for status in (301, 401, 403, 500, 503):
            response = Response(payload())
            response.status_code = status
            variants.append(response)
        for body in (
            b"not json",
            b'{"contract":1,"contract":2}',
            b"NaN",
            b"x" * 524289,
        ):
            response = Response(payload())
            response.body = body
            variants.append(response)
        response = Response(payload())
        response.failure = requests.Timeout("secret URL")
        variants.append(response)
        response = Response(payload())
        response.headers = {"Content-Type": "text/html"}
        variants.append(response)
        response = Response(payload())
        response.headers = {
            "Content-Type": "application/json",
            "Content-Length": "99999999",
        }
        variants.append(response)
        for response in variants:
            with self.subTest(status=response.status_code), self.assertRaises(
                StatsUnavailable
            ) as caught:
                fetch_inputs(
                    "2026-11", CONFIG, session_factory=lambda: Session(response)
                )
            self.assertEqual(str(caught.exception), "")

    def test_only_configured_controlled_prefixed_url_and_dedicated_token(self):
        for change in (
            {},
            {
                "DAILY_STATS_READ_URL": "https://1on1ball.com/api/internal/daily/monthly-ranking-inputs"
            },
            {
                "DAILY_STATS_READ_URL": "https://evil.example/1on1/api/internal/daily/monthly-ranking-inputs"
            },
            {"DAILY_STATS_READ_TOKEN": "short"},
            {"DAILY_STATS_READ_URL": CONFIG["DAILY_STATS_READ_URL"] + "?token=secret"},
        ):
            config = {**CONFIG, **change} if change else {}
            with self.assertRaises(StatsUnavailable):
                fetch_inputs(
                    "2026-11",
                    config,
                    session_factory=lambda: (_ for _ in ()).throw(
                        AssertionError("must not call")
                    ),
                )


class AuthenticatedFacadeTests(unittest.TestCase):
    def setUp(self):
        self.network = patch(
            "socket.socket.connect", side_effect=AssertionError("No network")
        )
        self.network.start()
        self.addCleanup(self.network.stop)
        self.subject = str(uuid.uuid4())
        self.data = payload([row(self.subject)])
        self.response = Response(self.data)
        self.session = Session(self.response)
        self.db = DB(
            [{"id": self.subject, "username": "CurrentCanonical", "auth_version": 3}]
        )
        self.rate = Mock(return_value=False)
        app = Flask(__name__)
        self.secret = "offline-only-nba-signing-secret-at-least32bytes"
        env = dict(
            app=app,
            request=request,
            jsonify=jsonify,
            wraps=wraps,
            jwt=jwt,
            JWT_SECRET=self.secret,
            JWT_ALGORITHM="HS256",
            supabase=self.db,
            daily_assertion_private_response=daily_assertion_private_response,
            StatsInvalidMonth=StatsInvalidMonth,
            get_daily_stats=lambda subject, month, db: get_daily_stats(
                subject,
                month,
                db,
                environ=CONFIG,
                now=NOW,
                session_factory=lambda: self.session,
            ),
            is_rate_limited=self.rate,
            get_client_ip=lambda: "offline",
        )
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        nodes = [
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name in {"decode_token", "require_auth", "daily_stats"}
        ]
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]), "isolated daily facade", "exec"
            ),
            env,
        )
        self.client = app.test_client()

    def token(self, **changes):
        claims = dict(
            user_id=self.subject,
            username="UNTRUSTED-CACHED",
            av=3,
            exp=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        claims.update(changes)
        return jwt.encode(claims, self.secret, algorithm="HS256")

    def get(self, token=None, query="?month=2026-11"):
        return self.client.get(
            "/daily/stats" + query,
            headers={"Authorization": "Bearer " + token} if token else {},
        )

    def test_actual_route_uses_normal_auth_and_current_name_not_jwt_name(self):
        response = self.get(self.token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["me"]["username"], "CurrentCanonical")
        self.assertEqual(
            [q[0] for q in self.db.queries], ["id,auth_version", "id,username"]
        )
        self.assertEqual(len(self.session.calls), 1)
        self.assertNotIn("Authorization", self.session.calls[0][1]["headers"])
        self.assertNotIn(self.subject, response.get_data(as_text=True))
        self.assertIn("private, no-store", response.headers["Cache-Control"])

    def test_missing_bad_expired_auth_version_and_deleted_current_rejected(self):
        for token in (
            None,
            "bad",
            self.token(exp=datetime.now(timezone.utc) - timedelta(seconds=1)),
            self.token(av=4),
        ):
            self.assertEqual(self.get(token).status_code, 401)
        self.db.users = []
        self.assertEqual(self.get(self.token()).status_code, 401)
        self.assertEqual(self.session.calls, [])

    def test_month_and_identity_selectors_are_not_trusted(self):
        for query in (
            "?month=2026-11&month=2026-11",
            "?nbaUserId=" + self.subject,
            "?username=Other",
            "?userId=" + self.subject,
            "?month=2026-12",
            "?month=bad",
        ):
            response = self.get(self.token(), query)
            self.assertEqual(response.status_code, 400)
            self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(self.session.calls, [])

    def test_unavailable_and_throttle_are_sanitized(self):
        self.response.failure = requests.Timeout("credential UUID secret failure")
        response = self.get(self.token())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json, {"error": "Daily stats unavailable"})
        self.rate.return_value = True
        self.assertEqual(self.get(self.token()).status_code, 429)
