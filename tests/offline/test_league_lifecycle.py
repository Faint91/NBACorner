"""F1 policy and safety regressions without DB, network or application import."""

import ast
import hashlib
from pathlib import Path
import re
import unittest
from unittest.mock import Mock
from league_service import (
    LeagueError,
    normalize_name,
    password_text,
    hash_password,
    verify_password,
    mutate,
    rpc,
)
from integration_harness import GuardedHarness
from environment_safety import SafetyError
from synthetic_fixtures import identity

ROOT = Path(__file__).resolve().parents[2]


class LeaguePolicy(unittest.TestCase):
    def test_name_and_password_domains_and_unicode_whitespace(self):
        self.assertEqual(normalize_name("\u2003NBA Friends\u00a0"), "NBA Friends")
        self.assertEqual(normalize_name("x"), "x")
        self.assertEqual(len(normalize_name("x" * 80)), 80)
        for value in (None, 1, True, [], {}, "", "  ", "x" * 81, "\x00", "\ud800"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(LeagueError):
                    normalize_name(value)
        self.assertEqual(password_text(" x "), "x")
        for value in (None, False, 123, {}, [], " ", "x" * 129, "\x00", "\ud800"):
            with self.assertRaises(LeagueError):
                password_text(value)

    def test_bcrypt_long_utf8_no_truncation_and_legacy(self):
        for value in ("x", "x" * 72, "x" * 128, "é" * 128):
            stored = hash_password(value, 4)
            self.assertNotEqual(stored, value)
            self.assertTrue(verify_password(" " + value + " ", stored))
            self.assertFalse(verify_password(value[:-1] + "z", stored))
        self.assertFalse(verify_password("x", "invalid-hash"))

    def test_malformed_body_fails_before_database(self):
        client = Mock()
        for action in (
            "create",
            "join",
            "settings",
            "transfer",
            "remove",
            "leave",
            "delete",
        ):
            with self.assertRaises(LeagueError):
                mutate(client, action, identity("user-a"), body=[])
        client.assert_not_called()
        client.rpc.assert_not_called()
        client.table.assert_not_called()

    def test_f1_scope_narrow_and_older_scopes_no_new_owner_writes(self):
        lid = identity("league-public")
        uid = identity("user-a")
        for scope in (
            None,
            "NC-01A",
            "NC-01B",
            "NC-01C",
            "NC-02A2",
            "NC-02D2",
            "NC-02F1",
        ):
            c = object.__new__(GuardedHarness)
            c.characterization_scope = scope
            c._leagues = {lid}
            c._brackets = set()
            c._matches = set()
            c._auth_subjects = {uid}
            for method, path in (
                ("PATCH", f"/leagues/{lid}"),
                ("POST", f"/leagues/{lid}/ownership"),
                ("DELETE", f"/leagues/{lid}/members/{uid}"),
            ):
                if scope == "NC-02F1":
                    c._check_path(method, path)
                else:
                    with self.assertRaises(SafetyError):
                        c._check_path(method, path)
            if scope == "NC-02F1":
                for method, path in (
                    ("PATCH", f"/leagues/{identity('unregistered')}"),
                    ("POST", "/auth/register"),
                    ("DELETE", "/users/all"),
                ):
                    with self.assertRaises(SafetyError):
                        c._check_path(method, path)

    def test_f1_preserves_all_unrelated_e_verifier_assertions(self):
        frozen = (ROOT / "db/post-baseline/verify_nc_02e_schema.sql").read_text()
        current = (ROOT / "db/post-baseline/verify_nc_02f1_schema.sql").read_text()

        def assertions(text):
            return {m.group(0) for m in re.finditer(r"  IF .*?  END IF;", text, re.S)}

        removed = assertions(frozen) - assertions(current)
        self.assertEqual(len(removed), 7)
        self.assertTrue(
            all(
                "leagues_name_unique" in check or "string_agg(p.proname" in check
                for check in removed
            )
        )
        self.assertIn("nc_f1_owner_membership", current)
        self.assertEqual(current.count("DO $f1$ DECLARE f oid"), 9)
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_current_schema.sql").read_bytes()
            ).hexdigest(),
            __import__(
                "scripts.reset_local_fixtures", fromlist=["VERIFIER_SHA"]
            ).VERIFIER_SHA,
        )

    def test_normalization_db_whitespace_exact_and_old_routes_preserved(self):
        sql = (ROOT / "db/post-baseline/0008_nc_02f1_league_lifecycle.sql").read_text()
        trim = re.search(r"U&'([^']+)'", sql).group(1)
        actual = {int(x, 16) for x in re.findall(r"\\([0-9A-F]{4})", trim)}
        self.assertEqual(actual, {i for i in range(0x3100) if chr(i).isspace()})
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertLess(
            source.index("def update_league("),
            source.index('if __name__ == "__main__"'),
        )
        for name in ("create_league", "join_league", "leave_league", "delete_league"):
            node = next(
                n
                for n in ast.parse(source).body
                if isinstance(n, ast.FunctionDef) and n.name == name
            )
            self.assertNotIn("playoffs_locked", ast.unparse(node))

    def test_unavailable_rpc_contract_fails_closed(self):
        client = Mock()
        for result in (
            None,
            [],
            {},
            {"ok": 1},
            {"ok": True, "password_hash": "untrusted"},
        ):
            if isinstance(result, dict) and result.get("ok") is True:
                continue
            client.rpc.return_value.execute.return_value.data = result
            with self.assertRaises(LeagueError) as error:
                rpc(client, "create_league_with_owner", {})
            self.assertEqual(error.exception.status, 503)
        client.rpc.return_value.execute.return_value.data = {
            "ok": False,
            "status": 409,
            "error": "League name is already in use",
        }
        with self.assertRaises(LeagueError) as error:
            rpc(client, "create_league_with_owner", {})
        self.assertEqual(error.exception.status, 409)
