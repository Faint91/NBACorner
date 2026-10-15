"""Pure C2 parser, validator, orchestration and guard/security regressions."""

import copy, json, unittest, hashlib
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
from synthetic_fixtures import foundation
import standings_service as service
from canonical_season import CurrentSeason

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    return json.loads(
        (
            ROOT / "tests/fixtures/providers/espn-standings-complete-2026.json"
        ).read_text()
    )


class StandingsServiceTests(unittest.TestCase):
    def test_valid_fixture_and_aliases(self):
        rows = service.parse_espn(fixture(), foundation()["teams"])
        self.assertEqual(len(rows), 30)
        self.assertEqual({r["code"] for r in rows}, set(service.CONFERENCES))
        for alias, code in service.ALIASES.items():
            self.assertIn(code, {r["code"] for r in rows})

    def test_invalid_provider_datasets(self):
        mutations = []

        def mutated(fn):
            data = fixture()
            fn(data["standings"]["entries"])
            mutations.append(data)

        mutated(lambda rows: rows.pop())
        mutated(lambda rows: rows.append(copy.deepcopy(rows[0])))
        mutated(lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])))
        mutated(lambda rows: rows[0]["team"].update(abbreviation="UNKNOWN"))
        mutated(lambda rows: rows[0]["team"].update(id="999"))
        mutated(lambda rows: rows[0]["team"].update(conference="west"))
        for value in [0, 16, None, 1.5, True, "1.5"]:
            mutated(lambda rows, value=value: rows[0]["stats"][3].update(value=value))
        mutated(lambda rows: rows[1]["stats"][3].update(value=1))
        mutated(lambda rows: rows[0]["stats"].pop())
        for value in [None, -1, 1.2, True, "bad"]:
            mutated(lambda rows, value=value: rows[0]["stats"][0].update(value=value))
        mutated(lambda rows: rows[0]["stats"][2].update(value="NaN"))
        mutated(
            lambda rows: rows[0]["stats"].append(copy.deepcopy(rows[0]["stats"][0]))
        )
        mutated(lambda rows: rows[0].update(team=None))
        for data in mutations + [
            {"bad": []},
            {"standings": None},
            {**fixture(), "league": {"slug": "wnba"}},
        ]:
            with self.subTest(
                data=mutations.index(data) if data in mutations else "shape"
            ), self.assertRaises(service.StandingsRefreshError):
                service.parse_espn(data, foundation()["teams"])

    def test_normalized_validator_conf_split_and_fields(self):
        valid = service.parse_espn(fixture(), foundation()["teams"])
        for change in [
            lambda r: r.pop(),
            lambda r: r.append(copy.deepcopy(r[0])),
            lambda r: r[0].update(conference="bad"),
            lambda r: r[0].update(conference="west"),
            lambda r: r[0].update(seed=1.5),
            lambda r: r[0].update(wins=None),
            lambda r: r[0].update(losses=-1),
            lambda r: r[0].update(win_pct=float("inf")),
            lambda r: r[0].update(name=""),
            lambda r: r[0].update(unexpected=True),
        ]:
            rows = copy.deepcopy(valid)
            change(rows)
            with self.assertRaises(service.StandingsRefreshError):
                service.validate_rows(rows, foundation()["teams"])

    def test_zero_is_preserved(self):
        data = fixture()
        stats = data["standings"]["entries"][0]["stats"]
        stats[0]["value"] = 0
        stats[1]["value"] = 0
        stats[2]["value"] = 0
        rows = service.parse_espn(data, foundation()["teams"])
        self.assertEqual(next(r for r in rows if r["code"] == "ATL")["wins"], 0)

    def test_provider_and_parse_error_sanitized(self):
        with patch.object(
            service, "provider_get", side_effect=RuntimeError("SECRET_DIAGNOSTIC")
        ), self.assertRaises(service.StandingsRefreshError) as e:
            service.fetch_espn(2026)
        self.assertEqual(e.exception.stage, "provider_failure")
        self.assertNotIn("SECRET", str(e.exception))
        response = Mock()
        response.json.side_effect = ValueError("SECRET_BODY")
        with patch.object(
            service, "provider_get", return_value=response
        ), self.assertRaises(service.StandingsRefreshError) as e:
            service.fetch_espn(2026)
        self.assertEqual(e.exception.stage, "parsing_failure")

    def test_freeze_before_at_after(self):
        opening = datetime(2026, 4, 12, tzinfo=timezone.utc)
        season = CurrentSeason("fixed", "2025-26", opening, opening + timedelta(days=6))
        client = Mock()
        for delta in [0, 1, 86400]:
            with patch.object(service, "guard_runtime_job"), patch.object(
                service, "get_current_season", return_value=season
            ), patch.object(service, "fetch_espn") as fetch:
                result = service.refresh_current_standings(
                    client, now=lambda: opening + timedelta(seconds=delta)
                )
                self.assertEqual(result["state"], "frozen")
                fetch.assert_not_called()
                client.rpc.assert_not_called()

    def test_migration_security_and_verifier(self):
        from scripts.reset_local_fixtures import VERIFIER_SHA

        sql = (ROOT / "db/post-baseline/0003_nc_02c2_atomic_standings.sql").read_text()
        for value in [
            "SECURITY INVOKER",
            "search_path=pg_catalog,public",
            "FROM PUBLIC,anon,authenticated",
            "TO postgres,service_role",
            "FOR UPDATE",
            "clock_timestamp() >= season_row.regular_season_end_utc",
        ]:
            self.assertIn(value, sql)
        self.assertLess(sql.index("DELETE FROM"), sql.index("INSERT INTO"))
        self.assertNotIn("playoffs_start_utc", sql)
        old = (
            (ROOT / "db/post-baseline/verify_nc_02c1_schema.sql")
            .read_text()
            .replace(
                "fix_season_master_on_bracket_soft_delete,set_master_bracket",
                "fix_season_master_on_bracket_soft_delete,publish_current_standings,set_master_bracket",
            )
            .rsplit("COMMIT;", 1)[0]
        )
        current = (ROOT / "db/post-baseline/verify_nc_02c2_schema.sql").read_text()
        self.assertEqual(current.split("DO $standings_verify$", 1)[0], old)
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "db/post-baseline/verify_current_schema.sql").read_bytes()
            ).hexdigest(),
            VERIFIER_SHA,
        )

    def test_no_unscoped_job_capability(self):
        from integration_harness import authorize_standings_test_job, GuardedHarness

        self.assertFalse(authorize_standings_test_job("standings-refresh"))
        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock(side_effect=RuntimeError("Lease"))
        with self.assertRaises(RuntimeError):
            c.standings_request("scheduled")
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02C1"
        with self.assertRaises(Exception):
            c.standings_request("scheduled")

    def test_seed_refusal_capability_cannot_run_team_maintenance(self):
        from environment_safety import SafetyError
        from integration_harness import GuardedHarness

        c = object.__new__(GuardedHarness)
        c._require_bracket_scope = Mock()
        c.characterization_scope = "NC-02C2"
        for payload in [
            None,
            {},
            {"seed_standings": False},
            {"seed_standings": True, "other": True},
        ]:
            with self.assertRaises(SafetyError):
                c.standings_request("seed", payload=payload)
