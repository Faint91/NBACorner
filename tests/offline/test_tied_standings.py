"""NC-06E parser, source identity and publication admission, entirely offline."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
from canonical_season import CurrentSeason
from synthetic_fixtures import foundation
import standings_service as service

ROOT = Path(__file__).resolve().parents[2]


def payload():
    return json.loads(
        (
            ROOT / "tests/fixtures/providers/espn-standings-complete-2027.json"
        ).read_text()
    )


def tied(data, observed=False):
    for entry in data["standings"]["entries"]:
        stats = {s["type"]: s for s in entry["stats"]}
        if observed and entry["team"]["conference"] == "east":
            original = stats["playoffseed"]["value"]
            stats["playoffseed"]["value"] = (
                1 if original == 1 else 15 if original == 15 else 2
            )
        else:
            stats["playoffseed"]["value"] = 1
    return data


class TiedStandingsTests(unittest.TestCase):
    def setUp(self):
        self.net = patch(
            "socket.socket.connect", side_effect=AssertionError("Offline only")
        )
        self.net.start()
        self.addCleanup(self.net.stop)
        self.teams = foundation()["teams"]

    def test_unique_ranks_remain_valid(self):
        self.assertEqual(
            len(service.parse_espn(payload(), self.teams, expected_year=2027)), 30
        )

    def test_all_fifteen_tied_values_preserved(self):
        rows = service.parse_espn(tied(payload()), self.teams, expected_year=2027)
        self.assertEqual([r["seed"] for r in rows], [1] * 30)

    def test_observed_partial_ties_and_gaps_preserved(self):
        data = tied(payload(), observed=True)
        rows = service.parse_espn(data, self.teams, expected_year=2027)
        east = sorted(r["seed"] for r in rows if r["conference"] == "east")
        self.assertEqual(east, [1] + [2] * 13 + [15])
        from playoff_seeding import required_playoff_teams, AmbiguousPlayoffSeeding

        with self.assertRaises(AmbiguousPlayoffSeeding):
            required_playoff_teams(rows, {t["code"]: t for t in self.teams})
        self.assertEqual(sum(r["conference"] == "west" for r in rows), 15)
        self.assertTrue(all(r["seed"] == 1 for r in rows if r["conference"] == "west"))

    def test_missing_malformed_or_conflicting_identity_rejected(self):
        variants = []
        for value in [
            None,
            {},
            {"year": 2026},
            {"year": True},
            {"year": "2027"},
            {"year": 2027, "displayName": "2025-26"},
        ]:
            data = payload()
            data["season"] = value
            variants.append(data)
        data = payload()
        del data["season"]
        variants.append(data)
        data = payload()
        data["standings"]["season"] = 2026
        variants.append(data)
        data = payload()
        data["standings"]["seasonDisplayName"] = "2025-26"
        variants.append(data)
        for data in variants:
            with self.subTest(identity=data.get("season")), self.assertRaises(
                service.StandingsRefreshError
            ):
                service.parse_espn(data, self.teams, expected_year=2027)

    def test_ties_do_not_relax_identity_count_conference_or_numeric_checks(self):
        for kind in [
            "missing",
            "extra",
            "duplicate",
            "conference",
            "seed",
            "unknown",
            "wins",
        ]:
            data = tied(payload())
            entries = data["standings"]["entries"]
            if kind == "missing":
                entries.pop()
            if kind == "extra":
                entries.append(copy.deepcopy(entries[0]))
            if kind == "duplicate":
                entries[1] = copy.deepcopy(entries[0])
            if kind == "conference":
                entries[0]["team"]["conference"] = "west"
            if kind == "seed":
                entries[0]["stats"][3]["value"] = 0
            if kind == "unknown":
                entries[0]["team"]["abbreviation"] = "UNKNOWN"
            if kind == "wins":
                entries[0]["stats"][0]["value"] = -1
            with self.subTest(kind=kind), self.assertRaises(
                service.StandingsRefreshError
            ):
                service.parse_espn(data, self.teams, expected_year=2027)

    def refresh(self, data):
        client = Mock()
        client.table.return_value.select.return_value.execute.return_value.data = (
            self.teams
        )
        client.rpc.return_value.execute.return_value.data = {
            "state": "refreshed",
            "team_count": 30,
        }
        now = datetime.now(timezone.utc)
        season = CurrentSeason(
            "synthetic-season",
            "2026-27",
            now + timedelta(days=1),
            now + timedelta(days=2),
        )
        with patch.object(service, "guard_runtime_job"), patch.object(
            service, "get_current_season", return_value=season
        ), patch.object(service, "fetch_espn", return_value=data) as fetch:
            try:
                result = service.refresh_current_standings(client, now=lambda: now)
            except service.StandingsRefreshError:
                client.rpc.assert_not_called()
                client.table.return_value.insert.assert_not_called()
                raise
        fetch.assert_called_once_with(2027)
        return client, result

    def test_tied_refresh_has_one_standings_only_publication(self):
        client, result = self.refresh(tied(payload()))
        self.assertEqual(result["team_count"], 30)
        client.rpc.assert_called_once()
        self.assertEqual(client.rpc.call_args.args[0], "publish_current_standings")
        self.assertEqual(
            [r["seed"] for r in client.rpc.call_args.args[1]["p_rows"]], [1] * 30
        )
        client.table.assert_called_once_with("teams")

    def test_wrong_year_refresh_never_reaches_publication(self):
        data = payload()
        data["season"]["year"] = 2026
        with self.assertRaises(service.StandingsRefreshError):
            self.refresh(data)

    def test_missing_identity_refresh_never_reaches_publication(self):
        data = payload()
        del data["season"]
        with self.assertRaises(service.StandingsRefreshError):
            self.refresh(data)
