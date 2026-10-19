"""ESPN-only current standings: validate completely, publish once, never fallback."""

from datetime import datetime, timezone
import json
import math
import re
import requests
from canonical_season import get_current_season, espn_season_year
from provider_transport import provider_get
from job_safety import guard_runtime_job

EAST = "ATL BOS BKN CHA CHI CLE DET IND MIA MIL NYK ORL PHI TOR WAS".split()
WEST = "DAL DEN GSW HOU LAC LAL MEM MIN NOP OKC PHX POR SAC SAS UTA".split()
CONFERENCES = {**dict.fromkeys(EAST, "east"), **dict.fromkeys(WEST, "west")}
ALIASES = {
    "NY": "NYK",
    "GS": "GSW",
    "SA": "SAS",
    "NO": "NOP",
    "WSH": "WAS",
    "UTAH": "UTA",
}
ESPN_IDS = dict(
    zip(
        "ATL BOS NOP CHI CLE DAL DEN DET GSW HOU IND LAC LAL MIA MIL MIN BKN NYK ORL PHI PHX POR SAC SAS OKC UTA WAS TOR MEM CHA".split(),
        map(str, range(1, 31)),
    )
)
URL = "https://site.web.api.espn.com/apis/v2/sports/basketball/nba/standings?region=us&lang=en&contentorigin=espn&type=0&level=1&sort=winpercent%3Adesc%2Cwins%3Adesc%2Cgamesbehind%3Aasc&season={season}"


class StandingsRefreshError(RuntimeError):
    def __init__(self, stage):
        self.stage = stage
        super().__init__("Standings refresh failed: " + stage)


def integer(value):
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    raise StandingsRefreshError("validation_failure")


def canonical_teams(teams):
    result = {}
    for team in teams:
        code = team.get("code")
        if code not in CONFERENCES:
            continue  # Unrelated maintenance teams are not NBA canonical identities.
        if (
            code in result
            or str(team.get("conference", "")).lower() != CONFERENCES[code]
        ):
            raise StandingsRefreshError("mapping_failure")
        if not isinstance(team.get("name"), str) or not team["name"].strip():
            raise StandingsRefreshError("mapping_failure")
        result[code] = team
    if set(result) != set(CONFERENCES):
        raise StandingsRefreshError("mapping_failure")
    return result


def validate_rows(rows, teams):
    canonical = canonical_teams(teams)
    if not isinstance(rows, list) or len(rows) != 30:
        raise StandingsRefreshError("validation_failure")
    seen, ranks = set(), {"east": set(), "west": set()}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "code",
            "name",
            "conference",
            "seed",
            "wins",
            "losses",
            "win_pct",
        }:
            raise StandingsRefreshError("validation_failure")
        code = row["code"]
        if (
            code not in canonical
            or code in seen
            or row["conference"] != CONFERENCES[code]
        ):
            raise StandingsRefreshError("validation_failure")
        seed = integer(row["seed"])
        if (
            type(row["seed"]) is not int
            or not 1 <= seed <= 15
            or seed in ranks[row["conference"]]
        ):
            raise StandingsRefreshError("validation_failure")
        for key in ("wins", "losses"):
            if integer(row[key]) < 0 or type(row[key]) is not int:
                raise StandingsRefreshError("validation_failure")
        pct = row["win_pct"]
        if type(pct) not in (int, float) or not math.isfinite(pct) or not 0 <= pct <= 1:
            raise StandingsRefreshError("validation_failure")
        games = row["wins"] + row["losses"]
        expected = row["wins"] / games if games else 0.0
        if (
            abs(pct - expected) > 0.001
            or not isinstance(row["name"], str)
            or not row["name"].strip()
        ):
            raise StandingsRefreshError("validation_failure")
        seen.add(code)
        ranks[row["conference"]].add(seed)
    if seen != set(canonical) or any(
        value != set(range(1, 16)) for value in ranks.values()
    ):
        raise StandingsRefreshError("validation_failure")
    return sorted(rows, key=lambda row: row["code"])


def parse_espn(data, teams):
    canonical = canonical_teams(teams)
    try:
        if not isinstance(data, dict):
            raise ValueError()
        if "league" in data:
            league = data["league"]
            slug = league.get("slug") if isinstance(league, dict) else league
            if slug != "nba":
                raise StandingsRefreshError("mapping_failure")
        groups = data["standings"]
        groups = groups if isinstance(groups, list) else [groups]
        entries = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(
                group.get("entries"), list
            ):
                raise ValueError()
            entries.extend(group["entries"])
    except (KeyError, TypeError, ValueError):
        raise StandingsRefreshError("parsing_failure") from None
    rows = []
    seen_provider = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("team"), dict)
            or not isinstance(entry.get("stats"), list)
        ):
            raise StandingsRefreshError("parsing_failure")
        team = entry["team"]
        raw_code = team.get("abbreviation")
        if not isinstance(raw_code, str) or raw_code in seen_provider:
            raise StandingsRefreshError("mapping_failure")
        seen_provider.add(raw_code)
        code = ALIASES.get(raw_code, raw_code)
        if code not in canonical or (
            "id" in team and str(team["id"]) != ESPN_IDS[code]
        ):
            raise StandingsRefreshError("mapping_failure")
        if (
            "conference" in team
            and str(team["conference"]).lower() != CONFERENCES[code]
        ):
            raise StandingsRefreshError("mapping_failure")
        stats = {}
        for stat in entry["stats"]:
            if not isinstance(stat, dict):
                raise StandingsRefreshError("parsing_failure")
            key = stat.get("type") or stat.get("name")
            if not isinstance(key, str) or key in stats:
                raise StandingsRefreshError("parsing_failure")
            value = stat.get("value")
            stats[key] = stat.get("summary") if value is None or value == "" else value
        try:
            wins, losses, seed = (
                integer(stats[key]) for key in ("wins", "losses", "playoffseed")
            )
            pct = wins / (wins + losses) if wins + losses else 0.0
            if "winpercent" in stats:
                supplied = stats["winpercent"]
                if isinstance(supplied, bool) or supplied is None:
                    raise ValueError()
                supplied = float(supplied)
                if (
                    not math.isfinite(supplied)
                    or not 0 <= supplied <= 1
                    or abs(supplied - pct) > 0.001
                ):
                    raise ValueError()
        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            raise StandingsRefreshError("validation_failure") from None
        rows.append(
            dict(
                code=code,
                name=canonical[code]["name"],
                conference=CONFERENCES[code],
                seed=seed,
                wins=wins,
                losses=losses,
                win_pct=pct,
            )
        )
    return validate_rows(rows, teams)


def fetch_espn(year):
    try:
        response = provider_get(
            requests.get,
            URL.format(season=year),
            timeout=30,
            headers={"Accept": "application/json", "User-Agent": "NBACorner standings"},
        )
        response.raise_for_status()
    except Exception:
        raise StandingsRefreshError("provider_failure") from None
    try:
        return response.json()
    except Exception:
        raise StandingsRefreshError("parsing_failure") from None


def utc_now():
    return datetime.now(timezone.utc)


def refresh_current_standings(client, *, now=None):
    guard_runtime_job("standings-refresh")
    now = now or utc_now
    season = get_current_season(client)
    if now() >= season.bracket_creation_opens_at:
        return {
            "state": "frozen",
            "refreshed": False,
            "season_code": season.code,
            "team_count": 0,
        }
    try:
        data = fetch_espn(espn_season_year(season.code))
        teams = (
            client.table("teams").select("id, code, name, conference").execute().data
            or []
        )
        rows = parse_espn(data, teams)
        result = (
            client.rpc(
                "publish_current_standings", {"p_season_id": season.id, "p_rows": rows}
            )
            .execute()
            .data
        )
        if not isinstance(result, dict) or result.get("state") not in {
            "refreshed",
            "frozen",
        }:
            raise StandingsRefreshError("publish_failure")
        return result
    except StandingsRefreshError:
        raise
    except Exception:
        raise StandingsRefreshError("publish_failure") from None


def log_result(result):
    # Explicit safe operational allowlist; never provider bodies, exceptions or env.
    print(
        json.dumps(
            {
                key: result[key]
                for key in ("state", "season_code", "team_count")
                if key in result
            },
            sort_keys=True,
        )
    )
