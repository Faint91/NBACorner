import os
import requests
from datetime import datetime, timezone
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

DEBUG_STANDINGS = True

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is not set. "
        "Make sure they are in your .env or environment before running update_standings.py."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ Use ESPN's public standings API instead of the broken data.nba.net feed
ESPN_STANDINGS_URL_TEMPLATE = (
    "https://site.web.api.espn.com/apis/v2/sports/basketball/nba/standings"
    "?region=us&lang=en&contentorigin=espn&type=0&level=1"
    "&sort=winpercent%3Adesc%2Cwins%3Adesc%2Cgamesbehind%3Aasc&season={season}"
)

# Optional override: if set, we use this as the NBA season year (e.g. 2025 for 2025-26)
NBA_STANDINGS_SEASON_OVERRIDE = os.getenv("NBA_STANDINGS_SEASON")

# Static mapping from abbreviation (your teams.code) -> conference
EAST_WEST_BY_CODE = {
    # Eastern Conference
    "ATL": "East",
    "BOS": "East",
    "BKN": "East",
    "CHA": "East",
    "CHI": "East",
    "CLE": "East",
    "DET": "East",
    "IND": "East",
    "MIA": "East",
    "MIL": "East",
    "NYK": "East",
    "ORL": "East",
    "PHI": "East",
    "TOR": "East",
    "WAS": "East",
    # Western Conference
    "DAL": "West",
    "DEN": "West",
    "GSW": "West",
    "HOU": "West",
    "LAC": "West",
    "LAL": "West",
    "MEM": "West",
    "MIN": "West",
    "NOP": "West",
    "OKC": "West",
    "PHX": "West",
    "POR": "West",
    "SAC": "West",
    "SAS": "West",
    "UTA": "West",
}

# Map ESPN abbreviations to our DB team codes
ESPN_TO_DB_CODE = {
    "NY": "NYK",
    "GS": "GSW",
    "SA": "SAS",
    "NO": "NOP",
    "WSH": "WAS",
    "UTAH": "UTA",
}


def _current_nba_season_year(today=None):
    """Return the ESPN 'season' year (the END year of the season).

    Examples with ESPN:
      - 2024-25 season  -> season=2025
      - 2025-26 season  -> season=2026
    """
    if today is None:
        today = datetime.now(timezone.utc).date()

    # From August onward, we're in the season that ENDS next calendar year.
    #   e.g. 2025-10 (2025-26 season) -> 2026
    # Before August, we're in the season that ENDS this calendar year.
    #   e.g. 2026-03 (2025-26 season) -> 2026
    if today.month >= 8:
        return today.year + 1
    return today.year



def _safe_int(val, default=None):
    try:
        if val is None or val == "":
            return default
        return int(float(val))
    except Exception:
        return default


def _safe_float(val, default=0.0):
    try:
        if val is None or val == "":
            return default
        return float(val)
    except Exception:
        return default


def update_standings_from_json():
    # Determine which season to ask ESPN for
    if NBA_STANDINGS_SEASON_OVERRIDE:
        try:
            season_year = int(NBA_STANDINGS_SEASON_OVERRIDE)
        except ValueError:
            raise RuntimeError(
                "Invalid NBA_STANDINGS_SEASON override: %r"
                % (NBA_STANDINGS_SEASON_OVERRIDE,)
            )
    else:
        season_year = _current_nba_season_year()

    standings_url = ESPN_STANDINGS_URL_TEMPLATE.format(season=season_year)

    print(
        "[%s] 🏀 Fetching latest NBA standings from ESPN feed for season %s..."
        % (datetime.now(timezone.utc), season_year)
    )

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
        }
        response = requests.get(standings_url, timeout=30, headers=headers)

        if DEBUG_STANDINGS:
            print("---- DEBUG: NBA standings HTTP response ----")
            print("URL: %s" % response.url)
            print("Status code: %s" % response.status_code)
            print("Response headers:")
            for k, v in response.headers.items():
                print("  %s: %s" % (k, v))
            print("First 500 chars of body:")
            print(response.text[:500])
            print("---- END DEBUG ----")

        response.raise_for_status()
        data = response.json()

        # ESPN structure: top-level "standings" key, then "entries" with team+stats
        raw_standings = data.get("standings")
        if isinstance(raw_standings, list):
            found = None
            for item in raw_standings:
                if isinstance(item, dict) and "entries" in item:
                    found = item
                    break
            raw_standings = found
        if not isinstance(raw_standings, dict):
            print("❌ No valid 'standings' object found in ESPN JSON.")
            return

        entries = raw_standings.get("entries") or []
        if not isinstance(entries, list) or not entries:
            print("❌ No 'entries' array found in ESPN standings JSON.")
            return

        print("✅ Retrieved %d teams from ESPN standings feed." % len(entries))

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            team = entry.get("team") or {}
            stats_list = entry.get("stats") or []

            if not isinstance(team, dict):
                continue

            name = (
                team.get("displayName")
                or team.get("name")
                or team.get("shortDisplayName")
            )
            # ESPN abbreviation (e.g. NY, GS, SA, NO, WSH, UTAH)
            raw_code = team.get("abbreviation") or team.get("shortDisplayName")
            # Translate to our DB code if needed (e.g. NY -> NYK)
            code = ESPN_TO_DB_CODE.get(raw_code, raw_code)

            # Build a stat_name -> value mapping
            stats_map = {}
            if isinstance(stats_list, list):
                for s in stats_list:
                    if not isinstance(s, dict):
                        continue
                    key = s.get("type") or s.get("name")
                    if not key:
                        continue
                    val = s.get("value")
                    if (val is None or val == "") and s.get("summary") not in (None, ""):
                        val = s.get("summary")
                    stats_map[str(key)] = val

            wins = _safe_int(stats_map.get("wins"), 0) or 0
            losses = _safe_int(stats_map.get("losses"), 0) or 0

            win_pct = _safe_float(stats_map.get("winpercent"), 0.0)
            if win_pct == 0.0:
                games = wins + losses
                win_pct = float(wins) / games if games > 0 else 0.0

            seed = _safe_int(stats_map.get("playoffseed"), None)

            if not code or not name:
                print("⚠️ Skipping invalid team entry (missing name/code): %r" % (team,))
                continue

            conference = EAST_WEST_BY_CODE.get(code)
            if not conference:
                print(f"⚠️ Unknown conference for code {code}, skipping.")
                continue

            seed_label = seed if seed is not None else "?"
            print(f"→ {conference} | Seed {seed_label} | {code} ({wins}-{losses})")

            # ---------- Manual UPSERT logic (no ON CONFLICT) ----------
            payload = {
                "name": name,
                "code": code,
                "conference": conference,
                "wins": wins,
                "losses": losses,
                "win_pct": win_pct,
                "seed": seed,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            # Check if a row for this code already exists
            existing = supabase.table("standings").select("id").eq("code", code).execute()
            existing_rows = existing.data or []

            if existing_rows:
                # Update existing row(s) for this team code
                supabase.table("standings").update(payload).eq("code", code).execute()
            else:
                # Insert new row
                supabase.table("standings").insert(payload).execute()
            # ---------------------------------------------------------

        print("✅ Standings table updated successfully.")

    except requests.HTTPError as e:
        print("🚨 HTTP error when fetching standings: %s" % e)
        if e.response is not None and DEBUG_STANDINGS:
            print("---- DEBUG: HTTPError response body snippet ----")
            print(e.response.text[:500])
            print("---- END DEBUG ----")
    except Exception as e:
        print("🚨 Error updating standings: %s" % e)


if __name__ == "__main__":
    update_standings_from_json()
