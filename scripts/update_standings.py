import os
import time
import requests
from collections import defaultdict


API_BASE = "https://api.balldontlie.io/v1"

BALLDONTLIE_API_KEY = os.environ["BALLDONTLIE_API_KEY"]
BACKEND_BASE_URL = os.environ["BACKEND_BASE_URL"].rstrip("/")
STANDINGS_CRON_TOKEN = os.environ["STANDINGS_CRON_TOKEN"]
SEASON_YEAR = int(os.environ.get("NBA_SEASON_YEAR", "2025"))  # e.g. 2025 for 2025-26 season

HEADERS_BDL = {
    "Authorization": BALLDONTLIE_API_KEY,
}


def fetch_all_teams():
    """Fetch all NBA teams (abbreviation, full_name, conference) from Balldontlie."""
    url = f"{API_BASE}/teams"
    print(f"Fetching teams from {url}")
    resp = requests.get(url, headers=HEADERS_BDL, timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data") or []

    teams = {}
    for t in data:
        code = t.get("abbreviation")
        if not code:
            continue
        teams[code] = {
            "name": t.get("full_name") or t.get("name") or code,
            "conference": (t.get("conference") or "").lower(),
        }

    print(f"Loaded {len(teams)} teams from Balldontlie")
    return teams


def fetch_season_games_and_compute_records(season_year, teams_meta):
    """
    Walk all regular-season games for the given season, compute wins/losses per team.

    Respects the free tier rate-limit (5 req/min) by sleeping ~15s between pages.
    """
    wins = defaultdict(int)
    losses = defaultdict(int)

    cursor = None
    pages_fetched = 0
    max_pages = 100  # safety

    while True:
        params = {
            "seasons[]": season_year,
            "per_page": 100,
        }
        if cursor is not None:
            params["cursor"] = cursor

        url = f"{API_BASE}/games"
        print(f"Requesting games page (cursor={cursor}) from {url} with params={params}")
        resp = requests.get(url, headers=HEADERS_BDL, params=params, timeout=20)

        if resp.status_code == 429:
            # Hit rate limit; wait and retry same cursor
            retry_after = int(resp.headers.get("Retry-After") or 15)
            print(f"⚠️ Rate limited by Balldontlie (429). Sleeping {retry_after}s...")
            time.sleep(retry_after)
            continue

        resp.raise_for_status()
        payload = resp.json()
        games = payload.get("data") or []

        if not games:
            print("No more games returned; stopping pagination.")
            break

        # Process games
        for g in games:
            # Skip playoffs
            if g.get("postseason"):
                continue

            home = g.get("home_team") or {}
            away = g.get("visitor_team") or {}

            home_code = home.get("abbreviation")
            away_code = away.get("abbreviation")

            # Skip if we don't know the team code
            if home_code not in teams_meta or away_code not in teams_meta:
                continue

            home_score = g.get("home_team_score") or 0
            away_score = g.get("visitor_team_score") or 0

            # Skip games not yet played
            if home_score == 0 and away_score == 0:
                continue

            if home_score > away_score:
                wins[home_code] += 1
                losses[away_code] += 1
            elif away_score > home_score:
                wins[away_code] += 1
                losses[home_code] += 1
            # ties are ignored

        meta = payload.get("meta") or {}
        cursor = meta.get("next_cursor")
        pages_fetched += 1

        print(f"Page {pages_fetched} processed; next_cursor={cursor}")

        if not cursor or pages_fetched >= max_pages:
            break

        # Stay under 5 req/min (4 requests/minute ~ every 15s)
        time.sleep(15)

    print(f"Finished fetching games. Pages fetched: {pages_fetched}")
    return wins, losses, pages_fetched


def build_standings_rows(teams_meta, wins, losses):
    """Build standings rows with seeds per conference."""
    rows = []

    for raw_code, meta in teams_meta.items():
        # Normalize team code
        code = (raw_code or "").strip().upper()

        # Normalize conference
        conf_raw = meta.get("conference") or ""
        conf = conf_raw.strip().lower()

        # 🔧 Safety: if Wizards have a weird conference string, force them to East
        if code == "WAS" and conf not in ("east", "west"):
            conf = "east"

        # Only real NBA conferences
        if conf not in ("east", "west"):
            continue

        rows.append(
            {
                "code": code,
                "name": meta.get("name") or code,
                "conference": conf,
                "wins": int(wins.get(code, 0)),
                "losses": int(losses.get(code, 0)),
            }
        )

    # Sort and assign seeds per conference
    east = [r for r in rows if r["conference"] == "east"]
    west = [r for r in rows if r["conference"] == "west"]

    east_sorted = sorted(
        east,
        key=lambda r: (-r["wins"], r["losses"], r["name"]),
    )
    west_sorted = sorted(
        west,
        key=lambda r: (-r["wins"], r["losses"], r["name"]),
    )

    seeded_rows = []
    for i, r in enumerate(east_sorted, start=1):
        seeded_rows.append({**r, "seed": i})
    for i, r in enumerate(west_sorted, start=1):
        seeded_rows.append({**r, "seed": i})

    # Debug info to track missing teams like WAS
    print(f"Built {len(seeded_rows)} seeded rows (East+West).")

    all_team_codes = sorted((raw_code or "").strip().upper() for raw_code in teams_meta.keys())
    print("All team codes in teams_meta:", all_team_codes)

    agg_codes = sorted(
        set(k.strip().upper() for k in wins.keys())
        | set(k.strip().upper() for k in losses.keys())
    )
    print("All team codes in aggregated wins/losses:", agg_codes)

    print("WAS in teams_meta:", "WAS" in all_team_codes)
    print("WAS in aggregated wins:", "WAS" in [k.strip().upper() for k in wins.keys()])
    print("WAS in aggregated losses:", "WAS" in [k.strip().upper() for k in losses.keys()])
    print(
        "Row for WAS in rows:",
        next((r for r in rows if r.get("code") == "WAS"), None),
    )

    return seeded_rows



def send_rows_to_backend(rows, pages_fetched, season_year):
    """POST the rows to your backend /internal/standings/overwrite endpoint."""
    url = f"{BACKEND_BASE_URL.rstrip('/')}/internal/standings/overwrite"
    headers = {
        "Content-Type": "application/json",
        "X-Cron-Token": STANDINGS_CRON_TOKEN,
    }

    # IMPORTANT: backend expects a raw JSON array, not {"rows": [...]}
    payload = rows

    print(f"Sending {len(rows)} rows to backend at {url}")
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    print("Backend response status:", resp.status_code)
    print("Backend response body:", resp.text)
    resp.raise_for_status()

    print(
        f"✅ Standings sync completed for season {season_year}. "
        f"Rows sent: {len(rows)}, pages_fetched: {pages_fetched}"
    )


def main():
    print(f"Starting standings sync for season {SEASON_YEAR}")
    teams_meta = fetch_all_teams()
    wins, losses, pages_fetched = fetch_season_games_and_compute_records(SEASON_YEAR, teams_meta)
    rows = build_standings_rows(teams_meta, wins, losses)
    send_rows_to_backend(rows, pages_fetched, SEASON_YEAR)


if __name__ == "__main__":
    main()
