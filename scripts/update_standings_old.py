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

NBA_STANDINGS_URL = "https://cdn.nba.com/static/json/staticData/leagueStandings.json"

def update_standings_from_json():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings from official NBA JSON feed...")

    try:
        # Make the request look like a real browser hitting nba.com
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
                "Gecko/20100101 Firefox/132.0"
            ),
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://www.nba.com/",
            "Origin": "https://www.nba.com",
        }
        response = requests.get(NBA_STANDINGS_URL, headers=headers, timeout=30, )
        
        if DEBUG_STANDINGS:
            print("---- DEBUG: NBA standings HTTP response ----")
            print(f"URL: {response.url}")
            print(f"Status code: {response.status_code}")
            print("Response headers:")
            for k, v in response.headers.items():
                print(f"  {k}: {v}")
            print("First 500 chars of body:")
            print(response.text[:500])
            print("---- END DEBUG ----")
        
        response.raise_for_status()
        data = response.json()

        teams_data = data.get("league", {}).get("standard", {}).get("teams", [])
        if not teams_data:
            print("❌ No team data found in NBA JSON feed.")
            return

        print(f"✅ Retrieved {len(teams_data)} teams from NBA feed.")

        for team in teams_data:
            team_info = team.get("teamSitesOnly", {})
            name = team_info.get("teamName") or team.get("teamTriCode")
            acronym = team.get("teamTricode") or team_info.get("teamTricode")
            conference = team.get("confName")
            try:
                wins = int(team.get("win") or 0)
            except Exception:
                wins = 0

            try:
                losses = int(team.get("loss") or 0)
            except Exception:
                losses = 0
            
            # Win% = wins / (wins + losses)
            games = wins + losses
            win_pct = float(wins) / games if games > 0 else 0.0

            seed = team.get("confRank")

            if not acronym or not name:
                print(f"⚠️ Skipping invalid team entry: {team}")
                continue

            print(f"→ {conference.upper()} | Seed {seed} | {acronym} ({wins}-{losses})")

            supabase.table("standings").upsert(
                {
                    "name": name,
                    "acronym": acronym,
                    "conference": conference,
                    "wins": wins,
                    "losses": losses,
                    "win_pct": win_pct,  # ⬅️ NEW
                    "seed": seed,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                on_conflict=["acronym"],
            ).execute()

        print("✅ Standings successfully updated in Supabase.")

    except requests.HTTPError as e:
        # HTTP-specific debug
        print(f"🚨 HTTP error when fetching standings: {e}")
        if e.response is not None and DEBUG_STANDINGS:
            print("---- DEBUG: HTTPError response body snippet ----")
            print(e.response.text[:500])
            print("---- END DEBUG ----")
    except Exception as e:
        # Any other unexpected error
        print(f"🚨 Error updating standings: {e}")

if __name__ == "__main__":
    update_standings_from_json()
