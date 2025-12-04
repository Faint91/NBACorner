import os
import requests
from datetime import datetime, timezone
from supabase import create_client, Client

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

NBA_STANDINGS_URL = "https://cdn.nba.com/static/json/staticData/leagueStandings.json"


NBA_STANDINGS_HEADERS = {
    # Pretend to be a normal Chrome browser visiting nba.com
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Referer": "https://www.nba.com/standings",
}

def update_standings_from_json():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings from official NBA JSON feed...")

    try:
        response = requests.get(NBA_STANDINGS_URL, headers=NBA_STANDINGS_HEADERS, timeout=30, )
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

    except Exception as e:
        print(f"🚨 Error updating standings: {e}")

if __name__ == "__main__":
    update_standings_from_json()
