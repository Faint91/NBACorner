import os
from datetime import datetime, timezone
from supabase import create_client, Client
from nba_api.stats.endpoints import leaguestandings
from nba_api.stats.library.parameters import LeagueID

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def update_standings_from_nba_api():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings from nba_api...")

    try:
        # Fetch standings from NBA API
        standings_data = leaguestandings.LeagueStandings(league_id=LeagueID.nba).get_dict()
        print("✅ Raw data retrieved from NBA API")

        result_sets = standings_data.get("resultSets", [])
        if not result_sets:
            print("❌ No resultSets found in API response.")
            return

        rows = result_sets[0].get("rowSet", [])
        headers = result_sets[0].get("headers", [])
        print(f"✅ Found {len(rows)} teams in standings")

        # Create a mapping between column names and values
        for row in rows:
            record = dict(zip(headers, row))

            name = record.get("TeamName")
            acronym = record.get("TeamAbbreviation")
            conference = record.get("Conference")
            wins = record.get("WINS")
            losses = record.get("LOSSES")
            seed = record.get("PlayoffRank") or record.get("ConferenceRank")

            if not name or not acronym:
                print(f"⚠️ Skipping invalid entry: {record}")
                continue

            print(f"→ {conference} | Seed {seed} | {acronym} ({wins}-{losses})")

            supabase.table("standings").upsert({
                "name": name,
                "acronym": acronym,
                "conference": conference,
                "wins": wins,
                "losses": losses,
                "seed": seed,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }, on_conflict=["acronym"]).execute()

        print("✅ Standings successfully updated in Supabase.")

    except Exception as e:
        print(f"🚨 Error while fetching or updating standings: {e}")

if __name__ == "__main__":
    update_standings_from_nba_api()
