import os
import time
from datetime import datetime, timezone
from supabase import create_client, Client
from nba_api.stats.endpoints import leaguestandings
from nba_api.stats.library.parameters import LeagueID
from requests.exceptions import ReadTimeout

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def fetch_standings_with_retry(max_retries=3, delay=10):
    """Fetch standings from NBA API with retry logic."""
    for attempt in range(1, max_retries + 1):
        try:
            print(f"Attempt {attempt}/{max_retries} – fetching standings...")
            standings_data = leaguestandings.LeagueStandings(
                league_id=LeagueID.nba,
                timeout=60,                # Increase timeout
                headers={                  # Spoof browser headers to reduce blocking
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/124.0.0.0 Safari/537.36",
                    "Referer": "https://www.nba.com/",
                    "Accept-Language": "en-US,en;q=0.9",
                }
            ).get_dict()
            print("✅ Successfully fetched standings from NBA API")
            return standings_data
        except ReadTimeout:
            print(f"⚠️ Timeout on attempt {attempt}. Retrying in {delay}s...")
            time.sleep(delay)
        except Exception as e:
            print(f"🚨 Unexpected error: {e}")
            time.sleep(delay)
    print("❌ Failed to fetch standings after multiple retries.")
    return None

def update_standings_from_nba_api():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings from nba_api...")

    standings_data = fetch_standings_with_retry()
    if not standings_data:
        print("❌ Could not retrieve standings data.")
        return

    result_sets = standings_data.get("resultSets", [])
    if not result_sets:
        print("❌ No resultSets found in API response.")
        return

    rows = result_sets[0].get("rowSet", [])
    headers = result_sets[0].get("headers", [])
    print(f"✅ Found {len(rows)} teams in standings")

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

if __name__ == "__main__":
    update_standings_from_nba_api()
