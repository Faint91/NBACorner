import os
import requests
from datetime import datetime
import pytz
from apscheduler.schedulers.blocking import BlockingScheduler
from supabase import create_client, Client

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ API-Sports setup
API_KEY = "840620db227fbe1c998e194d92bb0ba7"
API_URL = "https://v2.nba.api-sports.io/standings"

HEADERS = {
    "x-apisports-key": API_KEY
}

def update_standings_from_api():
    print(f"[{datetime.now()}] Fetching latest NBA standings...")

    try:
        response = requests.get(API_URL, headers=HEADERS)
        response.raise_for_status()
        data = response.json()

        if "response" not in data:
            print("❌ Unexpected API format.")
            return

        standings_data = data["response"]

        for team in standings_data:
            team_info = team["team"]
            conference = team["conference"]["name"]
            wins = team["win"]["total"]
            losses = team["loss"]["total"]
            seed = team["conference"]["rank"]  # API uses rank; we'll store as seed

            supabase.table("standings").upsert({
                "name": team_info["name"],
                "acronym": team_info["code"],
                "conference": conference,
                "wins": wins,
                "losses": losses,
                "seed": seed,
                "updated_at": datetime.utcnow().isoformat()
            }, on_conflict=["acronym"]).execute()

        print("✅ Standings successfully updated in Supabase.")

    except Exception as e:
        print(f"⚠️ Error updating standings: {e}")


# 🕒 Scheduler to run daily at 11:59:59 PM PST
scheduler = BlockingScheduler(timezone=pytz.timezone("America/Los_Angeles"))
scheduler.add_job(update_standings_from_api, 'cron', hour=23, minute=59, second=59)

if __name__ == "__main__":
    print("🏀 NBA Standings Auto-Updater started (runs daily 11:59:59 PM PST)...")
    update_standings_from_api()  # Run once at startup
    scheduler.start()
