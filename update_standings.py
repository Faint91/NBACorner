import os
import requests
from datetime import datetime, timezone
from supabase import create_client, Client

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ API-Sports setup
API_KEY = os.getenv("SPORTS_API_KEY")
API_URL = "https://v1.basketball.api-sports.io/standings"
HEADERS = {"x-apisports-key": API_KEY}

# League and season — adjust if needed
PARAMS = {
    "league": "12",  # NBA ID in API-Sports
    "season": "2024-2025"
}


def update_standings_from_api():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings...")

    try:
        response = requests.get(API_URL, headers=HEADERS, params=PARAMS, timeout=20)
        response.raise_for_status()
        data = response.json()

        if "response" not in data:
            print("❌ Unexpected API format:", data)
            return

        standings_data = data["response"]
        print(f"✅ Retrieved standings for {len(standings_data)} teams")

        for entry in standings_data:
            team_info = entry["team"]
            conference = entry["group"]["name"]  # "East" / "West"
            wins = entry["wins"]["total"]
            losses = entry["losses"]["total"]
            seed = entry["position"]

            supabase.table("standings").upsert({
                "name": team_info["name"],
                "acronym": team_info["code"],
                "conference": conference,
                "wins": wins,
                "losses": losses,
                "seed": seed,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }, on_conflict=["acronym"]).execute()

        print("✅ Standings successfully updated in Supabase!")

    except requests.exceptions.Timeout:
        print("⏰ Request to API-Sports timed out after 20s.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ HTTP error fetching standings: {e}")
    except Exception as e:
        print(f"🚨 Unexpected error: {e}")


if __name__ == "__main__":
    update_standings_from_api()
