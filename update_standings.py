import os
import requests
from datetime import datetime, timezone
from supabase import create_client, Client

# --- Initialize Supabase client ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- API-Sports setup ---
API_KEY = os.getenv("SPORTS_API_KEY")
API_URL = "https://v1.basketball.api-sports.io/standings"
HEADERS = {
    "x-apisports-key": API_KEY
}

# Set parameters (adjust league and season accordingly)
PARAMS = {
    "league": "12",        # NBA league ID in API-Sports
    "season": "2024-2025"
}

def update_standings_from_api():
    print(f"[{datetime.now(timezone.utc)}] 🏀 Fetching latest NBA standings...")
    try:
        response = requests.get(API_URL, headers=HEADERS, params=PARAMS, timeout=20)
        response.raise_for_status()
        data = response.json()
        print("Raw API response:", data)

        if "response" not in data or not data["response"]:
            print("❌ Unexpected or empty API format:", data)
            return

        standings_data = data["response"]
        print(f"✅ Retrieved standings for {len(standings_data)} teams")

        for entry in standings_data:
            team_info = entry.get("team") or {}
            group = entry.get("group") or {}
            conference = group.get("name", "Unknown")
            wins = entry.get("wins", {}).get("total", 0)
            losses = entry.get("losses", {}).get("total", 0)
            seed = entry.get("position", None)

            acr = team_info.get("code")
            name = team_info.get("name")

            if acr and name:
                supabase.table("standings").upsert({
                    "name": name,
                    "acronym": acr,
                    "conference": conference,
                    "wins": wins,
                    "losses": losses,
                    "seed": seed,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }, on_conflict=["acronym"]).execute()
            else:
                print(f"⚠️ Skipping team with missing data: {entry}")

        print("✅ Standings successfully updated in Supabase!")

    except requests.exceptions.Timeout:
        print("⏰ Request to API-Sports timed out after 20s.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ HTTP error fetching standings: {e}")
    except Exception as e:
        print(f"🚨 Unexpected error: {e}")

if __name__ == "__main__":
    update_standings_from_api()
