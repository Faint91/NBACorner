import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
from supabase import create_client, Client
from environment_safety import prepare_runtime_environment
from standings_service import (
    refresh_current_standings,
    StandingsRefreshError,
    log_result,
)
from job_safety import guard_runtime_job

guard_runtime_job("standings-script")
prepare_runtime_environment()

# ✅ Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is not set. "
        "Make sure they are in your .env or environment before running update_standings.py."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def update_standings_from_json():
    guard_runtime_job("standings-script")
    try:
        result = refresh_current_standings(supabase)
        log_result(result)
        return result
    except StandingsRefreshError as error:
        log_result({"state": error.stage})
        raise


if __name__ == "__main__":
    update_standings_from_json()
