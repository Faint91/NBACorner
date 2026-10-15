"""Single database-owned season authority. No environment or calendar selection."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re


class SeasonConfigurationError(RuntimeError):
    def __init__(self):
        super().__init__("Canonical season configuration is unavailable or invalid")


def season_start_year(code):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}", code):
        raise SeasonConfigurationError()
    start = int(code[:4])
    if int(code[5:]) != (start + 1) % 100:
        raise SeasonConfigurationError()
    return start


def espn_season_year(code):
    return season_start_year(code) + 1


def timestamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise SeasonConfigurationError() from None


@dataclass(frozen=True)
class CurrentSeason:
    id: str
    code: str
    bracket_creation_opens_at: datetime
    playoff_lock_at: datetime

    def status(self, now):
        freeze = now >= self.bracket_creation_opens_at
        locked = now >= self.playoff_lock_at
        return {
            "season_code": self.code,
            "bracket_creation_opens_at": self.bracket_creation_opens_at.isoformat(),
            "playoff_lock_at": self.playoff_lock_at.isoformat(),
            "standings_freeze_reached": freeze,
            "playoffs_locked": locked,
            "bracket_creation_open": freeze and not locked,
        }


def get_current_season(client):
    try:
        pointers = (
            client.table("application_season")
            .select("singleton, season_id")
            .limit(2)
            .execute()
            .data
            or []
        )
        if len(pointers) != 1 or pointers[0].get("singleton") is not True:
            raise SeasonConfigurationError()
        rows = (
            client.table("seasons")
            .select("id, code, regular_season_end_utc, playoffs_start_utc")
            .eq("id", pointers[0]["season_id"])
            .limit(2)
            .execute()
            .data
            or []
        )
        if len(rows) != 1 or not rows[0].get("id"):
            raise SeasonConfigurationError()
        row = rows[0]
        season_start_year(row["code"])
        opening = timestamp(row["regular_season_end_utc"])
        lock = timestamp(row["playoffs_start_utc"])
        if opening > lock:
            raise SeasonConfigurationError()
        return CurrentSeason(row["id"], row["code"], opening, lock)
    except Exception:
        raise SeasonConfigurationError() from None
