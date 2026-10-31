"""NBA-owned monthly read facade. No ordinary JWT or username goes to Daily."""

from calendar import monthrange
from datetime import datetime, timezone
from fractions import Fraction
import json
import os
import re
import time
import unicodedata
import uuid
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import requests

CONTRACT = "daily-monthly-stats-v1"
TIMEZONE = "America/Vancouver"
MAX_SUBJECTS = 500
MAX_RESPONSE_BYTES = 524288
TOKEN_PATTERN = r"[A-Za-z0-9_-]{43,128}"
UUID_PATTERN = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class StatsInvalidMonth(Exception):
    pass


class StatsUnavailable(Exception):
    pass


def validated_month(value=None, *, now=None):
    clock = datetime.now(timezone.utc) if now is None else now
    if clock.tzinfo is None:
        raise StatsInvalidMonth()
    current = clock.astimezone(ZoneInfo(TIMEZONE)).strftime("%Y-%m")
    month = current if value is None else value
    if (
        not isinstance(month, str)
        or not re.fullmatch(r"(?!0000)[0-9]{4}-(0[1-9]|1[0-2])", month)
        or month > current
    ):
        raise StatsInvalidMonth()
    return month


def canonical_uuid(value):
    if not isinstance(value, str) or not re.fullmatch(UUID_PATTERN, value):
        raise StatsUnavailable()
    return str(uuid.UUID(value))


def validate_inputs(data, month):
    if (
        not isinstance(data, dict)
        or set(data) != {"contract", "month", "timezone", "subjects"}
        or data["contract"] != CONTRACT
        or data["month"] != month
        or data["timezone"] != TIMEZONE
    ):
        raise StatsUnavailable()
    subjects = data["subjects"]
    if not isinstance(subjects, list) or len(subjects) > MAX_SUBJECTS:
        raise StatsUnavailable()
    days = monthrange(int(month[:4]), int(month[5:]))[1]
    seen, result = set(), []
    fields = {
        "nbaUserId",
        "correctPlayers",
        "correctPredictions",
        "hintNumerator",
        "hintDenominator",
        "rankingEligible",
    }
    for row in subjects:
        if not isinstance(row, dict) or set(row) != fields:
            raise StatsUnavailable()
        subject = canonical_uuid(row["nbaUserId"])
        if subject in seen:
            raise StatsUnavailable()
        seen.add(subject)
        for key in (
            "correctPlayers",
            "correctPredictions",
            "hintNumerator",
            "hintDenominator",
        ):
            if type(row[key]) is not int or row[key] < 0:
                raise StatsUnavailable()
        cp, denominator, numerator = (
            row["correctPlayers"],
            row["hintDenominator"],
            row["hintNumerator"],
        )
        if (
            cp > 2 * days
            or row["correctPredictions"] > days
            or denominator != cp
            or numerator > 3 * denominator
            or type(row["rankingEligible"]) is not bool
            or row["rankingEligible"]
            and cp == 0
        ):
            raise StatsUnavailable()
        result.append({**row, "nbaUserId": subject})
    return result


def read_configuration(environ):
    url, token = environ.get("DAILY_STATS_READ_URL", ""), environ.get(
        "DAILY_STATS_READ_TOKEN", ""
    )
    try:
        parsed = urlsplit(url)
        # A mandatory configured target, never an old-domain default or arbitrary URL.
        if (
            parsed.scheme != "https"
            or parsed.netloc != "www.nbacorner.com"
            or parsed.path != "/1on1/api/internal/daily/monthly-ranking-inputs"
            or parsed.query
            or parsed.fragment
            or not re.fullmatch(TOKEN_PATTERN, token)
        ):
            raise StatsUnavailable()
    except (ValueError, TypeError):
        raise StatsUnavailable() from None
    return url, token


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StatsUnavailable()
        result[key] = value
    return result


def fetch_inputs(month, environ, *, session_factory=requests.Session):
    url, token = read_configuration(environ)
    try:
        with session_factory() as session:
            # No netrc, inherited auth, proxy credential or persistent browser cookie.
            session.trust_env = False
            deadline = time.monotonic() + 7
            with session.get(
                url,
                params={"month": month},
                headers={
                    "Accept": "application/json",
                    "X-Daily-Stats-Read-Token": token,
                },
                timeout=(2, 3),
                allow_redirects=False,
                stream=True,
            ) as response:
                if (
                    response.status_code != 200
                    or response.headers.get("Content-Type", "")
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                    != "application/json"
                ):
                    raise StatsUnavailable()
                length = response.headers.get("Content-Length")
                if length is not None and (
                    not length.isdigit() or int(length) > MAX_RESPONSE_BYTES
                ):
                    raise StatsUnavailable()
                chunks, size = [], 0
                for chunk in response.iter_content(chunk_size=8192):
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES or time.monotonic() > deadline:
                        raise StatsUnavailable()
                    chunks.append(chunk)
                data = json.loads(
                    b"".join(chunks).decode("utf-8"),
                    object_pairs_hook=_unique_json_object,
                    parse_constant=lambda _: (_ for _ in ()).throw(StatsUnavailable()),
                )
        return validate_inputs(data, month)
    except Exception:
        # Requests/JSON exceptions may contain URLs, headers or internal UUIDs.
        raise StatsUnavailable() from None


def displayable_username(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 80
        and bool(value.strip())
        and not any(unicodedata.category(c).startswith("C") for c in value)
    )


def username_key(username):
    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFC", username).casefold()
    )


def assemble_stats(month, subjects, users, current_user_id):
    current = canonical_uuid(current_user_id)
    by_user = {}
    for user in users:
        user_id = canonical_uuid(user.get("id"))
        if user_id in by_user:
            raise StatsUnavailable()
        by_user[user_id] = user.get("username")
    if not displayable_username(by_user.get(current)):
        raise StatsUnavailable()
    visible = [r for r in subjects if displayable_username(by_user.get(r["nbaUserId"]))]
    ranked = [r for r in visible if r["rankingEligible"] and r["correctPlayers"] >= 1]
    ranked.sort(
        key=lambda r: (
            -r["correctPlayers"],
            Fraction(r["hintNumerator"], r["hintDenominator"]),
            username_key(by_user[r["nbaUserId"]]),
            r["nbaUserId"],
        )
    )
    positions = {r["nbaUserId"]: index + 1 for index, r in enumerate(ranked)}

    def average(row):
        return (
            row["hintNumerator"] / row["hintDenominator"]
            if row["hintDenominator"]
            else None
        )

    def public_row(row):
        return {
            "rank": positions[row["nbaUserId"]],
            "username": by_user[row["nbaUserId"]],
            "correctPlayers": row["correctPlayers"],
            "averageHints": average(row),
        }

    mine = next((r for r in subjects if r["nbaUserId"] == current), None)
    rank = positions.get(current)
    neighborhood = []
    if rank is not None and rank > 3:
        for row in ranked[max(0, rank - 3) : rank + 2]:
            public = public_row(row)
            if row["nbaUserId"] == current:
                public["isCurrentUser"] = True
            neighborhood.append(public)
    return {
        "contract": CONTRACT,
        "month": month,
        "timezone": TIMEZONE,
        "me": {
            "username": by_user[current],
            "correctPlayers": mine["correctPlayers"] if mine else 0,
            "correctPredictions": mine["correctPredictions"] if mine else 0,
            "averageHints": average(mine) if mine else None,
            "rank": rank,
        },
        "participantCount": len(ranked),
        "top3": [public_row(r) for r in ranked[:3]],
        "neighborhood": neighborhood,
    }


def get_daily_stats(
    verified_user_id,
    supplied_month,
    db,
    *,
    environ=None,
    now=None,
    session_factory=requests.Session
):
    month = validated_month(supplied_month, now=now)
    current = canonical_uuid(verified_user_id)
    subjects = fetch_inputs(
        month,
        os.environ if environ is None else environ,
        session_factory=session_factory,
    )
    ids = sorted({r["nbaUserId"] for r in subjects} | {current})
    try:
        # Exactly one current-username/account batch in addition to normal JWT auth.
        users = (
            db.table("users")
            .select("id,username")
            .in_("id", ids)
            .limit(len(ids))
            .execute()
            .data
        )
        if not isinstance(users, list) or any(
            not isinstance(u, dict) or canonical_uuid(u.get("id")) not in ids
            for u in users
        ):
            raise StatsUnavailable()
        return assemble_stats(month, subjects, users, current)
    except Exception:
        raise StatsUnavailable() from None
