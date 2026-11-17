"""Public projection of stored ESPN standings, with no refresh or writes."""

from canonical_season import get_current_season
from standings_service import validate_rows


def read_public_standings(client, season):
    rows = (
        client.table("standings")
        .select("code, name, conference, seed, wins, losses, win_pct")
        .execute()
        .data
    )
    if rows == []:
        validated = []
    else:
        teams = (
            client.table("teams")
            .select("code, name, conference")
            .execute()
            .data
        )
        validated = validate_rows(rows, teams)

    # The current standings store has no season_id. Reject a rollover spanning
    # these reads instead of attaching the previous season's rows to a new one.
    if get_current_season(client) != season:
        raise ValueError("Canonical season changed during standings read")

    return {
        "season_code": season.code,
        "status": "ok" if validated else "empty",
        "east": sorted(
            (row for row in validated if row["conference"] == "east"),
            key=lambda row: row["seed"],
        ),
        "west": sorted(
            (row for row in validated if row["conference"] == "west"),
            key=lambda row: row["seed"],
        ),
    }
