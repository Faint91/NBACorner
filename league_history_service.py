"""Read-only league history over immutable global rows; identities never serialized."""

from canonical_season import season_start_year
from history_service import public_snapshot_rows, public_columns
from league_service import LeagueError


def rows(query):
    result = query.execute().data
    if not isinstance(result, list):
        raise LeagueError("League history unavailable", 503)
    return result


def read_history(client, league, season_code=None):
    safe_league = {key: league[key] for key in ("id", "name", "requires_password")}
    headers = rows(
        client.table("league_history_seasons")
        .select("id,season_id,global_snapshot_id,expected_rows,finalized_at")
        .eq("league_id", league["id"])
        .eq("is_final", True)
    )
    if not headers:
        if season_code is not None:
            raise LeagueError("No finalized league history for this season", 404)
        return dict(league=safe_league, seasons=[])
    sources = rows(
        client.table("leaderboard_history_snapshots")
        .select("id,season_id,season_code,columns,is_final")
        .in_("id", [h["global_snapshot_id"] for h in headers])
    )
    by_id = {source["id"]: source for source in sources}
    seasons = []
    for header in headers:
        source = by_id.get(header["global_snapshot_id"])
        if (
            not source
            or source["is_final"] is not True
            or source["season_id"] != header["season_id"]
        ):
            raise LeagueError("League history requires consistency review", 503)
        seasons.append(
            dict(
                season_code=source["season_code"],
                finalized_at=header["finalized_at"],
                competitors=header["expected_rows"],
            )
        )
    seasons.sort(key=lambda item: season_start_year(item["season_code"]), reverse=True)
    if season_code is None:
        return dict(league=safe_league, seasons=seasons)
    try:
        season_start_year(season_code)
    except Exception:
        raise LeagueError("Invalid season code", 400) from None
    header = next(
        (
            h
            for h in headers
            if by_id[h["global_snapshot_id"]]["season_code"] == season_code
        ),
        None,
    )
    if header is None:
        raise LeagueError("No finalized league history for this season", 404)
    mapping = rows(
        client.table("league_history_rows")
        .select("global_snapshot_row_id,rank,display_order")
        .eq("history_season_id", header["id"])
        .order("display_order")
    )
    if len(mapping) != header["expected_rows"] or not mapping:
        raise LeagueError("Incomplete league history", 503)
    frozen = rows(
        client.table("leaderboard_history_rows")
        .select(
            "id,snapshot_id,display_name,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,saved_at,base_points,points_by_round,per_match_points"
        )
        .in_("id", [item["global_snapshot_row_id"] for item in mapping])
    )
    by_row = {item["id"]: item for item in frozen}
    output = []
    for item in mapping:
        source = by_row.get(item["global_snapshot_row_id"])
        if not source or source["snapshot_id"] != header["global_snapshot_id"]:
            raise LeagueError("League history source unavailable", 503)
        safe = public_snapshot_rows([dict(source, rank=item["rank"])])[0]
        safe.pop("id", None)
        safe["display_order"] = item["display_order"]
        output.append(safe)
    return dict(
        league=safe_league,
        season_code=season_code,
        finalized_at=header["finalized_at"],
        columns=public_columns(by_id[header["global_snapshot_id"]]["columns"]),
        rows=output,
    )
