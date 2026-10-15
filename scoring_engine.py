"""Pure SC1-SC3 scoring and SC4/SC6 live ranking. No IO or master authority."""

from datetime import datetime, timezone


def saved_timestamp(value):
    try:
        dt = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def rank_live_rows(rows):
    """Invalid save metadata is ineligible; deterministic display does not break ties."""
    items = []
    for source in rows:
        stamp = saved_timestamp(source.get("saved_at"))
        if stamp is None:
            continue
        points, hits = source.get("total_points"), source.get("full_hits")
        if type(points) is not int or type(hits) is not int or min(points, hits) < 0:
            raise ValueError("Invalid ranking score")
        row = dict(source)
        key = (-points, -hits, stamp)
        items.append(
            (
                key,
                (
                    str(row.get("username") or "").casefold(),
                    str(row.get("user_id") or ""),
                    str(row.get("bracket_id") or ""),
                ),
                row,
            )
        )
    items.sort(key=lambda item: (item[0], item[1]))
    previous = None
    rank = 0
    output = []
    for position, (key, _, row) in enumerate(items, 1):
        if key != previous:
            rank = position
        row["rank"] = rank
        previous = key
        output.append(row)
    return output


def score_bracket(user_matches, master_matches):
    """Compare pure keyed graphs; bonuses remain separate from round/base points."""
    out = dict(
        base_points=0,
        full_hits=0,
        partial_hits=0,
        misses=0,
        bonus_finalists=0,
        bonus_champion=0,
        points_by_round={},
        points_by_match={},
    )
    for key, actual in master_matches.items():
        conf, rnd, slot = (
            actual.get("conference"),
            actual.get("round"),
            actual.get("slot"),
        )
        winner, games = actual.get("predicted_winner"), actual.get(
            "predicted_winner_games"
        )
        user = user_matches.get(key)
        result = dict(points=0, status="pending", conference=conf, round=rnd, slot=slot)
        out["points_by_match"][key] = result
        # Winner-only incomplete master state does not establish a finished series.
        if not winner or games is None:
            continue
        if (
            winner not in {actual.get("team_a"), actual.get("team_b")}
            or not actual.get("team_a")
            or not actual.get("team_b")
        ):
            raise ValueError("Invalid established master result")
        if type(games) is not int or games not in ((1,) if rnd == 0 else (4, 5, 6, 7)):
            raise ValueError("Invalid established master game count")
        if not user:
            result["status"] = "no_match"
            out["misses"] += 1
            continue
        pick = user.get("predicted_winner")
        if not pick:
            result["status"] = "no_pick"
            out["misses"] += 1
            continue
        participants = {actual.get("team_a"), actual.get("team_b")} == {
            user.get("team_a"),
            user.get("team_b"),
        } and None not in {user.get("team_a"), user.get("team_b")}
        correct = pick == winner
        exact = (
            type(user.get("predicted_winner_games")) is int
            and user.get("predicted_winner_games") == games
        )
        full = correct and participants and (rnd == 0 or exact)
        points = (1 if rnd == 0 else 3) if full else (1 if correct else 0)
        status = "full" if full else "partial" if correct else "miss"
        out["full_hits" if full else "partial_hits" if correct else "misses"] += 1
        result.update(
            points=points,
            status=status,
            winner_correct=correct,
            series_len_correct=exact,
            participants_correct=participants,
        )
        out["base_points"] += points
        rk = str(rnd)
        out["points_by_round"][rk] = out["points_by_round"].get(rk, 0) + points
    actual = master_matches.get("nba-4-11") or {}
    predicted = user_matches.get("nba-4-11") or {}
    actual_pair = {actual.get("team_a"), actual.get("team_b")}
    user_pair = {predicted.get("team_a"), predicted.get("team_b")}
    if (
        len(actual_pair) == 2
        and None not in actual_pair
        and len(user_pair) == 2
        and actual_pair == user_pair
    ):
        out["bonus_finalists"] = 1
    champion = actual.get("predicted_winner")
    games = actual.get("predicted_winner_games")
    if (
        len(actual_pair) == 2
        and None not in actual_pair
        and champion in actual_pair
        and type(games) is int
        and games in (4, 5, 6, 7)
        and predicted.get("predicted_winner") == champion
    ):
        out["bonus_champion"] = 3
    out["total_points"] = (
        out["base_points"] + out["bonus_finalists"] + out["bonus_champion"]
    )
    return out
