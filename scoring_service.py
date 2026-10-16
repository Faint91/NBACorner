"""Canonical current scoring orchestration; only the RPC publishes complete scores."""

from canonical_season import get_current_season
from scoring_engine import score_bracket, saved_timestamp
from job_safety import guard_runtime_job

BRACKET_FIELDS = "id,user_id,season_id,is_master,is_done,deleted_at,saved_at"
MATCH_FIELDS = "id,bracket_id,season_id,conference,round,slot,team_a,team_b,predicted_winner,predicted_winner_games"
COORDINATES = {
    (c, r, s)
    for c in ("east", "west")
    for r, slots in ((0, (1, 2, 3)), (1, (4, 5, 6, 7)), (2, (8, 9)), (3, (10,)))
    for s in slots
} | {("nba", 4, 11)}


class ScoringError(RuntimeError):
    def __init__(self, stage):
        self.stage = stage
        super().__init__("Current score recomputation failed: " + stage)


def get_current_scoring_master(
    client, *, expected_season_id=None, expected_master_id=None
):
    """Caller IDs may only constrain canonical truth; they never select it."""
    try:
        season = get_current_season(client)
        if expected_season_id is not None and expected_season_id != season.id:
            raise ScoringError("canonical_source_changed")
        rows = (
            client.table("seasons")
            .select("id,master_bracket_id")
            .eq("id", season.id)
            .limit(2)
            .execute()
            .data
            or []
        )
        if (
            len(rows) != 1
            or rows[0].get("id") != season.id
            or not rows[0].get("master_bracket_id")
        ):
            raise ScoringError("canonical_master_unavailable")
        mid = rows[0]["master_bracket_id"]
        if expected_master_id is not None and expected_master_id != mid:
            raise ScoringError("caller_master_mismatch")
        brackets = (
            client.table("brackets")
            .select(BRACKET_FIELDS)
            .eq("id", mid)
            .limit(2)
            .execute()
            .data
            or []
        )
        if (
            len(brackets) != 1
            or brackets[0].get("id") != mid
            or brackets[0].get("season_id") != season.id
            or brackets[0].get("is_master") is not True
            or brackets[0].get("deleted_at") is not None
        ):
            raise ScoringError("canonical_master_invalid")
        return season, brackets[0]
    except ScoringError:
        raise
    except Exception:
        raise ScoringError("canonical_master_unavailable") from None


def eligible(bracket, season_id, master_id):
    return (
        bracket.get("id") != master_id
        and bracket.get("season_id") == season_id
        and bracket.get("is_done") is True
        and bracket.get("deleted_at") is None
        and saved_timestamp(bracket.get("saved_at")) is not None
    )


def keyed_matches(rows):
    result = {}
    for row in rows:
        coord = (row.get("conference"), row.get("round"), row.get("slot"))
        key = f"{coord[0]}-{coord[1]}-{coord[2]}"
        if coord not in COORDINATES or key in result:
            raise ScoringError("invalid_match_graph")
        result[key] = row
    return result


def recompute_current_scores(
    client,
    *,
    expected_season_id=None,
    expected_master_id=None,
    snapshot_context=False,
    calculation_only=False,
):
    if not calculation_only:
        guard_runtime_job("score-recompute")
    try:
        season, master = get_current_scoring_master(
            client,
            expected_season_id=expected_season_id,
            expected_master_id=expected_master_id,
        )
        brackets = (
            client.table("brackets")
            .select(BRACKET_FIELDS)
            .eq("season_id", season.id)
            .execute()
            .data
            or []
        )
        matches = (
            client.table("matches")
            .select(MATCH_FIELDS)
            .eq("season_id", season.id)
            .execute()
            .data
            or []
        )
        source = {
            "brackets": sorted(brackets, key=lambda r: r["id"]),
            "matches": sorted(matches, key=lambda r: r["id"]),
        }
        truth = keyed_matches([m for m in matches if m["bracket_id"] == master["id"]])
        if len(truth) != len(COORDINATES):
            raise ScoringError("canonical_master_graph_incomplete")
        targets = sorted(
            (b for b in brackets if eligible(b, season.id, master["id"])),
            key=lambda b: b["id"],
        )
        rows = []
        for b in targets:
            predictions = keyed_matches(
                [m for m in matches if m["bracket_id"] == b["id"]]
            )
            calculated = score_bracket(predictions, truth)
            base = calculated.pop("base_points")
            if (
                calculated["total_points"]
                != base + calculated["bonus_finalists"] + calculated["bonus_champion"]
                or base != sum(calculated["points_by_round"].values())
                or any(
                    type(calculated[k]) is not int or calculated[k] < 0
                    for k in (
                        "total_points",
                        "full_hits",
                        "partial_hits",
                        "misses",
                        "bonus_finalists",
                        "bonus_champion",
                    )
                )
            ):
                raise ScoringError("invalid_computed_scores")
            rows.append(
                dict(
                    calculated,
                    bracket_id=b["id"],
                    master_bracket_id=master["id"],
                    season_id=season.id,
                )
            )
    except ScoringError:
        raise
    except Exception:
        raise ScoringError("calculation_failure") from None
    if calculation_only:
        return dict(
            season=season, master=master, scoring_source=source, scoring_rows=rows
        )
    try:
        result = (
            client.rpc(
                "publish_current_bracket_scores",
                {
                    "p_season_id": season.id,
                    "p_master_id": master["id"],
                    "p_source": source,
                    "p_rows": rows,
                },
            )
            .execute()
            .data
        )
        if not isinstance(result, dict) or result.get("state") not in {
            "published",
            "unchanged",
        }:
            raise ValueError()
        if snapshot_context:
            return dict(result, scoring_source=source, scoring_rows=rows)
        return result
    except Exception:
        raise ScoringError("publication_failure") from None
