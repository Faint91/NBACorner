"""Canonical final snapshots; structured publication is the only preservation gate."""

from scoring_service import (
    get_current_scoring_master,
    recompute_current_scores,
    ScoringError,
)
from scoring_engine import rank_live_rows
from job_safety import guard_runtime_job


class SnapshotError(RuntimeError):
    def __init__(self, stage):
        self.stage = stage
        super().__init__("Final snapshot failed: " + stage)


SUMMARY = ("bonus_finalists", "bonus_champion", "full_hits", "partial_hits", "misses")
PUBLIC_ROW_FIELDS = (
    "id",
    "rank",
    "display_name",
    "total_points",
    *SUMMARY,
    "per_match_points",
    "saved_at",
    "base_points",
    "points_by_round",
)


def snapshot_columns(keys):
    def coordinate(key):
        c, r, s = key.split("-")
        return int(r), {"east": 0, "west": 1, "nba": 2}[c], int(s)

    columns = []
    for key in sorted(keys, key=coordinate):
        c, r, s = key.split("-")
        labels = {"0": "PI", "1": "R1", "2": "R2", "3": "CF"}
        label = "NBA Finals" if c == "nba" else f"{c[0].upper()} {labels[r]}-{s}"
        columns.append(dict(key=key, label=label, type="matchup", round=int(r)))
    columns.extend(
        dict(
            key=k,
            label=k.replace("_", " ").capitalize(),
            type="bonus" if k.startswith("bonus_") else "summary",
        )
        for k in SUMMARY
    )
    return columns


def snapshot_rows(scores, brackets, users):
    """Only frozen public competition fields; use the same competitive ranking as live."""
    by_bracket = {b["id"]: b for b in brackets}
    by_user = {u["id"]: u for u in users}
    ranked = []
    for score in scores:
        b = by_bracket[score["bracket_id"]]
        username = by_user[b["user_id"]]["username"] or "unknown"
        ranked.append(
            dict(
                score,
                saved_at=b["saved_at"],
                user_id=b["user_id"],
                username=username,
                bracket_name=b.get("name") or "Unnamed bracket",
            )
        )
    output = []
    for position, row in enumerate(rank_live_rows(ranked), 1):
        output.append(
            dict(
                bracket_id=row["bracket_id"],
                rank=row["rank"],
                display_order=position,
                display_name=f"{row['bracket_name']} ({row['username']})",
                total_points=row["total_points"],
                full_hits=row["full_hits"],
                partial_hits=row["partial_hits"],
                misses=row["misses"],
                bonus_finalists=row["bonus_finalists"],
                bonus_champion=row["bonus_champion"],
                saved_at=row["saved_at"],
                points_by_round=row["points_by_round"],
                base_points=sum(row["points_by_round"].values()),
                per_match_points={
                    k: v["points"] for k, v in row["points_by_match"].items()
                },
            )
        )
    if len(output) != len(scores):
        raise SnapshotError("incomplete_eligible_rows")
    return output, ranked


def confirmed_snapshot(result, season_id, expected_count):
    if not isinstance(result, dict):
        raise SnapshotError("unconfirmed_publication")
    count = result.get("expected_rows")
    if (
        result.get("state") not in {"created", "existing"}
        or result.get("season_id") != season_id
        or not isinstance(result.get("snapshot_id"), str)
        or not result.get("snapshot_id")
        or result.get("is_final") is not True
        or type(count) is not int
        or count < 0
        or type(result.get("actual_rows")) is not int
        or result.get("actual_rows") != count
        or (result["state"] == "created" and count != expected_count)
    ):
        raise SnapshotError("unconfirmed_publication")
    return dict(
        ok=True,
        structured_complete=True,
        season_id=season_id,
        season_code=result["season_code"],
        history_snapshot_id=result["snapshot_id"],
        rows_snapshot=count,
        history_rows_count=count,
        state=result["state"],
        expected_rows=count,
        actual_rows=count,
        is_final=True,
    )


def create_final_leaderboard_snapshot(
    client, *, expected_season_id=None, created_by=None
):
    guard_runtime_job("leaderboard-snapshot")
    try:
        season, master = get_current_scoring_master(
            client, expected_season_id=expected_season_id
        )
        evaluation = recompute_current_scores(
            client,
            expected_season_id=season.id,
            expected_master_id=master["id"],
            snapshot_context=True,
        )
        scores = evaluation["scoring_rows"]
        if evaluation["updated_brackets"] != len(scores):
            raise SnapshotError("inconsistent_evaluation")
        # Read failures are errors, never an empty participation result.
        brackets = (
            client.table("brackets")
            .select("id,user_id,name,saved_at")
            .eq("season_id", season.id)
            .execute()
            .data
        )
        users = client.table("users").select("id,username").execute().data
        if not isinstance(brackets, list) or not isinstance(users, list):
            raise SnapshotError("display_source_unavailable")
        rows, ranked = snapshot_rows(scores, brackets, users)
        existing = (
            client.table("leaderboard_history_snapshots")
            .select("id")
            .eq("season_id", season.id)
            .execute()
            .data
        )
        if not isinstance(existing, list):
            raise SnapshotError("history_read_failure")
        # Keep the established legacy-first dependency, but never use it as success.
        # Existing structured records are handled only by the atomic publisher.
        if not existing and ranked:
            legacy = (
                client.table("leaderboard_history")
                .select("id")
                .eq("season_id", season.id)
                .limit(1)
                .execute()
                .data
            )
            if not isinstance(legacy, list):
                raise SnapshotError("legacy_read_failure")
            if not legacy:
                client.table("leaderboard_history").insert(
                    [
                        dict(
                            season_id=season.id,
                            season_code=season.code,
                            rank=r["rank"],
                            bracket_name=r["bracket_name"],
                            username=r["username"],
                            bracket_id=r["bracket_id"],
                            user_id=r["user_id"],
                            **{
                                k: r[k]
                                for k in ("total_points", *SUMMARY, "points_by_match")
                            },
                        )
                        for r in rank_live_rows(ranked)
                    ]
                ).execute()
        keys = {k for s in scores for k in s["points_by_match"]}
        result = (
            client.rpc(
                "publish_leaderboard_snapshot",
                dict(
                    p_season_id=season.id,
                    p_master_id=master["id"],
                    p_source=evaluation["scoring_source"],
                    p_scores=scores,
                    p_rows=rows,
                    p_columns=snapshot_columns(keys),
                    p_created_by=created_by,
                ),
            )
            .execute()
            .data
        )
        return confirmed_snapshot(result, season.id, len(scores))
    except SnapshotError:
        raise
    except ScoringError:
        raise SnapshotError("canonical_recompute_failure") from None
    except Exception:
        raise SnapshotError("source_or_publication_failure") from None


def public_snapshot_rows(rows):
    import re

    output = []
    for source in rows:
        row = {
            k: source.get(k)
            for k in PUBLIC_ROW_FIELDS
            if k not in {"per_match_points", "points_by_round"}
        }
        for field, pattern in (
            ("per_match_points", r"(?:east|west|nba)-[0-4]-[0-9]+"),
            ("points_by_round", r"[0-4]"),
        ):
            raw = source.get(field)
            row[field] = (
                {
                    k: v
                    for k, v in raw.items()
                    if isinstance(k, str)
                    and re.fullmatch(pattern, k)
                    and type(v) is int
                    and v >= 0
                }
                if isinstance(raw, dict)
                else {}
            )
        output.append(row)
    return output


def public_columns(columns):
    import re

    if not isinstance(columns, list):
        return []
    output = []
    for c in columns:
        if (
            not isinstance(c, dict)
            or not isinstance(c.get("key"), str)
            or (
                c["key"] not in SUMMARY
                and not re.fullmatch(r"(?:east|west|nba)-[0-4]-[0-9]+", c["key"])
            )
            or not isinstance(c.get("label"), str)
            or c.get("type") not in {"matchup", "bonus", "summary"}
        ):
            continue
        clean = {k: c[k] for k in ("key", "label", "type")}
        if type(c.get("round")) is int:
            clean["round"] = c["round"]
        output.append(clean)
    return output
