"""Explicit trusted rollover; read-only preparation, one locked database operation."""

from canonical_season import season_start_year, timestamp
from bracket_rules import submission_error
from scoring_service import COORDINATES, recompute_current_scores
from history_service import snapshot_rows, snapshot_columns
from job_safety import guard_runtime_job


def validate_target(source_code, target_code, opening, lock):
    start = season_start_year(source_code) + 1
    expected = f"{start:04d}-{(start + 1) % 100:02d}"
    if target_code != expected or season_start_year(target_code) != start:
        raise ValueError("immediate_next_season_required")
    if timestamp(opening) >= timestamp(lock):
        raise ValueError("strict_target_timing_required")
    return expected


def completed_master_error(matches):
    """Final results require full graph and counts, unlike editable partial masters.

    Share graph/count integrity rules with B2, but never require a master's user
    submission flag. Exact canonical coordinates and a Finals winner are mandatory.
    """
    coordinates = {
        (m.get("conference"), m.get("round"), m.get("slot")) for m in matches
    }
    if len(matches) != 21 or coordinates != COORDINATES:
        return "master_graph_incomplete"
    if submission_error(matches, master=False):
        return "master_results_incomplete_or_invalid"
    return None


def run_rollover(client, *, target_code, opening, lock, requested_by):
    guard_runtime_job("season-rollover")
    # Repeat detection is authoritative in the RPC, before preparation validation.
    # A failed read/calculation is represented explicitly, never as zero competitors.
    prepared = None
    try:
        evaluation = recompute_current_scores(client, calculation_only=True)
        season, master = evaluation["season"], evaluation["master"]
        graph = (
            client.table("matches")
            .select("*")
            .eq("bracket_id", master["id"])
            .execute()
            .data
        )
        if not isinstance(graph, list) or completed_master_error(graph):
            raise ValueError("master_incomplete")
        validate_target(season.code, target_code, opening, lock)
        brackets = (
            client.table("brackets")
            .select("id,user_id,name,saved_at")
            .eq("season_id", season.id)
            .execute()
            .data
        )
        users = client.table("users").select("id,username").execute().data
        if not isinstance(brackets, list) or not isinstance(users, list):
            raise ValueError("display_source_unavailable")
        scores = evaluation["scoring_rows"]
        rows, _ = snapshot_rows(scores, brackets, users)
        prepared = dict(
            source=evaluation["scoring_source"],
            scores=scores,
            rows=rows,
            columns=snapshot_columns({k for s in scores for k in s["points_by_match"]}),
            master_id=master["id"],
            source_id=season.id,
        )
    except Exception:
        # No exception text/provider output is logged, returned or persisted.
        pass
    try:
        result = (
            client.rpc(
                "run_season_rollover",
                dict(
                    p_target_code=target_code,
                    p_opening=opening.isoformat() if opening else None,
                    p_lock=lock.isoformat() if lock else None,
                    p_admin=requested_by,
                    p_prepared=prepared,
                ),
            )
            .execute()
            .data
        )
        if not isinstance(result, dict) or result.get("state") not in {
            "completed",
            "already_completed",
            "failed",
            "busy",
        }:
            raise ValueError()
        if not result.get("ok") and result.get("audit_id"):
            result[
                "error"
            ] += f" Stage: {result.get('stage', 'unknown')}. Audit: {result['audit_id']}."
        return result
    except Exception:
        return dict(
            ok=False,
            state="failed",
            status=503,
            stage="database_unavailable",
            error="Rollover database operation unavailable; inspect durable audit before retry.",
        )
