"""Only the reviewed NC-ENV-06 smoke suite; no general test execution."""

import argparse
import json
import sys
import socket
from urllib.parse import urlsplit
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment_safety import SafetyError
from integration_harness import GuardedHarness, readiness_report
from scripts.local_supabase_environment import sql_file, ROOT
from scripts.reset_local_fixtures import LocalFixtureLease


def smoke(context, simulate_failure=False):
    context.verify_admission_denial()
    for role in ("user-a", "user-b", "admin"):
        context.login(role)
    for path in (
        "/",
        "/health",
        "/auth/test-me",
        "/brackets/me",
        "/brackets",
        "/leagues",
        "/leagues/me",
        "/leaderboard",
        "/leaderboard/history",
    ):
        status, body = context.request("GET", path, role="user-a")
        if status != 200:
            raise SafetyError("Read smoke unexpected status; payload withheld.")
    status, body = context.request("POST", "/bracket/create", payload={}, role="admin")
    if status not in (200, 201):
        raise SafetyError("Bracket creation smoke failed; payload withheld.")
    bid = body["bracket"]["id"]
    status, body = context.request("GET", "/bracket/" + bid, role="admin")
    if status != 200:
        raise SafetyError("Bracket readback failed.")
    matches = [
        m
        for rounds in body["matches"].values()
        for group in rounds.values()
        for m in group
    ]
    match = next(
        m
        for m in matches
        if m["conference"] == "east" and m["round"] == 0 and m["slot"] == 1
    )
    status, body = context.request(
        "PATCH",
        f"/bracket/{bid}/match/{match['id']}",
        payload={"action": "set_winner", "team": match["team_a"], "games": 1},
        role="admin",
    )
    if status != 200:
        raise SafetyError("Prediction write smoke failed.")
    status, body = context.request("GET", "/bracket/" + bid, role="admin")
    rows = [
        m
        for rounds in body["matches"].values()
        for group in rounds.values()
        for m in group
    ]
    saved = next(m for m in rows if m["id"] == match["id"])
    if (
        status != 200
        or saved["predicted_winner"] != match["team_a"]
        or saved["predicted_winner_games"] != 1
    ):
        raise SafetyError("Local prediction persistence smoke failed.")
    if simulate_failure:
        raise SafetyError("Intentional local smoke failure.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    parser.add_argument("--simulate-failure", action="store_true")
    args = parser.parse_args()
    context = None
    try:
        context = GuardedHarness(
            args.config, allow_local_mutations=args.allow_local_mutations
        )
        try:
            with context:
                smoke(context, args.simulate_failure)
        except SafetyError as error:
            if (
                not args.simulate_failure
                or str(error) != "Intentional local smoke failure."
            ):
                raise
        if (
            context.cleanup_proof is None
            or context.thread.is_alive()
            or context.server.socket.fileno() != -1
        ):
            raise SafetyError("Cleanup verification missing.")
        origin = urlsplit(context.target.backend_origin)
        try:
            connection = socket.create_connection(("127.0.0.1", origin.port), timeout=1)
        except OSError:
            pass
        else:
            connection.close()
            raise SafetyError("Backend listener remained after cleanup.")
        # A new verified session must be able to reacquire the exclusive lease.
        with LocalFixtureLease(context.original_settings, allow_local_reset=True):
            pass
        sql_file(ROOT / "db/baseline/verify_current_schema.sql")
        sql_file(
            ROOT / "test-infrastructure/local-supabase/verify-fixture-marker-v2.sql"
        )
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "mode": "failure-recovery" if args.simulate_failure else "smoke",
                    "responses": context.summary,
                    "cleanup": context.cleanup_proof,
                    "readiness": readiness_report(context.original_settings),
                    "harness_scoped_mutation": "allowed only during verified context",
                    "general_mutation_permitted": False,
                    "flask_stopped": True,
                    "lease_released": True,
                },
                indent=2,
            )
        )
        return 0
    except BaseException:
        print(
            "REFUSED/FAILED: guarded local smoke; sensitive diagnostics withheld.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
