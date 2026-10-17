"""NC-03 leased local auth/product cross-domain proof; no production entry point."""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from email_transport import test_mailbox
from integration_harness import GuardedHarness, CANONICAL_CHECKSUM
from synthetic_fixtures import identity


def auth(c, path, payload):
    # Bridge only the three explicit auth POSTs missing from the existing F2 lane.
    # Product requests still use the actual guarded HTTP transport and decorators.
    c._require_lease()
    assert c.characterization_scope == "NC-02F2" and c._ready
    assert path in {"/auth/login", "/auth/forgot-password", "/auth/reset-password"}
    if path != "/auth/reset-password":
        assert payload.get("email") in {
            "user-a@nba-corner.example",
            "admin@nba-corner.example",
        }
    app = c.module.app
    with app.test_request_context(path, method="POST", json=payload):
        from flask import request

        early = c.module._season_bootstrap()
        response = app.make_response(
            early if early is not None else app.view_functions[request.endpoint]()
        )
        return response.status_code, response.get_json()


def reset(c, role):
    assert role in {"user-a", "admin"}
    status, _ = auth(
        c, "/auth/forgot-password", {"email": role + "@nba-corner.example"}
    )
    assert status == 200
    token = re.search(
        r"token=([A-Za-z0-9_-]+)", test_mailbox().inspect_messages()[-1].body
    )[1]
    password = "NC03-explicit-synthetic-reset-" + role
    status, _ = auth(
        c, "/auth/reset-password", {"token": token, "new_password": password}
    )
    assert status == 200
    return password


def fresh_login(c, role, password):
    status, body = auth(
        c, "/auth/login", {"email": role + "@nba-corner.example", "password": password}
    )
    assert status == 200
    c._tokens[role] = body["token"]


def run(config):
    assert Path(config).resolve() == (ROOT / ".env.test.nba-local.local").resolve()
    results = {}
    with GuardedHarness(
        config, allow_local_mutations=True, characterization_scope="NC-02F2"
    ) as c:
        c.stack.enter_context(patch.object(c.module, "DISABLE_RATE_LIMITS", True))
        ids = c.install_league_history_scenario()
        c.bracket_timing("open")
        for role in ("admin", "owner", "user-a", "user-b"):
            c.login(role)
        db = c.module.supabase
        a = next(
            r
            for r in db.table("brackets").select("id,user_id,is_master").execute().data
            if r["user_id"] == identity("user-a") and not r["is_master"]
        )["id"]
        m = next(
            r
            for r in db.table("matches")
            .select("id,conference,slot")
            .eq("bracket_id", a)
            .execute()
            .data
            if r["conference"] == "east" and r["slot"] == 6
        )["id"]
        path = "/bracket/match/" + m + "/games"

        def edit(role, expected):
            status, _ = c.bracket_request(
                "PATCH", path, role=role, payload={"games": 5}
            )
            assert status == expected, ("bracket", status, expected)

        edit("user-a", 200)
        edit("user-b", 403)
        edit("admin", 403)
        status, _ = c.league_request(
            "POST", f"/leagues/{ids['empty']}/join", role="user-a", payload={}
        )
        assert status == 201
        password = reset(c, "user-a")
        edit("user-a", 401)
        status, _ = c.league_request(
            "DELETE", f"/leagues/{ids['empty']}/membership", role="user-a"
        )
        assert status == 401
        fresh_login(c, "user-a", password)
        edit("user-a", 200)
        status, _ = c.league_request(
            "DELETE", f"/leagues/{ids['empty']}/membership", role="user-a"
        )
        assert status == 200
        status, _ = c.bracket_request(
            "PATCH",
            f"/bracket/{a}/save",
            role="user-a",
            payload={"name": "NC03 synthetic submitted"},
        )
        assert status == 200
        results["CROSS-11"] = {
            "passed": True,
            "actual_non_auth_HTTP_endpoint": "PATCH /bracket/match/<synthetic-id>/games",
            "before_reset": 200,
            "after_committed_reset": 401,
            "after_new_login": 200,
        }
        lid = ids["mixed"]
        for method, url, role, payload, expected in [
            (
                "POST",
                f"/leagues/{lid}/ownership",
                "admin",
                {"target_user_id": identity("owner")},
                200,
            ),
            ("DELETE", f"/leagues/{lid}/membership", "admin", None, 200),
            (
                "PATCH",
                f"/leagues/{lid}",
                "owner",
                {"is_private": True, "password": "NC03 synthetic league password"},
                200,
            ),
            ("GET", f"/leagues/{lid}/members", "admin", None, 403),
            (
                "PATCH",
                f"/leagues/{lid}",
                "user-a",
                {"name": "Forbidden stale owner state"},
                403,
            ),
        ]:
            status, _ = c.league_request(method, url, role=role, payload=payload)
            assert status == expected, ("league", status, expected)
        results["CROSS-02"] = {
            "passed": True,
            "revoked_mutation": 401,
            "fresh_mutation": 200,
            "nonmember_admin_private_access": 403,
            "nonowner_mutation": 403,
        }
        c.bracket_timing("locked")
        target = dict(
            new_season_code="2026-27",
            regular_season_end_utc=(
                datetime.now(timezone.utc) + timedelta(days=2)
            ).isoformat(),
            playoffs_start_utc=(
                datetime.now(timezone.utc) + timedelta(days=5)
            ).isoformat(),
        )
        password = reset(c, "admin")
        status, _ = c.transition_request(payload=target, role="admin")
        assert status == 401
        fresh_login(c, "admin", password)
        status, body = c.transition_request(payload=target, role="admin")
        assert status == 200 and body["state"] == "completed"
        audits = db.table("season_rollover_audits").select("*").execute().data
        assert audits and any(
            row.get("requested_by_user_id") == identity("admin") for row in audits
        )
        forbidden = {
            "email",
            "password",
            "password_hash",
            "token",
            "jwt",
            "reset_token",
            "token_digest",
        }
        assert all(not forbidden.intersection(row) for row in audits)
        for row in audits:
            assert not any(value in str(row) for value in c._tokens.values())
        results["CROSS-10"] = {
            "passed": True,
            "revoked_admin": 401,
            "fresh_admin": 200,
            "audit_identity_safe": True,
        }
        status, _ = c.bracket_request("GET", "/history/bracket/" + a, role="user-a")
        assert status == 200
        edit("user-a", 403)
        results["CROSS-01"] = {
            "passed": True,
            "owner_mutates_own": 200,
            "other_user": 403,
            "admin_arbitrary_edit": 403,
            "revoked_owner": 401,
            "fresh_owner": 200,
            "historical_read": 200,
            "historical_mutation": 403,
        }
    assert c.cleanup_proof["fixture_checksum"] == CANONICAL_CHECKSUM
    assert not test_mailbox().inspect_messages()
    return {
        "results": results,
        "cleanup_checksum": CANONICAL_CHECKSUM,
        "production_contact": False,
        "auth_bridge": "Actual decorated Flask auth views within verified local lease; all non-auth product requests use existing guarded HTTP. No production/harness guard modified.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-mutations", action="store_true")
    args = parser.parse_args()
    if not args.allow_local_mutations:
        raise SystemExit("Explicit guarded local opt-in required")
    try:
        value = run(args.config)
        (ROOT / "db/records/nc_03_pass3_cross_auth.json").write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(json.dumps(value, indent=2))
    except Exception:
        print(
            "NC-03 cross auth proof failed; sensitive details withheld", file=sys.stderr
        )
        raise SystemExit(1) from None
