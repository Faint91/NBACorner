"""NC-03 audit-only diagnostic error reproduction: no DB, network or secrets."""

import ast
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parents[1]


def run():
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    function = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "debug_master_status"
    )
    before = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and any(
            isinstance(d, ast.Attribute)
            and isinstance(d.value, ast.Name)
            and d.value.id == "app"
            and d.attr == "before_request"
            for d in n.decorator_list
        )
    ]
    assert [n.name for n in before] == ["_season_bootstrap"]
    assert len(function.decorator_list) == 1
    bid = "00000000-0000-4000-8000-000000000003"
    sid = "00000000-0000-4000-8000-000000000004"
    marker = "NC03_SYNTHETIC_PROVIDER_INTERNAL_DETAIL"
    state = SimpleNamespace(mode="healthy", reads=0)

    class ReadQuery:
        def __init__(self, table):
            assert table in {"brackets", "seasons"}
            self.table = table

        def select(self, fields):
            return self

        def eq(self, field, value):
            assert field == "id"
            return self

        def single(self):
            return self

        def execute(self):
            state.reads += 1
            if self.table == "brackets":
                return SimpleNamespace(
                    data={"id": bid, "season_id": sid, "deleted_at": None}
                )
            if state.mode == "generic_failure":
                raise RuntimeError(marker + ": synthetic database constraint detail")
            if state.mode == "missing_column_failure":
                raise RuntimeError(
                    marker + ": master_bracket_id synthetic column failure"
                )
            return SimpleNamespace(
                data={"id": sid, "code": "2025-26", "master_bracket_id": bid}
            )

    app = Flask("nc03-debug-error-audit")
    env = dict(
        app=app,
        request=request,
        jsonify=jsonify,
        supabase=SimpleNamespace(table=ReadQuery),
        ensure_season_globals=lambda: None,
        SeasonConfigurationError=type("SeasonConfigurationError", (Exception,), {}),
    )
    with patch(
        "socket.socket.connect", side_effect=AssertionError("Network forbidden")
    ), patch(
        "socket.create_connection", side_effect=AssertionError("Network forbidden")
    ):
        exec(
            compile(
                ast.Module(body=before + [function], type_ignores=[]),
                "app.py current diagnostic + canonical before-request hook",
                "exec",
            ),
            env,
        )
        client = app.test_client()
        observations = {}
        for mode in ("healthy", "generic_failure", "missing_column_failure"):
            state.mode = mode
            response = client.get(
                "/__debug/master-status", query_string={"bracket_id": bid}
            )
            body = response.get_json()
            observations[mode] = dict(
                status=response.status_code,
                no_authorization_header=True,
                raw_provider_marker_returned=marker in response.get_data(as_text=True),
                exception_field_present="exception" in body,
                SQL_fix_in_response=bool(body.get("fix_sql")),
                supplied_existing_bracket_linkage_returned=body.get("season_id") == sid,
            )
        missing = client.get("/__debug/master-status")
        assert missing.status_code == 400
        assert observations["healthy"]["status"] == 200
        assert observations["healthy"]["supplied_existing_bracket_linkage_returned"]
        assert observations["generic_failure"]["status"] == 500
        assert observations["generic_failure"]["raw_provider_marker_returned"]
        assert observations["missing_column_failure"]["raw_provider_marker_returned"]
        assert observations["missing_column_failure"]["SQL_fix_in_response"]
    return dict(
        finding="NC03-SEC-002",
        classification="FAIL",
        affected_contract="NC-03 resumed section16: no raw DB/provider internals or SQL in user-facing responses",
        route="GET /__debug/master-status",
        source_line=function.lineno,
        observations=observations,
        control_missing_id_status=missing.status_code,
        actual_current_route_and_global_hook_compiled=True,
        database="Synthetic read double; one valid canonical-season precondition supplied",
        raw_fault_details_or_SQL_printed=False,
        database_mutations=0,
        network_used=False,
        production_contact=False,
        limitation="Not a production observation; no real stored credential leakage claimed.",
        product_requirement_ids_failed=[],
    )


if __name__ == "__main__":
    # Original vulnerable proof above and committed failure evidence are retained.
    from verify_nc03r2_diagnostic import run as verify_repaired_scenario

    print(json.dumps(verify_repaired_scenario(), indent=2))
