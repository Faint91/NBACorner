"""Historical detail regression against the disposable production-schema PostgREST fixture."""

import json
from pathlib import Path
import sys

import master_lifecycle as fixture


def seed_archive(sql):
    full = fixture.bracket_scenario("historical")
    saved = full["brackets"][0]
    season = saved["season_id"]
    sql(f"""
        INSERT INTO brackets(id,user_id,season_id,is_done,saved_at,name)
        VALUES ('{saved["id"]}','{saved["user_id"]}','{season}',true,now(),'Archived fixture'),
               ('{fixture.identity("archived-draft")}','{fixture.identity("user-b")}','{season}',false,NULL,'Private draft'),
               ('{fixture.identity("archived-empty")}','{fixture.identity("owner")}','{season}',true,now(),'Archived summary');
        INSERT INTO brackets(id,user_id,season_id,is_done,saved_at,deleted_at,name)
        VALUES ('{fixture.identity("archived-deleted")}','{fixture.identity("user-b")}','{season}',true,now(),now(),'Retired fixture');
    """)
    rows = full["matches"]
    fields = ",".join(rows[0])
    sql(f"""
        BEGIN; SET CONSTRAINTS ALL DEFERRED;
        INSERT INTO matches({fields})
        SELECT {fields} FROM jsonb_populate_recordset(NULL::matches,$rows$ {json.dumps(rows)} $rows$::jsonb);
        COMMIT;
    """)
    return "/history/bracket/" + saved["id"]


def exercise(app, sql):
    url = seed_archive(sql)
    client = app.app.test_client()
    owner = app.generate_token(fixture.identity("user-a"), "fixture-owner")
    draft_owner = app.generate_token(fixture.identity("user-b"), "fixture-draft")
    calls = []

    def log(request):
        assert request.url.host == "127.0.0.1"
        assert request.method == "GET" or (request.method == "POST" and request.url.path == "/rpc/ordinary_bracket_snapshot")
        calls.append(request.url.path)

    app.supabase.session.event_hooks["request"].append(log)

    def get(route, status, paths, token=None):
        calls.clear()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        result = client.get(route, headers=headers)
        assert result.status_code == status, (route, result.status_code)
        assert calls == paths, calls
        return result.get_json()

    canonical = ["/application_season", "/seasons"]
    historical_calls = [*canonical, "/brackets", "/matches", "/users"]
    authenticated_calls = [*canonical, "/users", *historical_calls[2:]]
    anon = get(url, 200, historical_calls)
    authenticated = get(url, 200, authenticated_calls, owner)
    authorized_other = get(url, 200, authenticated_calls, draft_owner)
    assert authenticated["bracket"].pop("is_owner") is True
    assert anon["bracket"].pop("is_owner") is False
    assert authorized_other["bracket"].pop("is_owner") is False
    assert authenticated == anon == authorized_other
    assert set(anon) == {"bracket", "matches"}
    bracket = anon["bracket"]
    assert bracket["read_only"] and bracket["is_historical"] and "season" not in bracket
    assert set(bracket["owner"]) == {"id", "username"}
    matches = anon["matches"]
    assert len([match for rounds in matches.values() for group in rounds.values() for match in group]) == 21
    assert set(matches["east"]) == {"0", "1", "2", "3"}
    match = next(m for m in matches["east"]["0"] if m["slot"] == 1)
    assert match["team_a_code"] == match["team_a"] and match["team_b_code"] == match["team_b"] != match["team_a"]
    assert "team_a_info" not in match and "team_b_info" not in match
    finals = matches["nba"]["4"][0]
    assert finals["team_a"] is None and finals["team_b"] is None and "team_a_code" not in finals
    empty = get("/history/bracket/" + fixture.identity("archived-empty"), 200, historical_calls)
    assert empty["matches"] == {}
    draft = "/history/bracket/" + fixture.identity("archived-draft")
    get(draft, 403, historical_calls[:3])
    get(draft, 403, authenticated_calls[:4], owner)
    draft_payload = get(draft, 200, authenticated_calls, draft_owner)
    assert draft_payload["bracket"]["is_owner"] and draft_payload["bracket"]["read_only"]
    for label in ("archived-deleted", "does-not-exist"):
        get("/history/bracket/" + fixture.identity(label), 404, historical_calls[:3])
    get("/history/bracket/not-a-uuid", 400, canonical)
    get(url, 401, canonical, "not-a-fixture-token")
    get("/history/bracket/" + fixture.identity("bracket-saved"), 404, historical_calls[:3])

    current = "/bracket/" + fixture.identity("bracket-saved")
    current_payload = get(current, 200, [*canonical, "/users", "/brackets", "/seasons", "/matches", "/teams", "/users"], owner)
    assert not current_payload["bracket"]["read_only"] and "revision" not in current_payload
    versioned = get(current + "?authoritative=1", 200, [*canonical, "/users", "/brackets", "/seasons", "/rpc/ordinary_bracket_snapshot"], owner)
    assert versioned["revision"] == "0"

    sql("REVOKE SELECT ON public.teams FROM service_role")
    try:
        error = get(url, 400, historical_calls[:4])
        assert set(error) == {"error"}
    finally:
        sql("GRANT SELECT ON public.teams TO service_role")
    get(url, 200, historical_calls)
    print("PASS real historical PostgREST reads, partial data, owner/guest authorization, failure handling, current-editor compatibility and request counts")


if __name__ == "__main__":
    fixture.exercise = exercise
    fixture.main(*map(Path, sys.argv[1:]))
