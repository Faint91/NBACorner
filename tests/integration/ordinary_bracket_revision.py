"""Real localhost Flask/PostgREST/PostgreSQL checks for the ordinary revision contract."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
import json
import sys
from unittest.mock import patch

import master_lifecycle as fixture
from bracket_rules import submission_error
sys.path.insert(0, str(fixture.ROOT / "tests/offline"))
from test_bracket_validity import complete

def exercise(app, sql):
    bracket_id = fixture.identity("bracket-saved")
    season_id = fixture.identity("current")
    owner_id = json.loads(sql(f"SELECT to_json(user_id) FROM brackets WHERE id='{bracket_id}'"))
    owner = next(role for role in ("user-a", "user-b") if fixture.identity(role) == owner_id)
    other = "user-b" if owner == "user-a" else "user-a"
    route = f"/bracket/{bracket_id}"
    detail = route + "?authoritative=1"
    ordinary_fixture = fixture.bracket_scenario("saved")["matches"]
    picks = {(row["conference"], row["slot"]): row for row in complete()}
    for row in ordinary_fixture:
        pick = picks[row["conference"], row["slot"]]
        row.update({key: pick[key] for key in ("team_a", "team_b", "predicted_winner", "predicted_winner_games")})
    assert submission_error(ordinary_fixture) is None
    first = next(row for row in ordinary_fixture if row["conference"] == "east" and row["slot"] == 4)
    match_id = first["id"]
    select_route = route + f"/match/{match_id}"
    save_route = route + "/save"
    games_route = f"/bracket/match/{match_id}/games"

    def open_window():
        sql(f"""UPDATE seasons SET regular_season_end_utc=clock_timestamp()-interval '1 day',
                            playoffs_start_utc=clock_timestamp()+interval '1 day' WHERE id='{season_id}';""")

    def restore_complete():
        values = json.dumps([{k: row[k] for k in
            ("id", "team_a", "team_b", "predicted_winner", "predicted_winner_games")} for row in ordinary_fixture])
        sql(f"""UPDATE matches m SET team_a=x.team_a,team_b=x.team_b,predicted_winner=x.predicted_winner,
             predicted_winner_games=x.predicted_winner_games
             FROM jsonb_populate_recordset(NULL::matches,$row${values}$row$::jsonb) x WHERE m.id=x.id;""")
        sql(f"UPDATE brackets SET is_done=true,saved_at=clock_timestamp() WHERE id='{bracket_id}'")

    def call(url, data=None, role=owner, method=None):
        headers = {"Origin": "http://fixture.local"}
        if role:
            headers["Authorization"] = "Bearer " + app.generate_token(fixture.identity(role), "fixture-" + role, role == "admin")
        with app.app.test_client() as client:
            res = client.open(url, method=method or ("GET" if data is None else "PATCH"), headers=headers, json=data)
            return res.status_code, res.get_json()

    def expect(status, url, data=None, **kwargs):
        actual, result = call(url, data, **kwargs)
        assert actual == status, (url, actual, result)
        return result

    def rows(snapshot):
        return [row for conference in snapshot["matches"].values() for group in conference.values() for row in group]

    def fingerprint():
        return sql(f"""SELECT md5(jsonb_build_array(
            (SELECT to_jsonb(b) FROM brackets b WHERE id='{bracket_id}'),
            (SELECT to_jsonb(v) FROM ordinary_bracket_revisions v WHERE bracket_id='{bracket_id}'),
            (SELECT jsonb_agg(m ORDER BY id) FROM matches m WHERE bracket_id='{bracket_id}')
        )::text)""")

    def pick(team, revision, opted=True):
        result = {"action": "set_winner", "team": team, "games": 4}
        if opted:
            result.update(expected_revision=revision, authoritative_response=True)
        return result

    def race(left, right):
        start = Barrier(2)
        def worker(args):
            start.wait(timeout=5)
            return call(*args)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(worker, args) for args in (left, right)]
            result = [job.result(timeout=15) for job in futures]
        assert sorted(status for status, _ in result) == [200, 409], result
        return result

    open_window()
    restore_complete()
    original_master = sql("SELECT md5(jsonb_agg(m ORDER BY m.id)::text) FROM matches m JOIN brackets b ON b.id=m.bracket_id WHERE b.is_master")
    version = expect(200, detail)["revision"]
    assert version == "0"

    # Concurrent opt-in winners and matching projection of the committed state.
    result = race((select_route, pick(first["team_a"], version)), (select_route, pick(first["team_b"], version)))
    winner = next(body["snapshot"] for status, body in result if status == 200)
    current = expect(200, detail)
    assert winner == current and current["revision"] == "1" and len(rows(winner)) == 21
    assert current["bracket"]["is_done"] is False and current["bracket"]["saved_at"] is None
    assert "revision" not in expect(200, route)

    # Reverse the upstream winner to guarantee changed downstream input.
    source = next(row for row in rows(current) if row["id"] == match_id)
    opposite = first["team_b"] if source["predicted_winner"] == first["team_a"] else first["team_a"]
    fresh = expect(200, select_route, pick(opposite, current["revision"]))["snapshot"]
    downstream = next(row for row in rows(fresh) if row["id"] == source["next_match_id"])
    assert downstream["team_" + source["next_slot"]] == opposite
    assert downstream["predicted_winner"] is None and downstream["predicted_winner_games"] is None
    unchanged = fingerprint()
    expect(409, select_route, pick(first["team_a"], "0"))
    expect(400, select_route, {"action": "set_winner", "team": "invalid", "games": 4})
    assert fingerprint() == unchanged

    # Race the legacy game-count route using a coordinated starting revision.
    # A legacy writer captures an internal revision from its plan, but cannot
    # detect a user working from a stale tab if that request begins later.
    old_plan = app.ordinary_plan
    barrier = Barrier(2)
    def synchronized_plan(*args):
        result = old_plan(*args)
        barrier.wait(timeout=6)
        return result
    with patch.object(app, "ordinary_plan", synchronized_plan):
        race((games_route, {"games": 6}), (select_route, pick(first["team_a"], fresh["revision"])))

    restore_complete()
    rev = expect(200, detail)["revision"]
    race((select_route, {"action": "undo", "expected_revision":rev}),
         (select_route, pick(first["team_b"], rev)))
    restore_complete()
    rev = expect(200, detail)["revision"]
    race((save_route, {"name": "Concurrent save", "expected_revision":rev}),
         (select_route, {"action":"undo","expected_revision":rev}))
    expect(409, save_route, {"name": "Stale save", "expected_revision":rev})

    restore_complete()
    rev = expect(200, detail)["revision"]
    race((save_route, {"name":"Save vs winner","expected_revision":rev}),
         (select_route, pick(first["team_b"], rev)))
    state = expect(200, detail)
    if state["bracket"]["is_done"]:
        assert submission_error(rows(state)) is None
    restore_complete()
    legacy_save=expect(200, save_route, {"name":"Legacy resubmission"})
    assert set(legacy_save)=={"message","name","saved_at"}
    legacy=expect(200, select_route, pick(first["team_b"], None, opted=False))
    assert legacy=={"message":"Winner updated"}
    after_upstream = expect(200, detail)
    assert not after_upstream["bracket"]["is_done"]
    # Rebuild actual downstream picks through the API before resubmitting.
    for coordinate in sorted((row["slot"], row["conference"]) for row in rows(after_upstream)):
        slot, conf = coordinate
        match = next(row for row in rows(after_upstream) if row["slot"] == slot and row["conference"] == conf)
        if not match["predicted_winner"]:
            after_upstream = expect(200, route + "/match/" + match["id"], {
                "action":"set_winner", "team":match["team_a"], "games":1 if match["round"] == 0 else 4,
                "expected_revision":after_upstream["revision"], "authoritative_response":True,
            })["snapshot"]
    assert submission_error(rows(after_upstream)) is None
    expect(200, save_route, {"name":"Resubmission after rebuild","expected_revision":after_upstream["revision"]})
    assert expect(200, detail)["bracket"]["is_done"]

    # Rejection after the match UPDATE but before bracket metadata/revision write.
    before=fingerprint()
    sql(f"""
        CREATE FUNCTION fixture_fail_ordinary() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.id='{bracket_id}' THEN RAISE EXCEPTION 'fixture mid-transaction failure'; END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER fixture_fail_ordinary BEFORE UPDATE ON brackets
        FOR EACH ROW EXECUTE FUNCTION fixture_fail_ordinary();
    """)
    try:
        expect(503, select_route, pick(first["team_a"], expect(200, detail)["revision"]))
        assert fingerprint() == before
    finally:
        sql("DROP TRIGGER fixture_fail_ordinary ON brackets; DROP FUNCTION fixture_fail_ordinary();")

    # The client loses/ignores the response after commit, then only reads recovery.
    rev=expect(200, detail)["revision"]
    assert call(select_route, pick(first["team_a"], rev))[0]==200
    recovered=expect(200, detail)
    assert int(recovered["revision"])==int(rev)+1
    expect(409, select_route, pick(first["team_a"], rev))

    before=fingerprint()
    expect(401, select_route, pick(first["team_b"], recovered["revision"]), role=None)
    expect(403, select_route, pick(first["team_b"], recovered["revision"]), role=other)
    expect(403, select_route, pick(first["team_b"], recovered["revision"]), role="admin")
    sql(f"UPDATE seasons SET playoffs_start_utc=clock_timestamp()-interval '1 hour' WHERE id='{season_id}'")
    expect(403, select_route, pick(first["team_b"], recovered["revision"]))
    expect(403, save_route, {"name":"Locked"})
    assert fingerprint()==before
    open_window()
    # Close the deadline after the app pinned the previous season row but
    # before the RPC acquires the lock. Transaction-time eligibility wins.
    def close_after_plan(*args):
        result = old_plan(*args)
        sql(f"UPDATE seasons SET playoffs_start_utc=clock_timestamp()-interval '1 hour' WHERE id='{season_id}'")
        return result
    with patch.object(app, "ordinary_plan", close_after_plan):
        result = expect(403, select_route, pick(first["team_b"], recovered["revision"]))
        assert result["error"] == "Brackets are locked; you can no longer edit."
    assert fingerprint()==before
    open_window()

    historical=fixture.identity("ordinary-prototype-archived")
    sql(f"""INSERT INTO brackets(id,user_id,season_id,is_done,saved_at) VALUES
             ('{historical}','{owner_id}','{fixture.identity("historical")}',true,clock_timestamp());""")
    assert expect(200, f"/history/bracket/{historical}", role=None)["bracket"]["read_only"]
    expect(400, f"/bracket/{historical}/save", {"name":"Historic"})
    expect(403, f"/bracket/{historical}", method="DELETE")
    assert original_master == sql("SELECT md5(jsonb_agg(m ORDER BY m.id)::text) FROM matches m JOIN brackets b ON b.id=m.bracket_id WHERE b.is_master")

    # Deletion and creation use the same season lock and never expose partial graphs.
    rev=expect(200, detail)["revision"]
    start=Barrier(2)
    def delete():
        start.wait(timeout=5)
        return call(route, method="DELETE")
    def select():
        start.wait(timeout=5)
        return call(select_route, pick(first["team_b"],rev))
    with ThreadPoolExecutor(max_workers=2) as executor:
        deleting=executor.submit(delete)
        selecting=executor.submit(select)
        statuses=deleting.result(timeout=15)[0],selecting.result(timeout=15)[0]
    assert statuses in ((200,404),(200,403),(409,200),(200,200)),statuses
    if statuses[0]==409:
        expect(200, route, method="DELETE")
    expect(404, detail)
    with app.app.test_client() as client:
        token=app.generate_token(owner_id,"fixture-owner")
        response=client.post("/bracket/create",headers={"Authorization":"Bearer "+token},json={})
        assert response.status_code==200,response.get_json()
        created=response.get_json()["bracket"]["id"]
    assert len(rows(expect(200,f"/bracket/{created}?authoritative=1")))==21
    assert sql("SELECT has_function_privilege('anon','public.write_ordinary_bracket(uuid,uuid,uuid,integer,bigint,text,jsonb,text,boolean)','EXECUTE')")=="f"
    print("PASS ordinary revision, concurrent picks/Undo/games/Save/delete, rollback, recovery, eligibility, creation and master parity")


if __name__ == "__main__":
    fixture.exercise = exercise
    fixture.main(Path(sys.argv[1]), Path(sys.argv[2]))
