"""Final Save regression with disposable production-schema PostgreSQL and PostgREST."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
from threading import Barrier
from unittest.mock import patch

import master_lifecycle as fixture
from ordinary_bracket_revision import complete


def prepare(sql):
    bracket = fixture.identity("bracket-saved")
    season = fixture.identity("current")
    rows = fixture.bracket_scenario("saved")["matches"]
    predictions = {(row["conference"], row["slot"]): row for row in complete()}
    for row in rows:
        prediction = predictions[row["conference"], row["slot"]]
        for key in ("team_a", "team_b", "predicted_winner", "predicted_winner_games"):
            row[key] = prediction[key]
    sql(f"""
        UPDATE seasons SET regular_season_end_utc=now()-interval '1 day',
                           playoffs_start_utc=now()+interval '1 day' WHERE id='{season}';
        UPDATE matches m SET team_a=x.team_a,team_b=x.team_b,
            predicted_winner=x.predicted_winner,predicted_winner_games=x.predicted_winner_games
           FROM jsonb_populate_recordset(NULL::matches,$rows$ {json.dumps(rows)} $rows$::jsonb) x WHERE m.id=x.id;
        UPDATE brackets SET is_done=false,saved_at=NULL WHERE id='{bracket}';
    """)
    return bracket, season, rows


def exercise(app, sql):
    bracket, season, rows = prepare(sql)
    route = f"/bracket/{bracket}"
    owner = sql(f"SELECT user_id FROM brackets WHERE id='{bracket}'")
    other = next(fixture.identity(role) for role in ("user-a", "user-b") if fixture.identity(role) != owner)
    admin = fixture.identity("admin")
    master = fixture.identity("bracket-master")
    calls = []
    app.supabase.session.event_hooks["request"].append(lambda req: calls.append(req.url.path))

    def request(path, method="GET", body=None, actor=owner):
        headers = {"Authorization": "Bearer " + app.generate_token(actor,"fixture",actor==admin)} if actor else {}
        with app.app.test_client() as client:
            response = client.open(path,method=method,json=body,headers=headers)
            return response.status_code,response.get_json()

    def save(revision=None, name="Fixture submission", actor=owner):
        data = {"name":name}
        if revision is not None:
            data["expected_revision"] = revision
        return request(route+"/save","PATCH",data,actor)

    def snapshot(expected):
        status,payload = request(route+"?authoritative=1")
        assert status==200 and payload["revision"]==str(expected),(status,payload)
        return payload["bracket"]

    def fingerprint():
        return sql(f"""SELECT md5(jsonb_build_array(
          (SELECT to_jsonb(b) FROM brackets b WHERE id='{bracket}'),
          (SELECT to_jsonb(r) FROM ordinary_bracket_revisions r WHERE bracket_id='{bracket}'),
          (SELECT jsonb_agg(m ORDER BY m.id) FROM matches m WHERE bracket_id='{bracket}')
        )::text)""")

    assert not snapshot(0)["is_done"]
    calls.clear()
    status, first = save("0", "  First save  ")
    assert status == 200 and first["name"]=="First save" and first["revision"]=="1"
    assert calls == ["/application_season","/seasons","/users","/rpc/ordinary_bracket_plan",
                     "/users","/seasons","/rpc/write_ordinary_bracket"], calls
    assert snapshot(1)["saved_at"] == first["saved_at"]
    status, repeated = save("1","First save")
    assert status==200 and repeated["revision"]=="2" and repeated["saved_at"]>first["saved_at"]
    state = fingerprint()
    assert save("1")[0]==409 and save("2",actor=other)[0]==403 and save("2",actor=None)[0]==401
    assert fingerprint()==state

    # Two Saves capture the same revision and only one may publish.
    plan = app.ordinary_plan
    barrier = Barrier(2)
    def synchronized_plan(*args):
        value = plan(*args)
        barrier.wait(timeout=5)
        return value
    with patch.object(app,"ordinary_plan",synchronized_plan), ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda name:save("2",name),("First tab","Second tab")))
    assert sorted(status for status,_ in responses)==[200,409]
    winning_save=next(body for status,body in responses if status==200)
    assert snapshot(3)["name"]==winning_save["name"]

    # A deadline change after the preflight read still blocks the locked transaction.
    state=fingerprint()
    def close_after_plan(*args):
        value=plan(*args)
        sql(f"UPDATE seasons SET playoffs_start_utc=now()-interval '1 hour' WHERE id='{season}'")
        return value
    with patch.object(app,"ordinary_plan",close_after_plan):
        status,error=save("3")
        assert status==403 and error["error"]=="Brackets are locked; you can no longer edit."
    assert fingerprint()==state
    sql(f"UPDATE seasons SET playoffs_start_utc=now()+interval '1 day' WHERE id='{season}'")

    # Fail revision publication after the bracket update. Both must roll back.
    sql(f"""
        CREATE FUNCTION fail_save_revision() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.bracket_id='{bracket}' THEN RAISE EXCEPTION 'fixture failure'; END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER fail_save_revision BEFORE UPDATE ON ordinary_bracket_revisions
          FOR EACH ROW EXECUTE FUNCTION fail_save_revision();
    """)
    try:
        assert save("3")[0]==503 and fingerprint()==state
    finally:
        sql("DROP TRIGGER fail_save_revision ON ordinary_bracket_revisions; DROP FUNCTION fail_save_revision()")

    assert request(f"/bracket/{master}/save","PATCH",{"name":"Fixture master"},admin)[0]==200
    assert request(f"/admin/bracket/master/{master}/retire","POST",{},admin)[0]==200
    assert request(f"/bracket/{master}/save","PATCH",{"name":"Retired master"},admin)[0]==404
    assert save("3","Without a master")[0]==200
    status,_=request("/bracket/create","POST",{},admin)
    assert status==200
    status,replacement=request("/bracket/create","POST",{"replace_existing_master":True},admin)
    assert status==200
    assert request(f"/bracket/{replacement['bracket']['id']}/save","PATCH",{"name":"Replacement master"},admin)[0]==200

    # Simulate a lost response after commit. Recover with GET, without replay.
    assert save("4","Recovered by read")[0]==200
    assert snapshot(5)["name"]=="Recovered by read"
    status,legacy=save(name="Legacy repeat")
    assert status==200 and set(legacy)=={"message","name","saved_at"}
    assert snapshot(6)["saved_at"]==legacy["saved_at"]

    final=next(row for row in rows if row["conference"]=="nba")
    status,_=request(route+f"/match/{final['id']}","PATCH",{"action":"undo","expected_revision":"6"})
    assert status==200 and not snapshot(7)["is_done"]
    state=fingerprint()
    assert save("7")[0]==400 and fingerprint()==state
    sql(f"UPDATE matches SET predicted_winner=team_a,predicted_winner_games=1 WHERE id='{final['id']}'")
    state=fingerprint()
    assert save("7")[0]==400 and fingerprint()==state
    print("PASS Final Save request count, resubmission, Save race, transaction deadline, rollback, master lifecycle, recovery and legacy contract")


if __name__ == "__main__":
    fixture.exercise=exercise
    fixture.main(*map(Path,sys.argv[1:]))
