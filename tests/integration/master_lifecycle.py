"""Run with local executable paths: python -B tests/integration/master_lifecycle.py PG_BIN POSTGREST_EXE."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import requests
from postgrest import SyncPostgrestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from synthetic_fixtures import bracket_scenario, identity, league_scenario


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exercise(app, sql):
    season, old, player = map(identity, ("current", "bracket-master", "bracket-saved"))
    historical = identity("historical")
    league = identity("league-private")
    history_before = sql(f"SELECT to_jsonb(s) FROM seasons s WHERE id='{historical}'")
    historical_rows_before = sql(
        "SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM leaderboard_history h"
    )
    user_before = sql(
        f"SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM matches m WHERE bracket_id='{player}'"
    )

    def call(path, role=None, method="GET", body=None):
        headers = {}
        if role:
            headers["Authorization"] = "Bearer " + app.generate_token(
                identity(role), "fixture-" + role, role == "admin"
            )
        with app.app.test_client() as client:
            response = client.open(path, method=method, headers=headers, json=body)
        return response.status_code, response.get_json()

    def want(path, status=200, **kwargs):
        actual, data = call(path, **kwargs)
        assert actual == status, (path, actual, data)
        return data

    def boards(status, *, scored_matchup=False):
        for role, suffix in ((None, ""), ("user-a", "?league_id=" + league)):
            data = want("/leaderboard" + suffix, role=role)
            assert data["scoring_status"] == status, data
            assert len(data["rows"]) == (1 if status == "ready" else 0), data
        stats = want("/stats/champion-picks?league_id=" + league, role="user-a")
        assert stats["scoring_status"] == status and stats["total_brackets"] == 1, stats
        assert (
            stats["rows"][0]["team_code"] == "BOS"
            and stats["rows"][0]["percent"] == 100
        ), stats
        if status == "pending" or scored_matchup:
            assert (stats["most_predicted_matchup"] is None) == (
                status == "pending"
            ), stats

    admin = dict(role="admin", method="POST")
    recompute = "/admin/score/recompute"

    def retire(master):
        return f"/admin/bracket/master/{master}/retire"

    boards("pending")
    assert sql("SELECT count(*) FROM bracket_scores") == "1"
    want(recompute, **admin)
    boards("ready", scored_matchup=True)
    assert want(recompute, **admin)["state"] == "unchanged"
    boards("ready", scored_matchup=True)
    want(retire(old), 403, role="user-a", method="POST")
    want(retire(identity("bracket-historical")), 409, **admin)
    # Simulate an accepted same-master result edit before its separate publication.
    sql(
        f"UPDATE matches SET predicted_winner=team_b WHERE bracket_id='{old}' AND conference='east' AND slot=1"
    )
    boards("pending")
    sql("""
      CREATE FUNCTION deny_fixture_scores() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'Synthetic publication interruption'; END $$;
      CREATE TRIGGER deny_fixture_scores BEFORE INSERT ON bracket_scores
        FOR EACH ROW EXECUTE FUNCTION deny_fixture_scores();
    """)
    want(recompute, 503, **admin)
    boards("pending")
    assert sql("SELECT count(*) FROM bracket_scores") == "1"
    sql("DROP TRIGGER deny_fixture_scores ON bracket_scores")
    want(recompute, **admin)
    boards("ready")
    want(retire(old), **admin)
    want(retire(old), 409, **admin)
    assert (
        sql(
            f"SELECT deleted_at IS NOT NULL AND NOT is_master AND deleted_by_user_id='{identity('admin')}' FROM brackets WHERE id='{old}'"
        )
        == "t"
    )
    assert sql(f"SELECT count(*) FROM matches WHERE bracket_id='{old}'") == "21"
    assert (
        sql(f"SELECT master_bracket_id IS NULL FROM seasons WHERE id='{season}'") == "t"
    )
    boards("pending")
    want(recompute, 503, **admin)
    new = want("/bracket/create", **admin)["bracket"]["id"]
    assert new != old
    boards("ready")
    with ThreadPoolExecutor(max_workers=2) as pool:
        replacement = pool.submit(
            call, "/bracket/create", "admin", "POST", {"replace_existing_master": True}
        )
        retirement = pool.submit(call, retire(new), "admin", "POST")
        replacement_state, replacement_data = replacement.result()
        retirement_state, _ = retirement.result()
    assert (replacement_state, retirement_state) in {(200, 200), (200, 409)}, (
        replacement_state,
        retirement_state,
        replacement_data,
    )
    authoritative = replacement_data["bracket"]["id"]
    assert (
        sql(f"SELECT master_bracket_id FROM seasons WHERE id='{season}'")
        == authoritative
    )
    assert (
        sql(
            f"SELECT count(*) FROM brackets WHERE season_id='{season}' AND is_master AND deleted_at IS NULL"
        )
        == "1"
    )
    assert (
        sql(
            f"SELECT DISTINCT master_bracket_id FROM bracket_scores WHERE season_id='{season}'"
        )
        == authoritative
    )
    want(retire(new), 409, **admin)
    boards("ready")
    assert (
        sql(f"SELECT to_jsonb(s) FROM seasons s WHERE id='{historical}'")
        == history_before
    )
    assert (
        sql(
            f"SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM matches m WHERE bracket_id='{player}'"
        )
        == user_before
    )
    sql("""CREATE TRIGGER deny_fixture_scores BEFORE INSERT ON bracket_scores
        FOR EACH ROW EXECUTE FUNCTION deny_fixture_scores()""")
    failure = want(
        "/bracket/create", 503, body={"replace_existing_master": True}, **admin
    )
    assert failure["master_mutation_committed"] is True
    replacement = sql(f"SELECT master_bracket_id FROM seasons WHERE id='{season}'")
    assert replacement != authoritative
    assert (
        sql(
            f"SELECT DISTINCT master_bracket_id FROM bracket_scores WHERE season_id='{season}'"
        )
        == authoritative
    )
    boards("pending")
    sql("DROP TRIGGER deny_fixture_scores ON bracket_scores")
    want(recompute, **admin)
    boards("ready")
    assert (
        sql(
            f"SELECT DISTINCT master_bracket_id FROM bracket_scores WHERE season_id='{season}'"
        )
        == replacement
    )
    assert (
        sql("SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM leaderboard_history h")
        == historical_rows_before
    )
    print(
        "PASS master retirement, retained audit, readiness, failure/recovery, replacement race, champion counts and isolation"
    )


def main(pg, postgrest, *, server_timing=False):
    pgport, apiport = free_port(), free_port()
    assert pgport != apiport
    api = f"http://127.0.0.1:{apiport}"
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(
            (
                "PG",
                "PGRST",
                "SUPABASE",
                "NBA_",
                "JWT_",
                "DATABASE",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
            )
        )
    }
    env["PATH"] = str(pg) + os.pathsep + env["PATH"]
    env.update(NO_PROXY="127.0.0.1,localhost", PGPASSWORD=secrets.token_hex(24))
    with tempfile.TemporaryDirectory(
        prefix="nba-03k1-", ignore_cleanup_errors=True
    ) as tmp, ExitStack() as stack:
        work = Path(tmp)
        data, pw = work / "db", work / "pw"
        pw.write_text(env["PGPASSWORD"])

        def pg_run(command, *args, **kwargs):
            return subprocess.run(
                [pg / (command + ".exe"), *args], env=env, check=True, **kwargs
            )

        pg_run(
            "initdb",
            "-D",
            data,
            "-U",
            "postgres",
            "-A",
            "scram-sha-256",
            "--pwfile",
            pw,
            "--encoding=UTF8",
            "--locale=C",
            stdout=subprocess.DEVNULL,
        )
        pw.unlink()
        pg_run(
            "pg_ctl",
            "-D",
            data,
            "-l",
            work / "pg.log",
            "-o",
            f"-h 127.0.0.1 -p {pgport}" + (" -c shared_preload_libraries=pg_stat_statements" if server_timing else ""),
            "-w",
            "start",
            stdout=subprocess.DEVNULL,
        )
        stack.callback(
            pg_run,
            "pg_ctl",
            "-D",
            data,
            "-m",
            "fast",
            "-w",
            "stop",
            stdout=subprocess.DEVNULL,
        )

        def sql(body):
            return pg_run(
                "psql",
                "-XqAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "127.0.0.1",
                "-p",
                str(pgport),
                "-U",
                "postgres",
                "-d",
                "postgres",
                input=body,
                encoding="utf-8",
                stdout=subprocess.PIPE,
            ).stdout.strip()

        baseline = (ROOT / "db/baseline/000_current_schema.sql").read_text(
            encoding="utf-8"
        )
        schema = baseline.split("-- Application DDL preserved", 1)[1].split(
            "DO $baseline_verify$", 1
        )[0]
        sql("""
          CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
          CREATE SCHEMA auth; CREATE SCHEMA extensions;
          CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS 'SELECT NULL::uuid';
          CREATE EXTENSION "uuid-ossp" WITH SCHEMA extensions;
          GRANT USAGE ON SCHEMA extensions TO service_role;
        """)
        sql("SET check_function_bodies=false;\n-- Application DDL preserved" + schema)
        migrations = sorted((ROOT / "db/post-baseline").glob("00[0-9][0-9]*.sql"))
        score_migration = next(i for i, migration in enumerate(migrations) if migration.name.startswith("0013_"))
        for migration in migrations[:score_migration]:
            sql(migration.read_text(encoding="utf-8"))

        fixture = bracket_scenario("master")
        fixture["brackets"] += bracket_scenario("saved")["brackets"]
        fixture["matches"] += bracket_scenario("saved")["matches"]
        fixture["leagues"] = league_scenario()["leagues"]
        fixture["league_members"] = league_scenario()["league_members"]
        fixture["seasons"][0]["master_bracket_id"] = None
        inserts = []
        for name in (
            "users",
            "seasons",
            "teams",
            "standings",
            "brackets",
            "matches",
            "leagues",
            "league_members",
        ):
            rows = fixture[name]
            columns = ",".join(rows[0])
            inserts.append(
                f"INSERT INTO {name}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::{name}, $fixture${json.dumps(rows)}$fixture$::jsonb);"
            )
        sql("BEGIN; SET CONSTRAINTS ALL DEFERRED;\n" + "\n".join(inserts) + "COMMIT;")
        season, old, player, historic = map(
            identity, ("current", "bracket-master", "bracket-saved", "historical")
        )
        sql(f"""
          INSERT INTO application_season(season_id) VALUES ('{season}');
          UPDATE seasons SET master_bracket_id='{old}' WHERE id='{season}';
          UPDATE matches SET predicted_winner='BOS' WHERE bracket_id='{player}' AND conference='nba';
          INSERT INTO bracket_scores(bracket_id,master_bracket_id,season_id) VALUES('{player}','{old}','{season}');
          INSERT INTO leaderboard_history(season_id,season_code,rank,bracket_name,username,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion)
           VALUES ('{historic}','2024-25',1,'Archived fixture','archive',14,0,0,0,0,0);
        """)
        for migration in migrations[score_migration:]:
            sql(migration.read_text(encoding="utf-8"))
        assert (
            sql(
                "SELECT has_function_privilege('anon','public.retire_current_master(uuid,uuid,uuid)','EXECUTE')"
            )
            == "f"
        )
        assert (
            sql(
                "SELECT has_function_privilege('authenticated','public.read_current_score_snapshot(uuid)','EXECUTE')"
            )
            == "f"
        )
        rest_log = stack.enter_context((work / "postgrest.log").open("w+b"))
        proc = subprocess.Popen(
            [postgrest],
            env={
                **env,
                "PGRST_DB_URI": f"postgres://postgres@127.0.0.1:{pgport}/postgres",
                "PGRST_DB_ANON_ROLE": "service_role",
                "PGRST_SERVER_PORT": str(apiport),
                "PGRST_SERVER_HOST": "127.0.0.1",
                "PGRST_SERVER_TIMING_ENABLED": str(server_timing).lower(),
            },
            stdout=rest_log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        stack.callback(proc.wait, 10)
        stack.callback(proc.terminate)
        http = requests.Session()
        http.trust_env = False
        for _ in range(100):
            try:
                if http.get(api + "/seasons", timeout=1).ok:
                    break
            except requests.ConnectionError:
                pass
            if proc.poll() is not None:
                raise RuntimeError(f"Fixture PostgREST exited ({proc.returncode})")
            time.sleep(0.1)
        else:
            raise RuntimeError("Fixture PostgREST is unavailable")
        db = SyncPostgrestClient(api)
        with patch.dict(
            os.environ,
            {
                "NBA_CORNER_ENV": "production",
                "SUPABASE_URL": api,
                "SUPABASE_KEY": "local-fixture",
                "JWT_SECRET": "local-synthetic-not-a-production-key",
                "FRONTEND_ORIGIN": api,
                "BCRYPT_ROUNDS": "4",
                "NO_PROXY": "127.0.0.1",
            },
            clear=True,
        ), patch("dotenv.load_dotenv", return_value=False), patch(
            "supabase.create_client", return_value=db
        ):
            import app

            assert Path(app.__file__).resolve() == ROOT / "app.py"
            exercise(app, sql)


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:]))
