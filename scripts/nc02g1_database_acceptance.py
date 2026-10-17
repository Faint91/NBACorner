"""Fixed disposable G1 migration refusal, identity uniqueness and real races."""

import subprocess
import threading
import queue
import time
from synthetic_fixtures import identity
from scripts.local_supabase_environment import CONTAINER, child_environment


def preflight(sql, migration):
    findings = []
    for name, username, email in (
        ("username_collision", " FIXTURE-USER-A ", "g1-collision@nba-corner.example"),
        ("email_collision", "G1Collision", " USER-A@NBA-CORNER.EXAMPLE "),
        ("blank_identity", " ", "g1-blank@nba-corner.example"),
        ("null_identity", "G1Null", None),
    ):
        literal = "NULL" if email is None else "'" + email + "'"
        try:
            sql(
                f"BEGIN; INSERT INTO public.users(username,email) VALUES('{username}',{literal});\n"
                + migration
            )
        except Exception:
            # Failure ends that fresh psql session, rolling back all preflight DDL/DML.
            pass
        else:
            raise AssertionError("G1 migration accepted invalid source identities")
        sql(
            "DO $$ BEGIN IF to_regprocedure('public.auth_identity_key(text)') IS NOT NULL OR (SELECT count(*) FROM public.users)<>4 THEN RAISE EXCEPTION 'Failed preflight escaped rollback'; END IF; END $$;"
        )
        findings.append(name + "_migration_refused_without_repair")
    return findings


def run(sql):
    sql("""BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO public.users(username,email) VALUES('G1Unique','g1-unique@nba-corner.example');
DO $$ BEGIN
 BEGIN INSERT INTO public.users(username,email) VALUES(' g1unique ','g1-second@nba-corner.example'); RAISE EXCEPTION 'Username duplicate accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN INSERT INTO public.users(username,email) VALUES('G1Second',' G1-UNIQUE@NBA-CORNER.EXAMPLE '); RAISE EXCEPTION 'Email duplicate accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN INSERT INTO public.users(username,email) VALUES(' ','g1-blank@nba-corner.example'); RAISE EXCEPTION 'Blank accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 IF public.find_auth_user('username',' G1UNIQUE ')->>'username'<>'G1Unique' OR public.find_auth_user('email',' G1-UNIQUE@NBA-CORNER.EXAMPLE ')->>'username'<>'G1Unique' THEN RAISE EXCEPTION 'Normalized trusted lookup failed'; END IF;
 IF public.find_auth_user('password','anything') IS NOT NULL THEN RAISE EXCEPTION 'Unsupported identity field accepted'; END IF;
END $$;
ROLLBACK;
""")
    for role in ("anon", "authenticated"):
        sql(f"""BEGIN; SET LOCAL ROLE {role}; DO $$ BEGIN
 BEGIN PERFORM public.auth_identity_key('value'); RAISE EXCEPTION 'Untrusted normalization access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM public.find_auth_user('username','fixture-user-a'); RAISE EXCEPTION 'Untrusted credential access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM password FROM public.users; RAISE EXCEPTION 'Untrusted user access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$; ROLLBACK;""")
    return [
        "trusted_structural_username_email_uniqueness",
        "trusted_normalized_lookup",
        "blank_direct_write_refused",
        "unknown_lookup_field_empty",
        "anon_and_authenticated_functions_and_users_denied",
    ]


def contention(sql, database):
    if database != "nc_02f2_bootstrap_proof":
        raise ValueError("Fixed disposable database required")
    findings = []
    for field in ("username", "email"):
        first_name, second_name = (
            ("G1Race", " g1race ") if field == "username" else ("G1RaceA", "G1RaceB")
        )
        first_email, second_email = (
            ("g1-race-a@nba-corner.example", "g1-race-b@nba-corner.example")
            if field == "username"
            else ("g1-race@nba-corner.example", " G1-RACE@NBA-CORNER.EXAMPLE ")
        )
        args = [
            "docker",
            "exec",
            "-i",
            CONTAINER,
            "psql",
            "-X",
            "-qAt",
            "-U",
            "postgres",
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            "VERBOSITY=sqlstate",
        ]
        holder = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment(),
        )
        contender = None
        ready = queue.Queue()

        def drain():
            for line in holder.stdout:
                if b"G1_READY" in line:
                    ready.put(True)
                    return
            ready.put(False)

        threading.Thread(target=drain, daemon=True).start()
        try:
            holder.stdin.write(
                (
                    f"BEGIN; SET LOCAL ROLE service_role; INSERT INTO public.users(id,username,email) VALUES('{identity('g1-race-a')}','{first_name}','{first_email}');\n\\echo G1_READY\n"
                ).encode()
            )
            holder.stdin.flush()
            if not ready.get(timeout=10):
                raise AssertionError("Registration holder failed")
            contender = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment(),
            )
            contender.stdin.write(
                (
                    f"SET ROLE service_role; INSERT INTO public.users(id,username,email) VALUES('{identity('g1-race-b')}','{second_name}','{second_email}');\n"
                ).encode()
            )
            contender.stdin.close()
            for _ in range(40):
                check = sql(
                    "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND NOT l.granted;"
                )
                if any(line.strip() == b"1" for line in check.splitlines()):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Registration contender did not wait")
            holder.stdin.write(b"COMMIT;\n")
            holder.stdin.close()
            holder.wait(timeout=15)
            contender.wait(timeout=15)
            assert holder.returncode == 0 and contender.returncode != 0
            assert (
                b"23505" in contender.stderr.read()
            ), "Expected structural uniqueness conflict"
            sql(
                f"DO $$ BEGIN IF (SELECT count(*) FROM public.users WHERE id IN('{identity('g1-race-a')}','{identity('g1-race-b')}'))<>1 THEN RAISE EXCEPTION 'Race created duplicates'; END IF; END $$; DELETE FROM public.users WHERE id='{identity('g1-race-a')}';"
            )
            findings.append(
                field + "_real_concurrent_normalized_insert_exactly_one_commit"
            )
        finally:
            for process in (holder, contender):
                if process is None:
                    continue
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream and not stream.closed:
                        stream.close()
    return findings


def routes(sql, *, versioned=False):
    """Actual G1 Flask routes + password/JWT helpers over the fresh fixed SQL DB."""
    import ast
    import json
    import secrets
    from pathlib import Path
    from types import SimpleNamespace
    from datetime import datetime, timedelta
    from flask import Flask, request, jsonify
    import jwt
    from identity_auth_service import hash_password

    def literal(value):
        return (
            "'" + json.dumps(value, ensure_ascii=False).replace("'", "''") + "'::jsonb"
        )

    def result(query):
        output = sql(query).decode("utf-8")
        return json.loads(
            next(
                line.strip()
                for line in output.splitlines()
                if line.lstrip().startswith("{")
            )
        )["data"]

    class Query:
        def __init__(self, query):
            self.query = query

        def execute(self):
            return SimpleNamespace(data=result(self.query))

    class Users:
        def insert(self, payload):
            data = literal(payload)
            return Query(
                "WITH added AS (INSERT INTO public.users(username,email,password) SELECT p->>'username',p->>'email',p->>'password' FROM (SELECT "
                + data
                + " AS p) v RETURNING *) SELECT jsonb_build_object('data',jsonb_agg(to_jsonb(added))) FROM added;"
            )

    class DB:
        def table(self, name):
            if name != "users":
                raise ValueError("Only fixed registration table admitted")
            return Users()

        def rpc(self, name, params):
            if name == "auth_identity_key":
                expression = (
                    "public.auth_identity_key("
                    + literal(params["p_value"])
                    + "#>>'{}')"
                )
            elif name == "find_auth_user":
                expression = (
                    "public.find_auth_user("
                    + literal(params["p_field"])
                    + "#>>'{}',"
                    + literal(params["p_identity"])
                    + "#>>'{}')"
                )
            else:
                raise ValueError("Only fixed G1 read functions admitted")
            return Query("SELECT jsonb_build_object('data'," + expression + ");")

    root = Path(__file__).resolve().parents[1]
    if versioned:
        source = (root / "app.py").read_text(encoding="utf-8")
    else:
        # Freeze the historical G1 proof before migration 0011. G2's proof
        # explicitly requests current actual routes with versioned=True.
        source = subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=" + root.as_posix(),
                "-C",
                str(root),
                "show",
                "6eb31070c55b2a8b2c789fafcf90adea55f017b8:app.py",
            ],
            capture_output=True,
            check=True,
            env=child_environment(),
        ).stdout.decode("utf-8")
    tree = ast.parse(source)
    nodes = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name in {"register", "login", "generate_token", "decode_token"}
    ]
    app = Flask("g1-fresh-route-proof")
    key = secrets.token_urlsafe(48)
    env = dict(
        app=app,
        request=request,
        jsonify=jsonify,
        supabase=DB(),
        BCRYPT_ROUNDS=4,
        DUMMY_LOGIN_HASH=hash_password(secrets.token_hex(32), rounds=4),
        is_rate_limited=lambda *args: False,
        get_client_ip=lambda: "local-proof",
        datetime=datetime,
        timedelta=timedelta,
        jwt=jwt,
        JWT_SECRET=key,
        JWT_ALGORITHM="HS256",
    )
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]),
            "actual G1 routes over fixed fresh database",
            "exec",
        ),
        env,
    )
    client = app.test_client()
    password = " " + "界" * 40 + " "
    registered = client.post(
        "/auth/register",
        json=dict(
            username=" FreshG1 ",
            email=" FRESH-G1@NBA-CORNER.EXAMPLE ",
            password=password,
        ),
    )
    assert registered.status_code == 201
    assert registered.json["user"]["username"] == "FreshG1"
    for field, value in (
        ("username", " freshg1 "),
        ("email", " FRESH-G1@NBA-CORNER.EXAMPLE "),
    ):
        response = client.post("/auth/login", json={field: value, "password": password})
        assert response.status_code == 200
        claims = jwt.decode(response.json["token"], key, algorithms=["HS256"])
        assert set(claims) == (
            {"user_id", "username", "is_admin", "exp", "av"}
            if versioned
            else {"user_id", "username", "is_admin", "exp"}
        )
        assert claims["user_id"] == registered.json["user"]["id"]
        assert (
            client.post(
                "/auth/login", json={field: value, "password": password.strip()}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/auth/login",
            json=dict(
                email="user-a@nba-corner.example", password="NCFixture!2026-user-a"
            ),
        ).status_code
        == 200
    )
    sql("DELETE FROM public.users WHERE username='FreshG1';")
    return [
        "fresh_actual_flask_registration_normalized_storage",
        "fresh_actual_flask_both_identifier_login_exact_long_unicode_spaces",
        "fresh_original_JWT_claims_and_legacy_login",
    ]
