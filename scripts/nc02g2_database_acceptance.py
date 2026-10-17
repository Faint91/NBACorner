"""Fixed disposable local G2 SQL/actual-route and concurrency acceptance."""

import hashlib
import json
import secrets
import subprocess
import threading
import queue
import time
from pathlib import Path
from synthetic_fixtures import identity
from identity_auth_service import hash_password
from scripts.local_supabase_environment import CONTAINER, child_environment

SUBJECT = identity("user-a")


def literal(value):
    return "'" + json.dumps(value).replace("'", "''") + "'::jsonb"


def digest():
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def issue(value):
    return f"public.issue_password_reset('{SUBJECT}','{value}')"


def complete(value, hashed):
    return f"public.complete_password_reset('{value}',{literal(hashed)}#>>'{{}}')"


def run(sql):
    sql(
        "DO $g2proof$ BEGIN IF EXISTS(SELECT 1 FROM public.password_resets) OR EXISTS(SELECT 1 FROM public.users WHERE auth_version<>0 OR reset_token IS NOT NULL OR reset_token_expires IS NOT NULL) THEN RAISE EXCEPTION 'Legacy reset migration/default failed'; END IF; END $g2proof$;"
    )
    value = digest()
    newer = digest()
    hashed = hash_password("new exact password ", rounds=4)
    sql(f"""BEGIN;
SELECT {issue(value)}; SELECT {issue(newer)};
DO $g2proof$ BEGIN
 IF {complete(value,hashed)} THEN RAISE EXCEPTION 'Superseded reset accepted'; END IF;
 IF (SELECT count(*) FROM public.password_resets)<>1 THEN RAISE EXCEPTION 'Multiple active reset links'; END IF;
END $g2proof$;
SELECT public.cancel_password_reset('{SUBJECT}','{value}');
DO $g2proof$ BEGIN IF NOT EXISTS(SELECT 1 FROM public.password_resets WHERE token_digest='{newer}') THEN RAISE EXCEPTION 'Cancellation removed newer token'; END IF; END $g2proof$;
CREATE FUNCTION public.g2_password_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'Synthetic password update failure'; END $f$;
CREATE TRIGGER g2_password_fault BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.g2_password_fault();
DO $g2proof$ BEGIN
 BEGIN PERFORM {complete(newer,hashed)}; RAISE EXCEPTION 'Fault missing'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic password update failure' THEN RAISE; END IF; END;
 IF NOT EXISTS(SELECT 1 FROM public.password_resets WHERE token_digest='{newer}') OR (SELECT auth_version FROM public.users WHERE id='{SUBJECT}')<>0 THEN RAISE EXCEPTION 'Partial reset committed'; END IF;
END $g2proof$;
DROP TRIGGER g2_password_fault ON public.users; DROP FUNCTION public.g2_password_fault();
DO $g2proof$ BEGIN
 IF NOT {complete(newer,hashed)} OR {complete(newer,hashed)} THEN RAISE EXCEPTION 'Completion/replay failed'; END IF;
 IF EXISTS(SELECT 1 FROM public.password_resets) OR (SELECT auth_version FROM public.users WHERE id='{SUBJECT}')<>1 THEN RAISE EXCEPTION 'Completion state failed'; END IF;
END $g2proof$;
ROLLBACK;
""")
    # Controlled clock: only the production function's clock expression changes,
    # transactionally in the disposable DB; all validation/locking stays actual.
    migration = Path(
        "db/post-baseline/0011_nc_02g2_password_reset_sessions.sql"
    ).read_text(encoding="utf-8")
    import re

    source = re.search(
        r"CREATE FUNCTION public.complete_password_reset.*?\$body\$;", migration, re.S
    )[0]
    fixed = source.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1).replace(
        "clock_timestamp()", "'2030-01-01T00:00:00Z'::timestamptz"
    )
    for offset, expected in ((1, True), (0, False), (-1, False)):
        sql(
            f"BEGIN; {fixed} SELECT {issue(value)}; UPDATE public.password_resets SET expires_at='2030-01-01T00:00:00Z'::timestamptz+interval '{offset} seconds'; DO $g2proof$ BEGIN IF {complete(value,hashed)} IS DISTINCT FROM {str(expected).lower()} THEN RAISE EXCEPTION 'Exact expiry boundary failed'; END IF; END $g2proof$; ROLLBACK;"
        )
    for role in ("anon", "authenticated"):
        sql(f"""BEGIN; SET LOCAL ROLE {role}; DO $g2proof$ BEGIN
 BEGIN PERFORM public.issue_password_reset('{SUBJECT}','{value}'); RAISE EXCEPTION 'Untrusted issuance'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM {complete(value,hashed)}; RAISE EXCEPTION 'Untrusted completion'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM public.cancel_password_reset('{SUBJECT}','{value}'); RAISE EXCEPTION 'Untrusted cancellation'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM token_digest FROM public.password_resets; RAISE EXCEPTION 'Untrusted digest read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE public.users SET auth_version=1; RAISE EXCEPTION 'Untrusted version write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 END $g2proof$; ROLLBACK;""")
    return [
        "legacy_tokens_deleted_user_fields_cleared_default_zero",
        "supersession_and_conditional_cancellation",
        "password_update_fault_rolls_back_token_and_version",
        "single_completion_replay_no_extra_increment",
        "controlled_clock_before_exact_after_expiry",
        "browser_table_column_and_RPC_access_denied",
    ]


def routes(sql):
    import ast
    from types import SimpleNamespace
    from datetime import datetime, timedelta
    from flask import Flask, request, jsonify
    import jwt
    from functools import wraps
    from identity_auth_service import hash_password as hasher

    def result(query):
        output = sql(query).decode()
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
        def select(self, fields):
            if fields != "id,auth_version":
                raise ValueError("Only reviewed session projection")
            return self

        def eq(self, key, value):
            if key != "id":
                raise ValueError("Only reviewed user identity")
            self.value = value
            return self

        def execute(self):
            return SimpleNamespace(
                data=result(
                    "SELECT jsonb_build_object('data',coalesce(jsonb_agg(jsonb_build_object('id',id,'auth_version',auth_version)),'[]')) FROM public.users WHERE id=("
                    + literal(self.value)
                    + "#>>'{}')::uuid;"
                )
            )

    class DB:
        def table(self, name):
            if name != "users":
                raise ValueError("Only reviewed session table")
            return Users()

        def rpc(self, name, params):
            signatures = {
                "auth_identity_key": (("p_value",), ()),
                "find_auth_user": (("p_field", "p_identity"), ()),
                "issue_password_reset": (("p_user_id", "p_digest"), ("p_user_id",)),
                "cancel_password_reset": (("p_user_id", "p_digest"), ("p_user_id",)),
                "complete_password_reset": (("p_digest", "p_password_hash"), ()),
            }
            keys, uuids = signatures[name]
            if set(keys) != set(params):
                raise ValueError("Unexpected RPC parameters")
            args = ",".join(
                "(" + literal(params[k]) + "#>>'{}')" + ("::uuid" if k in uuids else "")
                for k in keys
            )
            return Query(
                "SELECT jsonb_build_object('data',public." + name + "(" + args + "));"
            )

    source = ast.parse(Path("app.py").read_text(encoding="utf-8"))
    names = {
        "login_user",
        "generate_token",
        "decode_token",
        "require_auth",
        "forgot_password",
        "reset_password",
        "test_me",
    }
    # Login function name follows current source, not an invented route.
    nodes = [
        n
        for n in source.body
        if isinstance(n, ast.FunctionDef)
        and (
            n.name in names
            or any(
                isinstance(d, ast.Call)
                and d.args
                and isinstance(d.args[0], ast.Constant)
                and d.args[0].value == "/auth/login"
                for d in n.decorator_list
            )
        )
    ]
    app = Flask("g2-fresh-proof")
    mails = []
    key = secrets.token_hex(32)
    env = dict(
        app=app,
        request=request,
        jsonify=jsonify,
        supabase=DB(),
        BCRYPT_ROUNDS=4,
        DUMMY_LOGIN_HASH=hasher("synthetic dummy password", rounds=4),
        is_rate_limited=lambda *a: False,
        get_client_ip=lambda: "local-proof",
        datetime=datetime,
        timedelta=timedelta,
        jwt=jwt,
        JWT_SECRET=key,
        JWT_ALGORITHM="HS256",
        wraps=wraps,
        safe_print=lambda *a: None,
        build_reset_link=lambda raw: "http://127.0.0.1:55410/reset-password?token="
        + raw,
        send_email_via_brevo=lambda recipient, subject, body: (
            mails.append(body) or True
        ),
    )
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]),
            "actual G2 routes over fixed disposable SQL",
            "exec",
        ),
        env,
    )
    client = app.test_client()

    def login(password):
        return client.post(
            "/auth/login",
            json={"email": "user-a@nba-corner.example", "password": password},
        )

    tokens = [login("NCFixture!2026-user-a").json["token"] for _ in range(2)]
    claims = jwt.decode(tokens[0], key, algorithms=["HS256"])
    claims.pop("av")
    tokens.append(jwt.encode(claims, key, algorithm="HS256"))

    def auth(token):
        return client.get(
            "/auth/test-me", headers={"Authorization": "Bearer " + token}
        ).status_code

    assert all(auth(t) == 200 for t in tokens)
    assert (
        client.post(
            "/auth/forgot-password", json={"email": "user-a@nba-corner.example"}
        ).status_code
        == 200
    )
    import re

    raw = re.search(r"token=([A-Za-z0-9_-]+)", mails.pop())[1]
    password = " " + "😀" * 80 + " "
    assert (
        client.post(
            "/auth/reset-password", json={"token": raw, "new_password": password}
        ).status_code
        == 200
    )
    assert all(auth(t) == 401 for t in tokens)
    assert login("NCFixture!2026-user-a").status_code == 401
    fresh = login(password)
    assert fresh.status_code == 200 and auth(fresh.json["token"]) == 200
    assert (
        client.post(
            "/auth/reset-password",
            json={"token": raw, "new_password": "another password"},
        ).status_code
        == 400
    )
    # A normal MVCC auth read can finish while a reset is uncommitted;
    # the same JWT must fail once the reset commits, without process restart.
    assert (
        client.post(
            "/auth/forgot-password", json={"email": "user-a@nba-corner.example"}
        ).status_code
        == 200
    )
    raw = re.search(r"token=([A-Za-z0-9_-]+)", mails.pop())[1]
    verifier = hashlib.sha256(raw.encode()).hexdigest()
    hashed = hasher("post race password", rounds=4)
    holder = subprocess.Popen(
        [
            "docker",
            "exec",
            "-i",
            CONTAINER,
            "psql",
            "-X",
            "-q",
            "-U",
            "postgres",
            "-d",
            "nc_02f2_bootstrap_proof",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment(),
    )
    ready = queue.Queue()

    def drain_auth_race():
        for line in holder.stdout:
            if line.strip() == b"G2_AUTH_READY":
                ready.put(True)

    threading.Thread(target=drain_auth_race, daemon=True).start()
    try:
        holder.stdin.write(
            (
                "BEGIN; SELECT "
                + complete(verifier, hashed)
                + ";\n\\echo G2_AUTH_READY\n"
            ).encode()
        )
        holder.stdin.flush()
        assert ready.get(timeout=10)
        assert auth(fresh.json["token"]) == 200
        holder.stdin.write(b"COMMIT;\n")
        holder.stdin.close()
        holder.wait(timeout=15)
        assert holder.returncode == 0
        assert auth(fresh.json["token"]) == 401
    finally:
        if holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=10)
        for stream in (holder.stdin, holder.stdout, holder.stderr):
            if stream and not stream.closed:
                stream.close()
    from scripts.nc02f2_database_acceptance import reset_disposable

    reset_disposable(sql)
    return [
        "fresh_actual_Flask_request_completion_and_capture",
        "fresh_actual_JWT_two_devices_and_missing_av_revoked",
        "fresh_old_password_rejected_exact_long_new_password_login",
        "fresh_replay_refused_fixture_restored",
        "actual_JWT_read_during_uncommitted_reset_then_rejected_after_commit",
    ]


def contention(sql, database):
    if database != "nc_02f2_bootstrap_proof":
        raise ValueError("Fixed disposable database only")
    findings = []
    hashed = hash_password("concurrent password", rounds=4)
    args = [
        "docker",
        "exec",
        "-i",
        CONTAINER,
        "psql",
        "-X",
        "-q",
        "-U",
        "postgres",
        "-d",
        database,
        "-v",
        "ON_ERROR_STOP=1",
        "-At",
    ]
    for mode in (
        "issue_issue",
        "complete_complete",
        "issue_complete",
        "complete_issue",
    ):
        first, second, third = digest(), digest(), digest()
        sql(f"SELECT {issue(first)};")
        before = (
            "SELECT "
            + (issue(second) if mode.startswith("issue_") else complete(first, hashed))
            + ";"
        )
        after = (
            "SELECT "
            + (
                issue(third if mode == "issue_issue" else second)
                if mode.endswith("_issue")
                else complete(first, hashed)
            )
            + ";"
        )
        holder = contender = None
        ready = queue.Queue()
        try:
            holder = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment(),
            )

            def drain():
                for line in holder.stdout:
                    if line.strip() == b"G2_READY":
                        ready.put(True)

            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            holder.stdin.write(("BEGIN; " + before + "\n\\echo G2_READY\n").encode())
            holder.stdin.flush()
            assert ready.get(timeout=10)
            contender = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment(),
            )
            contender.stdin.write(after.encode())
            contender.stdin.close()
            for _ in range(60):
                waiting = sql(
                    "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND NOT l.granted;"
                )
                if any(line.strip() == b"1" for line in waiting.splitlines()):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Contender did not serialize")
            holder.stdin.write(b"COMMIT;\n")
            holder.stdin.close()
            holder.wait(timeout=15)
            contender.wait(timeout=15)
            assert holder.returncode == 0 and contender.returncode == 0
            output = contender.stdout.read().splitlines()
            expected = b"f" if mode.endswith("_complete") else b"t"
            assert expected in output
            expected_version = 0 if mode in {"issue_issue", "issue_complete"} else 1
            expected_rows = 0 if mode == "complete_complete" else 1
            sql(
                f"DO $g2proof$ BEGIN IF (SELECT auth_version FROM public.users WHERE id='{SUBJECT}')<>{expected_version} OR (SELECT count(*) FROM public.password_resets)<>{expected_rows} THEN RAISE EXCEPTION 'Race state inconsistent'; END IF; END $g2proof$;"
            )
            if expected_rows:
                sql(
                    f"DO $g2proof$ BEGIN IF NOT {complete(third if mode=="issue_issue" else second,hashed)} THEN RAISE EXCEPTION 'Winning token not usable'; END IF; END $g2proof$;"
                )
            findings.append(mode + "_real_two_sessions_serialized_consistent_winner")
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
            from scripts.nc02f2_database_acceptance import reset_disposable

            reset_disposable(sql)
    return findings
