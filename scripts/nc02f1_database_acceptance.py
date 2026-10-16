"""Reviewed F1 SQL acceptance in a disposable, enrolled-local schema clone only."""

from synthetic_fixtures import identity


def preflight(sql, migrate):
    from environment_safety import SafetyError

    owner = identity("owner")
    a = identity("f1-preflight-a")
    b = identity("f1-preflight-b")
    findings = []
    for category, name, second, member in (
        ("normalized_collision", "NBA Friends", "nba friends", True),
        ("owner_membership", "NBA Friends", None, False),
        ("untrimmed_name", " NBA Friends ", None, True),
    ):
        sql(
            f"INSERT INTO public.leagues(id,name,owner_user_id) VALUES('{a}','{name}','{owner}');"
            + (
                f"INSERT INTO public.league_members(league_id,user_id) VALUES('{a}','{owner}');"
                if member
                else ""
            )
            + (
                f"INSERT INTO public.leagues(id,name,owner_user_id) VALUES('{b}','{second}','{owner}'); INSERT INTO public.league_members(league_id,user_id) VALUES('{b}','{owner}');"
                if second
                else ""
            )
        )
        try:
            migrate()
        except SafetyError:
            pass
        else:
            raise AssertionError("Unsafe preflight accepted")
        sql(
            f"DO $$ BEGIN IF to_regprocedure('public.normalize_league_name(text)') IS NOT NULL OR (SELECT count(*) FROM public.leagues) <> {2 if second else 1} THEN RAISE EXCEPTION 'Preflight did not fully roll back'; END IF; END $$; DELETE FROM public.leagues WHERE id IN ('{a}','{b}');"
        )
        findings.append(category + "_fails_without_data_repair")
    return findings


def run(sql):
    owner = identity("owner")
    a = identity("user-a")
    b = identity("user-b")
    sql(f"""BEGIN;
DO $proof$ DECLARE r jsonb; lid uuid; other uuid; BEGIN
 r:=public.create_league_with_owner('{owner}',' NBA Friends ',NULL);
 IF r->>'state'<>'created' THEN RAISE EXCEPTION 'Atomic create failed'; END IF;
 lid:=(r->'league'->>'id')::uuid;
 SET CONSTRAINTS ALL IMMEDIATE;
 IF NOT EXISTS(SELECT 1 FROM public.league_members WHERE league_id=lid AND user_id='{owner}') THEN RAISE EXCEPTION 'Owner membership missing'; END IF;
 IF (public.create_league_with_owner('{a}','nba friends',NULL))->>'status'<>'409' THEN RAISE EXCEPTION 'DB case collision accepted'; END IF;
 BEGIN INSERT INTO public.leagues(name,owner_user_id) VALUES('nBa FrIeNdS','{a}'); RAISE EXCEPTION 'Raw duplicate accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN INSERT INTO public.leagues(name,owner_user_id) VALUES('raw ownerless','{b}'); RAISE EXCEPTION 'Ownerless committed'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 BEGIN DELETE FROM public.league_members WHERE league_id=lid AND user_id='{owner}'; RAISE EXCEPTION 'Owner deletion accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 IF (public.remove_league_membership('{owner}',lid,NULL))->>'status'<>'409' THEN RAISE EXCEPTION 'Owner leave accepted'; END IF;
 IF (public.transfer_league_ownership('{owner}',lid,'{b}'))->>'status'<>'400' THEN RAISE EXCEPTION 'Nonmember transfer accepted'; END IF;
 PERFORM public.join_league_member('{a}',lid,NULL);
 IF (public.join_league_member('{a}',lid,NULL))->>'state'<>'already_member' THEN RAISE EXCEPTION 'Join not idempotent'; END IF;
 PERFORM public.transfer_league_ownership('{owner}',lid,'{a}');
 IF (SELECT count(*) FROM public.league_members WHERE league_id=lid)<>2 THEN RAISE EXCEPTION 'Transfer removed member'; END IF;
 PERFORM public.remove_league_membership('{owner}',lid,NULL);
 IF (public.update_league_settings('{owner}',lid,'stolen',NULL,NULL,NULL))->>'status'<>'403' THEN RAISE EXCEPTION 'Old owner retained powers'; END IF;
 PERFORM public.update_league_settings('{a}',lid,NULL,true,'synthetic-private-hash',NULL);
 IF (public.join_league_member('{b}',lid,NULL))->>'status'<>'409' THEN RAISE EXCEPTION 'Stale public join admitted'; END IF;
 IF (public.update_league_settings('{a}',lid,NULL,false,NULL,NULL))->>'status'<>'409' THEN RAISE EXCEPTION 'Stale settings admitted'; END IF;
 IF (public.delete_league_confirmed('{a}',lid,false))->>'status'<>'400' THEN RAISE EXCEPTION 'Unconfirmed delete admitted'; END IF;
 PERFORM public.delete_league_confirmed('{a}',lid,true);
 SET CONSTRAINTS ALL DEFERRED;
 r:=public.create_league_with_owner('{a}','NBA FRIENDS',NULL);
 IF r->>'state'<>'created' THEN RAISE EXCEPTION 'Name not reusable'; END IF;
 SET CONSTRAINTS ALL IMMEDIATE;
END $proof$;
ROLLBACK;
""")
    sql(f"""BEGIN;
CREATE FUNCTION public.f1_synthetic_member_failure() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'Synthetic membership insert failure'; END $fault$;
CREATE TRIGGER f1_synthetic_member_failure BEFORE INSERT ON public.league_members FOR EACH ROW EXECUTE FUNCTION public.f1_synthetic_member_failure();
DO $$ DECLARE old_count integer; BEGIN
 SELECT count(*) INTO old_count FROM public.leagues;
 BEGIN PERFORM public.create_league_with_owner('{owner}','F1 orphan fault',NULL); RAISE EXCEPTION 'Create failure did not fire'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic membership insert failure' THEN RAISE; END IF; END;
 IF (SELECT count(*) FROM public.leagues)<>old_count THEN RAISE EXCEPTION 'Orphan league escaped failed membership insert'; END IF;
END $$;
ROLLBACK;""")
    for role in ("anon", "authenticated"):
        sql(f"""BEGIN; SET LOCAL ROLE {role}; DO $$ BEGIN
 BEGIN PERFORM public.create_league_with_owner(NULL,NULL,NULL); RAISE EXCEPTION 'Untrusted create'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO public.leagues(name,owner_user_id) VALUES('browser','{owner}'); RAISE EXCEPTION 'Untrusted table write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$; ROLLBACK;""")
    return [
        "atomic_owner_create_fk_deletion_transfer_and_membership_unique",
        "real_member_insert_failure_rolls_back_league_creation",
        "raw_normalized_unique_and_name_reuse",
        "privacy_hash_state_fences",
        "untrusted_rpc_and_table_mutations_refused",
    ]


def contention(sql, database):
    import subprocess, queue, threading
    from scripts.local_supabase_environment import CONTAINER, child_environment

    holder = subprocess.Popen(
        [
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
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=child_environment(),
    )
    ready = queue.Queue()

    def drain():
        for line in holder.stdout:
            if b"F1_READY" in line:
                ready.put(True)
                return
        ready.put(False)

    threading.Thread(target=drain, daemon=True).start()
    try:
        holder.stdin.write(
            f"BEGIN; SELECT public.create_league_with_owner('{identity('owner')}','F1 RACE',NULL);\n\\echo F1_READY\nSELECT pg_sleep(5); COMMIT;\n".encode()
        )
        holder.stdin.flush()
        if not ready.get(timeout=10):
            raise AssertionError("F1 race holder failed")
        sql(
            f"DO $$ BEGIN IF (public.create_league_with_owner('{identity('user-a')}',' f1 race ',NULL))->>'status'<>'409' THEN RAISE EXCEPTION 'Race duplicate accepted'; END IF; END $$;"
        )
        holder.stdin.close()
        holder.wait(timeout=10)
        if holder.returncode:
            raise AssertionError("F1 race holder did not commit")
        sql(
            "DO $$ BEGIN IF (SELECT count(*) FROM public.leagues WHERE league_name_key(name)='f1 race')<>1 THEN RAISE EXCEPTION 'Race count mismatch'; END IF; END $$; DELETE FROM public.leagues WHERE league_name_key(name)='f1 race';"
        )
    finally:
        if holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=10)
        holder.stdin.close()
        holder.stdout.close()
    return "real_concurrent_create_one_winner_one_sanitized_conflict"
