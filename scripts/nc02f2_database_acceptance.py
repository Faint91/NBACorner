"""Fixed synthetic F2 fixtures/proofs, only for guarded local/disposable databases."""

import copy
from synthetic_fixtures import identity, STAMP, hashes
from scripts.nc02e_database_acceptance import scene as e_scene, encoded, call
from scoring_service import BRACKET_FIELDS, MATCH_FIELDS, eligible, keyed_matches
from scoring_engine import score_bracket
from history_service import snapshot_rows, snapshot_columns

F2_TABLES = (
    "league_history_rows",
    "league_history_seasons",
    "league_history_cutoffs",
    "leaderboard_history_competitors",
)


def scene():
    data, _ = e_scene()
    d = dict(
        data["users"][0],
        id=identity("f2-member-d"),
        username="fixture-d",
        email="d@nba-corner.example",
        password=hashes()["owner"],
    )
    data["users"].append(d)
    # A saved, B draft, C admin no bracket, D saved, E owner deleted.
    for b in data["brackets"]:
        if b["user_id"] == identity("owner"):
            b.update(is_done=True, deleted_at=STAMP)
    master = data["brackets"][0]
    b = dict(
        master,
        id=identity("f2-d-bracket"),
        user_id=d["id"],
        is_master=False,
        is_done=True,
        saved_at=STAMP,
        deleted_at=None,
        name="Synthetic D",
    )
    data["brackets"].append(b)
    graph = copy.deepcopy(data["matches"][:21])
    mapping = {m["id"]: identity("f2-d-" + m["id"]) for m in graph}
    for m in graph:
        m.update(
            id=mapping[m["id"]],
            bracket_id=b["id"],
            next_match_id=mapping.get(m["next_match_id"]),
        )
    data["matches"] += graph
    truth = keyed_matches(data["matches"][:21])
    scores = []
    for b in data["brackets"]:
        if eligible(b, identity("current"), master["id"]):
            row = score_bracket(
                keyed_matches(
                    [m for m in data["matches"] if m["bracket_id"] == b["id"]]
                ),
                truth,
            )
            row.pop("base_points")
            scores.append(
                dict(
                    row,
                    bracket_id=b["id"],
                    master_bracket_id=master["id"],
                    season_id=identity("current"),
                )
            )
    rows, _ = snapshot_rows(scores, data["brackets"], data["users"])
    prepared = dict(
        source_id=identity("current"),
        master_id=master["id"],
        source={
            "brackets": sorted(
                [
                    {k: b[k] for k in BRACKET_FIELDS.split(",")}
                    for b in data["brackets"]
                ],
                key=lambda x: x["id"],
            ),
            "matches": sorted(
                [{k: m[k] for k in MATCH_FIELDS.split(",")} for m in data["matches"]],
                key=lambda x: x["id"],
            ),
        },
        scores=scores,
        rows=rows,
        columns=snapshot_columns(truth),
    )
    return data, prepared


def setup(data, p):
    from scripts.nc02e_database_acceptance import setup as e_setup

    sql = e_setup(data, p)
    extra = [u for u in data["users"] if u["id"] == identity("f2-member-d")]
    columns = ",".join(extra[0])
    insertion = f"INSERT INTO public.users({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.users,{encoded(extra)});\n"
    sql = sql.replace("BEGIN;\n", "BEGIN;\n" + insertion, 1)
    sql += f"""INSERT INTO public.leagues(id,name,owner_user_id) VALUES('{identity('f2-league')}','Synthetic F2 League','{identity('admin')}'),('{identity('f2-empty-league')}','Synthetic F2 Empty','{identity('admin')}');
INSERT INTO public.league_members(league_id,user_id) SELECT '{identity('f2-league')}',id FROM public.users;
INSERT INTO public.league_members(league_id,user_id) VALUES('{identity('f2-empty-league')}','{identity('admin')}');
"""
    return sql


def publish_global(p):
    return f"public.publish_leaderboard_snapshot('{p['source_id']}','{p['master_id']}',{encoded(p['source'])},{encoded(p['scores'])},{encoded(p['rows'])},{encoded(p['columns'])},'{identity('admin')}')"


def publish_cutoff():
    return f"public.publish_league_history_cutoff('{identity('current')}',(SELECT id FROM public.leaderboard_history_snapshots WHERE season_id='{identity('current')}' AND is_final IS TRUE))"


def run(sql):
    data, p = scene()
    base = setup(data, p)
    sql(base + f"""
SELECT {publish_global(p)};
SELECT {publish_cutoff()};
DO $$ DECLARE sid uuid; old_rows jsonb; global_rows jsonb; BEGIN
 SELECT id INTO STRICT sid FROM public.league_history_seasons WHERE league_id='{identity('f2-league')}';
 IF (SELECT expected_rows FROM public.league_history_seasons WHERE id=sid)<>2 OR (SELECT count(*) FROM public.league_history_rows WHERE history_season_id=sid)<>2 THEN RAISE EXCEPTION 'Eligible-only publication failed'; END IF;
 IF EXISTS(SELECT 1 FROM public.league_history_seasons WHERE league_id='{identity('f2-empty-league')}') THEN RAISE EXCEPTION 'Zero league received history'; END IF;
 IF (SELECT count(*) FROM public.leaderboard_history_competitors)<>2 THEN RAISE EXCEPTION 'Global internal identity mapping incomplete'; END IF;
 SELECT jsonb_agg(to_jsonb(r) ORDER BY display_order) INTO old_rows FROM public.league_history_rows r;
 SELECT jsonb_agg(to_jsonb(r) ORDER BY id) INTO global_rows FROM public.leaderboard_history_rows r;
 PERFORM public.remove_league_membership('{identity('user-a')}','{identity('f2-league')}',NULL);
 PERFORM public.remove_league_membership('{identity('admin')}','{identity('f2-league')}','{identity('f2-member-d')}');
 PERFORM public.transfer_league_ownership('{identity('admin')}','{identity('f2-league')}','{identity('user-b')}');
 PERFORM public.update_league_settings('{identity('user-b')}','{identity('f2-league')}','Renamed F2',NULL,NULL,NULL);
 IF ({publish_cutoff()})->>'state'<>'existing' THEN RAISE EXCEPTION 'Retry not reused'; END IF;
 IF (SELECT jsonb_agg(to_jsonb(r) ORDER BY display_order) FROM public.league_history_rows r) IS DISTINCT FROM old_rows THEN RAISE EXCEPTION 'Later lifecycle rewrote history'; END IF;
 PERFORM public.delete_league_confirmed('{identity('user-b')}','{identity('f2-league')}',true);
 IF EXISTS(SELECT 1 FROM public.league_history_seasons WHERE id=sid) OR EXISTS(SELECT 1 FROM public.league_history_rows) THEN RAISE EXCEPTION 'League deletion did not cascade'; END IF;
 IF (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM public.leaderboard_history_rows r) IS DISTINCT FROM global_rows THEN RAISE EXCEPTION 'League deletion changed global history'; END IF;
 PERFORM {publish_cutoff()};
END $$;
ROLLBACK;
""")
    return [
        "actual_global_mapping_and_eligible_A_D_only_no_placeholders",
        "zero_league_omitted",
        "immutable_history_after_leave_kick_transfer_rename",
        "cutoff_retry_and_full_league_deletion_cascade_global_preservation",
    ]


def ranking_and_immutability(sql):
    from synthetic_fixtures import foundation

    template = foundation()["users"][0]
    entries = [
        ("outside", 200, 5, "2025-08-01"),
        ("top", 100, 3, "2025-08-01"),
        ("tie-z", 90, 2, "2025-08-01"),
        ("tie-a", 90, 2, "2025-08-01"),
        ("later", 90, 2, "2025-08-02"),
        ("hits", 90, 1, "2025-07-31"),
        ("zero", 0, 0, "2025-08-01"),
    ]
    users = [
        dict(
            template,
            id=identity("f2-rank-" + label),
            username="f2-" + label,
            email=label + "@nba-corner.example",
        )
        for label, _, _, _ in entries
    ]
    sid = identity("f2-rank-snapshot")
    lid = identity("f2-rank-league")
    columns = ",".join(users[0])
    body = f"BEGIN; INSERT INTO public.users({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.users,{encoded(users)}); INSERT INTO public.leagues(id,name,owner_user_id) VALUES('{lid}','Synthetic ranking','{identity('admin')}'); INSERT INTO public.league_members(league_id,user_id) VALUES('{lid}','{identity('admin')}');"
    body += f"INSERT INTO public.leaderboard_history_snapshots(id,season_id,season_code,expected_rows,is_final,master_bracket_id) VALUES('{sid}','{identity('current')}','2025-26',7,false,'{identity('f2-rank-master')}');"
    global_ranks = [1, 2, 3, 3, 5, 6, 7]
    for i, (label, points, hits, stamp) in enumerate(entries, 1):
        rid = identity("f2-rank-row-" + label)
        uid = identity("f2-rank-" + label)
        body += f"INSERT INTO public.leaderboard_history_rows(id,snapshot_id,rank,display_name,total_points,full_hits,saved_at,display_order) VALUES('{rid}','{sid}',{global_ranks[i-1]},'{label}',{points},{hits},'{stamp}',{i}); INSERT INTO public.leaderboard_history_competitors VALUES('{rid}','{uid}');"
        if label != "outside":
            body += f"INSERT INTO public.league_members(league_id,user_id) VALUES('{lid}','{uid}');"
    body += f"UPDATE public.leaderboard_history_snapshots SET is_final=true WHERE id='{sid}'; SELECT public.publish_league_history_cutoff('{identity('current')}','{sid}');"
    body += f"""DO $$ DECLARE hid uuid; BEGIN
 SELECT id INTO STRICT hid FROM public.league_history_seasons WHERE league_id='{lid}';
 IF (SELECT array_agg(rank ORDER BY display_order) FROM public.league_history_rows WHERE history_season_id=hid) IS DISTINCT FROM ARRAY[1,2,2,4,5,6] THEN RAISE EXCEPTION 'League competitive ties/reranking incorrect'; END IF;
 IF (SELECT array_agg(rank ORDER BY display_order) FROM public.leaderboard_history_rows WHERE snapshot_id='{sid}') IS DISTINCT FROM ARRAY[1,2,3,3,5,6,7] THEN RAISE EXCEPTION 'Global ranks changed'; END IF;
 BEGIN UPDATE public.league_history_rows SET rank=99 WHERE history_season_id=hid; RAISE EXCEPTION 'Immutable row changed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'League history rows are immutable' THEN RAISE; END IF; END;
 BEGIN UPDATE public.league_history_seasons SET is_final=false WHERE id=hid; RAISE EXCEPTION 'Immutable header changed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'League history is immutable' THEN RAISE; END IF; END;
 BEGIN INSERT INTO public.league_history_rows VALUES(hid,'{identity('f2-rank-row-outside')}',7,7); RAISE EXCEPTION 'Append to final accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Invalid immutable league row/source' THEN RAISE; END IF; END;
END $$;
SET LOCAL ROLE service_role;
DO $$ BEGIN
 BEGIN DELETE FROM public.league_history_rows; RAISE EXCEPTION 'Generic row delete accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM public.league_history_seasons; RAISE EXCEPTION 'Generic header delete accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE public.league_history_rows SET rank=99; RAISE EXCEPTION 'Generic rank update accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN TRUNCATE public.league_history_cutoffs; RAISE EXCEPTION 'Generic truncate accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
ALTER TABLE public.league_history_rows DISABLE TRIGGER nc_f2_immutable;
UPDATE public.league_history_rows SET rank=99 WHERE display_order=1;
DO $$ BEGIN
 BEGIN PERFORM public.verify_league_history_cutoff('{identity('current')}','{sid}'); RAISE EXCEPTION 'Corrupt final source accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Conflicting league rank/order' THEN RAISE; END IF; END;
END $$;
ROLLBACK;
"""
    sql(body)
    for role in ("anon", "authenticated"):
        sql(f"""BEGIN; SET LOCAL ROLE {role}; DO $$ BEGIN
 BEGIN PERFORM public.publish_league_history_cutoff(NULL,NULL); RAISE EXCEPTION 'Untrusted publication accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM public.league_history_rows; RAISE EXCEPTION 'Untrusted direct read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO public.league_history_cutoffs VALUES(NULL,0,0,now(),false); RAISE EXCEPTION 'Untrusted write accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$; ROLLBACK;""")
    return [
        "league_rank_is_not_global_rank_and_total_hits_saved_time_ties",
        "true_ties_1_2_2_4_and_real_zero_row",
        "final_append_update_delete_truncate_refused",
        "conflicting_final_rank_requires_review",
        "untrusted_tables_and_rpc_refused",
    ]


def partial_all_league_failure(sql):
    data, p = scene()
    body = setup(data, p) + f"""
INSERT INTO public.league_members(league_id,user_id) VALUES('{identity('f2-empty-league')}','{identity('user-a')}');
CREATE FUNCTION public.f2_second_league_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM public.league_history_seasons)>0 THEN RAISE EXCEPTION 'Synthetic second league failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER f2_second_league_fault BEFORE INSERT ON public.league_history_seasons FOR EACH ROW EXECUTE FUNCTION public.f2_second_league_fault();
DO $$ DECLARE r jsonb; BEGIN
 r:={call(p)};
 IF r->>'stage'<>'league_history' OR r->>'ok'<>'false' OR EXISTS(SELECT 1 FROM public.league_history_seasons) OR EXISTS(SELECT 1 FROM public.league_history_rows) OR EXISTS(SELECT 1 FROM public.league_history_cutoffs) THEN RAISE EXCEPTION 'Partial all-league publication escaped'; END IF;
 IF (SELECT count(*) FROM public.leaderboard_history_snapshots WHERE is_final IS TRUE)<>1 OR (SELECT season_id FROM public.application_season)<>'{identity('current')}'::uuid OR (SELECT count(*) FROM public.leagues)<>2 THEN RAISE EXCEPTION 'Global/source not preserved'; END IF;
END $$;
DROP TRIGGER f2_second_league_fault ON public.league_history_seasons; DROP FUNCTION public.f2_second_league_fault();
DO $$ DECLARE r jsonb; BEGIN
 r:={call(p)};
 IF r->>'state'<>'completed' OR (SELECT count(*) FROM public.league_history_seasons WHERE is_final IS TRUE)<>2 OR (SELECT count(*) FROM public.league_history_rows)<>3 THEN RAISE EXCEPTION 'Retry did not finalize all leagues'; END IF;
END $$;
ROLLBACK;
"""
    sql(body)
    return "second_league_failure_rolls_back_all_league_history_preserves_global_blocks_cleanup_then_retries"


def old_source_refusal(sql):
    import re
    from pathlib import Path

    old = (
        Path(__file__).resolve().parents[1]
        / "db/post-baseline/0006_nc_02d2_final_snapshots.sql"
    ).read_text(encoding="utf-8")
    fn = (
        re.search(
            r"CREATE FUNCTION public.publish_leaderboard_snapshot\(.*?\$body\$;",
            old,
            re.S,
        )
        .group()
        .replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    )
    data, p = scene()
    sql(setup(data, p) + fn + f"""
SELECT {publish_global(p)};
DO $$ DECLARE r jsonb; BEGIN
 r:={call(p)};
 IF r->>'stage'<>'league_history' OR r->>'ok'<>'false' OR EXISTS(SELECT 1 FROM public.league_history_seasons) OR EXISTS(SELECT 1 FROM public.leaderboard_history_competitors) THEN RAISE EXCEPTION 'Old source guessed/backfilled'; END IF;
 IF (SELECT season_id FROM public.application_season)<>'{identity('current')}'::uuid OR (SELECT count(*) FROM public.leaderboard_history_snapshots WHERE is_final IS TRUE)<>1 THEN RAISE EXCEPTION 'Old source failure did not preserve current/global state'; END IF;
END $$;
ROLLBACK;
""")
    return "pre_feature_global_snapshot_without_mapping_blocks_without_backfill"


def reset_disposable(sql):
    from synthetic_fixtures import TABLES, foundation

    body = (
        "BEGIN; TRUNCATE TABLE "
        + ",".join(
            "public." + t
            for t in (
                *F2_TABLES,
                "season_rollover_audits",
                "application_season",
                *TABLES,
            )
        )
        + " RESTART IDENTITY RESTRICT;\n"
    )
    for table, items in foundation().items():
        if items:
            columns = ",".join('"' + k + '"' for k in items[0])
            body += f"INSERT INTO public.{table}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.{table},{encoded(items)});\n"
    body += f"INSERT INTO public.application_season VALUES(true,'{identity('current')}'); SELECT setval('public.standings_id_seq',30,true); COMMIT;"
    sql(body)


def membership_contention(sql, database):
    import subprocess, queue, threading, time
    from scripts.local_supabase_environment import CONTAINER, child_environment

    if database != "nc_02f2_bootstrap_proof":
        raise ValueError("Fixed disposable F2 DB required")
    findings = []
    from itertools import product

    for operation, before in product(("leave", "join", "owner_removal"), (True, False)):
        data, p = scene()
        initial = setup(data, p)
        if operation == "join":
            initial += f"DELETE FROM public.league_members WHERE league_id='{identity('f2-league')}' AND user_id='{identity('user-a')}';"
        sql(initial + "SELECT " + publish_global(p) + "; COMMIT;")
        if operation == "join":
            mutation = f"SELECT public.join_league_member('{identity('user-a')}','{identity('f2-league')}',NULL);"
        else:
            actor = (
                identity("admin")
                if operation == "owner_removal"
                else identity("user-a")
            )
            target = (
                "'" + identity("user-a") + "'"
                if operation == "owner_removal"
                else "NULL"
            )
            mutation = f"SELECT public.remove_league_membership('{actor}','{identity('f2-league')}',{target});"
        cutoff = "SELECT " + publish_cutoff() + ";"
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
        ]
        holder = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment(),
        )
        ready = queue.Queue()

        def drain():
            for line in holder.stdout:
                if b"F2_READY" in line:
                    ready.put(True)
                    return
            ready.put(False)

        threading.Thread(target=drain, daemon=True).start()
        try:
            holder.stdin.write(
                (
                    "BEGIN; " + (mutation if before else cutoff) + "\n\\echo F2_READY\n"
                ).encode()
            )
            holder.stdin.flush()
            if not ready.get(timeout=10):
                raise AssertionError("Cutoff lock holder failed")
            contender = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment(),
            )
            contender.stdin.write(((cutoff if before else mutation) + "\n").encode())
            contender.stdin.flush()
            contender.stdin.close()
            # Observe a genuine blocked PostgreSQL lock before releasing the holder.
            for _ in range(40):
                check = sql(
                    "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND NOT l.granted;"
                )
                if any(line.strip() == b"1" for line in check.splitlines()):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Contending membership operation did not block")
            holder.stdin.write(b"COMMIT;\n")
            holder.stdin.flush()
            holder.stdin.close()
            holder.wait(timeout=15)
            contender.wait(timeout=15)
            if holder.returncode or contender.returncode:
                raise AssertionError("Concurrent cutoff/membership mutation failed")
            expected = (
                (2 if before else 1) if operation == "join" else (1 if before else 2)
            )
            member_count = 1 if operation == "join" else 0
            sql(
                f"DO $$ BEGIN IF (SELECT count(*) FROM public.league_history_rows)<>{expected} OR (SELECT count(*) FROM public.league_members WHERE league_id='{identity('f2-league')}' AND user_id='{identity('user-a')}')<>{member_count} THEN RAISE EXCEPTION 'Concurrent cutoff membership result incorrect'; END IF; END $$;"
            )
            findings.append(
                f"{operation}_{'before' if before else 'after'}_cutoff_"
                + ("included" if (operation == "join") == before else "excluded")
                + "_after_real_lock_wait"
            )
        finally:
            for process in (holder, locals().get("contender")):
                if process is None:
                    continue
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if process.stdin:
                    process.stdin.close()
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
        reset_disposable(sql)
    return findings
