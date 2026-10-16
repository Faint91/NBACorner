"""Fixed synthetic rollover SQL scenarios; usable only by disposable local proof."""

import copy
import json
import importlib.util
from pathlib import Path
from synthetic_fixtures import foundation, bracket_scenario, identity, STAMP
from scoring_service import BRACKET_FIELDS, MATCH_FIELDS, eligible, keyed_matches
from scoring_engine import score_bracket
from history_service import snapshot_rows, snapshot_columns


def encoded(value):
    return "'" + json.dumps(value).replace("'", "''") + "'::jsonb"


def scene(zero=False):
    spec = importlib.util.spec_from_file_location(
        "rollover_pure_fixture",
        Path(__file__).resolve().parents[1] / "tests/offline/test_rollover_rules.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = foundation()
    master_scene = bracket_scenario("master")
    data["brackets"] = master_scene["brackets"]
    master = data["brackets"][0]
    # A completed master is not an ordinary saved user prediction.
    master.update(is_done=False, saved_at=None)
    data["matches"] = module.complete_graph(master_scene["matches"])
    data["seasons"] = master_scene["seasons"]
    for kind, role, done, saved, deleted in [
        ("saved", "user-a", not zero, STAMP if not zero else None, None),
        ("draft", "user-b", False, None, None),
        ("edited-unsaved", "owner", False, STAMP, None),
        ("deleted", "user-b", True, STAMP, STAMP),
    ]:
        b = dict(
            master,
            id=identity("e-" + kind),
            user_id=identity(role),
            is_master=False,
            is_done=done,
            saved_at=saved,
            deleted_at=deleted,
            name="Synthetic " + kind,
        )
        data["brackets"].append(b)
        originals = copy.deepcopy(data["matches"][:21])
        ids = {m["id"]: identity(kind + m["id"]) for m in originals}
        for m in originals:
            m.update(
                id=ids[m["id"]],
                bracket_id=b["id"],
                next_match_id=ids.get(m["next_match_id"]),
            )
        data["matches"] += originals
    source = {
        "brackets": sorted(
            [{k: b[k] for k in BRACKET_FIELDS.split(",")} for b in data["brackets"]],
            key=lambda x: x["id"],
        ),
        "matches": sorted(
            [{k: m[k] for k in MATCH_FIELDS.split(",")} for m in data["matches"]],
            key=lambda x: x["id"],
        ),
    }
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
        source=source,
        scores=scores,
        rows=rows,
        columns=snapshot_columns(truth),
    )
    return data, prepared


def setup(data, prepared):
    body = "BEGIN;\n"
    for table in ("brackets", "matches"):
        body += f"INSERT INTO public.{table} SELECT * FROM jsonb_populate_recordset(NULL::public.{table},{encoded(data[table])});\n"
    body += f"UPDATE public.seasons SET master_bracket_id='{prepared['master_id']}' WHERE id='{identity('current')}';\n"
    # Align known synthetic score state before testing transition rollback.
    body += f"SELECT public.publish_current_bracket_scores('{identity('current')}','{prepared['master_id']}',{encoded(prepared['source'])},{encoded(prepared['scores'])});\n"
    return body


def competition_state():
    # Audit/final history intentionally outside destructive state comparison.
    return (
        "jsonb_build_object("
        + ",".join(
            "'"
            + t
            + "',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb) FROM public."
            + t
            + " x)"
            for t in (
                "application_season",
                "seasons",
                "brackets",
                "matches",
                "bracket_scores",
                "standings",
            )
        )
        + ")"
    )


def call(
    prepared,
    target="2026-27",
    opening="2027-04-12T00:00:00Z",
    lock="2027-04-18T00:00:00Z",
):
    return f"public.run_season_rollover('{target}','{opening}','{lock}','{identity('admin')}',{encoded(prepared)})"


def run(sql):
    data, p = scene()
    base = setup(data, p)
    state = competition_state()
    findings = []
    # Real failures occur after actual destructive statements, not mocked clients.
    faults = [
        (
            "draft_delete",
            "brackets",
            "AFTER DELETE",
            "FOR EACH ROW",
            "RETURN OLD;",
            "true",
        ),
        (
            "score_cleanup",
            "bracket_scores",
            "AFTER DELETE",
            "FOR EACH STATEMENT",
            "RETURN NULL;",
            "EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots WHERE is_final IS TRUE)",
        ),
        (
            "target_insert",
            "seasons",
            "AFTER INSERT",
            "FOR EACH ROW",
            "RETURN NEW;",
            "NEW.code='2026-27'",
        ),
        (
            "canonical_activation",
            "application_season",
            "AFTER UPDATE",
            "FOR EACH ROW",
            "RETURN NEW;",
            "NEW.season_id<>OLD.season_id",
        ),
        (
            "standings_clear",
            "standings",
            "AFTER DELETE",
            "FOR EACH STATEMENT",
            "RETURN NULL;",
            "true",
        ),
        (
            "audit_complete",
            "season_rollover_audits",
            "BEFORE UPDATE",
            "FOR EACH ROW",
            "RETURN NEW;",
            "NEW.status='COMPLETED'",
        ),
    ]
    for label, table, event, scope, returns, condition in faults:
        sql(base + f"""
CREATE FUNCTION public.e_fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF {condition} THEN RAISE EXCEPTION 'Synthetic failure'; END IF; {returns} END $fault$;
CREATE TRIGGER e_fault {event} ON public.{table} {scope} EXECUTE FUNCTION public.e_fault();
DO $proof$ DECLARE before_state jsonb; r jsonb; snap uuid; BEGIN
 before_state:={state}; r:={call(p)};
 IF r->>'stage' IS DISTINCT FROM 'transition' OR r->>'ok'<>'false' THEN RAISE EXCEPTION 'Expected atomic transition failure: {label}'; END IF;
 IF {state} IS DISTINCT FROM before_state THEN RAISE EXCEPTION 'Transition state escaped rollback: {label}'; END IF;
 SELECT id INTO STRICT snap FROM public.leaderboard_history_snapshots WHERE season_id='{identity('current')}' AND is_final IS TRUE AND expected_rows=1;
 IF (SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=snap)<>1 THEN RAISE EXCEPTION 'Snapshot lost'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.season_rollover_audits WHERE id=(r->>'audit_id')::uuid AND status='FAILED' AND failure_stage='transition' AND snapshot_id=snap AND completed_at IS NOT NULL) THEN RAISE EXCEPTION 'Failure audit missing'; END IF;
END $proof$;
DROP TRIGGER e_fault ON public.{table}; DROP FUNCTION public.e_fault();
DO $proof$ DECLARE r jsonb; sid uuid; BEGIN
 SELECT id INTO sid FROM public.leaderboard_history_snapshots WHERE season_id='{identity('current')}';
 r:={call(p)};
 IF r->>'state'<>'completed' OR r->>'snapshot_id'<>sid::text OR (SELECT count(*) FROM public.leaderboard_history_snapshots WHERE season_id='{identity('current')}')<>1 THEN RAISE EXCEPTION 'Retry did not reuse final snapshot'; END IF;
END $proof$;
ROLLBACK;
""")
        findings.append(label + "_rollback_and_retry")
    # Preparation failures must not accidentally refresh stale live scores.
    for label, change, expected in [
        (
            "incomplete_master",
            f"UPDATE public.matches SET predicted_winner=NULL,predicted_winner_games=NULL WHERE bracket_id='{p['master_id']}' AND round=4;",
            "prerequisite",
        ),
        (
            "missing_master",
            f"UPDATE public.seasons SET master_bracket_id=NULL WHERE id='{identity('current')}';",
            "prerequisite",
        ),
        (
            "missing_graph_match",
            f"DELETE FROM public.matches WHERE bracket_id='{p['master_id']}' AND round=4;",
            "prerequisite",
        ),
        (
            "invalid_result_count",
            f"UPDATE public.matches SET predicted_winner_games=8 WHERE bracket_id='{p['master_id']}' AND round=4;",
            "prerequisite",
        ),
        (
            "inconsistent_downstream",
            f"UPDATE public.matches SET team_a='BOS',predicted_winner=team_b WHERE bracket_id='{p['master_id']}' AND round=4;",
            "prerequisite",
        ),
        (
            "recompute_failure",
            "CREATE FUNCTION public.e_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic'; END $$; CREATE TRIGGER e_fault BEFORE INSERT ON public.bracket_scores FOR EACH ROW EXECUTE FUNCTION public.e_fault(); DELETE FROM public.bracket_scores;",
            "recompute",
        ),
        (
            "snapshot_failure",
            "CREATE FUNCTION public.e_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic'; END $$; CREATE TRIGGER e_fault BEFORE INSERT ON public.leaderboard_history_rows FOR EACH ROW EXECUTE FUNCTION public.e_fault(); DELETE FROM public.bracket_scores;",
            "snapshot",
        ),
    ]:
        sql(base + change + f"""
DO $proof$ DECLARE before_state jsonb; r jsonb; BEGIN before_state:={state}; r:={call(p)};
 IF r->>'stage' IS DISTINCT FROM '{expected}' OR r->>'ok'<>'false' OR {state} IS DISTINCT FROM before_state OR EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots) THEN RAISE EXCEPTION 'Preparation mutated competition: {label}'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.season_rollover_audits WHERE id=(r->>'audit_id')::uuid AND status='FAILED' AND completed_at IS NOT NULL) THEN RAISE EXCEPTION 'Preparation audit absent'; END IF;
END $proof$; ROLLBACK;
""")
        findings.append(label + "_no_competition_mutation")
    for target, opening, lock in [
        ("2024-25", "2025-04-12", "2025-04-18"),
        ("2027-28", "2028-04-12", "2028-04-18"),
        ("2025-26", "2026-04-12", "2026-04-18"),
        ("bad", "2027-04-12", "2027-04-18"),
        ("2026-27", "2027-04-12", "2027-04-12"),
    ]:
        sql(
            base
            + f"DO $$ DECLARE old jsonb; r jsonb; BEGIN old:={state}; r:={call(p,target,opening,lock)}; IF r->>'ok'<>'false' OR {state} IS DISTINCT FROM old OR EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots) THEN RAISE EXCEPTION 'Invalid target mutated state'; END IF; END $$; ROLLBACK;"
        )
    findings.append("invalid_targets_and_equal_times_no_mutation")
    # Stale/unverified structured source cannot be overwritten, even with no rows.
    sql(
        base
        + f"""INSERT INTO public.leaderboard_history_snapshots(season_id,season_code,expected_rows,is_final,master_bracket_id) VALUES('{identity('current')}','2025-26',1,false,'{p['master_id']}');
DO $$ DECLARE r jsonb; old jsonb; BEGIN old:={state};r:={call(p)}; IF r->>'stage'<>'snapshot' OR {state} IS DISTINCT FROM old OR (SELECT is_final FROM public.leaderboard_history_snapshots) IS DISTINCT FROM false THEN RAISE EXCEPTION 'Unverified snapshot accepted'; END IF; END $$; ROLLBACK;"""
    )
    findings.append("unverified_snapshot_blocks")
    sql(
        base
        + f"""INSERT INTO public.leaderboard_history_snapshots(season_id,season_code,expected_rows,is_final,master_bracket_id) VALUES('{identity('current')}','2025-26',0,false,'{identity('wrong-master')}');
UPDATE public.leaderboard_history_snapshots SET is_final=true; DELETE FROM public.bracket_scores;
DO $$ DECLARE r jsonb; old jsonb; BEGIN old:={state}; r:={call(p)}; IF r->>'stage'<>'snapshot' OR {state} IS DISTINCT FROM old THEN RAISE EXCEPTION 'Snapshot identity mismatch accepted'; END IF; END $$; ROLLBACK;"""
    )
    findings.append("snapshot_identity_mismatch_blocks_before_transition")

    for zero in (False, True):
        data, p = scene(zero)
        base = setup(data, p)
        n = 0 if zero else 1
        sql(base + f"""
CREATE FUNCTION public.e_legacy_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic optional legacy failure'; END $$;
CREATE TRIGGER e_legacy_fault BEFORE INSERT ON public.leaderboard_history FOR EACH ROW EXECUTE FUNCTION public.e_legacy_fault();
CREATE TEMP TABLE e_saved AS SELECT to_jsonb(b) AS row FROM public.brackets b WHERE id='{identity('e-saved')}';
CREATE TEMP TABLE e_graph AS SELECT to_jsonb(m) AS row FROM public.matches m WHERE bracket_id='{identity('e-saved')}';
DO $proof$ DECLARE r jsonb; before_repeat jsonb; final_snapshot_id uuid; BEGIN
 r:={call(p)};
 IF r->>'state'<>'completed' THEN RAISE EXCEPTION 'Full rollover failed'; END IF;
 final_snapshot_id:=(r->>'snapshot_id')::uuid;
 IF (SELECT expected_rows FROM public.leaderboard_history_snapshots WHERE id=final_snapshot_id)<>{n} OR (SELECT count(*) FROM public.leaderboard_history_rows WHERE snapshot_id=final_snapshot_id)<>{n} THEN RAISE EXCEPTION 'Final snapshot count mismatch'; END IF;
 IF (SELECT count(*) FROM public.brackets WHERE season_id='{identity('current')}')<>{n} OR EXISTS(SELECT 1 FROM public.brackets WHERE id IN ('{identity('e-draft')}','{identity('e-edited-unsaved')}','{identity('e-deleted')}')) THEN RAISE EXCEPTION 'RR12 physical draft deletion failed'; END IF;
 IF EXISTS(SELECT 1 FROM public.matches m LEFT JOIN public.brackets b ON b.id=m.bracket_id WHERE b.id IS NULL) OR EXISTS(SELECT 1 FROM public.bracket_scores) OR EXISTS(SELECT 1 FROM public.standings) THEN RAISE EXCEPTION 'Current cleanup failed'; END IF;
 IF {str(not zero).lower()} AND ((SELECT row FROM e_saved) IS DISTINCT FROM (SELECT to_jsonb(b) FROM public.brackets b WHERE id='{identity('e-saved')}') OR (SELECT jsonb_agg(row ORDER BY row::text) FROM e_graph) IS DISTINCT FROM (SELECT jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text) FROM public.matches m WHERE bracket_id='{identity('e-saved')}')) THEN RAISE EXCEPTION 'Saved historical content changed'; END IF;
 IF (SELECT code FROM public.seasons WHERE id=(SELECT season_id FROM public.application_season))<>'2026-27' THEN RAISE EXCEPTION 'Canonical not advanced'; END IF;
 IF {str(not zero).lower()} AND r->>'legacy_warning'<>'true' THEN RAISE EXCEPTION 'Optional legacy warning missing'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.season_rollover_audits WHERE id=(r->>'audit_id')::uuid AND status='COMPLETED' AND snapshot_id IS NOT NULL AND target_season_id IS NOT NULL AND requested_by_user_id='{identity('admin')}' AND completed_at>=started_at) THEN RAISE EXCEPTION 'Complete audit missing'; END IF;
 -- Protect new-season state against repeat, including a new standings refresh.
 INSERT INTO public.standings(code,name,wins,losses,conference,seed) VALUES('ATL','New synthetic standings',1,0,'east',1);
 before_repeat:={state}||jsonb_build_object('audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM public.season_rollover_audits a));
 r:={call(p)};
 IF r->>'state'<>'already_completed' OR ({state}||jsonb_build_object('audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM public.season_rollover_audits a))) IS DISTINCT FROM before_repeat THEN RAISE EXCEPTION 'Repeat mutated target state'; END IF;
END $proof$;
ROLLBACK;
""")
        findings.append(
            "zero_full_success_and_repeat"
            if zero
            else "full_success_retention_legacy_warning_audit_repeat"
        )
    for role in ("anon", "authenticated"):
        sql(
            f"BEGIN; SET LOCAL ROLE {role}; DO $$ BEGIN BEGIN PERFORM public.run_season_rollover(NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'Untrusted rollover allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; BEGIN INSERT INTO public.season_rollover_audits(target_code,requested_by_user_id,status) VALUES('x','{identity('admin')}','STARTED'); RAISE EXCEPTION 'Untrusted audit allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$; ROLLBACK;"
        )
    findings.append("untrusted_rpc_and_audit_denied")
    return findings


def contention(sql, database):
    """A real second PostgreSQL session holds the fixed rollover lock then rolls back."""
    import subprocess
    import queue
    import threading
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

    def read_ready():
        for line in holder.stdout:
            if b"E_LOCK_READY" in line:
                ready.put(True)
                return
        ready.put(False)

    threading.Thread(target=read_ready, daemon=True).start()
    try:
        holder.stdin.write(
            b"BEGIN; SELECT pg_advisory_xact_lock(50405,2);\n\\echo E_LOCK_READY\nSELECT pg_sleep(8); ROLLBACK;\n".replace(
                b"\\\\echo", b"\\echo"
            )
        )
        holder.stdin.flush()
        holder.stdin.close()
        if not ready.get(timeout=10):
            raise AssertionError("Contention holder failed")
        state = competition_state()
        sql(
            f"""DO $$ DECLARE old jsonb; r jsonb; BEGIN old:={state}; r:=public.run_season_rollover('2026-27','2027-04-12','2027-04-18','{identity('admin')}',NULL);
 IF r->>'state'<>'busy' OR {state} IS DISTINCT FROM old OR EXISTS(SELECT 1 FROM public.season_rollover_audits) OR EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots) THEN RAISE EXCEPTION 'Busy contender mutated state'; END IF; END $$;"""
        )
        holder.wait(timeout=15)
        if holder.returncode:
            raise AssertionError("Lock holder did not roll back normally")
        sql(
            "BEGIN; DO $$ BEGIN IF NOT pg_try_advisory_xact_lock(50405,2) THEN RAISE EXCEPTION 'Rollover lock leaked'; END IF; END $$; ROLLBACK;"
        )
    finally:
        if holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=10)
        if holder.stdin:
            holder.stdin.close()
        if holder.stdout:
            holder.stdout.close()
    return "real_lock_contention_busy_without_mutation_and_release"


def committed_failure_retry(sql):
    """Real commits and separate psql sessions prove durable failure and snapshot reuse."""
    from synthetic_fixtures import TABLES
    from scripts.reset_local_fixtures import state_sql, digest_sql
    from integration_harness import CANONICAL_CHECKSUM

    data, prepared = scene()
    sql(setup(data, prepared) + f"""
CREATE FUNCTION public.e_durable_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic target failure'; END $$;
CREATE TRIGGER e_durable_fault AFTER INSERT ON public.seasons FOR EACH ROW EXECUTE FUNCTION public.e_durable_fault();
DO $$ DECLARE r jsonb; BEGIN r:={call(prepared)};
 IF r->>'stage'<>'transition' OR r->>'ok'<>'false' THEN RAISE EXCEPTION 'Committed failure not returned'; END IF;
END $$; COMMIT;
""")
    # Different transport/session, after previous RPC's transaction has committed.
    sql(f"""DO $$ BEGIN
 IF (SELECT season_id FROM public.application_season)<>'{identity('current')}'::uuid
 OR (SELECT count(*) FROM public.brackets WHERE season_id='{identity('current')}')<>5
 OR (SELECT count(*) FROM public.matches WHERE season_id='{identity('current')}')<>105
 OR (SELECT count(*) FROM public.bracket_scores)<>1 OR (SELECT count(*) FROM public.standings)<>30
 OR (SELECT count(*) FROM public.season_rollover_audits WHERE status='FAILED' AND failure_stage='transition' AND snapshot_id IS NOT NULL)<>1
 OR (SELECT count(*) FROM public.leaderboard_history_snapshots WHERE is_final IS TRUE AND expected_rows=1)<>1
 THEN RAISE EXCEPTION 'Committed failure preservation missing'; END IF;
END $$;
DROP TRIGGER e_durable_fault ON public.seasons; DROP FUNCTION public.e_durable_fault();
DO $$ DECLARE original_snapshot uuid; r jsonb; BEGIN
 SELECT id INTO STRICT original_snapshot FROM public.leaderboard_history_snapshots;
 r:={call(prepared)};
 IF r->>'state'<>'completed' OR r->>'snapshot_id'<>original_snapshot::text THEN RAISE EXCEPTION 'Cross-session snapshot reuse failed'; END IF;
END $$;
""")
    sql(
        "DO $$ BEGIN IF (SELECT count(*) FROM public.season_rollover_audits WHERE status='COMPLETED')<>1 OR (SELECT count(*) FROM public.season_rollover_audits WHERE status='FAILED')<>1 OR (SELECT count(*) FROM public.leaderboard_history_snapshots)<>1 THEN RAISE EXCEPTION 'Committed retry audit missing'; END IF; END $$;"
    )
    # Exact fixed scratch reset, not an arbitrary-target reset entry point.
    tables = ",".join(
        "public." + t for t in ("season_rollover_audits", "application_season", *TABLES)
    )
    reset = "BEGIN; TRUNCATE TABLE " + tables + " RESTART IDENTITY RESTRICT;\n"
    for table, rows in foundation().items():
        if rows:
            columns = ",".join('"' + c + '"' for c in rows[0])
            reset += f"INSERT INTO public.{table}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.{table},{encoded(rows)});\n"
    reset += f"INSERT INTO public.application_season VALUES(true,'{identity('current')}'); SELECT setval('public.standings_id_seq',30,true); COMMIT;"
    sql(reset)
    sql(
        "DO $$ BEGIN IF "
        + digest_sql(state_sql())
        + "<>'"
        + CANONICAL_CHECKSUM
        + "' OR EXISTS(SELECT 1 FROM public.season_rollover_audits) THEN RAISE EXCEPTION 'Scratch canonical reset failed'; END IF; END $$;"
    )
    return "committed_failure_audit_snapshot_survive_and_separate_session_retry_reuses_snapshot"
