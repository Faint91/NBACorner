"""Fixed disposable LOCAL DB proof; schema-only platform clone, no production IO."""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.local_supabase_environment import (
    ROOT,
    CONTAINER,
    child_environment,
    container_identity,
    check_configuration,
)
from environment_safety import load_test_config, verify_live_local_identity, SafetyError
from synthetic_fixtures import (
    foundation,
    validate_state,
    TABLES,
    identity,
    bracket_scenario,
)

PROOF_DB = "nc_02f2_bootstrap_proof"


def command(args, body=None):
    result = subprocess.run(
        ["docker", "exec", *(["-i"] if body is not None else []), CONTAINER, *args],
        input=body,
        capture_output=True,
        env=child_environment(),
        timeout=120,
    )
    if result.returncode:
        # Fixed disposable SQL contains synthetic data only. Report a narrow
        # assertion category, never the SQL/context/provider output.
        error = result.stderr.decode("utf-8", errors="replace")
        allowed = (
            "ambiguous",
            "Full rollover failed",
            "snapshot count",
            "RR12",
            "Current cleanup",
            "Saved historical",
            "Canonical not",
            "legacy warning",
            "Complete audit",
            "Repeat mutated",
            "null value",
            "does not exist",
        )
        categories = [label for label in allowed if label in error]
        print("Disposable proof failure categories:", categories)
        raise SafetyError(
            "Local disposable migration proof failed; raw output withheld."
        )
    return result.stdout


def sql(body):
    return command(
        ["psql", "-X", "-U", "postgres", "-d", PROOF_DB, "-v", "ON_ERROR_STOP=1"],
        (
            "SET timezone='UTC'; SET datestyle='ISO, YMD'; "
            "SET extra_float_digits=3;\n" + body
        ).encode(),
    )


def main():
    check_configuration()
    container_identity()
    verify_live_local_identity(
        load_test_config(str(ROOT / ".env.test.nba-local.local"))
    )
    exists = command(
        [
            "psql",
            "-X",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-Atc",
            "SELECT count(*) FROM pg_database WHERE datname='nc_02f2_bootstrap_proof'",
        ]
    ).strip()
    if exists != b"0":
        raise SafetyError(
            "Disposable proof name already exists; will not reuse/drop it."
        )
    # Schema only: roles/passwords and all row contents are excluded by pg_dump.
    platform = command(
        [
            "pg_dump",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "--schema-only",
            "--exclude-schema=nba_corner_test_control",
        ]
    )
    created = False
    try:
        command(["createdb", "-U", "postgres", "--template=template0", PROOF_DB])
        created = True
        # Restore managed-schema ownership using the local platform admin only.
        # Application baseline/migration/acceptance still execute as postgres.
        command(
            [
                "psql",
                "-X",
                "-U",
                "supabase_admin",
                "-d",
                PROOF_DB,
                "-v",
                "ON_ERROR_STOP=1",
            ],
            platform,
        )
        # Remove only the source application's reviewed objects in our new DB.
        tables = ",".join("public." + t for t in TABLES)
        # Resolve exact original function signatures from immutable manifest/catalog,
        # never accept an arbitrary function or target argument.
        cleanup = (
            "DROP TABLE IF EXISTS public.league_history_rows,public.league_history_seasons,public.league_history_cutoffs,public.leaderboard_history_competitors CASCADE;\nDROP TABLE IF EXISTS public.season_rollover_audits;\nDROP TABLE public.application_season;\nDROP TABLE "
            + tables
            + " CASCADE;\n"
        )
        cleanup += "DO $$ DECLARE f record; BEGIN FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e') LOOP EXECUTE 'DROP FUNCTION '||f.sig||' CASCADE'; END LOOP; END $$;\n"
        sql(cleanup)
        sql((ROOT / "db/baseline/000_current_schema.sql").read_text(encoding="utf-8"))
        sql(
            (ROOT / "db/baseline/verify_current_schema.sql").read_text(encoding="utf-8")
        )
        sql(
            (ROOT / "db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02b3_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/0002_nc_02c1_canonical_season.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02c1_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/0003_nc_02c2_atomic_standings.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02c2_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/0004_nc_02c3_season_transition.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02c3_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/0005_nc_02d1_atomic_scores.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02d1_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/0006_nc_02d2_final_snapshots.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02d2_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            "DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.application_season) THEN RAISE EXCEPTION 'Migration guessed designation'; END IF; END $$;"
        )
        data = foundation()
        validate_state(data)
        seed = "BEGIN;\n"
        for table in TABLES:
            if data[table]:
                columns = ",".join('"' + c + '"' for c in data[table][0])
                payload = json.dumps(data[table]).replace("'", "''")
                seed += f"INSERT INTO public.{table}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.{table},'{payload}'::jsonb);\n"
        seed += f"INSERT INTO public.application_season(singleton,season_id) VALUES(true,'{identity('current')}');\n"
        seed += "SELECT setval('public.standings_id_seq',30,true);\nCOMMIT;\n"
        sql(seed)
        acceptance = f"""BEGIN;
INSERT INTO public.brackets(user_id,season_id) VALUES ('{identity('user-a')}','{identity('historical')}'),('{identity('user-a')}','{identity('current')}');
DO $$ BEGIN
 BEGIN INSERT INTO public.brackets(user_id,season_id) VALUES ('{identity('user-a')}','{identity('current')}'); RAISE EXCEPTION 'Duplicate accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
UPDATE public.brackets SET deleted_at=now() WHERE user_id='{identity('user-a')}' AND season_id='{identity('current')}';
INSERT INTO public.brackets(user_id,season_id) VALUES ('{identity('user-a')}','{identity('current')}');
ROLLBACK;
"""
        sql(acceptance)
        sql(f"""BEGIN;
DO $proof$ BEGIN
 BEGIN INSERT INTO public.application_season VALUES(true,'{identity('historical')}'); RAISE EXCEPTION 'Duplicate current accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN INSERT INTO public.application_season VALUES(false,'{identity('historical')}'); RAISE EXCEPTION 'Second singleton accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE public.application_season SET season_id='{identity('nonexistent-season')}'; RAISE EXCEPTION 'Invalid reference accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
END $proof$;
SET LOCAL ROLE anon;
DO $$ BEGIN BEGIN PERFORM * FROM public.application_season; RAISE EXCEPTION 'Anonymous direct read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN BEGIN UPDATE public.application_season SET singleton=true; RAISE EXCEPTION 'Authenticated direct write accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE service_role;
DO $$ BEGIN IF (SELECT count(*) FROM public.application_season) <> 1 THEN RAISE EXCEPTION 'Trusted read failed'; END IF; END $$;
ROLLBACK;
""")
        # Exercise the secure replacement transaction on the freshly bootstrapped DB.
        graph = bracket_scenario("draft")["matches"]

        def encoded(label, broken=False):
            import copy

            rows = copy.deepcopy(graph)
            for row in rows:
                row["id"] = identity(label + row["id"])
                if row["next_match_id"]:
                    row["next_match_id"] = identity(label + row["next_match_id"])
            if broken:
                rows[0]["team_a"] = "INVALID_SYNTHETIC_TEAM"
            return "'" + json.dumps(rows).replace("'", "''") + "'::jsonb"

        master_sql = f"""BEGIN;
DO $proof$ DECLARE old_row jsonb; new_row jsonb; BEGIN
 old_row := public.create_master_bracket_atomic('{identity('admin')}','{identity('current')}',false,{encoded('fresh-master-a')});
 BEGIN
  PERFORM public.create_master_bracket_atomic('{identity('admin')}','{identity('current')}',false,{encoded('fresh-master-b')});
  RAISE EXCEPTION 'Unconfirmed replacement accepted';
 EXCEPTION WHEN SQLSTATE 'P0001' THEN
  IF SQLERRM <> 'Explicit master replacement confirmation required' THEN RAISE; END IF;
 END;
 new_row := public.create_master_bracket_atomic('{identity('admin')}','{identity('current')}',true,{encoded('fresh-master-b')});
 IF (SELECT count(*) FROM public.brackets WHERE is_master IS TRUE AND deleted_at IS NULL) <> 1 THEN RAISE EXCEPTION 'Master count mismatch'; END IF;
 IF (SELECT master_bracket_id FROM public.seasons WHERE id='{identity('current')}') <> (new_row->>'id')::uuid THEN RAISE EXCEPTION 'Master pointer mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.brackets WHERE id=(old_row->>'id')::uuid AND deleted_at IS NOT NULL AND is_master IS FALSE) THEN RAISE EXCEPTION 'Master retirement mismatch'; END IF;
 BEGIN
  PERFORM public.create_master_bracket_atomic('{identity('admin')}','{identity('current')}',true,{encoded('fresh-master-fail', True)});
  RAISE EXCEPTION 'Invalid synthetic graph accepted';
 EXCEPTION WHEN foreign_key_violation THEN NULL;
 END;
 IF (SELECT master_bracket_id FROM public.seasons WHERE id='{identity('current')}') <> (new_row->>'id')::uuid THEN RAISE EXCEPTION 'Replacement rollback failed'; END IF;
END $proof$;
ROLLBACK;
"""
        sql(master_sql)
        from standings_service import parse_espn

        rows = parse_espn(
            json.loads(
                (
                    ROOT / "tests/fixtures/providers/espn-standings-complete-2026.json"
                ).read_text()
            ),
            data["teams"],
        )
        payload = "'" + json.dumps(rows).replace("'", "''") + "'::jsonb"
        sql(f"""BEGIN;
UPDATE public.seasons SET regular_season_end_utc=now()+interval '2 days',playoffs_start_utc=now()+interval '3 days' WHERE id='{identity('current')}';
SET LOCAL ROLE service_role;
DO $proof$ DECLARE result jsonb; BEGIN
 result:=public.publish_current_standings('{identity('current')}',{payload});
 IF result->>'state'<>'refreshed' OR (SELECT count(*) FROM public.standings)<>30 OR (SELECT count(DISTINCT code) FROM public.standings)<>30 THEN RAISE EXCEPTION 'Fresh publish failed'; END IF;
END $proof$;
RESET ROLE;
CREATE FUNCTION public.c2_synthetic_insert_failure() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.code='LAL' THEN RAISE EXCEPTION 'Synthetic mid-insert failure'; END IF; RETURN NEW; END $fault$;
CREATE TRIGGER c2_synthetic_insert_failure BEFORE INSERT ON public.standings FOR EACH ROW EXECUTE FUNCTION public.c2_synthetic_insert_failure();
DO $proof$ DECLARE before_rows jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO before_rows FROM public.standings s;
 BEGIN
  PERFORM public.publish_current_standings('{identity('current')}',{payload});
  RAISE EXCEPTION 'Failure injection did not fire';
 EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic mid-insert failure' THEN RAISE; END IF; END;
 IF (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'Atomic replacement rollback lost last good state'; END IF;
END $proof$;
DROP TRIGGER c2_synthetic_insert_failure ON public.standings;
DROP FUNCTION public.c2_synthetic_insert_failure();
UPDATE public.seasons SET regular_season_end_utc=now()-interval '1 second' WHERE id='{identity('current')}';
DO $proof$ DECLARE before_rows jsonb; result jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO before_rows FROM public.standings s;
 result:=public.publish_current_standings('{identity('current')}',{payload});
 IF result->>'state'<>'frozen' OR (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'DB freeze did not preserve state'; END IF;
 BEGIN PERFORM public.publish_current_standings('{identity('historical')}',{payload}); RAISE EXCEPTION 'Stale canonical ID accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
END $proof$;
SET LOCAL ROLE anon;
DO $$ BEGIN BEGIN PERFORM public.publish_current_standings(NULL,'[]'::jsonb); RAISE EXCEPTION 'Anonymous publish allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN BEGIN PERFORM public.publish_current_standings(NULL,'[]'::jsonb); RAISE EXCEPTION 'Authenticated publish allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
ROLLBACK;
-- PostgreSQL sequence consumption is nontransactional; restore only this disposable fixture counter.
SELECT setval('public.standings_id_seq',30,true);
""")
        # Narrow C3 finalization proof, never a full rollover transaction claim.
        sql(f"""BEGIN;
INSERT INTO public.seasons(id,code,regular_season_end_utc,playoffs_start_utc) VALUES ('{identity('c3-target')}','2026-27',now()+interval '2 days',now()+interval '8 days');
CREATE FUNCTION public.c3_synthetic_reset_failure() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'Synthetic reset failure after pointer movement'; END $fault$;
CREATE TRIGGER c3_synthetic_reset_failure BEFORE DELETE ON public.standings FOR EACH ROW EXECUTE FUNCTION public.c3_synthetic_reset_failure();
DO $proof$ DECLARE before_rows jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO before_rows FROM public.standings s;
 BEGIN
  PERFORM public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2026-27');
  RAISE EXCEPTION 'Failure injection did not fire';
 EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic reset failure after pointer movement' THEN RAISE; END IF; END;
 IF (SELECT season_id FROM public.application_season WHERE singleton)<>'{identity('current')}'::uuid OR (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'Finalization rollback failed'; END IF;
END $proof$;
DROP TRIGGER c3_synthetic_reset_failure ON public.standings;
DROP FUNCTION public.c3_synthetic_reset_failure();
SET LOCAL ROLE anon;
DO $$ BEGIN BEGIN PERFORM public.finalize_season_transition(NULL,NULL,NULL); RAISE EXCEPTION 'Anon finalize allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN BEGIN PERFORM public.finalize_season_transition(NULL,NULL,NULL); RAISE EXCEPTION 'Authenticated finalize allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
DO $proof$ BEGIN
 UPDATE public.seasons SET regular_season_end_utc=NULL WHERE id='{identity('c3-target')}';
 BEGIN PERFORM public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2026-27'); RAISE EXCEPTION 'Missing timing allowed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Target season timing is unconfigured or invalid' THEN RAISE; END IF; END;
 UPDATE public.seasons SET regular_season_end_utc=now()+interval '10 days' WHERE id='{identity('c3-target')}';
 BEGIN PERFORM public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2026-27'); RAISE EXCEPTION 'Reversed timing allowed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Target season timing is unconfigured or invalid' THEN RAISE; END IF; END;
 UPDATE public.seasons SET regular_season_end_utc=now()+interval '2 days' WHERE id='{identity('c3-target')}';
 BEGIN PERFORM public.finalize_season_transition('{identity('current')}','{identity('nonexistent-season')}','2026-27'); RAISE EXCEPTION 'Missing target allowed'; EXCEPTION WHEN no_data_found THEN NULL; END;
END $proof$;
SET LOCAL ROLE service_role;
DO $proof$ DECLARE before_rows jsonb; result jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO before_rows FROM public.standings s;
 BEGIN PERFORM public.finalize_season_transition('{identity('historical')}','{identity('c3-target')}','2026-27'); RAISE EXCEPTION 'Stale source allowed'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 BEGIN PERFORM public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2025-26'); RAISE EXCEPTION 'Wrong target allowed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Target season code mismatch' THEN RAISE; END IF; END;
 IF (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'Rejected transition lost standings'; END IF;
 result:=public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2026-27');
 IF result->>'state'<>'transitioned' OR (SELECT season_id FROM public.application_season WHERE singleton)<>'{identity('c3-target')}'::uuid OR EXISTS(SELECT 1 FROM public.standings) THEN RAISE EXCEPTION 'Transition did not activate/reset'; END IF;
 BEGIN PERFORM public.publish_current_standings('{identity('current')}',{payload}); RAISE EXCEPTION 'Old refresh crossed activation'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 result:=public.publish_current_standings('{identity('c3-target')}',{payload});
 IF result->>'state'<>'refreshed' OR (SELECT count(*) FROM public.standings)<>30 THEN RAISE EXCEPTION 'First target refresh failed'; END IF;
 BEGIN PERFORM public.finalize_season_transition('{identity('current')}','{identity('c3-target')}','2026-27'); RAISE EXCEPTION 'Repeat allowed'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 IF (SELECT count(*) FROM public.standings)<>30 THEN RAISE EXCEPTION 'Repeat cleared target standings'; END IF;
END $proof$;
RESET ROLE;
ROLLBACK;
SELECT setval('public.standings_id_seq',30,true);
""")
        # Actual atomic scoring proof after pointer/result source validation.
        from synthetic_fixtures import score_history_scenario
        from scoring_engine import score_bracket
        import copy

        scene = score_history_scenario()
        master_id = identity("bracket-master")
        graph = copy.deepcopy(scene["matches"])
        for role in ("user-a", "user-b"):
            bid = identity("score-" + role)
            for row in copy.deepcopy(graph):
                row["bracket_id"] = bid
                row["id"] = identity(role + row["id"])
                if row["next_match_id"]:
                    row["next_match_id"] = identity(role + row["next_match_id"])
                scene["matches"].append(row)

        def encode(value):
            return "'" + json.dumps(value).replace("'", "''") + "'::jsonb"

        graph_by = {
            f"{m['conference']}-{m['round']}-{m['slot']}": m
            for m in graph
            if m["bracket_id"] == master_id
        }

        def scoring_rows(truth):
            result = []
            for role in ("user-a", "user-b"):
                bid = identity("score-" + role)
                user = {
                    f"{m['conference']}-{m['round']}-{m['slot']}": m
                    for m in scene["matches"]
                    if m["bracket_id"] == bid
                }
                points = score_bracket(user, truth)
                points.pop("base_points")
                result.append(
                    dict(
                        points,
                        bracket_id=bid,
                        master_bracket_id=master_id,
                        season_id=identity("current"),
                    )
                )
            return sorted(result, key=lambda r: r["bracket_id"])

        good = scoring_rows(graph_by)
        altered = copy.deepcopy(graph_by)
        first = next(iter(altered.values()))
        first["predicted_winner"] = first["team_b"]
        changed = scoring_rows(altered)
        setup = "BEGIN;\n"
        for table in ("brackets", "matches"):
            setup += f"INSERT INTO public.{table} SELECT * FROM jsonb_populate_recordset(NULL::public.{table},{encode(scene[table])});\n"
        setup += f"UPDATE public.seasons SET master_bracket_id='{master_id}' WHERE id='{identity('current')}';\n"
        # Source expression has the identical typed semantic fields as the service.
        source_sql = """jsonb_build_object('brackets',(SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM (SELECT id,user_id,season_id,is_master,is_done,deleted_at,saved_at FROM public.brackets WHERE season_id='CURRENT') b),'matches',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM (SELECT id,bracket_id,season_id,conference,round,slot,team_a,team_b,predicted_winner,predicted_winner_games FROM public.matches WHERE season_id='CURRENT') m))""".replace(
            "CURRENT", identity("current")
        )
        sql(setup + f"""
SET LOCAL ROLE service_role;
DO $proof$ DECLARE source jsonb; result jsonb; before_rows jsonb; BEGIN
 source:={source_sql};
 result:=public.publish_current_bracket_scores('{identity('current')}','{master_id}',source,{encode(good)});
 IF result->>'state'<>'published' OR (SELECT count(*) FROM public.bracket_scores)<>2 THEN RAISE EXCEPTION 'Complete score publish failed'; END IF;
 SELECT jsonb_agg(to_jsonb(s) ORDER BY bracket_id) INTO before_rows FROM public.bracket_scores s;
 result:=public.publish_current_bracket_scores('{identity('current')}','{master_id}',source,{encode(good)});
 IF result->>'state'<>'unchanged' OR (SELECT jsonb_agg(to_jsonb(s) ORDER BY bracket_id) FROM public.bracket_scores s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'Idempotence failed'; END IF;
 BEGIN PERFORM public.publish_current_bracket_scores('{identity('current')}','{identity('score-user-a')}',source,{encode(good)}); RAISE EXCEPTION 'Master spoof accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 BEGIN PERFORM public.publish_current_bracket_scores('{identity('current')}','{master_id}',source,{encode(good[:1])}); RAISE EXCEPTION 'Partial set accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Complete eligible score set required' THEN RAISE; END IF; END;
END $proof$;
RESET ROLE;
CREATE FUNCTION public.d1_synthetic_score_failure() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.bracket_id='{max(r['bracket_id'] for r in good)}'::uuid THEN RAISE EXCEPTION 'Synthetic score insert failure'; END IF; RETURN NEW; END $fault$;
CREATE TRIGGER d1_synthetic_score_failure BEFORE INSERT ON public.bracket_scores FOR EACH ROW EXECUTE FUNCTION public.d1_synthetic_score_failure();
DO $proof$ DECLARE before_rows jsonb; old_source jsonb; source jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(s) ORDER BY bracket_id) INTO before_rows FROM public.bracket_scores s;
 old_source:={source_sql};
 UPDATE public.matches SET predicted_winner=team_b WHERE id='{first['id']}';
 source:={source_sql};
 BEGIN PERFORM public.publish_current_bracket_scores('{identity('current')}','{master_id}',old_source,{encode(changed)}); RAISE EXCEPTION 'Changed source accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END;
 BEGIN PERFORM public.publish_current_bracket_scores('{identity('current')}','{master_id}',source,{encode(changed)}); RAISE EXCEPTION 'Failure injection did not fire'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic score insert failure' THEN RAISE; END IF; END;
 IF (SELECT jsonb_agg(to_jsonb(s) ORDER BY bracket_id) FROM public.bracket_scores s) IS DISTINCT FROM before_rows THEN RAISE EXCEPTION 'Atomic score rollback lost last good rows'; END IF;
END $proof$;
SET LOCAL ROLE anon;
DO $$ BEGIN BEGIN PERFORM public.publish_current_bracket_scores(NULL,NULL,NULL,NULL); RAISE EXCEPTION 'Anon score publish allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN BEGIN PERFORM public.publish_current_bracket_scores(NULL,NULL,NULL,NULL); RAISE EXCEPTION 'Authenticated score publish allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
ROLLBACK;
""")
        from history_service import snapshot_rows, snapshot_columns

        frozen, _ = snapshot_rows(good, scene["brackets"], foundation()["users"])
        columns = snapshot_columns(graph_by)
        invalid_order = [dict(row, display_order=None) for row in frozen]
        # Actual header/second-row failure, immutable complete rows, safe zero and gate token.
        sql(setup + f"""
INSERT INTO public.leaderboard_history_snapshots(season_id,season_code,expected_rows,is_final,master_bracket_id) VALUES('{identity('historical')}','2024-25',0,false,'{master_id}');
UPDATE public.leaderboard_history_snapshots SET is_final=true WHERE season_id='{identity('historical')}';
SELECT public.publish_current_bracket_scores('{identity('current')}','{master_id}',{source_sql},{encode(good)});
CREATE FUNCTION public.d2_synthetic_row_failure() RETURNS trigger LANGUAGE plpgsql AS $fault$
BEGIN IF NEW.display_order=2 THEN RAISE EXCEPTION 'Synthetic snapshot row failure'; END IF; RETURN NEW; END $fault$;
CREATE TRIGGER d2_synthetic_row_failure BEFORE INSERT ON public.leaderboard_history_rows FOR EACH ROW EXECUTE FUNCTION public.d2_synthetic_row_failure();
DO $proof$ DECLARE before_headers integer; before_rows integer; old_complete jsonb; BEGIN
 SELECT jsonb_agg(to_jsonb(h) ORDER BY id) INTO old_complete FROM public.leaderboard_history_snapshots h;
 SELECT count(*) INTO before_headers FROM public.leaderboard_history_snapshots;
 SELECT count(*) INTO before_rows FROM public.leaderboard_history_rows;
 BEGIN PERFORM public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},{encode(good)},{encode(invalid_order)},{encode(columns)},NULL);
  RAISE EXCEPTION 'Invalid order accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Invalid frozen row' THEN RAISE; END IF; END;
 BEGIN PERFORM public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},{encode(good)},{encode(frozen)},{encode(columns)},NULL);
  RAISE EXCEPTION 'Snapshot failure did not fire'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Synthetic snapshot row failure' THEN RAISE; END IF; END;
 IF (SELECT count(*) FROM public.leaderboard_history_snapshots)<>before_headers OR (SELECT count(*) FROM public.leaderboard_history_rows)<>before_rows THEN RAISE EXCEPTION 'Partial snapshot escaped rollback'; END IF;
 IF (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM public.leaderboard_history_snapshots h) IS DISTINCT FROM old_complete THEN RAISE EXCEPTION 'Older complete snapshot changed'; END IF;
END $proof$;
DROP TRIGGER d2_synthetic_row_failure ON public.leaderboard_history_rows;
DROP FUNCTION public.d2_synthetic_row_failure();
SET LOCAL ROLE service_role;
DO $proof$ DECLARE result jsonb; before_state jsonb; repeat_state jsonb; BEGIN
 result:=public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},{encode(good)},{encode(frozen)},{encode(columns)},NULL);
 IF result->>'state'<>'created' OR (result->>'actual_rows')::integer<>2 OR result->>'is_final'<>'true' THEN RAISE EXCEPTION 'Complete snapshot failed'; END IF;
 SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM public.leaderboard_history_snapshots h),(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM public.leaderboard_history_rows r)) INTO before_state;
 result:=public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},{encode(good)},{encode(frozen)},{encode(columns)},NULL);
 IF result->>'state'<>'existing' THEN RAISE EXCEPTION 'Repeat not recognized'; END IF;
 BEGIN UPDATE public.leaderboard_history_rows SET total_points=99 WHERE snapshot_id=(result->>'snapshot_id')::uuid; RAISE EXCEPTION 'Row overwrite accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Historical snapshots are immutable' THEN RAISE; END IF; END;
 BEGIN DELETE FROM public.leaderboard_history_snapshots WHERE id=(result->>'snapshot_id')::uuid; RAISE EXCEPTION 'Header delete accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Historical snapshots are immutable' THEN RAISE; END IF; END;
 BEGIN TRUNCATE public.leaderboard_history_rows; RAISE EXCEPTION 'Application truncate accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Historical snapshots are immutable' THEN RAISE; END IF; END;
 SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM public.leaderboard_history_snapshots h),(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM public.leaderboard_history_rows r)) INTO repeat_state;
 IF repeat_state IS DISTINCT FROM before_state THEN RAISE EXCEPTION 'Immutable snapshot changed'; END IF;
END $proof$;
RESET ROLE;
SET LOCAL ROLE anon;
DO $$ BEGIN BEGIN PERFORM public.publish_leaderboard_snapshot(NULL,NULL,NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'Anonymous publisher admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN BEGIN PERFORM public.publish_leaderboard_snapshot(NULL,NULL,NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'Authenticated publisher admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
ROLLBACK;
""")
        zero_setup = (
            setup
            + f"UPDATE public.brackets SET is_done=false,saved_at=NULL WHERE id<>'{master_id}';\n"
        )
        sql(zero_setup + f"""
SELECT public.publish_current_bracket_scores('{identity('current')}','{master_id}',{source_sql},'[]');
SET LOCAL ROLE service_role;
DO $proof$ DECLARE result jsonb; repeated jsonb; BEGIN
 result:=public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},'[]','[]','[]',NULL);
 IF (result->>'expected_rows')::integer<>0 OR (result->>'actual_rows')::integer<>0 OR result->>'is_final'<>'true' OR (SELECT count(*) FROM public.leaderboard_history_snapshots)<>1 THEN RAISE EXCEPTION 'Verified zero final failed'; END IF;
 repeated:=public.publish_leaderboard_snapshot('{identity('current')}','{master_id}',{source_sql},'[]','[]','[]',NULL);
 IF repeated->>'state'<>'existing' OR repeated->>'snapshot_id'<>result->>'snapshot_id' THEN RAISE EXCEPTION 'Zero repeat changed'; END IF;
 BEGIN DELETE FROM public.leaderboard_history_snapshots WHERE id=(result->>'snapshot_id')::uuid; RAISE EXCEPTION 'Zero deletion accepted'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'Historical snapshots are immutable' THEN RAISE; END IF; END;
END $proof$;
RESET ROLE;
ROLLBACK;
""")
        from scripts.reset_local_fixtures import digest_sql, state_sql
        from integration_harness import CANONICAL_CHECKSUM

        sql(
            "DO $$ BEGIN IF "
            + digest_sql(state_sql())
            + " <> '"
            + CANONICAL_CHECKSUM
            + "' THEN RAISE EXCEPTION 'Fresh fixture checksum mismatch'; END IF; END $$;"
        )
        sql(
            (ROOT / "db/post-baseline/0007_nc_02e_atomic_rollover.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_nc_02e_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        from scripts.nc02e_database_acceptance import (
            run,
            contention,
            committed_failure_retry,
        )

        rollover_findings = run(sql)
        rollover_findings.append(contention(sql, PROOF_DB))
        rollover_findings.append(committed_failure_retry(sql))
        sql(
            (ROOT / "db/post-baseline/verify_nc_02e_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        from scripts.nc02f1_database_acceptance import (
            preflight as f1_preflight,
            run as f1_run,
            contention as f1_contention,
        )

        migration = (
            ROOT / "db/post-baseline/0008_nc_02f1_league_lifecycle.sql"
        ).read_text(encoding="utf-8")
        league_findings = f1_preflight(sql, lambda: sql(migration))
        sql(migration)
        sql(
            (ROOT / "db/post-baseline/verify_nc_02f1_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        league_findings += f1_run(sql)
        league_findings.append(f1_contention(sql, PROOF_DB))
        sql(
            (ROOT / "db/post-baseline/verify_nc_02f1_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        from scripts import nc02f2_database_acceptance as f2

        sql(
            (ROOT / "db/post-baseline/0009_nc_02f2_league_history.sql").read_text(
                encoding="utf-8"
            )
        )
        sql(
            (ROOT / "db/post-baseline/verify_current_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        history_findings = f2.run(sql)
        history_findings += f2.ranking_and_immutability(sql)
        history_findings.append(f2.partial_all_league_failure(sql))
        history_findings.append(f2.old_source_refusal(sql))
        history_findings += f2.membership_contention(sql, PROOF_DB)
        post_f2_rollover = run(sql)
        post_f2_rollover.append(contention(sql, PROOF_DB))

        def current_sql(body):
            return sql(
                body.replace(
                    "TRUNCATE TABLE public.season_rollover_audits,",
                    "TRUNCATE TABLE "
                    + ",".join("public." + t for t in f2.F2_TABLES)
                    + ",public.season_rollover_audits,",
                )
            )

        post_f2_rollover.append(committed_failure_retry(current_sql))
        sql(
            (ROOT / "db/post-baseline/verify_current_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        proof = {
            "history_findings": history_findings,
            "post_f2_rollover_findings": post_f2_rollover,
            "f2_migration": "0009_nc_02f2_league_history.sql",
            "league_findings": league_findings,
            "f1_migration": "0008_nc_02f1_league_lifecycle.sql",
            "rollover_findings": rollover_findings,
            "full_rollover_atomicity_verified": True,
            "phase": "NC-02F2",
            "fresh_database": True,
            "platform_source": "schema-only verified local Supabase; no rows/roles/password dump",
            "baseline_bootstrap": True,
            "prior_post_baseline_migrations": [
                "0001_nc_02b3_bracket_lifecycle.sql",
                "0002_nc_02c1_canonical_season.sql",
                "0003_nc_02c2_atomic_standings.sql",
                "0004_nc_02c3_season_transition.sql",
                "0005_nc_02d1_atomic_scores.sql",
                "0006_nc_02d2_final_snapshots.sql",
            ],
            "migration": "db/post-baseline/0007_nc_02e_atomic_rollover.sql",
            "atomic_snapshot_header_second_row_failure_rollback": True,
            "older_complete_snapshot_preserved_on_failure": True,
            "null_display_order_refused": True,
            "complete_final_snapshot_and_exact_repeat": True,
            "immutable_rows_header_and_service_truncate_refused": True,
            "verified_zero_snapshot_and_repeat": True,
            "untrusted_snapshot_execution_refused": True,
            "complete_score_publication": True,
            "unchanged_exact_row_idempotence": True,
            "actual_mid_insert_score_failure_rollback": True,
            "score_source_change_and_master_spoof_fenced": True,
            "partial_score_set_refused": True,
            "untrusted_score_publication_refused": True,
            "atomic_pointer_reset_rollback_after_pointer_update": True,
            "trusted_transition_success": True,
            "stale_source_wrong_target_refused": True,
            "old_refresh_fenced_after_transition": True,
            "first_new_season_refresh": True,
            "repeat_does_not_reset_new_standings": True,
            "untrusted_transition_denied": True,
            "invalid_missing_target_timing_refused": True,
            "full_rollover_atomicity_claimed": True,
            "fresh_service_role_publish": True,
            "mid_insert_failure_after_delete_rolled_back": True,
            "last_good_rows_ids_timestamps_preserved": True,
            "db_freeze_recheck": True,
            "canonical_fencing": True,
            "untrusted_rpc_execution_refused": True,
            "migration_does_not_designate": True,
            "single_canonical_fixture": True,
            "duplicate_false_singleton_and_invalid_fk_refused": True,
            "untrusted_direct_access_refused": True,
            "trusted_service_read": True,
            "semantic_verification": True,
            "synthetic_seed": True,
            "cross_season_coexistence": True,
            "same_season_duplicate_refused": True,
            "soft_delete_recreation": True,
            "fresh_master_create_replace_rollback": True,
            "canonical_fixture_checksum": CANONICAL_CHECKSUM,
            "production_contact": False,
        }
    finally:
        if created:
            command(["dropdb", "-U", "postgres", PROOF_DB])
    proof["disposable_database_removed"] = True
    (ROOT / "db/records/nc_02f2_fresh_migration_proof.json").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        "PASS fresh local baseline + forward migration + semantic verifier + synthetic seed/uniqueness acceptance; disposable DB removed."
    )


if __name__ == "__main__":
    main()
