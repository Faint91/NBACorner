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

PROOF_DB = "nc_02c2_bootstrap_proof"


def command(args, body=None):
    result = subprocess.run(
        ["docker", "exec", *(["-i"] if body is not None else []), CONTAINER, *args],
        input=body,
        capture_output=True,
        env=child_environment(),
        timeout=120,
    )
    if result.returncode:
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
            "SELECT count(*) FROM pg_database WHERE datname='nc_02c2_bootstrap_proof'",
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
            "DROP TABLE public.application_season;\nDROP TABLE "
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
        from scripts.reset_local_fixtures import digest_sql, state_sql
        from integration_harness import CANONICAL_CHECKSUM

        sql(
            "DO $$ BEGIN IF "
            + digest_sql(state_sql())
            + " <> '"
            + CANONICAL_CHECKSUM
            + "' THEN RAISE EXCEPTION 'Fresh fixture checksum mismatch'; END IF; END $$;"
        )
        proof = {
            "phase": "NC-02C2",
            "fresh_database": True,
            "platform_source": "schema-only verified local Supabase; no rows/roles/password dump",
            "baseline_bootstrap": True,
            "prior_post_baseline_migrations": [
                "0001_nc_02b3_bracket_lifecycle.sql",
                "0002_nc_02c1_canonical_season.sql",
            ],
            "migration": "db/post-baseline/0003_nc_02c2_atomic_standings.sql",
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
    (ROOT / "db/records/nc_02c2_fresh_migration_proof.json").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        "PASS fresh local baseline + forward migration + semantic verifier + synthetic seed/uniqueness acceptance; disposable DB removed."
    )


if __name__ == "__main__":
    main()
