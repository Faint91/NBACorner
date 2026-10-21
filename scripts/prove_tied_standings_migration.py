"""NC-06E fixed disposable LOCAL proof; reuses guarded G2 recovery utilities."""

import copy
import json
from pathlib import Path
from scripts import prove_password_reset_migration as local
from environment_safety import load_test_config, verify_live_local_identity, SafetyError
from synthetic_fixtures import foundation, TABLES, identity
from standings_service import parse_espn

ROOT = Path(__file__).resolve().parents[1]
DB = "nc_06e_tied_standings_proof"


def encoded(rows):
    return "'" + json.dumps(rows).replace("'", "''") + "'::jsonb"


def run():
    local.check_configuration()
    local.container_identity()
    verify_live_local_identity(
        load_test_config(str(ROOT / ".env.test.nba-local.local"))
    )
    local.PROOF_DB = DB
    if (
        local.command(
            [
                "psql",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-Atc",
                "SELECT count(*) FROM pg_database WHERE datname='" + DB + "'",
            ]
        ).strip()
        != b"0"
    ):
        raise SafetyError("Fixed disposable name already exists; refusing reuse")
    platform = local.command(
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
    groups = []
    try:
        local.command(["createdb", "-U", "postgres", "--template=template0", DB])
        created = True
        local.command(
            ["psql", "-X", "-U", "supabase_admin", "-d", DB, "-v", "ON_ERROR_STOP=1"],
            platform,
        )
        extras = "public.league_history_rows,public.league_history_seasons,public.league_history_cutoffs,public.leaderboard_history_competitors,public.season_rollover_audits,public.application_season,"
        local.sql(
            "DROP TABLE IF EXISTS "
            + extras
            + ",".join("public." + t for t in TABLES)
            + " CASCADE; DO $$ DECLARE f record; BEGIN FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e') LOOP EXECUTE 'DROP FUNCTION '||f.sig||' CASCADE'; END LOOP; END $$;"
        )
        local.sql(
            (ROOT / "db/baseline/000_current_schema.sql").read_text(encoding="utf-8")
        )
        for migration in sorted(
            (ROOT / "db/post-baseline").glob("[0-9][0-9][0-9][0-9]_*.sql")
        ):
            if migration.name.startswith("0012"):
                break
            local.sql(migration.read_text(encoding="utf-8"))
        local.sql(
            (ROOT / "db/post-baseline/verify_nc_02g2_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        data = foundation()
        for table in TABLES:
            if data[table]:
                columns = ",".join('"' + c + '"' for c in data[table][0])
                local.sql(
                    f"INSERT INTO public.{table}({columns}) SELECT {columns} FROM jsonb_populate_recordset(NULL::public.{table},{encoded(data[table])});"
                )
        local.sql(
            f"INSERT INTO public.application_season VALUES(true,'{identity('current')}'); UPDATE public.seasons SET regular_season_end_utc=now()+interval '2 days',playoffs_start_utc=now()+interval '3 days' WHERE id='{identity('current')}'; SELECT setval('public.standings_id_seq',30,true);"
        )
        local.sql(
            (ROOT / "db/post-baseline/0012_nc_06e_tied_standings.sql").read_text()
        )
        local.sql(
            (ROOT / "db/post-baseline/verify_current_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        groups.append("fresh_0001_through_0012_and_exact_semantic_verifier")
        valid = parse_espn(
            json.loads(
                (
                    ROOT / "tests/fixtures/providers/espn-standings-complete-2026.json"
                ).read_text()
            ),
            data["teams"],
            expected_year=2026,
        )
        tied = copy.deepcopy(valid)
        for row in tied:
            row["seed"] = 1
        observed = copy.deepcopy(tied)
        for row in observed:
            if row["conference"] == "east":
                original = next(r["seed"] for r in valid if r["code"] == row["code"])
                row["seed"] = 1 if original == 1 else 15 if original == 15 else 2

        def publish(rows, source=identity("current")):
            return f"public.publish_current_standings('{source}',{encoded(rows)})"

        for label, rows in [
            ("unique", valid),
            ("all_tied", tied),
            ("partial_ties_and_gaps", observed),
        ]:
            local.sql(
                f"DO $$ DECLARE result jsonb; BEGIN result:={publish(rows)}; IF result->>'state'<>'refreshed' OR (SELECT count(*) FROM public.standings)<>30 OR (SELECT count(DISTINCT code) FROM public.standings)<>30 OR (SELECT count(*) FROM public.standings WHERE conference='east')<>15 OR (SELECT count(*) FROM public.standings WHERE conference='west')<>15 THEN RAISE EXCEPTION 'Invalid successful publication'; END IF; IF EXISTS(SELECT 1 FROM public.brackets) OR EXISTS(SELECT 1 FROM public.matches) THEN RAISE EXCEPTION 'Publication created bracket graph'; END IF; IF EXISTS(SELECT 1 FROM public.standings s JOIN jsonb_to_recordset({encoded(rows)}) AS x(code text,seed integer) USING(code) WHERE s.seed<>x.seed) THEN RAISE EXCEPTION 'Provider positions changed'; END IF; END $$;"
            )
            groups.append(label + "_30_rows_15_15_exact_positions_zero_master")
        for label in [
            "duplicate_team",
            "incomplete",
            "extra",
            "conference",
            "invalid_seed",
            "null_seed",
            "invalid_wins",
            "canonical_mismatch",
        ]:
            rows = copy.deepcopy(tied)
            source = identity("current")
            if label == "duplicate_team":
                rows[1] = copy.deepcopy(rows[0])
            if label == "incomplete":
                rows.pop()
            if label == "extra":
                rows.append(copy.deepcopy(rows[0]))
            if label == "conference":
                rows[0]["conference"] = "west"
            if label == "invalid_seed":
                rows[0]["seed"] = 16
            if label == "null_seed":
                rows[0]["seed"] = None
            if label == "invalid_wins":
                rows[0]["wins"] = -1
            if label == "canonical_mismatch":
                source = identity("historical")
            local.sql(
                f"DO $$ DECLARE old jsonb; accepted boolean:=false; BEGIN SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO old FROM public.standings s; BEGIN PERFORM {publish(rows,source)}; accepted:=true; EXCEPTION WHEN OTHERS THEN NULL; END; IF accepted OR old IS DISTINCT FROM (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) THEN RAISE EXCEPTION 'Invalid publication accepted or last good lost'; END IF; END $$;"
            )
            groups.append(label + "_rejected_preserves_last_good")
        local.sql(
            "CREATE FUNCTION public.nc06e_insert_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.code='LAL' THEN RAISE EXCEPTION 'Synthetic insert failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER nc06e_insert_failure BEFORE INSERT ON public.standings FOR EACH ROW EXECUTE FUNCTION public.nc06e_insert_failure();"
        )
        local.sql(
            f"DO $$ DECLARE old jsonb; accepted boolean:=false; BEGIN SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO old FROM public.standings s; BEGIN PERFORM {publish(tied)}; accepted:=true; EXCEPTION WHEN OTHERS THEN NULL; END; IF accepted OR old IS DISTINCT FROM (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) THEN RAISE EXCEPTION 'Atomic rollback lost rows'; END IF; END $$;"
        )
        local.sql(
            "DROP TRIGGER nc06e_insert_failure ON public.standings; DROP FUNCTION public.nc06e_insert_failure();"
        )
        groups.append("mid_insert_failure_rolls_back_delete_and_inserts")
        local.sql(
            f"UPDATE public.seasons SET regular_season_end_utc=now()-interval '1 second' WHERE id='{identity('current')}'; DO $$ DECLARE old jsonb; result jsonb; BEGIN SELECT jsonb_agg(to_jsonb(s) ORDER BY id) INTO old FROM public.standings s; result:={publish(tied)}; IF result->>'state'<>'frozen' OR old IS DISTINCT FROM (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.standings s) THEN RAISE EXCEPTION 'Freeze lost rows'; END IF; END $$;"
        )
        groups.append("database_freeze_preserves_last_good")
        local.sql(
            (ROOT / "db/post-baseline/verify_current_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        groups.append("function_security_acl_and_schema_unchanged_after_tests")
    finally:
        if created:
            local.command(["dropdb", "-U", "postgres", DB])
    result = {
        "phase": "NC-06E",
        "status": "PASS",
        "groups": groups,
        "group_count": len(groups),
        "disposable_database_removed": True,
        "production_contact": False,
    }
    (ROOT / "db/records/nc_06e_migration_validation.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result))


if __name__ == "__main__":
    run()
