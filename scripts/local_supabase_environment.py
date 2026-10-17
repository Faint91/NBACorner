"""Guarded LOCAL TEST ONLY lifecycle. No remote link/reset or application startup."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "test-infrastructure/local-supabase"
PROJECT = "nba-corner-local-test"
CONTAINER = "supabase_db_" + PROJECT
CLI_VERSION = "2.118.0"
sys.path.insert(0, str(ROOT))
from environment_safety import (
    verify_test_email_readiness,
    verify_provider_job_readiness,
)
from environment_safety import SafetyError, load_test_config, verify_live_local_identity


def child_environment():
    return {
        k: v
        for k, v in os.environ.items()
        if k.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        }
    }


def check_configuration():
    config = tomllib.loads((WORK / "supabase/config.toml").read_text(encoding="utf-8"))
    if (
        config["project_id"] != PROJECT
        or config["db"]["major_version"] != 17
        or config["api"]["port"] != 55421
        or config["db"]["port"] != 55422
        or config["db"]["seed"]["enabled"]
        or config["db"]["migrations"]["enabled"]
        or config["auth"]["site_url"] != "http://127.0.0.1:55410"
        or config["auth"]["enable_signup"]
        or config["auth"]["additional_redirect_urls"]
        or config["api"]["schemas"] != ["public", "nba_corner_test_control"]
    ):
        raise SafetyError("Local-only configuration contract mismatch.")
    for service in [
        "studio",
        "local_smtp",
        "realtime",
        "storage",
        "edge_runtime",
        "analytics",
    ]:
        if config[service]["enabled"]:
            raise SafetyError("Unreviewed local service configuration.")
    if (WORK / ".env").exists() or (WORK / "supabase/.temp/project-ref").exists():
        raise SafetyError("Ambient environment/remote project link prohibited.")
    text = (WORK / "supabase/config.toml").read_text(encoding="utf-8")
    if "env(" in text or "supabase.co" in text or "rpwesmvzmgoctrokrbhy" in text:
        raise SafetyError("External configuration or production identity prohibited.")


def cli():
    candidates = [Path(shutil.which("supabase"))] if shutil.which("supabase") else []
    cache = Path(os.environ.get("LOCALAPPDATA", "")) / "npm-cache/_npx"
    candidates += sorted(
        cache.glob("*/node_modules/@supabase/cli-windows-x64/bin/supabase.exe")
    )
    for path in candidates:
        result = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            env=child_environment(),
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.decode().strip() == CLI_VERSION:
            return str(path)
    raise SafetyError(
        "Reviewed official Supabase CLI 2.118.0 not available; no automatic install/upgrade."
    )


def container_identity():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER],
        capture_output=True,
        env=child_environment(),
        timeout=10,
    )
    if result.returncode:
        raise SafetyError("Expected local database container unavailable.")
    metadata = json.loads(result.stdout)[0]
    if (
        metadata["Name"] != "/" + CONTAINER
        or metadata["Config"]["Image"] != "public.ecr.aws/supabase/postgres:17.6.1.171"
        or list(metadata["NetworkSettings"]["Networks"])
        != ["supabase_network_" + PROJECT]
        or not metadata["State"]["Running"]
    ):
        raise SafetyError("Local container image/network identity mismatch.")
    ports = metadata["NetworkSettings"]["Ports"].get("5432/tcp", [])
    if not ports or any(p["HostPort"] != "55422" for p in ports):
        raise SafetyError("Local DB port identity mismatch.")
    # The API must be the same project's gateway/PostgREST, not another loopback listener.
    for name, image, published in [
        ("supabase_kong_" + PROJECT, "public.ecr.aws/supabase/kong:2.8.1", "55421"),
        ("supabase_rest_" + PROJECT, "public.ecr.aws/supabase/postgrest:v16.3", None),
    ]:
        result = subprocess.run(
            ["docker", "inspect", name],
            capture_output=True,
            env=child_environment(),
            timeout=10,
        )
        if result.returncode:
            raise SafetyError("Expected local API container unavailable.")
        api = json.loads(result.stdout)[0]
        if (
            api["Name"] != "/" + name
            or api["Config"]["Image"] != image
            or not api["State"]["Running"]
            or list(api["NetworkSettings"]["Networks"])
            != ["supabase_network_" + PROJECT]
        ):
            raise SafetyError("Local API image/network identity mismatch.")
        if published:
            bindings = api["NetworkSettings"]["Ports"].get("8000/tcp", [])
            if not bindings or any(
                binding["HostPort"] != published for binding in bindings
            ):
                raise SafetyError("Local API port mapping mismatch.")
    return metadata


def sql_file(path):
    container_identity()
    # Binary stdin avoids Windows LF->CRLF alteration of SQL dollar/string bodies.
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            CONTAINER,
            "psql",
            "-X",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        input=path.read_bytes(),
        capture_output=True,
        env=child_environment(),
        timeout=120,
    )
    if result.returncode:
        raise SafetyError(
            "Local SQL failed and stopped on error; inspect schema-only diagnostics separately."
        )
    print(path.name + ": PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "start",
            "stop",
            "bootstrap",
            "verify",
            "configure",
            "identity",
            "email-readiness",
            "provider-job-readiness",
        ],
    )
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    try:
        check_configuration()
        if args.action in {"start", "stop"}:
            result = subprocess.run(
                [cli(), args.action, "--workdir", str(WORK)],
                cwd=WORK,
                env=child_environment(),
                capture_output=True,
                timeout=900,
            )
            # CLI startup/status may contain credentials: never print its raw output.
            if result.returncode:
                raise SafetyError(
                    "Local lifecycle command failed; raw CLI output withheld."
                )
            print("LOCAL TEST ONLY " + args.action + ": PASS; credentials withheld")
        elif args.action == "bootstrap":
            # Empty-only baseline refuses existing objects. No reset or DROP helper.
            sql_file(ROOT / "db/baseline/000_current_schema.sql")
            sql_file(ROOT / "db/baseline/verify_current_schema.sql")
            sql_file(ROOT / "db/post-baseline/0001_nc_02b3_bracket_lifecycle.sql")
            sql_file(ROOT / "db/post-baseline/0002_nc_02c1_canonical_season.sql")
            sql_file(ROOT / "db/post-baseline/0003_nc_02c2_atomic_standings.sql")
            sql_file(ROOT / "db/post-baseline/0004_nc_02c3_season_transition.sql")
            sql_file(ROOT / "db/post-baseline/0005_nc_02d1_atomic_scores.sql")
            sql_file(ROOT / "db/post-baseline/0006_nc_02d2_final_snapshots.sql")
            sql_file(ROOT / "db/post-baseline/0007_nc_02e_atomic_rollover.sql")
            sql_file(ROOT / "db/post-baseline/0008_nc_02f1_league_lifecycle.sql")
            sql_file(ROOT / "db/post-baseline/0009_nc_02f2_league_history.sql")
            sql_file(ROOT / "db/post-baseline/0010_nc_02g1_identity_auth.sql")
            sql_file(ROOT / "db/post-baseline/0011_nc_02g2_password_reset_sessions.sql")
            sql_file(ROOT / "db/post-baseline/verify_current_schema.sql")
            sql_file(WORK / "identity-marker.sql")
            sql_file(WORK / "fixture-marker-v2.sql")
            sql_file(WORK / "verify-fixture-marker-v2.sql")
        elif args.action == "verify":
            sql_file(ROOT / "db/post-baseline/verify_current_schema.sql")
            sql_file(WORK / "verify-fixture-marker-v2.sql")
        elif args.action == "configure":
            container_identity()
            destination = ROOT / ".env.test.nba-local.local"
            ignored = subprocess.run(
                [
                    "git",
                    "-c",
                    "safe.directory=" + ROOT.as_posix(),
                    "-C",
                    str(ROOT),
                    "check-ignore",
                    "--quiet",
                    str(destination),
                ],
                capture_output=True,
            )
            if ignored.returncode:
                raise SafetyError("Local credential destination is not ignored by Git.")
            if destination.exists():
                verify_live_local_identity(load_test_config(str(destination)))
                print("Existing ignored local configuration verified; not overwritten.")
            else:
                result = subprocess.run(
                    [cli(), "status", "--workdir", str(WORK), "--output", "json"],
                    cwd=WORK,
                    env=child_environment(),
                    capture_output=True,
                    timeout=30,
                )
                if result.returncode:
                    raise SafetyError(
                        "Local status failed; raw credential-bearing output withheld."
                    )
                values = json.loads(result.stdout)
                if values.get("API_URL") != "http://127.0.0.1:55421" or not values.get(
                    "SERVICE_ROLE_KEY"
                ):
                    raise SafetyError("Native local credential origin mismatch.")
                key = values["SERVICE_ROLE_KEY"]
                settings = {
                    "NBA_CORNER_ENV": "test",
                    "NBA_CORNER_ALLOW_MUTATING_TESTS": "0",
                    "NBA_CORNER_TEST_TARGET": "local-nba-corner-test",
                    "NBA_CORNER_EXPECTED_PROJECT_REF": "local:" + PROJECT,
                    "SUPABASE_URL": values["API_URL"],
                    "NBACORNER_BASE_URL": "http://127.0.0.1:55410",
                    "SUPABASE_KEY": key,
                    "SUPABASE_SERVICE_ROLE_KEY": key,
                    "NBA_CORNER_JOBS_ENABLED": "false",
                    "NBA_CORNER_PROVIDER_MODE": "fixtures",
                    "NBA_CORNER_EMAIL_MODE": "capture",
                    "NBA_CORNER_RESET_LINK_ORIGIN": "http://127.0.0.1:55410",
                }
                verify_live_local_identity(settings)
                destination.write_text(
                    "\n".join(k + "=" + v for k, v in settings.items()) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                print(
                    "Ignored local configuration created; no secret values displayed."
                )
        else:
            container_identity()
            if args.config is None:
                raise SafetyError("Explicit ignored local test configuration required.")
            settings = load_test_config(str(args.config))
            result = (
                verify_provider_job_readiness(settings)
                if args.action == "provider-job-readiness"
                else (
                    verify_test_email_readiness(settings)
                    if args.action == "email-readiness"
                    else verify_live_local_identity(settings)
                )
            )
            print(json.dumps(result, indent=2))
        return 0
    except (
        SafetyError,
        OSError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            "REFUSED: "
            + (
                str(error)
                if isinstance(error, SafetyError)
                else "Local tooling/configuration unavailable."
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
