"""Fixed local-only foundation reset. No arbitrary SQL, URL, table or scenario executor."""

import argparse
import hashlib
import json
import subprocess
import sys
import queue
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment_safety import (
    SafetyError,
    load_test_config,
    load_enrollments,
    validate_test_target,
    validate_test_email_settings,
    validate_test_provider_settings,
    validate_test_job_settings,
    verify_live_local_identity,
)
from scripts.local_supabase_environment import (
    ROOT,
    CONTAINER,
    check_configuration,
    container_identity,
    child_environment,
)
from synthetic_fixtures import TABLES, SEQUENCES, VERSION, foundation, validate_state

VERIFIER_SHA = "e041a918814b6a052b82888fddf9e721763884089aecd36a695e3a5ef279252f"


def validate_inventory(tables, sequences, external_dependencies=()):
    if (
        set(tables) != set(TABLES)
        or len(tables) != len(TABLES)
        or set(sequences) != set(SEQUENCES)
        or len(sequences) != 3
        or external_dependencies
    ):
        raise SafetyError("Unexpected reset target or dependency inventory.")


def preflight(settings, opt_in):
    if opt_in is not True:
        raise SafetyError("Explicit local reset/seed opt-in is required.")
    target = validate_test_target(settings, load_enrollments(), identity_only=True)
    validate_test_email_settings(settings, target)
    validate_test_provider_settings(settings, target)
    validate_test_job_settings(settings)
    identity = verify_live_local_identity(settings)
    marker = identity["marker"]
    if marker["fixture_state"] == "SEEDED" and marker["fixture_version"] != VERSION:
        raise SafetyError("Unreviewed existing fixture version.")
    return marker


def literal(value):
    return (
        "'"
        + json.dumps(value, sort_keys=True, separators=(",", ":")).replace("'", "''")
        + "'::jsonb"
    )


def baseline_body():
    raw = (ROOT / "db/baseline/verify_current_schema.sql").read_bytes()
    if hashlib.sha256(raw).hexdigest() != VERIFIER_SHA:
        raise SafetyError("Reviewed semantic verifier bytes changed.")
    return raw.decode().replace("BEGIN READ ONLY;", "", 1).rsplit("COMMIT;", 1)[0]


def state_sql(data=None):
    parts = []
    for table in TABLES:
        source = (
            f"public.{table} r"
            if data is None
            else f"jsonb_populate_recordset(NULL::public.{table},{literal(data[table])}) r"
        )
        parts += [
            "'" + table + "'",
            f"(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text COLLATE \"C\"),'[]'::jsonb) FROM {source})",
        ]
    seq = []
    for name in SEQUENCES:
        seq += [
            "'" + name + "'",
            (
                f"(SELECT jsonb_build_array(last_value,is_called) FROM public.{name})"
                if data is None
                else (
                    "jsonb_build_array(30,true)"
                    if name == "standings_id_seq"
                    else "jsonb_build_array(1,false)"
                )
            ),
        ]
    return f"jsonb_build_object('fixture_version','{VERSION}','tables',jsonb_build_object({','.join(parts)}),'sequences',jsonb_build_object({','.join(seq)}))"


def digest_sql(state):
    return (
        f"encode(extensions.digest(convert_to(({state})::text,'UTF8'),'sha256'),'hex')"
    )


def reset_sql(marker):
    validate_inventory(TABLES, SEQUENCES)
    data = foundation()
    validate_state(data)
    identity_keys = tuple(marker)
    pairs = ",".join("'" + k + "'," + k for k in identity_keys)
    prefix = f"""BEGIN;
SET LOCAL statement_timeout='60s';
SET LOCAL lock_timeout='5s';
SET LOCAL timezone='UTC';
SET LOCAL datestyle='ISO, YMD';
SET LOCAL extra_float_digits=3;
DO $lease$ BEGIN
 IF current_user <> 'postgres' OR current_database() <> 'postgres' THEN
   RAISE EXCEPTION 'Local reset execution identity mismatch'; END IF;
 IF NOT pg_try_advisory_xact_lock(50405,1) THEN
   RAISE EXCEPTION 'Local fixture reset lease unavailable'; END IF;
END $lease$;
LOCK TABLE nba_corner_test_control.test_environment_identity IN ACCESS EXCLUSIVE MODE;
DO $identity$ BEGIN
 IF (SELECT count(*) FROM nba_corner_test_control.test_environment_identity) <> 1
 OR (SELECT jsonb_build_object({pairs}) FROM nba_corner_test_control.test_environment_identity)
 IS DISTINCT FROM {literal(marker)} THEN
   RAISE EXCEPTION 'Local marker changed before reset'; END IF;
 IF EXISTS (SELECT 1 FROM pg_constraint WHERE contype='f'
   AND confrelid IN ({','.join("'public."+t+"'::regclass" for t in TABLES)})
   AND conrelid NOT IN ({','.join("'public."+t+"'::regclass" for t in TABLES)})) THEN
   RAISE EXCEPTION 'Unexpected inbound reset dependency'; END IF;
END $identity$;
"""
    # Exact secured-schema verification is inside the same locked transaction.
    sql = prefix + baseline_body() + "\n"
    marker_verify = (
        (ROOT / "test-infrastructure/local-supabase/verify-fixture-marker-v2.sql")
        .read_text(encoding="utf-8")
        .replace("BEGIN READ ONLY;", "", 1)
        .rsplit("COMMIT;", 1)[0]
    )
    sql += marker_verify + "\n"
    sql += (
        "TRUNCATE TABLE "
        + ",".join("public." + t for t in TABLES)
        + " RESTART IDENTITY RESTRICT;\n"
    )
    sql += "UPDATE nba_corner_test_control.test_environment_identity SET fixture_state='UNSEEDED',fixture_version=NULL,fixture_checksum=NULL WHERE singleton;\n"
    for table in TABLES:
        if data[table]:
            sql += f"INSERT INTO public.{table} SELECT * FROM jsonb_populate_recordset(NULL::public.{table},{literal(data[table])});\n"
    sql += "SELECT setval('public.standings_id_seq',30,true);\n"
    # Both other owned sequences remain freshly restarted at (1,false).
    actual, expected = state_sql(), state_sql(data)
    sql += f"""DO $fixture_verify$ BEGIN
 IF ({actual}) IS DISTINCT FROM ({expected}) THEN
   RAISE EXCEPTION 'Complete fixture-state verification failed'; END IF;
END $fixture_verify$;
UPDATE nba_corner_test_control.test_environment_identity
 SET fixture_state='SEEDED',fixture_version='{VERSION}',fixture_checksum={digest_sql(actual)}
 WHERE singleton;
"""
    sql += baseline_body() + "\n" + marker_verify + "\n"
    sql += f"SELECT jsonb_build_object('fixture_version','{VERSION}','fixture_checksum',{digest_sql(actual)},'counts',jsonb_build_object({','.join(chr(39)+t+chr(39)+', (SELECT count(*) FROM public.'+t+')' for t in TABLES)}),'mutation_permitted',false);\nCOMMIT;\n"
    return sql.encode()


class LocalFixtureLease:
    """Fixed local psql session lease; no public arbitrary-SQL execution API."""

    def __init__(self, settings, *, allow_local_reset=False):
        self.allow_local_reset = allow_local_reset
        self.settings = dict(settings)
        self.active = False
        self.process = None
        self.lines = queue.Queue()

    def __enter__(self):
        preflight(self.settings, self.allow_local_reset)
        check_configuration()
        container_identity()
        self.process = subprocess.Popen(
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
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-At",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment(),
        )

        def drain():
            for line in self.process.stdout:
                if line.startswith(b"{"):
                    self.lines.put(line)
            self.lines.put(None)

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        try:
            result = self._exchange(
                b"SELECT jsonb_build_object('lease',pg_try_advisory_lock(50405,1));\n"
            )
            if result.get("lease") is not True:
                raise SafetyError("Exclusive local fixture lease unavailable.")
            self.active = True
            return self
        except BaseException:
            self.close()
            raise

    def _exchange(self, sql):
        if self.process is None or self.process.poll() is not None:
            raise SafetyError("Local lease session is unavailable.")
        try:
            self.process.stdin.write(sql)
            self.process.stdin.flush()
            line = self.lines.get(timeout=120)
            if line is None:
                raise SafetyError(
                    "Local lease transaction failed; sensitive diagnostics withheld."
                )
            return json.loads(line)
        except (OSError, ValueError, queue.Empty):
            raise SafetyError(
                "Local lease transport failed; recover with approved reset."
            ) from None

    def reset_foundation(self, marker):
        if not self.active:
            raise SafetyError("Active local lease required.")
        # Same DB session can acquire the transaction-level reset lock reentrantly.
        # A response is returned only AFTER COMMIT has completed.
        sql = reset_sql(marker)
        lines = sql.decode().splitlines(keepends=True)
        summary = next(
            line
            for line in lines
            if line.startswith("SELECT jsonb_build_object('fixture_version'")
        )
        sql = "".join(line for line in lines if line != summary).encode()
        # Canonical settings are transaction-local; reapply for the post-commit read.
        sql += b"BEGIN READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO, YMD'; SET LOCAL extra_float_digits=3;\n"
        sql += summary.encode() + b"COMMIT;\n"
        return self._exchange(sql)

    def close(self):
        self.active = False
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.stdin.write(
                        b"ROLLBACK; SELECT pg_advisory_unlock(50405,1);\n\\q\n"
                    )
                    self.process.stdin.flush()
                    self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=10)
            self.process.stdin.close()
            self.process.stdout.close()
            self.process = None

    def __exit__(self, *args):
        self.close()


def run_reset(settings, opt_in, *, lease=None):
    # Validate configuration before any docker/DB connection.
    marker = preflight(settings, opt_in)
    check_configuration()
    container_identity()
    sql = reset_sql(marker)
    # Re-authenticate marker immediately before entering the locked DB transaction.
    if preflight(settings, opt_in) != marker:
        raise SafetyError("Identity changed before reset.")
    container_identity()
    if lease is not None:
        if (
            type(lease) is not LocalFixtureLease
            or not lease.active
            or lease.settings != settings
        ):
            raise SafetyError("Verified matching local lease required.")
        proof = lease.reset_foundation(marker)
    else:
        result = subprocess.run(
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
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-At",
            ],
            input=sql,
            capture_output=True,
            env=child_environment(),
            timeout=120,
        )
        if result.returncode:
            raise SafetyError(
                "Local reset transaction failed; rolled back; SQL/credential-bearing diagnostics withheld."
            )
        rows = [
            json.loads(line)
            for line in result.stdout.decode().splitlines()
            if line.startswith("{")
        ]
        if len(rows) != 1:
            raise SafetyError(
                "Reset verification output missing; inspect local state before retrying."
            )
        proof = rows[0]
    current = verify_live_local_identity(settings)["marker"]
    if (
        current["fixture_state"] != "SEEDED"
        or current["fixture_version"] != proof["fixture_version"]
        or current["fixture_checksum"] != proof["fixture_checksum"]
    ):
        raise SafetyError("Committed fixture marker verification failed.")
    from email_transport import test_mailbox

    test_mailbox().clear()  # Current process only; no Flask process runs in this phase.
    return proof


def verify_fixture_readiness(settings):
    marker = preflight(settings, True)
    if marker["fixture_state"] != "SEEDED" or marker["fixture_version"] != VERSION:
        raise SafetyError("Seed/reset proof is not ready.")
    check_configuration()
    container_identity()
    actual, expected = state_sql(), state_sql(foundation())
    sql = f"BEGIN READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO, YMD'; SET LOCAL extra_float_digits=3; SELECT jsonb_build_object('matches',({actual})=({expected}),'checksum',{digest_sql(actual)}); COMMIT;"
    result = subprocess.run(
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
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
        ],
        input=sql.encode(),
        capture_output=True,
        env=child_environment(),
        timeout=30,
    )
    if result.returncode:
        raise SafetyError("Read-only fixture proof failed.")
    proof = json.loads(
        next(
            line for line in result.stdout.decode().splitlines() if line.startswith("{")
        )
    )
    if not proof["matches"] or proof["checksum"] != marker["fixture_checksum"]:
        raise SafetyError("Persisted fixture state has drifted.")
    return {
        "identity": "PASS",
        "marker": "PASS",
        "email": "PASS",
        "providers": "PASS",
        "jobs": "PASS",
        "fixture_reset": "PASS",
        "harness": "UNMET",
        "fixture_version": VERSION,
        "fixture_checksum": proof["checksum"],
        "mutation_permitted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--allow-local-reset", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        settings = load_test_config(args.config)
        result = (
            verify_fixture_readiness(settings)
            if args.verify_only
            else run_reset(settings, args.allow_local_reset)
        )
        print(json.dumps(result, indent=2))
        return 0
    except (SafetyError, OSError, ValueError, subprocess.TimeoutExpired):
        print(
            "REFUSED: local fixture safety/verification failed; sensitive diagnostics withheld.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
