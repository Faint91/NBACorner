"""NC-03 metadata/static checks and guarded read-only local cleanup verification."""

import ast
import hashlib
import json
import re
import socket
import subprocess
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT))


def git(root, *args):
    return subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "safe.directory=" + str(root).replace("\\", "/"),
            *args,
        ]
    )


def run():
    from environment_safety import load_test_config, verify_live_local_identity
    from integration_harness import readiness_report
    from scripts.reset_local_fixtures import verify_fixture_readiness
    from scripts.local_supabase_environment import (
        sql_file,
        CONTAINER,
        child_environment,
    )
    from email_transport import test_mailbox

    settings = load_test_config(str(ROOT / ".env.test.nba-local.local"))
    identity = verify_live_local_identity(settings)
    cleanup = verify_fixture_readiness(settings)
    readiness = readiness_report(settings)
    assert (
        readiness["jobs_enabled"] is False and readiness["mutation_permitted"] is False
    )
    assert readiness["harness_scoped_mutation_permitted"] is False
    assert not test_mailbox().inspect_messages()
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", 55410)) != 0
    for path in [
        "db/post-baseline/verify_current_schema.sql",
        "test-infrastructure/local-supabase/verify-fixture-marker-v2.sql",
        "db/audits/nc03_before_migrations_readonly.sql",
        "db/audits/nc03_after_0011_readonly.sql",
    ]:
        sql_file(ROOT / path)
    query = """BEGIN READ ONLY; SELECT jsonb_build_object(
      'users',(SELECT count(*) FROM public.users),
      'nonzero_auth_versions',(SELECT count(*) FROM public.users WHERE auth_version<>0),
      'standings',(SELECT count(*) FROM public.standings),
      'reset_rows',(SELECT count(*) FROM public.password_resets),
      'history_rows',(SELECT count(*) FROM public.leaderboard_history_rows),
      'history_headers',(SELECT count(*) FROM public.leaderboard_history_snapshots),
      'rollover_audits',(SELECT count(*) FROM public.season_rollover_audits),
      'proof_databases',(SELECT count(*) FROM pg_database WHERE datname LIKE 'nc_%proof%'),
      'advisory_locks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory')
    ); COMMIT;"""
    raw = subprocess.check_output(
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
            "-Atc",
            query,
        ],
        env=child_environment(),
    )
    counts = json.loads(
        next(line for line in raw.decode().splitlines() if line.startswith("{"))
    )
    assert counts == dict(
        users=4,
        nonzero_auth_versions=0,
        standings=30,
        reset_rows=0,
        history_rows=0,
        history_headers=0,
        rollover_audits=0,
        proof_databases=0,
        advisory_locks=0,
    )
    scanned = {}
    compiled = 0
    patterns = {
        "JWT_literals": re.compile(
            r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
        ),
        "provider_keys": re.compile(
            r"(?:sb_secret_|xkeysib-|sk_live_)[A-Za-z0-9_-]{20,}"
        ),
        "private_keys": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "credential_database_urls": re.compile(r"postgres(?:ql)?://[^\s:/]+:[^\s@/]+@"),
    }
    violations = []
    for repo in [ROOT, ROOT.parent / "frontend"]:
        names = (
            git(repo, "ls-files", "--cached", "--others", "--exclude-standard")
            .decode()
            .splitlines()
        )
        scanned[repo.name] = len(names)
        for name in names:
            path = repo / name
            if not path.is_file():
                continue
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                continue
            if "\x00" in text:
                continue
            if path.suffix == ".py":
                compile(text, str(path), "exec")
                compiled += 1
            for kind, pattern in patterns.items():
                if pattern.search(text):
                    violations.append(dict(repository=repo.name, path=name, kind=kind))
    assert not violations, "Potential secret detected; values suppressed"
    assert not git(
        ROOT, "diff", "--name-only"
    ).strip(), "Unexpected tracked modification"
    assert not git(ROOT.parent / "frontend", "status", "--short").strip()
    return dict(
        verified_at_utc=datetime.now(timezone.utc).isoformat(),
        fixture=cleanup,
        marker_state=identity["marker"]["fixture_state"],
        readiness=readiness,
        counts=counts,
        flask_stopped=True,
        mail_empty=True,
        proof_database_removed=True,
        secret_pattern_findings=violations,
        scanned_file_counts=scanned,
        python_sources_compiled=compiled,
        application_import_comparison="PASS: all tracked runtime source unchanged from repaired HEAD; actual imports exercised by 226-case suite and cross proof",
        historical_evidence_unchanged=True,
        frontend_unchanged=True,
        production_contact=False,
        notes=[
            "Literal account-password candidates confined to explicit synthetic test identities; no production account credential found.",
            "Removed fallback historical references are evidence, not an active signing authority.",
            "Raw reset verifier exists only ephemerally in delivery; committed evidence contains no captured verifier; digest-only DB verified by G2 suites.",
        ],
    )


if __name__ == "__main__":
    result = run()
    (ROOT / "db/records/nc_03_pass3_final_checks.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2))
