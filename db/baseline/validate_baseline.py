"""Offline lexical/evidence validation only: no DB/network/application imports."""

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

PREFIXES = (
    "CREATE OR REPLACE FUNCTION",
    "CREATE TABLE",
    "CREATE OR REPLACE VIEW",
    "CREATE SEQUENCE",
    "CREATE INDEX",
    "CREATE UNIQUE INDEX",
    "CREATE OR REPLACE TRIGGER",
    "CREATE POLICY",
    "ALTER FUNCTION",
    "ALTER TABLE",
    "ALTER SEQUENCE",
)
TRANSFORMS = (
    ("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION"),
    ("CREATE OR REPLACE VIEW", "CREATE VIEW"),
    ("CREATE OR REPLACE TRIGGER", "CREATE TRIGGER"),
    ("CREATE TABLE IF NOT EXISTS", "CREATE TABLE"),
    ("CREATE SEQUENCE IF NOT EXISTS", "CREATE SEQUENCE"),
)
START = "-- Application DDL preserved from NC-00 audit.\n"
END = "-- Current secured ACLs.\n"


def split_sql(s):
    """Recognize quotes/dollar bodies/comments; not a PostgreSQL grammar parser."""
    result = []
    start = i = 0
    quote = dollar = None
    line = False
    block = 0
    while i < len(s):
        if line:
            if s[i] == "\n":
                line = False
            i += 1
            continue
        if block:
            if s[i : i + 2] == "/*":
                block += 1
                i += 2
            elif s[i : i + 2] == "*/":
                block -= 1
                i += 2
            else:
                i += 1
            continue
        if dollar:
            if s.startswith(dollar, i):
                i += len(dollar)
                dollar = None
            else:
                i += 1
            continue
        if quote:
            if s[i] == quote:
                if s[i : i + 2] == quote * 2:
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if s[i : i + 2] == "--":
            line = True
            i += 2
            continue
        if s[i : i + 2] == "/*":
            block = 1
            i += 2
            continue
        if s[i] in "'\"":
            quote = s[i]
            i += 1
            continue
        m = re.match(r"\$[A-Za-z_0-9]*\$", s[i:])
        if m:
            dollar = m.group()
            i += len(dollar)
            continue
        if s[i] == ";":
            result.append(s[start : i + 1].strip())
            start = i + 1
        i += 1
    if quote or dollar or block:
        raise ValueError("Unterminated SQL lexical construct")
    tail = s[start:].strip()
    if tail and not all(
        not x.strip() or x.strip().startswith("--") for x in tail.splitlines()
    ):
        raise ValueError("Unterminated SQL statement")
    return result


def audit_ddl(source):
    result = []
    for s in split_sql(source):
        if s.startswith(PREFIXES):
            for old, new in TRANSFORMS:
                s = s.replace(old, new, 1)
            result.append(s)
    return result


def decoded(s):
    value = s.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    return re.sub(r"\r+\n", "\n", value).replace("\r", "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", type=Path)
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    record = json.loads((base / "provenance.json").read_text(encoding="utf-8"))
    for name, digest in record["artifact_sha256"].items():
        assert (
            hashlib.sha256((base / name).read_bytes()).hexdigest() == digest
        ), f"Artifact checksum: {name}"
    for name, digest in record["security_evidence_sha256"].items():
        assert (
            hashlib.sha256((base.parent.parent / name).read_bytes()).hexdigest()
            == digest
        ), f"Security evidence: {name}"
    sql = (base / "000_current_schema.sql").read_text(encoding="utf-8")
    verifier = (base / "verify_current_schema.sql").read_text(encoding="utf-8")
    split_sql(sql)
    split_sql(verifier)
    body = (
        "DO $baseline_verify$"
        + verifier.split("DO $baseline_verify$", 1)[1].split("$baseline_verify$;", 1)[0]
        + "$baseline_verify$;"
    )
    assert body in sql, "Embedded/standalone verifier mismatch"
    assert "BEGIN READ ONLY;" in verifier
    assert "DROP " not in sql.upper()
    assert not re.search(r"ALTER DEFAULT PRIVILEGES[^;]+ON FUNCTIONS", sql, re.I)
    assert not re.search(
        r"(?:https?://|supabase\.co|postgres(?:ql)?://|eyJ[A-Za-z0-9_-]{20,}|sb_secret_|password\s*=)",
        sql,
        re.I,
    )
    assert "CREATE SCHEMA" not in sql and "CREATE EXTENSION" not in sql
    application = sql.split(START, 1)[1].split(END, 1)[0].strip()
    ddl = split_sql(application)
    assert all(
        not s.startswith("CREATE OR REPLACE")
        and not s.startswith(
            ("CREATE TABLE IF NOT EXISTS", "CREATE SEQUENCE IF NOT EXISTS")
        )
        for s in ddl
    )
    assert (
        hashlib.sha256(application.encode()).hexdigest()
        == record["application_ddl_sha256"]
    )
    app = manifest["application"]
    for prefix, expected in [
        ("CREATE TABLE", len(app["tables"])),
        ("CREATE SEQUENCE", len(app["sequences"])),
        ("CREATE FUNCTION", len(app["functions"])),
        ("CREATE VIEW", 1),
        ("CREATE TRIGGER", len(app["triggers"])),
        ("CREATE POLICY", len(app["policies"])),
    ]:
        assert sum(s.startswith(prefix) for s in ddl) == expected, prefix
    assert sql.index(END) < sql.index(body) < sql.rindex("COMMIT;")
    for f in app["functions"]:
        revoke = (
            f"REVOKE ALL ON FUNCTION {f['signature']} FROM PUBLIC, anon, authenticated;"
        )
        if f["trigger_only"]:
            assert (
                revoke not in sql
            ), "Audited trigger ACL must not receive blanket RPC revocation"
        else:
            assert revoke in sql
        roles = (
            "PUBLIC, postgres, anon, authenticated, service_role"
            if f["trigger_only"]
            else "postgres, service_role"
        )
        assert f"GRANT EXECUTE ON FUNCTION {f['signature']} TO {roles};" in sql
        stmt = next(
            s for s in ddl if s.startswith(f'CREATE FUNCTION "public"."{f["name"]}"(')
        )
        assert (
            re.search(r"AS (\$[A-Za-z_]*\$)(.*?)\1", stmt, re.S).group(2).strip()
            == f["body"]
        ), f"Function body: {f['name']}"
    for kind, names in [
        ("TABLE", list(app["tables"]) + ["bracket_view"]),
        ("SEQUENCE", [s["name"] for s in app["sequences"]]),
    ]:
        for name in names:
            assert (
                f"REVOKE ALL ON {kind} public.{name} FROM PUBLIC, anon, authenticated;"
                in sql
            )
            assert (
                f"GRANT ALL ON {kind} public.{name} TO postgres, service_role;" in sql
            )
    for kind in ["TABLES", "SEQUENCES"]:
        assert (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON {kind} FROM PUBLIC, anon, authenticated;"
            in sql
        )
        assert (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON {kind} TO postgres, service_role;"
            in sql
        )
    assert not re.search(
        r"^\s*(INSERT INTO|COPY|DELETE FROM|UPDATE)\b",
        "\n".join(s for s in ddl if not s.startswith("CREATE FUNCTION")),
        re.M | re.I,
    )
    last_table = max(i for i, s in enumerate(ddl) if s.startswith("CREATE TABLE"))
    assert all(
        i > last_table
        for i, s in enumerate(ddl)
        if "FOREIGN KEY" in s or s.startswith("CREATE POLICY")
    )
    for seq in app["sequences"]:
        create = next(
            i
            for i, s in enumerate(ddl)
            if s.startswith(f'CREATE SEQUENCE "public"."{seq["name"]}"')
        )
        own = next(
            i
            for i, s in enumerate(ddl)
            if s.startswith(f'ALTER SEQUENCE "public"."{seq["name"]}" OWNED BY')
        )
        assert create < own
    if args.audit_dir:
        for name, digest in record["audit_sha256"].items():
            assert (
                hashlib.sha256((args.audit_dir / name).read_bytes()).hexdigest()
                == digest
            ), f"Audit checksum: {name}"
        assert ddl == audit_ddl(
            (args.audit_dir / "nbacorner_schema.sql").read_text(encoding="utf-8")
        ), "Source DDL mismatch"
        for collection in ["constraints", "indexes", "triggers"]:
            rows = list(
                csv.DictReader(
                    (args.audit_dir / f"nbacorner_{collection}.csv").open(
                        encoding="utf-8-sig", newline=""
                    )
                )
            )
            assert rows == app[collection], f"Audit reconciliation: {collection}"
        policy_rows = list(
            csv.DictReader(
                (args.audit_dir / "nbacorner_policies.csv").open(
                    encoding="utf-8-sig", newline=""
                )
            )
        )
        for row in policy_rows:
            for key in ["using_expression", "with_check"]:
                row[key] = None if row[key] == "null" else decoded(row[key])
        assert app["policies"] == policy_rows, "Policy reconciliation"
        view_row = next(
            csv.DictReader(
                (args.audit_dir / "nbacorner_views.csv").open(
                    encoding="utf-8-sig", newline=""
                )
            )
        )
        view_row["definition"] = decoded(view_row["definition"])
        assert app["view"] == view_row, "View reconciliation"
        rls_rows = list(
            csv.DictReader(
                (args.audit_dir / "nbacorner_rls.csv").open(
                    encoding="utf-8-sig", newline=""
                )
            )
        )
        expected_rls = {
            r["table_name"]: {
                "enabled": r["rls_enabled"] == "true",
                "forced": r["rls_forced"] == "true",
            }
            for r in rls_rows
        }
        assert app["rls"] == expected_rls, "RLS reconciliation"
        function_rows = [
            r
            for r in csv.DictReader(
                (args.audit_dir / "nbacorner_functions.csv").open(
                    encoding="utf-8-sig", newline=""
                )
            )
            if r["language"] == "plpgsql"
        ]
        assert [f["name"] for f in app["functions"]] == [
            r["function_name"] for r in function_rows
        ], "Application/extension function boundary"
        for function, row in zip(app["functions"], function_rows):
            definition = decoded(row["definition"])
            expected_body = (
                re.search(r"AS (\$[A-Za-z_]*\$)(.*?)\1", definition, re.S)
                .group(2)
                .strip()
            )
            assert function["body"] == expected_body, "Audit function body"
            assert (
                function["identity_arguments"] == row["arguments"]
            ), "Audit function identity"
            assert function["result"] == row["return_type"], "Audit return type"
            assert function["security_definer"] == (
                row["security_definer"] == "true"
            ), "Audit security mode"
        constraint_names = re.findall(r'CONSTRAINT "([^"\n]+)"', application)
        assert sorted(constraint_names) == sorted(
            r["constraint_name"] for r in app["constraints"]
        ), "Constraint name/count reconciliation"
        explicit_indexes = re.findall(
            r'CREATE (?:UNIQUE )?INDEX "([^"\n]+)"', application
        )
        backing_indexes = [
            r["constraint_name"]
            for r in app["constraints"]
            if r["constraint_type"] in ["p", "u"]
        ]
        assert sorted(explicit_indexes + backing_indexes) == sorted(
            r["indexname"] for r in app["indexes"]
        ), "Explicit plus constraint-backed index reconciliation"
    print(
        "PASS: lexical statements, source DDL/body evidence, ACL rules, dependency ordering, portability, checksums"
    )
    print(
        "NOT PARSED / NOT EXECUTED: PostgreSQL grammar/live bootstrap deferred to NC-ENV-03"
    )


if __name__ == "__main__":
    main()
