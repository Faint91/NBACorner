"""Offline NC-04A schema-only comparison; no network, DB connection or execution."""

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def normalize(value):
    if value is None:
        return None
    return re.sub(
        r"\s+",
        " ",
        value.replace('"', "").replace("public.", "").replace("extensions.", ""),
    ).strip()


def compare(path):
    rows = list(csv.DictReader(Path(path).open(encoding="utf-8-sig")))
    assert len(rows) == 1 and set(rows[0]) == {"nc04a_catalog"}
    actual = json.loads(rows[0]["nc04a_catalog"])
    assert actual["read_only"] == "on"
    expected = json.loads(
        (ROOT / "db/baseline/manifest.json").read_text(encoding="utf-8")
    )["application"]
    differences = []

    def check(kind, name, a, b):
        if a != b:
            differences.append(dict(kind=kind, name=name, expected=b, actual=a))

    expected_columns = {
        (table, c["name"]): c
        for table, cols in expected["tables"].items()
        for c in cols
    }
    actual_columns = {(c["table"], c["name"]): c for c in actual["columns"]}
    check(
        "column_inventory", "public", sorted(actual_columns), sorted(expected_columns)
    )
    for key in expected_columns.keys() & actual_columns.keys():
        a, b = actual_columns[key], expected_columns[key]
        for field in ["type", "not_null", "default"]:
            check(
                "column_" + field,
                ".".join(key),
                normalize(a[field]) if isinstance(a[field], str) else a[field],
                normalize(b[field]) if isinstance(b[field], str) else b[field],
            )
    for kind, key, definition, sourcekey, sourcedef in [
        ("indexes", "indexname", "indexdef", "indexname", "indexdef"),
        ("constraints", "name", "definition", "constraint_name", "definition"),
        ("triggers", "name", "definition", "trigger_name", "trigger_definition"),
    ]:
        aa = {x[key]: normalize(x[definition]) for x in actual[kind]}
        bb = {x[sourcekey]: normalize(x[sourcedef]) for x in expected[kind]}
        check(kind + "_names", "public", sorted(aa), sorted(bb))
        for name in aa.keys() & bb.keys():
            av, bv = aa[name], bb[name]
            if kind == "constraints":
                av = re.sub(r"^CHECK \(\((.*)\)\)$", r"CHECK (\1)", av)
                bv = re.sub(r"^CHECK \(\((.*)\)\)$", r"CHECK (\1)", bv)
            check(kind + "_definition", name, av, bv)
    aa = {f["name"]: f for f in actual["functions"]}
    bb = {f["name"]: f for f in expected["functions"]}
    check("function_names", "public", sorted(aa), sorted(bb))
    for name in aa.keys() & bb.keys():
        a, b = aa[name], bb[name]
        for field in ["arguments", "result", "security_definer"]:
            check(
                "function_" + field,
                name,
                normalize(a[field]) if isinstance(a[field], str) else a[field],
                normalize(b[field]) if isinstance(b[field], str) else b[field],
            )
        body = re.sub(r"\s+", " ", b["body"].strip())
        # SQL btrim removes spaces, not boundary newlines. Preserve only this
        # documented lexical variability; interior normalized body must match.
        allowed = [
            hashlib.md5((l + body + r).encode()).hexdigest()
            for l in ["", " "]
            for r in ["", " "]
        ]
        check("function_body", name, a["body_normalized_md5"] in allowed, True)
        check("function_owner", name, a["owner"], "postgres")
        check("function_language", name, a["language"], "plpgsql")
        check("function_settings", name, a["settings"], None)
    check(
        "view",
        expected["view"]["viewname"],
        normalize(actual["views"][0]["definition"]),
        normalize(expected["view"]["definition"]),
    )
    aa = {(x["tablename"], x["policyname"]): x for x in actual["policies"]}
    bb = {(x["tablename"], x["policyname"]): x for x in expected["policies"]}
    check("policy_inventory", "public", sorted(aa), sorted(bb))
    for key in aa.keys() & bb.keys():
        a, b = aa[key], bb[key]
        for af, bf in [
            ("cmd", "cmd"),
            ("qual", "using_expression"),
            ("with_check", "with_check"),
            ("permissive", "permissive"),
        ]:
            check("policy_" + af, "/".join(key), normalize(a[af]), normalize(b[bf]))
        check(
            "policy_roles",
            "/".join(key),
            sorted(a["roles"]),
            sorted(b["roles"].strip("{}").split(",")),
        )
    return dict(
        mode="NC-04A READ-ONLY PREFLIGHT; offline metadata comparison",
        source_file_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        observed_at=actual["observed_at"],
        status="PASS" if not differences else "BLOCKED",
        differences=differences,
        counts={k: len(v) for k, v in actual.items() if isinstance(v, list)},
        known_release_migrations_present=[],
        release_migrations_pending=list(range(1, 12)),
        production_marker_table=actual["migration_marker"],
        canonical_table=actual["canonical_table"],
        app_schema_matches_secured_baseline=not differences,
        scope="Columns/defaults, constraints, indexes, triggers, policies, view and function definitions/modes/owners. Supplemental live SELECT covers ACL/sequence metadata. No product rows or credentials imported.",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-csv", required=True)
    args = parser.parse_args()
    result = compare(args.catalog_csv)
    (ROOT / "db/records/nc_04a_schema_comparison.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2))
