"""Offline NC-04A export verification. Never connects to a DB, app or provider."""

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bracket_rules import dependency_edges, submission_error


def read_export(path):
    rows = list(csv.DictReader(Path(path).open(encoding="utf-8-sig")))
    if len(rows) != 1 or set(rows[0]) != {"evidence"}:
        raise ValueError("Expected one safe evidence result")
    value = json.loads(rows[0]["evidence"])
    if value.get("read_only") != "on":
        raise ValueError("Explicit READ ONLY observation required")
    return value


def verify(catalog_path, data_path, acl_path):
    catalog, data, acl = map(read_export, (catalog_path, data_path, acl_path))
    manifest = json.loads(
        (ROOT / "db/baseline/manifest.json").read_text(encoding="utf-8")
    )["application"]
    checks = {}
    checks["all_transactions_read_only"] = all(
        x["read_only"] == "on" for x in (catalog, data, acl)
    )
    checks["reader_identity"] = (
        catalog["reader"] == "postgres" and catalog["database"] == "postgres"
    )
    for key in (
        "effective_browser_relation_grants",
        "effective_browser_sequence_grants",
        "effective_browser_mutation_rpc_grants",
    ):
        checks[key + "_zero"] = acl[key] == 0
    checks["no_column_grants"] = catalog["column_acls"] is None
    checks["no_browser_schema_create"] = not any(
        catalog["browser_schema_create"].values()
    )
    checks["relations_trusted_only"] = all(
        x["acl"]
        and all(
            y.split("=")[0] in {"postgres", "service_role"}
            for y in x["acl"].strip("{}").split(",")
        )
        for x in catalog["relations"]
    )
    checks["three_owned_sequences"] = len(catalog["sequences"]) == 3 and all(
        x["owner"] == "postgres" and len(x["owned_by"]) == 1
        for x in catalog["sequences"]
    )
    functions = [x for x in catalog["functions"] if x["owner"] == "postgres"]
    expected_functions = manifest["functions"]
    checks["app_function_inventory"] = {x["name"] for x in functions} == {
        x["name"] for x in expected_functions
    }
    checks["app_function_bodies_unchanged"] = all(
        next(x["body_md5"] for x in functions if x["name"] == f["name"])
        == hashlib.md5(re.sub(r"\s+", " ", f["body"]).strip().encode()).hexdigest()
        for f in expected_functions
    )
    old_policies = json.loads(
        (ROOT / "db/records/nc_04a_production_catalog.json").read_text(encoding="utf-8")
    )["policies"]

    def policy_key(p):
        return (p["tablename"], p["policyname"])

    def normalized_policy(p):
        return {
            k: re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else v
            for k, v in p.items()
            if k != "schemaname"
        }

    checks["policies_unchanged"] = sorted(
        map(normalized_policy, acl["policies"]), key=policy_key
    ) == sorted(map(normalized_policy, old_policies), key=policy_key)
    for group in ("identity", "leagues", "lifecycle", "history"):
        checks[group + "_zero_findings"] = all(x == 0 for x in data[group].values())
    checks["no_release_object_collision"] = (
        data["collision_objects"] is None and catalog["rollover_objects"] is None
    )
    checks["no_auth_version_collision"] = catalog["auth_version_columns"] == 0
    checks["no_live_rollover_observed"] = (
        catalog["advisory_locks"] == 0 and catalog["active_rollover_queries"] == 0
    )
    checks["standings_seed_uniqueness"] = (
        data["standings"]["conference_seed_duplicates"] == 0
    )
    checks["no_pg_cron_extension"] = not any(
        x["name"] == "pg_cron" for x in acl["extensions"]
    )
    graphs = catalog.pop("master_graphs")
    checks["single_master"] = len(graphs) == 1
    graph = graphs[0]
    matches = graph["matches"]
    checks["master_identity_admin"] = (
        graph["admin"] is True
        and graph["is_master"] is True
        and not graph["deleted"]
        and graph["pointer"] == graph["bracket"]
    )
    checks["master_complete_valid_graph"] = (
        len(matches) == 21
        and submission_error(matches, master=True) is None
        and submission_error(matches) is None
    )
    summary = {k: v for k, v in graph.items() if k != "matches"}
    summary.update(
        match_count=len(matches),
        edge_count=sum(map(len, dependency_edges(matches).values())),
        graph_sha256=hashlib.sha256(
            json.dumps(matches, sort_keys=True).encode()
        ).hexdigest(),
        master_validation_error=submission_error(matches, master=True),
        complete_graph_validation_error=submission_error(matches),
    )
    return dict(
        mode="OFFLINE VERIFICATION OF EXPLICIT READ ONLY EXPORTS",
        status="PASS" if all(checks.values()) else "BLOCKED",
        checks=checks,
        check_count=len(checks),
        source_sha256={
            label: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for label, path in zip(
                ("catalog", "data", "acl"), (catalog_path, data_path, acl_path)
            )
        },
        catalog=catalog,
        data=data,
        security=acl,
        master_summary=summary,
        production_writes=0,
        no_credentials_or_product_identity_payloads=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog")
    parser.add_argument("data")
    parser.add_argument("acl")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.catalog, args.data, args.acl)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                k: result[k]
                for k in ("status", "check_count", "checks", "master_summary")
            }
        )
    )
    raise SystemExit(0 if result["status"] == "PASS" else 1)
