"""Read-only NC-01 consolidated provenance/relationship validation; no app import."""

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LABELS = [
    "MATCHES REQUIREMENT",
    "KNOWN GAP",
    "REQUIREMENT NOT YET REVIEWED",
    "UNCLEAR / NEEDS BUSINESS CHECKPOINT",
]


def main():
    data = json.loads((ROOT / "db/records/nc_01_consolidated.json").read_text())
    rows = data["findings"]
    assert len(rows) == 155 and len({r["id"] for r in rows}) == len(rows)
    assert {k: Counter(r["classification"] for r in rows)[k] for k in LABELS} == data[
        "classification_totals"
    ]
    assert data["original_checkpoint_totals"] == dict(zip(LABELS, [17, 24, 113, 1]))
    assert data["classification_totals"] == dict(zip(LABELS, [17, 28, 109, 1]))
    lookup = {r["id"]: r for r in rows}
    req = {r["id"] for r in data["requirements"]}
    gaps = {g["id"] for g in data["canonical_gaps"]}
    assert len(req) == len(data["requirements"]) == 19
    assert len(gaps) == len(data["canonical_gaps"]) == 19
    assert len(data["classification_corrections"]) == 4
    observed_corrections = set()
    original_totals = Counter()
    source_files = []
    for m in data["source_manifest"]:
        for key in ["report", "evidence"]:
            p = ROOT / m[key]
            source_files.append(p)
            assert hashlib.sha256(p.read_bytes()).hexdigest() == m[key + "_sha256"]
        assert (ROOT / m["fixed_runner"]).is_file()
        current = json.loads((ROOT / m["evidence"]).read_text())
        original = json.loads(
            subprocess.check_output(
                [
                    "git",
                    "-c",
                    "safe.directory=" + str(ROOT).replace("\\", "/"),
                    "-C",
                    str(ROOT),
                    "show",
                    m["checkpoint_commit"] + ":" + m["evidence"],
                ],
                text=True,
                encoding="utf-8",
            )
        )
        original_totals.update(original["classification_counts"])
        assert current["classification_counts"] == m["current_classification_counts"]
        assert (
            original["classification_counts"] == m["checkpoint_classification_counts"]
        )
        assert len(original["findings"]) == len(current["findings"])
        counts = Counter(r["classification"] for r in current["findings"])
        assert all(counts[k] == v for k, v in current["classification_counts"].items())
        report = (ROOT / m["report"]).read_text(encoding="utf-8")
        for k, v in counts.items():
            assert k + "=" + str(v) in report
        for i, (a, b) in enumerate(zip(original["findings"], current["findings"])):
            allowed = {"classification", "approved_requirement", "classification_audit"}
            assert {k: v for k, v in a.items() if k not in allowed} == {
                k: v for k, v in b.items() if k not in allowed
            }
            row = next(
                r
                for r in rows
                if r["original_phase"] == m["phase"]
                and r["original_finding_id"] == b["scenario"]
            )
            assert (
                row["original_classification"] == a["classification"]
                and row["classification"] == b["classification"]
            )
            assert row["observed_current_behavior"] == a["current_behavior"]
            assert row["evidence_pointer"] == "/findings/" + str(i)
            if a["classification"] != b["classification"]:
                observed_corrections.add(row["id"])
                assert b["classification_audit"]["observations_changed"] is False
        for path in m["test_files"]:
            assert (ROOT / path).is_file()
    assert dict(original_totals) == data["original_checkpoint_totals"]
    assert observed_corrections == {
        r["finding_id"] for r in data["classification_corrections"]
    }
    for row in rows:
        assert row["evidence_type"] in {"LIVE", "OFFLINE", "STATIC"}
        test = row["test_reference"]
        tree = ast.parse((ROOT / test["file"]).read_text(encoding="utf-8"))
        assert any(
            isinstance(n, ast.FunctionDef)
            and n.name == test["name"]
            and n.lineno == test["line"]
            for n in ast.walk(tree)
        )
        assert row["classification_review"]["reviewed_in"] == "NC-01F"
        assert all(
            l["requirement_id"] in req for l in row["approved_requirement_links"]
        )
        assert all(g in gaps for g in row["gap_ids"])
        if row["classification"] in LABELS[:2]:
            assert row["approved_requirement_links"]
        if row["classification"] == LABELS[1]:
            assert row["gap_ids"]
    for gap in data["canonical_gaps"]:
        assert gap["approved_requirement_id"] in req
        assert gap["source_finding_ids"] and gap["regression_tests"]
        for fid in gap["source_finding_ids"]:
            row = lookup[fid]
            assert row["classification"] == LABELS[1] and gap["id"] in row["gap_ids"]
            assert any(
                l["requirement_id"] == gap["approved_requirement_id"]
                and l["relationship"] == LABELS[1]
                for l in row["approved_requirement_links"]
            )
    for coverage in data["requirement_coverage"]:
        assert coverage["requirement_id"] in req
        for k in ["matching_findings", "gap_findings", "other_findings"]:
            assert all(fid in lookup for fid in coverage[k])
        if coverage["gap_findings"]:
            assert coverage["assessment"] != "FULLY MATCHES OBSERVED"
    assert {
        fid
        for q in data["unreviewed_question_registry"]
        for fid in q["source_findings"]
    } == {r["id"] for r in rows if r["classification"] == LABELS[2]}
    assert len(data["unclear_findings"]) == 1
    assert len(data["regression_inventory"]) == 155
    assert {r["finding_id"] for r in data["regression_inventory"]} == set(lookup)
    assert {g for p in data["proposed_repair_order"] for g in p["gap_ids"]} == gaps
    assert all(v == "PASS" for v in data["completion_criteria"].values())
    assert data["canonical_environment"]["readiness"]["jobs_enabled"] is False
    assert (
        not any(data["production"].values()) and not data["business_behavior_changed"]
    )
    # Scan generated/source evidence, not this validator's regex literals.
    blob = (
        (ROOT / "db/records/nc_01_consolidated.json").read_bytes()
        + (ROOT / "docs/characterization/nc-01-consolidated-baseline.md").read_bytes()
        + b"".join(p.read_bytes() for p in source_files)
    )
    for pattern in [
        rb"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        rb"-----BEGIN .*PRIVATE KEY",
        rb"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}",
    ]:
        assert not re.search(pattern, blob), "Sensitive credential pattern found"
    print(
        "PASS: 155 source rows, 19 requirements, 19 canonical gaps, four explicit corrections; all provenance/test/relationship/secret checks passed."
    )


if __name__ == "__main__":
    main()
