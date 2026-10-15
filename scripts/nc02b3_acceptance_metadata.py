"""Explicit B10–B15 conversions; immutable prior evidence is retained."""

NAMES = {
    "historical_creation_constraint",
    "admin_creation_bypass",
    "master_replacement",
    "admin_arbitrary_mutations",
    "delete_recreate",
    "master_delete",
    "historical_boundaries",
    "triggers_rpc",
    "timing",
    "frontend_creation",
    "schema_constraints",
}


def mark_acceptance(cls):
    for name in dir(cls):
        if (
            name.startswith("current_behavior__bracket__")
            and name.removeprefix("current_behavior__bracket__") in NAMES
        ):
            fn = getattr(cls, name)
            fn.metadata = {
                "scenario": name,
                "phase": "NC-02B3",
                "classification": "APPROVED REQUIREMENT",
                "requirements": ["B10", "B11", "B12", "B13", "B14", "B15"],
                "source_finding_id": "NC-01B:" + name,
                "previous_metadata": dict(fn.metadata),
                "current_behavior": "Approved lifecycle/season/master/history acceptance; earlier observations retained as provenance.",
            }
