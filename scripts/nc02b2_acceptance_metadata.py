"""NC-02B2 expectation conversions; original historical reports stay unchanged."""

NAMES = {
    "prediction_validation",
    "game_count_values",
    "winner_change_graph",
    "undo_graph",
    "partial_graph_save",
    "save_completeness_static",
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
                "phase": "NC-02B2",
                "classification": "APPROVED REQUIREMENT",
                "requirements": ["B6", "B7", "B8", "B9"],
                "source_finding_id": "NC-01B:" + name,
                "previous_metadata": dict(fn.metadata),
                "current_behavior": "Approved validity and dependency acceptance; prior NC-01 observations preserved as provenance.",
            }
