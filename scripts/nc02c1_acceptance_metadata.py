"""Convert only repaired season-source observations; retain prior metadata."""

NAMES = {
    "current_behavior__standings__season_sources",
    "current_behavior__standings__year",
    "current_behavior__bracket__timing",
}


def mark_acceptance(cls):
    for name in NAMES:
        if hasattr(cls, name):
            fn = getattr(cls, name)
            fn.metadata = convert(fn.metadata)


def convert(row):
    if row.get("scenario") not in NAMES or row.get("phase") == "NC-02C1":
        return row
    return {
        "scenario": row["scenario"],
        "phase": "NC-02C1",
        "classification": "APPROVED REQUIREMENT",
        "requirements": ["S1", "S2", "S12", "S14"],
        "previous_metadata": dict(row),
        "current_behavior": "Canonical database season, no independent environment/calendar selection; distinct opening/final-lock timing. Standings freeze enforcement remains deferred.",
    }
