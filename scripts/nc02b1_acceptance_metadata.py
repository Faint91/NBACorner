"""Approved NC-02B1 transitions; original NC-01/NC-02A2 evidence is immutable."""

TRANSITIONS = {
    "current_behavior__bracket__admin_arbitrary_mutations": ["GAP-ADMIN-MUTATE-001"],
    "current_behavior__bracket__postlock_content": ["GAP-LOCK-BACKEND-001"],
    "current_behavior__bracket__frontend_undo": ["GAP-UNDO-FRONTEND-001"],
    "current_behavior__bracket__frontend_lock": ["GAP-LOCK-FRONTEND-001"],
    "current_behavior__bracket__frontend_controls": ["GAP-LOCK-FRONTEND-001"],
    "current_behavior__bracket__frontend_creation": ["GAP-LOCK-FRONTEND-001"],
    "current_behavior__bracket__timing": ["GAP-LOCK-BACKEND-001"],
    "test_postlock_edits_still_allowed_but_all_invalidate": ["GAP-LOCK-BACKEND-001"],
    "test_admin_mutation_authorization_unchanged_invalidation_shared": [
        "GAP-ADMIN-MUTATE-001"
    ],
}


def mark_acceptance(cls):
    for name, gaps in TRANSITIONS.items():
        fn = getattr(cls, name, None)
        if fn is None:
            continue
        previous = dict(fn.metadata)
        fn.metadata = {
            "scenario": name,
            "phase": "NC-02B1",
            "classification": "APPROVED REQUIREMENT",
            "requirements": ["B1", "B2", "B3", "B4", "B5", "B16"],
            "source_finding_id": (
                "NC-01B:" if name.startswith("current_behavior") else "NC-02A2:"
            )
            + name,
            "gap_ids": gaps,
            "previous_metadata": previous,
            "current_behavior": "Content lock/owner/master authorization acceptance; deletion and lifecycle remain deferred.",
        }
