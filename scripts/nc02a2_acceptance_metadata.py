"""NC-02A2 deliberate expectation transitions; historical evidence stays immutable."""

TRANSITIONS = [
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__game_count_values",
        "source_finding_id": "NC-01B:current_behavior__bracket__game_count_values",
        "gap_ids": ["GAP-RESAVE-001"],
        "requirement_ids": ["REQ-BRACKET-RESAVE-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__games_only_saved_edit",
        "source_finding_id": "NC-01B:current_behavior__bracket__games_only_saved_edit",
        "gap_ids": ["GAP-RESAVE-001"],
        "requirement_ids": ["REQ-BRACKET-EDIT-001", "REQ-BRACKET-RESAVE-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__save_edit_resubmit",
        "source_finding_id": "NC-01B:current_behavior__bracket__save_edit_resubmit",
        "gap_ids": [],
        "requirement_ids": ["REQ-BRACKET-EDIT-001", "REQ-BRACKET-RESAVE-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__undo_graph",
        "source_finding_id": "NC-01B:current_behavior__bracket__undo_graph",
        "gap_ids": [],
        "requirement_ids": [],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/league_static.py",
        "name": "current_behavior__league__frontend_leaderboard",
        "source_finding_id": "NC-01C:current_behavior__league__frontend_leaderboard",
        "gap_ids": ["GAP-PRIVATE-SCORES-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__draft_scored_leaderboard",
        "source_finding_id": "NC-01C:current_behavior__league__draft_scored_leaderboard",
        "gap_ids": ["GAP-DRAFT-SCORES-001"],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/scoring_live.py",
        "name": "current_behavior__scoring__draft",
        "source_finding_id": "NC-01D:current_behavior__scoring__draft",
        "gap_ids": ["GAP-DRAFT-SCORES-001"],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
    {
        "file": "tests/characterization/scoring_static.py",
        "name": "current_behavior__scoring__league_surface",
        "source_finding_id": "NC-01D:current_behavior__scoring__league_surface",
        "gap_ids": ["GAP-PRIVATE-SCORES-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "phase_requirements": ["P4", "P5", "P9"],
    },
]


def mark_acceptance(test_class):
    for item in TRANSITIONS:
        fn = getattr(test_class, item["name"], None)
        if fn is None:
            continue
        prior = dict(fn.metadata)
        fn.metadata.update(
            classification="APPROVED REQUIREMENT",
            repair_phase="NC-02A2",
            approved_requirement_ids=item["requirement_ids"],
            phase_requirements=item["phase_requirements"],
            canonical_gap_ids=item["gap_ids"],
            provenance=item,
            pre_NC02A2_metadata=prior,
            current_behavior="NC-02A2 saved-state/competitive-eligibility acceptance; unrelated mixed-row behavior retained",
        )
