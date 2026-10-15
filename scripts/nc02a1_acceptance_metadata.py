"""Explicit NC-01 -> NC-02A1 test provenance; no historical evidence rewriting."""

CONVERSIONS = [
    {
        "file": "tests/characterization/auth_access.py",
        "name": "current_behavior__auth__cross_user_draft_boundary",
        "source_finding_id": "NC-01A:current_behavior__auth__cross_user_draft_boundary",
        "gap_ids": ["GAP-ADMIN-DRAFT-001"],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/auth_access.py",
        "name": "current_behavior__auth__cross_user_saved_owner_display",
        "source_finding_id": "NC-01A:current_behavior__auth__cross_user_saved_owner_display",
        "gap_ids": ["GAP-EMAIL-001"],
        "requirement_ids": ["REQ-PRIVACY-EMAIL-001", "REQ-BRACKET-SAVED-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/auth_static.py",
        "name": "current_behavior__auth__display_fields_static",
        "source_finding_id": "NC-01A:current_behavior__auth__display_fields_static",
        "gap_ids": ["GAP-EMAIL-001"],
        "requirement_ids": ["REQ-PRIVACY-EMAIL-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__admin_draft_visibility",
        "source_finding_id": "NC-01B:current_behavior__bracket__admin_draft_visibility",
        "gap_ids": ["GAP-ADMIN-DRAFT-001"],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/bracket_access.py",
        "name": "current_behavior__bracket__email_serialization",
        "source_finding_id": "NC-01B:current_behavior__bracket__email_serialization",
        "gap_ids": ["GAP-EMAIL-001"],
        "requirement_ids": ["REQ-PRIVACY-EMAIL-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__admin_private_bracket",
        "source_finding_id": "NC-01C:current_behavior__league__admin_private_bracket",
        "gap_ids": ["GAP-PRIVATE-MEMBERS-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__draft_saved_visibility",
        "source_finding_id": "NC-01C:current_behavior__league__draft_saved_visibility",
        "gap_ids": [],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__leaderboard_private_surface",
        "source_finding_id": "NC-01C:current_behavior__league__leaderboard_private_surface",
        "gap_ids": ["GAP-PRIVATE-SCORES-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__member_email",
        "source_finding_id": "NC-01C:current_behavior__league__member_email",
        "gap_ids": ["GAP-EMAIL-001"],
        "requirement_ids": ["REQ-PRIVACY-EMAIL-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__own_list_hash_surface",
        "source_finding_id": "NC-01C:current_behavior__league__own_list_hash_surface",
        "gap_ids": [],
        "requirement_ids": ["NC-02A1-P8"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__owner_not_member",
        "source_finding_id": "NC-01C:current_behavior__league__owner_not_member",
        "gap_ids": ["GAP-PRIVATE-MEMBERS-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__private_bracket_bypass",
        "source_finding_id": "NC-01C:current_behavior__league__private_bracket_bypass",
        "gap_ids": ["GAP-PRIVATE-LIST-001", "GAP-PRIVATE-DETAIL-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__stats_admin_bypass",
        "source_finding_id": "NC-01C:current_behavior__league__stats_admin_bypass",
        "gap_ids": ["GAP-PRIVATE-STATS-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_static.py",
        "name": "current_behavior__league__frontend_leaderboard",
        "source_finding_id": "NC-01C:current_behavior__league__frontend_leaderboard",
        "gap_ids": ["GAP-PRIVATE-SCORES-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
    {
        "file": "tests/characterization/league_access.py",
        "name": "current_behavior__league__draft_scored_leaderboard",
        "source_finding_id": "NC-01C:current_behavior__league__draft_scored_leaderboard",
        "gap_ids": ["GAP-DRAFT-SCORES-001"],
        "requirement_ids": ["REQ-BRACKET-SAVED-001"],
        "disposition": "KNOWN-GAP retained: P4/P5 now observed via unscoped global leaderboard; private scoped access covered separately",
    },
    {
        "file": "tests/characterization/scoring_static.py",
        "name": "current_behavior__scoring__league_surface",
        "source_finding_id": "NC-01D:current_behavior__scoring__league_surface",
        "gap_ids": ["GAP-PRIVATE-SCORES-001"],
        "requirement_ids": ["REQ-LEAGUE-PRIVATE-001"],
        "disposition": "APPROVED REQUIREMENT acceptance (NC-02A1); prior NC-01 evidence remains immutable",
    },
]


def mark_acceptance(test_class):
    for item in CONVERSIONS:
        fn = getattr(test_class, item["name"], None)
        if fn is None:
            continue
        original = dict(fn.metadata)
        fn.metadata.update(
            repair_phase="NC-02A1",
            provenance=item,
            approved_requirement_ids=item["requirement_ids"],
            canonical_gap_ids=item["gap_ids"],
            pre_repair_metadata=original,
            phase_requirements=["P1", "P2", "P3", "P6", "P7", "P8", "P10"],
            classification=(
                "KNOWN GAP"
                if "KNOWN-GAP retained" in item["disposition"]
                else "APPROVED REQUIREMENT"
            ),
            current_behavior=item["disposition"],
        )
