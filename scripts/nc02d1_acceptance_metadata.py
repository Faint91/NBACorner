"""Classify repaired live scoring only; retain historical findings for D2."""


def mark_scoring_acceptance(cls):
    for name in dir(cls):
        if name.startswith("current_behavior__scoring__") or name in {
            "test_recompute_selection_skips_unsaved_without_deleting_stale_score",
            "current_behavior__league__frontend_leaderboard",
        }:
            fn = getattr(cls, name)
            fn.metadata = {
                "scenario": name,
                "phase": "NC-02D1",
                "classification": "APPROVED REQUIREMENT (live scoring only)",
                "requirements": [
                    "SC1",
                    "SC2",
                    "SC3",
                    "SC4",
                    "SC6",
                    "SC7",
                    "SC8",
                    "SC9",
                ],
                "previous_metadata": dict(fn.metadata),
                "historical_snapshot_policy_unchanged": True,
                "current_behavior": "Canonical active master; clarified participant-dependent full hit; separate +3/+1 bonuses; complete atomic scores; server competition ranks. Historical behavior remains deferred.",
            }
