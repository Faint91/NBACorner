"""Convert repaired standings observations, retaining immutable prior provenance."""


def mark_standings_acceptance(cls):
    for name in dir(cls):
        if (
            name.startswith("current_behavior__standings__")
            or name
            in {
                "current_behavior__admin_ops__token",
                "current_behavior__admin_ops__teams",
            }
        ) and name not in {"current_behavior__standings__schedule"}:
            fn = getattr(cls, name)
            fn.metadata = {
                "scenario": name,
                "phase": "NC-02C2",
                "classification": "APPROVED REQUIREMENT",
                "requirements": ["S3", "S4", "S5", "S6", "S7", "S8", "S9", "S13"],
                "previous_metadata": dict(fn.metadata),
                "unreviewed_non_standings_policy_preserved": True,
                "current_behavior": "Standings scope only: ESPN shared validated atomic refresh; inclusive canonical opening freeze; failures preserve last good standings. Rollover remains deferred.",
            }
