"""Retain old provenance and deferred recovery policy when recording S10/S11."""


def mark_transition_acceptance(cls):
    for name in dir(cls):
        if name.startswith("current_behavior__rollover__"):
            fn = getattr(cls, name)
            fn.metadata = {
                "scenario": name,
                "phase": "NC-02C3",
                "classification": "APPROVED REQUIREMENT (S10/S11 only); broader recovery remains unreviewed",
                "requirements": ["S10", "S11"],
                "previous_metadata": dict(fn.metadata),
                "current_behavior": "Existing rollover order retained; valid target finalized by atomic canonical movement + current standings reset. Legacy snapshot/recovery policies unchanged.",
                "deferred": [
                    "legacy-only snapshot success",
                    "full transactionality",
                    "partial recovery/resume",
                    "retry",
                    "trigger timing",
                    "master completion",
                    "retention",
                ],
            }
