"""Preserve prior characterization provenance while classifying approved D2 repairs."""


def mark_history_acceptance(cls):
    for name in dir(cls):
        if name.startswith(
            ("current_behavior__history__", "current_behavior__rollover__")
        ):
            fn = getattr(cls, name)
            fn.metadata = dict(
                scenario=name,
                phase="NC-02D2",
                classification="APPROVED REQUIREMENT (snapshot/history and cleanup gate only)",
                requirements=[
                    "SC5",
                    "SC10",
                    "SC11",
                    "SC12",
                    "SC13",
                    "SC14",
                    "SC15",
                    "SC16",
                    "SC17",
                ],
                previous_metadata=dict(fn.metadata),
                current_behavior="Canonical fresh scores; complete atomic immutable structured snapshot; shared competition ranks; safe public stored-order history. Genuine zero participation is supported; failures never count as empty.",
                full_rollover_atomicity_claimed=False,
            )
