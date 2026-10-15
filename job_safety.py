"""Operational job guard. No scheduler, executor, shell or HTTP bypass."""

from environment_safety import (
    SafetyError,
    runtime_safety_settings,
    load_enrollments,
    validate_test_target,
    validate_test_email_settings,
    validate_test_provider_settings,
    validate_test_job_settings,
    verify_live_local_identity,
    require_live_identity,
)

JOB_NAMES = frozenset(
    {
        "standings-script",
        "standings-refresh",
        "standings-overwrite",
        "score-recompute",
        "leaderboard-snapshot",
        "season-rollover",
        "team-insert",
    }
)


def require_explicit_test_job(settings, job, *, requested_job=None):
    if job not in JOB_NAMES or requested_job != job:
        raise SafetyError("A known test job must be explicitly requested in-process.")
    target = validate_test_target(settings, load_enrollments())
    validate_test_email_settings(settings, target)
    validate_test_provider_settings(settings, target)
    validate_test_job_settings(settings)
    identity = verify_live_local_identity(settings)
    if identity["marker"].get("fixture_state") != "UNSEEDED":
        raise SafetyError("Unreviewed test fixture state.")
    # Even valid live identity/opt-in/request cannot bypass missing seed/reset/harness.
    require_live_identity(target)


def guard_runtime_job(job):
    settings = runtime_safety_settings()
    if settings.get("NBA_CORNER_ENV") == "test":
        from integration_harness import authorize_standings_test_job

        if authorize_standings_test_job(job):
            return
        require_explicit_test_job(settings, job)
    # Production is a no-op: existing JWT/cron auth and job behavior unchanged.
