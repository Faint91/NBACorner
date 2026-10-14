"""Refuse general pytest collection before application/database imports."""

from pathlib import Path

import pytest

from environment_safety import SafetyError, get_test_client


def pytest_sessionstart(session):
    invocation = Path(session.config.invocation_params.dir)
    selected = [str(arg).split("::", 1)[0] for arg in session.config.args]
    offline_file = Path(__file__).parent / "tests/offline/test_environment_safety.py"
    if (
        len(selected) == 1
        and (invocation / selected[0]).resolve() == offline_file.resolve()
    ):
        return  # Reviewed offline file only, never broad directory discovery.
    try:
        get_test_client()
    except SafetyError as error:
        raise pytest.UsageError(f"REFUSED before collection: {error}") from None
