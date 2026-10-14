"""Controlled test launcher; intentionally refuses until live verification exists."""

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environment_safety import (  # noqa: E402
    SafetyError,
    controlled_child_environment,
    load_enrollments,
    load_test_config,
    require_live_identity,
    validate_test_target,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--entry", choices=["backend", "standings", "integration"], required=True
    )
    args = parser.parse_args()
    try:
        settings = load_test_config(args.config)
        target = validate_test_target(settings, load_enrollments())
        require_live_identity(target)
    except SafetyError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    commands = {
        "backend": [sys.executable, "app.py"],
        "standings": [sys.executable, "scripts/update_standings.py"],
        "integration": [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_bracket_fill_and_save.py",
        ],
    }
    return subprocess.run(
        commands[args.entry],
        cwd=root,
        env=controlled_child_environment(settings, args.config),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
