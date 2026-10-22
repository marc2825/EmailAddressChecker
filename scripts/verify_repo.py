from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = [
    [sys.executable, "-m", "pytest"],
    [sys.executable, "-m", "ruff", "check", "."],
    [sys.executable, "-m", "ruff", "format", "--check", "."],
    [sys.executable, "-m", "mypy", "src"],
    [sys.executable, "scripts/check_forbidden_smtp.py"],
    [sys.executable, "-m", "emailcheck", "--version"],
]


def main() -> int:
    for command in COMMANDS:
        print("+", " ".join(command), flush=True)
        # The S603 suppression below is intentional: every command is a fixed
        # literal list starting with the current interpreter, with no shell and
        # no external input.
        result = subprocess.run(command, cwd=ROOT, check=False)  # noqa: S603
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
