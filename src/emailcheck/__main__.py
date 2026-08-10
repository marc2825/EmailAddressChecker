"""The console entry point.

`pyproject.toml` binds `emailcheck` here, and everything the command does lives
in `apps/cli.py`. Keeping this file a delegation rather than an implementation
means the CLI is importable and testable without going through `__main__`, and
that there is one parser rather than two that drift.
"""

from __future__ import annotations

from emailcheck.apps.cli import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
