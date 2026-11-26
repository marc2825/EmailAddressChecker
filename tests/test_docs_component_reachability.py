"""The component reachability table names code that exists.

Issue #2 asked for the library-only service components to be stated, with the
plan for connecting them, rather than left for a reader to discover. The table
in `docs/architecture.md` is that statement; this keeps it from drifting into a
list of files that were renamed or removed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.docs_contract

ROOT: Final = Path(__file__).resolve().parents[1]
ARCHITECTURE: Final = ROOT / "docs" / "architecture.md"
PACKAGE: Final = ROOT / "src" / "emailcheck"


def reachability_table() -> list[str]:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("### Component reachability", 1)[1].split("\n## ", 1)[0]
    return [line for line in section.splitlines() if line.startswith("| ") and "---" not in line]


def test_the_table_exists_and_lists_the_service_components() -> None:
    rows = reachability_table()
    names = " ".join(row.split("|")[1] for row in rows)
    for component in ("API-key", "HTTP request handler", "Active batch", "Accept-all", "beta"):
        assert component in names


@pytest.mark.parametrize("row", reachability_table()[1:], ids=lambda row: row.split("|")[1].strip())
def test_every_named_path_exists(row: str) -> None:
    code_cell = row.split("|")[2]
    paths = re.findall(r"`([a-z_/*]+(?:\.py)?/?)`", code_cell)
    assert paths, row
    for path in paths:
        assert list(PACKAGE.glob(path.rstrip("/"))), f"{path} named in the table does not exist"


def test_the_plan_is_in_the_roadmap_and_linked_from_the_table() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("### Component reachability", 1)[1].split("\n## ", 1)[0]
    assert "No public service surface is scheduled for 1.0.0" in section
    assert "](../ROADMAP.md)" in section
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    plan = roadmap.split("## Service components", 1)[1].split("\n## ", 1)[0]
    for step in ("1. An HTTP binding", "2. Active jobs", "3. Active batch upload"):
        assert step in plan, step
    status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    assert "docs/architecture.md#component-reachability" in status
    assert "](ROADMAP.md)" in status
