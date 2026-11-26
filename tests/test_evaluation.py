"""The published evaluation is the script's output (docs/evaluation.md).

Runs `scripts/evaluate_modes.py` in process. It drives the real pipeline with
scripted DNS and SMTP, and the suite-wide guard refuses any real socket.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

import evaluate_modes

pytestmark = pytest.mark.docs_contract

DOCUMENT: Final = Path(__file__).resolve().parent.parent / "docs" / "evaluation.md"


def test_the_document_shows_the_scripts_current_output() -> None:
    results = evaluate_modes.evaluate()
    published = DOCUMENT.read_text(encoding="utf-8")
    assert evaluate_modes.table(results) in published
    assert evaluate_modes.summary(results) in published


def test_neither_mode_calls_an_existing_or_undecidable_mailbox_invalid() -> None:
    for scenario, passive, active in evaluate_modes.evaluate():
        if scenario.truth != "absent":
            assert passive.status != "invalid", scenario.name
            assert active.status != "invalid", scenario.name


def test_smtp_runs_only_in_active_mode() -> None:
    for scenario, passive, _active in evaluate_modes.evaluate():
        assert passive.smtp is False, scenario.name
