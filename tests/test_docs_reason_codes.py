"""Keep the published reason-code documentation and the enum in one set.

`docs/status-model.md` declares the enum the machine-readable source of truth
and requires documentation to stay synchronized. This test is that check.
"""

import re
from pathlib import Path

from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.reasons import ReasonCode

STATUS_MODEL = Path(__file__).resolve().parents[1] / "docs" / "status-model.md"
TABLE_ROW = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|\s*`([a-z0-9_]+)`\s*\|", re.MULTILINE)


def documented_rows() -> list[tuple[str, str]]:
    return TABLE_ROW.findall(STATUS_MODEL.read_text(encoding="utf-8"))


def test_documented_reason_codes_match_the_enum() -> None:
    documented = {code for code, _layer in documented_rows()}
    assert documented == {reason.value for reason in ReasonCode}


def test_documented_reason_codes_are_listed_once() -> None:
    documented = [code for code, _layer in documented_rows()]
    assert len(documented) == len(set(documented))


def test_documented_evidence_layers_exist() -> None:
    layers = {layer for _code, layer in documented_rows()}
    assert layers <= {layer.value for layer in EvidenceLayer}
