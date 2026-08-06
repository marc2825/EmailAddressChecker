from __future__ import annotations

from collections.abc import Sequence

from emailcheck.domain.evidence import Evidence
from emailcheck.domain.verdict import Verdict


def aggregate_evidence(evidence: Sequence[Evidence]) -> Verdict:
    """Aggregate evidence in Phase 5.

    Deliberately unimplemented in the baseline so the status rules are added
    together with their complete decision-table tests.
    """

    del evidence
    raise NotImplementedError("Evidence aggregation is implemented in Phase 5.")
