"""Phase 5 decisions that bind Phase 6, pinned so they cannot be deleted quietly.

Phase 4 established the pattern in `tests/test_docs_smtp_contracts.py`: a stop
condition recorded in a plan and pinned by nothing is a stop condition the next
author has no way to find, because a document can be tidied away without anything
failing. Phase 5 recorded five more and pinned none of them, which the
independent review found.

Every assertion is on **substance** — the distinction the condition draws, the
thing it forbids — rather than on a heading or on exact whitespace, so the prose
may be rewritten freely and the commitment may not be removed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "plans" / "phase-05-aggregation.md"
ADR = ROOT / "docs" / "adr" / "0012-evidence-aggregation-and-final-status.md"
STATUS_MODEL = ROOT / "docs" / "status-model.md"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
PHASE_4_PLAN = ROOT / "plans" / "phase-04-smtp.md"


def flattened(path: Path) -> str:
    """Lower-cased, blockquote-stripped, one-space text.

    A commitment that spans a line break is still the commitment, so matching
    the raw file would fail on a reflow and pass on a deletion — the opposite of
    what these tests are for.
    """
    text = path.read_text(encoding="utf-8").lower()
    text = re.sub(r"^\s*>\s?", " ", text, flags=re.MULTILINE)
    return re.sub(r"\s+", " ", text)


# --- the five Phase 5 → Phase 6 stop conditions -----------------------------
#
# Each entry is the substance a Phase 6 author must be able to find. Deleting a
# condition removes its markers and fails its row.

PHASE_6_STOP_CONDITIONS = {
    "no re-derived status": (
        "must not re-derive a status",
        "comes from `aggregate_evidence`",
        "evidencestrength",
        "riskflag",
        "one aggregation policy",
    ),
    "no score, percentage, or rank": (
        "must not carry a score, a percentage, or a rank",
        "uncalibrated categorical evidence",
        "sort key",
        "range of a calibrated score is undefined",
    ),
    "evidence details are not automatically public": (
        "`evidence.details` is not automatically a public field",
        "dedicated public response schema",
        "safe to store",
    ),
    "cache keyed by the aggregation ruleset": (
        "cache that outlives the ruleset",
        "cache key must include the aggregation ruleset",
        "invalidated when it changes",
    ),
    "internal_error reaches an operator": (
        "must reach an operator",
        "operator telemetry and logging",
        "target invalidity",
    ),
}


@pytest.mark.parametrize(("condition", "markers"), sorted(PHASE_6_STOP_CONDITIONS.items()))
def test_every_phase_5_stop_condition_for_phase_6_is_recorded(
    condition: str, markers: tuple[str, ...]
) -> None:
    """By substance, so prose may be rewritten and a commitment may not vanish."""
    plan = flattened(PLAN)

    missing = [marker for marker in markers if marker not in plan]
    assert missing == [], f"the Phase 6 stop condition for {condition} is not recorded: {missing}"


def test_the_phase_5_conditions_join_the_phase_4_ones_rather_than_replacing_them() -> None:
    """Twelve conditions in total, and the plan says so rather than implying it.

    A Phase 6 author who opens only the Phase 5 plan must be sent to the Phase 4
    one, because seven of the twelve live there and none of them was superseded.
    """
    plan = flattened(PLAN)

    assert "seven phase 6 stop conditions in `plans/phase-04-smtp.md` are unchanged" in plan
    assert "phase-04-smtp.md" in plan
    assert PHASE_4_PLAN.exists()


def test_each_stop_condition_is_pinned_by_this_file_rather_than_only_written() -> None:
    """The lesson from the review, applied to the test rather than to the plan.

    Five conditions were recorded and none was pinned. This asserts the count so
    that adding a sixth to the plan without a row here is visible.
    """
    plan = flattened(PLAN)
    numbered = re.findall(r"\*\*\d+\. ", plan)

    assert len(numbered) == len(PHASE_6_STOP_CONDITIONS) == 5


# --- the semantics the review approved, which must not drift ----------------


APPROVED_SEMANTICS = {
    "five hard-invalid reasons": (STATUS_MODEL, ("a reason among the five section 2 lists",)),
    "route required for a positive verdict": (
        STATUS_MODEL,
        ("a lone acceptance is `unknown`", "`mx_available` or `implicit_mx_available`"),
    ),
    "strength is never read": (
        STATUS_MODEL,
        ("does not import `evidencestrength` at all",),
    ),
    "252 is not an acceptance": (STATUS_MODEL, ("`252` is not an acceptance",)),
    "line-too-long option b": (
        ADR,
        ("keeps its entry-point difference", "neither can ever produce `invalid`"),
    ),
    "internal_error does not outrank a hard invalid": (
        STATUS_MODEL,
        ("does not outrank a hard invalid",),
    ),
}


@pytest.mark.parametrize(("decision", "location"), sorted(APPROVED_SEMANTICS.items()))
def test_the_reviewed_semantics_are_still_documented(
    decision: str, location: tuple[Path, tuple[str, ...]]
) -> None:
    """The independent review approved these. A follow-up must not quietly move one."""
    path, markers = location
    text = flattened(path)

    missing = [marker for marker in markers if marker not in text]
    assert missing == [], f"the reviewed decision {decision!r} is no longer recorded: {missing}"


# --- the corrections the review asked for -----------------------------------


def test_tier_six_is_no_longer_described_as_passive_only() -> None:
    """The label the review found narrower than the code.

    `mx_available` and `implicit_mx_available` are in tier 6 too. Both readings
    produce `unknown`, so nothing behavioural depended on it — which is exactly
    why a document could stay wrong.
    """
    status_model = flattened(STATUS_MODEL)

    assert "6. passive-only unknown." not in status_model
    assert "residual non-blocking evidence" in status_model
    assert "route and passive metadata" in status_model


def test_the_temporary_tier_is_documented_as_reading_the_flag() -> None:
    """Fail-safe, and previously unstated.

    Tier 3 is `Evidence.temporary` and not a second reason list. The document
    must also say why one flag is enough: neither a wrongly-set nor a
    wrongly-cleared flag can reach `likely_deliverable`.
    """
    status_model = flattened(STATUS_MODEL)

    assert "the `evidence.temporary` flag, and nothing else" in status_model
    assert "neither error can reach `likely_deliverable`" in status_model


def test_the_primary_reason_ordering_is_documented_as_enforced() -> None:
    """F1, recorded where a reader of the model will find it."""
    for path in (STATUS_MODEL, ARCHITECTURE):
        text = flattened(path)
        assert "lead" in text
        assert "primary reason" in text
    assert "unconstructible" in flattened(STATUS_MODEL)


def test_the_calibrated_score_range_is_deferred_rather_than_guessed() -> None:
    """F8's decision, recorded so a later author does not invent `0..1`."""
    plan = flattened(PLAN)

    assert "range of a calibrated score is undefined" in plan
    assert "checks no range" in plan


def test_the_internal_error_future_caution_is_recorded() -> None:
    """The review's forward-looking note, kept as a Phase 6 caution.

    The policy is unchanged and the combination is unreachable today. What must
    survive is the reason it is unreachable, so a Phase 6 that makes it reachable
    knows to revisit rather than discovering the question for the first time.
    """
    plan = flattened(PLAN)

    assert "hard-invalid evidence survives an `internal_error`" in plan
    assert "not reachable from the current pipeline" in plan
