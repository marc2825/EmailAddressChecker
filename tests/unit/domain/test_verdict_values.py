"""`Verdict` and `Confidence` refusing the shapes they must not take.

Phase 5 is the first code that builds a `Verdict`, so these invariants are added
with their first producer rather than after it. The important ones are not the
type checks — mypy catches most of those on `src` — but the two contradictions:
a verdict of `invalid` naming an accepted recipient, and a confidence carrying a
score nobody calibrated.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import (
    HARD_INVALID_REASONS,
    PERMITTED_PRIMARY_REASONS,
    POSITIVE_DELIVERY_REASONS,
    Confidence,
    ConfidenceLevel,
    RiskFlag,
    Status,
    Verdict,
)

OBSERVED_AT = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)

LOW = Confidence(level=ConfidenceLevel.LOW)

SOME_EVIDENCE = Evidence(
    layer=EvidenceLayer.DNS,
    reason=ReasonCode.NULL_MX,
    strength=EvidenceStrength.STRONG,
    observed_at=OBSERVED_AT,
)


def verdict(**overrides: object) -> Verdict:
    fields: dict[str, object] = {
        "status": Status.UNKNOWN,
        "confidence": LOW,
        "primary_reason": ReasonCode.MX_AVAILABLE,
        "reason_codes": (ReasonCode.MX_AVAILABLE,),
    }
    fields.update(overrides)
    return Verdict(**fields)  # type: ignore[arg-type]


# --- confidence -------------------------------------------------------------


def test_confidence_is_categorical_and_uncalibrated_by_default() -> None:
    """`docs/status-model.md` section 3, and requirements section 17."""
    confidence = Confidence(level=ConfidenceLevel.MEDIUM)

    assert confidence.calibrated is False
    assert confidence.score is None


def test_an_uncalibrated_confidence_cannot_carry_a_score() -> None:
    """The number a reader would treat as a probability, refused at the type.

    `0.87` next to a status is read as "87% likely", and there is no study
    behind any such number. Until there is one, a score is unconstructible
    rather than merely unset.
    """
    with pytest.raises(ValueError, match="uncalibrated"):
        Confidence(level=ConfidenceLevel.HIGH, score=0.87)


def test_a_confidence_level_must_be_published() -> None:
    with pytest.raises(ValueError, match="published level"):
        Confidence(level="very high")  # type: ignore[arg-type]


# --- the contradiction that matters -----------------------------------------


def test_an_invalid_verdict_cannot_name_an_accepted_recipient() -> None:
    """The shape section 32 of the Phase 5 brief names, made unconstructible.

    Not "the aggregator does not produce it" — nothing can, including a future
    Phase 6 that assembles a result some other way.
    """
    with pytest.raises(ValueError, match="cannot be the primary reason"):
        verdict(
            status=Status.INVALID,
            primary_reason=ReasonCode.RCPT_ACCEPTED,
            reason_codes=(ReasonCode.RCPT_ACCEPTED,),
        )


def test_a_likely_deliverable_verdict_cannot_name_a_rejection() -> None:
    with pytest.raises(ValueError, match="cannot be the primary reason"):
        verdict(
            status=Status.LIKELY_DELIVERABLE,
            primary_reason=ReasonCode.RCPT_REJECTED_ADDRESS,
            reason_codes=(ReasonCode.RCPT_REJECTED_ADDRESS,),
        )


@pytest.mark.parametrize("reason", sorted(HARD_INVALID_REASONS))
def test_every_hard_invalid_reason_may_lead_an_invalid_verdict(reason: ReasonCode) -> None:
    assert verdict(status=Status.INVALID, primary_reason=reason, reason_codes=(reason,))


@pytest.mark.parametrize("reason", sorted(POSITIVE_DELIVERY_REASONS))
def test_every_positive_reason_may_lead_a_likely_deliverable_verdict(reason: ReasonCode) -> None:
    assert verdict(status=Status.LIKELY_DELIVERABLE, primary_reason=reason, reason_codes=(reason,))


def test_the_two_unknown_statuses_accept_any_published_reason() -> None:
    """Deliberately permissive, and the asymmetry is the design.

    `docs/status-model.md` section 5 says one reason code may appear under
    different statuses depending on the other evidence present. An aggregator
    that raised on a contradictory evidence set would be worse than one that
    answered `unknown`, which is what `CONTRIBUTING.md` requires ambiguity to do.
    """
    assert PERMITTED_PRIMARY_REASONS[Status.UNKNOWN] == frozenset(ReasonCode)
    assert PERMITTED_PRIMARY_REASONS[Status.TEMPORARY_UNKNOWN] == frozenset(ReasonCode)
    for reason in ReasonCode:
        assert verdict(status=Status.UNKNOWN, primary_reason=reason, reason_codes=(reason,))


def test_every_status_has_a_permitted_reason_set() -> None:
    """A status added later fails here rather than raising a `KeyError` later."""
    assert set(PERMITTED_PRIMARY_REASONS) == set(Status)


# --- the rest of the shape --------------------------------------------------


def test_a_primary_reason_must_appear_among_the_reported_reasons() -> None:
    """Otherwise the primary reason is a claim no listed evidence made."""
    with pytest.raises(ValueError, match="must appear in its reason codes"):
        verdict(primary_reason=ReasonCode.ROLE_ACCOUNT, reason_codes=(ReasonCode.MX_AVAILABLE,))


def test_only_an_empty_verdict_may_omit_a_primary_reason() -> None:
    assert (
        Verdict(
            status=Status.UNKNOWN, confidence=LOW, primary_reason=None, reason_codes=()
        ).primary_reason
        is None
    )

    with pytest.raises(ValueError, match="must name a primary one"):
        verdict(primary_reason=None)


def test_a_verdict_may_not_repeat_a_reason() -> None:
    with pytest.raises(ValueError, match="may not repeat"):
        verdict(reason_codes=(ReasonCode.MX_AVAILABLE, ReasonCode.MX_AVAILABLE))


def test_reason_codes_must_be_an_immutable_tuple() -> None:
    """A verdict a caller can edit after the fact is not a verdict."""
    with pytest.raises(ValueError, match="must be a tuple"):
        verdict(reason_codes=[ReasonCode.MX_AVAILABLE])


def test_a_verdict_refuses_unpublished_vocabulary() -> None:
    with pytest.raises(ValueError, match="published status"):
        verdict(status="probably_fine")
    with pytest.raises(ValueError, match="published reason code"):
        verdict(primary_reason="looked_alright", reason_codes=("looked_alright",))
    with pytest.raises(ValueError, match="published risk flag"):
        verdict(risk_flags=frozenset({"suspicious"}))
    with pytest.raises(ValueError, match="must be a frozenset"):
        verdict(risk_flags={RiskFlag.ROLE_ACCOUNT})


def test_retained_evidence_must_be_an_immutable_tuple_of_evidence() -> None:
    assert verdict(evidence=(SOME_EVIDENCE,)).evidence == (SOME_EVIDENCE,)
    with pytest.raises(ValueError, match="must be a tuple"):
        verdict(evidence=[SOME_EVIDENCE])
    with pytest.raises(ValueError, match="only retain Evidence"):
        verdict(evidence=({"reason": "null_mx"},))


def test_the_no_message_data_promise_is_a_boolean_and_not_an_integer() -> None:
    """`1` is truthy and is not the promise. `bool` is an `int`, so this checks."""
    with pytest.raises(ValueError, match="must be a boolean"):
        verdict(no_message_data_sent=1)


# --- the independent review's value-type findings ---------------------------


def test_a_verdict_must_lead_with_its_primary_reason() -> None:
    """F1. The ordering the docstring promises, enforced by the type.

    The review mutated `_ranked_reasons` to sort by the enum's declaration order
    instead of `REASON_PRIORITY`. `primary_reason` stayed correct — it is
    computed by a different function — a different reason led the list, and the
    entire suite passed. A caller reading only `reason_codes[0]` would have been
    given the wrong reason.

    Enforcing it here rather than only in the aggregator means a Phase 6 that
    assembles a result some other way cannot produce the inconsistent shape
    either.
    """
    with pytest.raises(ValueError, match="must lead with the primary reason"):
        verdict(
            primary_reason=ReasonCode.MX_AVAILABLE,
            reason_codes=(ReasonCode.ROLE_ACCOUNT, ReasonCode.MX_AVAILABLE),
        )

    assert verdict(
        primary_reason=ReasonCode.MX_AVAILABLE,
        reason_codes=(ReasonCode.MX_AVAILABLE, ReasonCode.ROLE_ACCOUNT),
    )


def test_every_member_of_reason_codes_is_checked_and_not_only_the_primary() -> None:
    """F5. The element barrier, isolated from the primary-reason barrier.

    The earlier test matched on `"published reason code"`, which is wording the
    *primary reason* check also produces — so removing the element loop left it
    passing via the other barrier. This shape passes every primary-reason check
    and is refused only by the loop, and the match is on wording only the loop
    uses.
    """
    with pytest.raises(ValueError, match="every verdict reason"):
        verdict(
            primary_reason=ReasonCode.MX_AVAILABLE,
            reason_codes=(ReasonCode.MX_AVAILABLE, "looked_alright"),
        )


# --- F8: the value shapes Phase 6 will serialize ----------------------------


def test_a_calibrated_confidence_must_carry_the_number_its_study_produced() -> None:
    """The mirror of the uncalibrated rule.

    `calibrated=True` asserts a controlled labelled evaluation happened. Without
    the score it produced, the flag is a claim with nothing behind it, and a
    reader would take the categorical *level* as the calibrated output.
    """
    with pytest.raises(ValueError, match="must carry the score"):
        Confidence(level=ConfidenceLevel.HIGH, calibrated=True)


@pytest.mark.parametrize(
    ("score", "match"),
    [
        ("high", "must be a real number"),
        (True, "must be a real number"),
        (float("nan"), "must be finite"),
        (float("inf"), "must be finite"),
        (float("-inf"), "must be finite"),
    ],
    ids=["a string", "a boolean", "NaN", "infinity", "negative infinity"],
)
def test_a_confidence_score_must_be_a_real_finite_number(score: object, match: str) -> None:
    """Shape, and deliberately not range.

    No document defines what range a calibrated score would live in, so guessing
    `0..1` here would invent the semantics the calibration study is supposed to
    establish. What is checked is true of a number under every reading — and
    `True` recorded as `1.0` is a value nobody wrote, the same reason
    `TransportTimeouts` refuses a boolean.
    """
    with pytest.raises(ValueError, match=match):
        Confidence(level=ConfidenceLevel.HIGH, calibrated=True, score=score)  # type: ignore[arg-type]


def test_a_score_outside_any_obvious_range_is_deliberately_not_refused() -> None:
    """The decision recorded as a test, so it is visible rather than an omission.

    `42.0` is not a probability under any reading, and it is accepted, because
    refusing it needs a range no document states.
    ADR 0012
    carries the range as a pre-calibration stop condition instead of it being
    guessed here.
    """
    assert Confidence(level=ConfidenceLevel.HIGH, calibrated=True, score=42.0).score == 42.0


def test_a_verdict_ruleset_must_identify_something() -> None:
    """`ruleset` is provenance; a cache is matched against it."""
    with pytest.raises(ValueError, match="ruleset must be a non-empty string"):
        verdict(ruleset=123)
    with pytest.raises(ValueError, match="ruleset must be a non-empty string"):
        verdict(ruleset="")


def test_check_summaries_are_keyed_by_layer_names_and_their_values_stay_open() -> None:
    """Only the keys are closed, and the reason is in `docs/status-model.md`.

    Section 6 publishes a layer summary carrying `"mx_hosts": [...]` — a list —
    so closing the values to safe scalars here would forbid the shape the
    document itself shows. What may reach a **public response** is Phase 6's
    schema to choose explicitly, which is why that is a stop condition rather
    than a guess made in this type.
    """
    with pytest.raises(ValueError, match="keyed by a string"):
        verdict(checks={1: "dns"})

    assert verdict(checks={"dns": {"result": "mx_available", "mx_hosts": ["mx.example.net"]}})
