"""`Evidence` checks itself, because an annotation is not a runtime check.

mypy runs on `src` only, `Any` launders a wrong value, and this is a value
assembled from a caller's parameters rather than from parts that have already
validated themselves. Phase 4A found the same thing about `SMTPSession.peer` and
Phase 4B about `SMTPTransport.connect`.

The timestamp is the field that matters. A naive datetime cannot be compared
with an aware one — the comparison raises `TypeError` rather than answering — so
one naive value anywhere makes ordering a mixed set of evidence fail at run time.
Phase 5 orders evidence from four producers, three of which take a `Clock` and
one of which takes the timestamp as a parameter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode

AWARE = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def build(**overrides: object) -> Evidence:
    fields: dict[str, object] = {
        "layer": EvidenceLayer.SMTP,
        "reason": ReasonCode.RCPT_ACCEPTED,
        "strength": EvidenceStrength.MODERATE,
        "observed_at": AWARE,
    }
    fields.update(overrides)
    return Evidence(**fields)  # type: ignore[arg-type]


# --- the timestamp -----------------------------------------------------------


def test_an_aware_timestamp_is_accepted() -> None:
    assert build().observed_at is AWARE


def test_any_explicit_offset_is_accepted() -> None:
    """The requirement is an explicit offset, not one particular offset.

    An aware `+09:00` orders correctly against an aware UTC one, which is the
    property being protected. Normalizing to UTC here would discard information
    the producer chose to record.
    """
    tokyo = datetime(2026, 8, 8, 21, 0, tzinfo=timezone(timedelta(hours=9)))

    assert build(observed_at=tokyo).observed_at == AWARE


def test_a_naive_timestamp_is_refused() -> None:
    """The one that gets through review: it is a `datetime` and it prints fine."""
    with pytest.raises(ValueError, match="timezone-aware"):
        build(observed_at=datetime(2026, 8, 8, 12, 0))


@pytest.mark.parametrize(
    "observed_at", [None, "2026-08-08T12:00:00Z", 1_754_654_400, 0.0, object(), AWARE.date()]
)
def test_a_timestamp_that_is_not_a_datetime_is_refused(observed_at: object) -> None:
    with pytest.raises(ValueError):
        build(observed_at=observed_at)


def test_two_timestamps_from_different_producers_stay_comparable() -> None:
    """The failure this invariant exists to prevent, shown rather than asserted.

    A naive value cannot reach `Evidence`, so ordering a set of it cannot raise.
    """
    with pytest.raises(TypeError):
        _ = datetime(2026, 8, 8, 12, 0) < AWARE

    ordered = sorted(
        (build(observed_at=AWARE + timedelta(minutes=1)), build()),
        key=lambda item: item.observed_at,
    )
    assert ordered[0].observed_at == AWARE


# --- the published vocabulary ------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("layer", "smtp"),
        ("layer", None),
        ("reason", "rcpt_accepted"),
        ("reason", None),
        ("strength", "moderate"),
        ("strength", EvidenceLayer.SMTP),
    ],
)
def test_evidence_must_carry_published_enum_members(field: str, value: object) -> None:
    """A string that happens to equal a member's value is not a member.

    `ReasonCode` is a `StrEnum`, so `"rcpt_accepted" == ReasonCode.RCPT_ACCEPTED`
    is true and a caller could pass either. Only one of them is a value Phase 5
    can dispatch on with `is`.
    """
    with pytest.raises(ValueError):
        build(**{field: value})


def test_permanence_must_be_a_boolean() -> None:
    with pytest.raises(ValueError):
        build(temporary=1)
    with pytest.raises(ValueError):
        build(temporary="yes")


def test_a_source_version_must_be_a_string_when_present() -> None:
    assert build(source_version=None).source_version is None
    assert build(source_version="smtp-evidence-2026-08-08").source_version is not None
    with pytest.raises(ValueError):
        build(source_version=3)


# --- the details -------------------------------------------------------------


def test_a_safe_scalar_detail_is_accepted() -> None:
    evidence = build(
        details={"basic_code": 550, "diagnostic": "no such user", "tls": True, "defect": None}
    )

    assert evidence.details["basic_code"] == 550


@pytest.mark.parametrize(
    "value", [1.5, [1, 2], {"nested": 1}, (1, 2), {1, 2}, object(), b"bytes", AWARE]
)
def test_a_detail_that_is_not_a_safe_scalar_is_refused(value: object) -> None:
    """`docs/status-model.md` section 7.5 bounds what may reach a response.

    A float also breaks the equality two equal reports are required to produce,
    and a container is a place an address or a transcript could hide.
    """
    with pytest.raises(ValueError, match="safe scalar"):
        build(details={"whatever": value})


def test_a_detail_key_must_be_a_string() -> None:
    with pytest.raises(ValueError):
        build(details={1: "one"})


def test_evidence_is_still_immutable() -> None:
    from dataclasses import FrozenInstanceError

    evidence = build()
    with pytest.raises(FrozenInstanceError):
        evidence.reason = ReasonCode.RCPT_REJECTED_ADDRESS  # type: ignore[misc]


def test_the_invariants_hold_through_dataclasses_replace() -> None:
    """The path Phase 4A found around `SMTPSession`'s check."""
    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(build(), observed_at=datetime(2026, 8, 8, 12, 0))
