"""The Phase 1 layer's producer, and what it deliberately cannot say.

Two rules carry everything here: a broken grammar is strong, target-specific,
permanent evidence; an unsupported form is none of those and must reach
`unknown`. The tests run each through the aggregator as well as checking the
evidence, because "unsupported is not invalid" is a claim about the verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.syntax_evidence import (
    SYNTAX_EVIDENCE_RULESET,
    SyntaxEvidenceProducer,
)
from emailcheck.domain.address import AddressRejected, RawAddressInput, parse_address
from emailcheck.domain.evidence import EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Status

OBSERVED_AT = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return OBSERVED_AT


def rejection(text: str) -> AddressRejected:
    """Reject through Phase 1 rather than by hand, so the issue is a real one."""
    result = parse_address(RawAddressInput(text))
    assert isinstance(result, AddressRejected), text
    return result


def evidence_for(text: str):  # type: ignore[no-untyped-def]
    (item,) = SyntaxEvidenceProducer(clock=FixedClock()).evidence(rejection(text))
    return item


INVALID_INPUTS = ("", "no-at-sign", "a@@b.example", "a b@example.com", "user@")
UNSUPPORTED_INPUTS = ('"quoted"@example.com', "user@[192.0.2.1]", "ユーザー@example.com")


@pytest.mark.parametrize("text", INVALID_INPUTS)
def test_a_broken_grammar_is_strong_permanent_target_evidence(text: str) -> None:
    item = evidence_for(text)

    assert item.layer is EvidenceLayer.SYNTAX
    assert item.reason is ReasonCode.INVALID_SYNTAX
    assert item.strength is EvidenceStrength.STRONG
    assert item.temporary is False
    assert item.details["about_the_target"] is True
    assert item.source_version == SYNTAX_EVIDENCE_RULESET
    assert item.observed_at is OBSERVED_AT


@pytest.mark.parametrize("text", INVALID_INPUTS)
def test_a_broken_grammar_aggregates_to_invalid(text: str) -> None:
    verdict = aggregate_evidence((evidence_for(text),))

    assert verdict.status is Status.INVALID
    assert verdict.primary_reason is ReasonCode.INVALID_SYNTAX


@pytest.mark.parametrize("text", UNSUPPORTED_INPUTS)
def test_an_unsupported_form_is_weak_and_never_invalid(text: str) -> None:
    """`docs/requirements.md` section 6: unsupported produces `unknown`.

    Both barriers are asserted, and neither is load-bearing alone: the strength
    is weak, *and* the reason is in no hard-invalid set.
    """
    item = evidence_for(text)

    assert item.strength is EvidenceStrength.WEAK
    assert item.temporary is False
    assert aggregate_evidence((item,)).status is Status.UNKNOWN


def test_an_unsupported_unicode_local_part_raises_the_published_risk_flag() -> None:
    """The one flag with no other producer, derived from published vocabulary."""
    verdict = aggregate_evidence((evidence_for("ユーザー@example.com"),))

    assert verdict.primary_reason is ReasonCode.UNSUPPORTED_SMTPUTF8
    assert verdict.status is Status.UNKNOWN


def test_an_accepted_address_has_no_producer_here_at_all() -> None:
    """There is no evidence for syntax that parsed, and that is the design.

    A reason code meaning "the syntax was fine" would be the first thing a later
    aggregation mistook for delivery evidence, so `SyntaxEvidenceProducer` takes
    a rejection and nothing else.
    """
    with pytest.raises(ValueError, match="AddressRejected"):
        SyntaxEvidenceProducer(clock=FixedClock()).evidence("user@example.com")  # type: ignore[arg-type]


def test_the_producer_carries_no_submitted_text_into_the_evidence() -> None:
    """`docs/requirements.md` section 16: no full address, anywhere.

    `AddressRejected` holds a redacted form of the input, and even that does not
    reach the evidence — only the issue and the kind do.
    """
    item = evidence_for("SecretUser+tag@@example.com")
    rendered = repr(item)

    for leaked in ("SecretUser", "secretuser", "@", "+tag"):
        assert leaked not in rendered, leaked
    assert set(item.details) == {"issue", "kind", "about_the_target", "no_message_data_sent"}
