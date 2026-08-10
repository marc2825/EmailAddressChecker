"""What a `Verdict` may carry, on the surfaces Phase 6 will publish.

Phase 5 added `Verdict.evidence`, and with it a carrier that did not exist
before: `repr(verdict)` now reaches every retained `Evidence` and therefore every
detail on it. Gate 4D tests `repr(Evidence)` for leakage; nothing tested the
surface that wraps it.

**The invariant asserted here is narrow, and the narrowness is the point.**

> Aggregation does not reintroduce information that upstream producers removed.

It is *not* "a `Verdict` makes arbitrary evidence safe". A `Verdict` is exactly
as private as the evidence handed to it, so the evidence below is built through
the real Phase 4D mapper from a session whose reply echoes the recipient — the
normal sanitization contract, exercised end to end — rather than by hand-placing
an already-unsafe value that no producer would create. A test built the other way
would be asserting a guarantee this project does not make.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.smtp_evidence import map_session_evidence
from emailcheck.application.syntax_evidence import SyntaxEvidenceProducer
from emailcheck.domain.address import AddressRejected, RawAddressInput, parse_address
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPState
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_reply import ReplyParsed, parse_reply
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSOutcomeDetail
from emailcheck.domain.verdict import Verdict

OBSERVED_AT = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)

#: The probed address, in the forms a careless implementation would echo.
TARGET = "probe.target+secret@example.test"
LOCAL_PART = "probe.target+secret"

#: A reply that quotes the recipient back, which real servers do constantly.
#: The Phase 4A sanitizer is what removes it, and this is the path that exercises
#: the sanitizer rather than bypassing it.
ECHOING_REPLY = (f"550 5.1.1 <{TARGET}> recipient unknown; RCPT TO:<{TARGET}> rejected",)

RECIPIENT_TRANSCRIPT = (
    SMTPCommand.EHLO,
    SMTPCommand.MAIL_FROM,
    SMTPCommand.RCPT_TO,
    SMTPCommand.RSET,
    SMTPCommand.QUIT,
)


class FixedClock:
    def now(self) -> datetime:
        return OBSERVED_AT


def echoing_session_evidence() -> tuple[Evidence, ...]:
    """SMTP evidence from a session whose server echoed the recipient."""
    parsed = parse_reply(list(ECHOING_REPLY))
    assert isinstance(parsed, ReplyParsed)
    report = SessionReport(
        observation=RecipientObservation(
            outcome=RecipientStageOutcome.REJECTED,
            final_state=SMTPState.CLOSED,
            reply=parsed.reply,
            tls_used=True,
            recipients_attempted=1,
            elapsed_milliseconds=120,
        ),
        stage_reached=DialogueStage.CLEANUP,
        tls=TLSOutcomeDetail(negotiated=True),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.COMPLETED,
        commands_issued=RECIPIENT_TRANSCRIPT,
        deadline_exhausted=False,
    )
    return map_session_evidence(report, observed_at=OBSERVED_AT)


def syntax_evidence_for(text: str) -> tuple[Evidence, ...]:
    rejection = parse_address(RawAddressInput(text))
    assert isinstance(rejection, AddressRejected)
    return SyntaxEvidenceProducer(clock=FixedClock()).evidence(rejection)


def route_evidence() -> Evidence:
    return Evidence(
        layer=EvidenceLayer.DNS,
        reason=ReasonCode.MX_AVAILABLE,
        strength=EvidenceStrength.WEAK,
        observed_at=OBSERVED_AT,
        details={"outcome": "mx_route", "candidate_count": 2},
    )


#: Everything a public response must never carry, from `docs/requirements.md`
#: section 11 and section 16.
FORBIDDEN_SUBSTRINGS = (
    TARGET,
    TARGET.lower(),
    LOCAL_PART,
    "@",
    "-----BEGIN CERTIFICATE-----",
)


def surfaces_of(verdict: Verdict) -> dict[str, str]:
    """Every rendering a Phase 6 author might reach for."""
    return {
        "repr(verdict)": repr(verdict),
        "str(verdict)": str(verdict),
        "repr(verdict.evidence)": repr(verdict.evidence),
        "repr(verdict.reason_codes)": repr(verdict.reason_codes),
        "repr(verdict.risk_flags)": repr(verdict.risk_flags),
        "repr(verdict.primary_reason)": repr(verdict.primary_reason),
        "repr(verdict.confidence)": repr(verdict.confidence),
        "repr(verdict.checks)": repr(verdict.checks),
        "verdict.ruleset": verdict.ruleset,
    }


def test_a_verdict_over_echoing_smtp_evidence_carries_no_recipient() -> None:
    """The end-to-end property: a real echoing reply, through the real mapper."""
    verdict = aggregate_evidence((route_evidence(), *echoing_session_evidence()))

    for name, rendered in surfaces_of(verdict).items():
        for leaked in FORBIDDEN_SUBSTRINGS:
            assert leaked not in rendered, (name, leaked)


def test_a_verdict_over_a_rejected_address_carries_no_submitted_text() -> None:
    """The syntax layer, whose input *is* the address the user typed."""
    verdict = aggregate_evidence(syntax_evidence_for(f"{LOCAL_PART}@@example.test"))

    for name, rendered in surfaces_of(verdict).items():
        for leaked in FORBIDDEN_SUBSTRINGS:
            assert leaked not in rendered, (name, leaked)


def test_the_layer_summaries_carry_no_evidence_detail_at_all() -> None:
    """`checks` is built from reason codes and counts, never from a detail.

    That is what keeps it safe independently of what a producer put in
    `Evidence.details` — and it is why the stop condition about `Evidence.details`
    not being automatically public is about the *evidence*, not about `checks`.
    """
    evidence = echoing_session_evidence()
    verdict = aggregate_evidence((route_evidence(), *evidence))

    (smtp_detail,) = (item.details for item in evidence)
    diagnostic = smtp_detail["diagnostic"]
    assert isinstance(diagnostic, str) and diagnostic

    assert diagnostic not in repr(verdict.checks)
    assert verdict.checks["smtp"] == {
        "result": ReasonCode.RCPT_REJECTED_ADDRESS.value,
        "reason_count": 1,
        "evidence_count": 1,
    }


def test_aggregation_reintroduces_nothing_the_producer_removed() -> None:
    """The invariant stated exactly, and it is a comparison rather than a claim.

    Whatever appears anywhere on the verdict, other than in the retained evidence
    tuple, must already have appeared on the evidence the producer emitted. The
    aggregator reads two boolean details and builds no string from any of them,
    so this holds by construction — and now by assertion.
    """
    evidence = echoing_session_evidence()
    verdict = aggregate_evidence((route_evidence(), *evidence))

    produced = repr(evidence)
    derived = repr(
        (
            verdict.status,
            verdict.confidence,
            verdict.primary_reason,
            verdict.reason_codes,
            verdict.risk_flags,
            verdict.checks,
            verdict.ruleset,
            verdict.no_message_data_sent,
        )
    )

    for detail_value in ("diagnostic", "elapsed_milliseconds", "stage_reached"):
        assert detail_value in produced
        assert detail_value not in derived


def test_the_retained_evidence_is_as_private_as_the_evidence_itself() -> None:
    """Stated so nobody reads the tests above as a stronger promise.

    A `Verdict` retains what it was given. It is exactly as private as its
    input — no more, and no less — so hand-placing an unsafe value would show up
    here, and that is a producer defect rather than an aggregation one.
    """
    unsafe = Evidence(
        layer=EvidenceLayer.SMTP,
        reason=ReasonCode.RCPT_ACCEPTED,
        strength=EvidenceStrength.MODERATE,
        observed_at=OBSERVED_AT,
        details={"about_the_target": True, "diagnostic": TARGET},
    )
    verdict = aggregate_evidence((route_evidence(), unsafe))

    assert TARGET in repr(verdict.evidence)
    assert TARGET not in repr(verdict.checks)
    assert TARGET not in repr(verdict.reason_codes)

    # And the producers this project actually has cannot emit that value: the
    # Phase 4A sanitizer removes any token containing an `@`.
    (produced,) = echoing_session_evidence()
    assert "@" not in repr(produced)


@pytest.mark.parametrize(
    "text", [f"{LOCAL_PART}@@example.test", f'"{LOCAL_PART}"@example.test', ""]
)
def test_no_rejected_input_reaches_a_verdict_surface(text: str) -> None:
    """Every `RejectionKind`, since the redacted form differs between them."""
    verdict = aggregate_evidence(syntax_evidence_for(text))

    for name, rendered in surfaces_of(verdict).items():
        assert LOCAL_PART not in rendered, (name, text)
        assert "@" not in rendered, (name, text)
