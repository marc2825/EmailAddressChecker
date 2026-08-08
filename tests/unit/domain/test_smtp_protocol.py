"""The session report: complete, consistent, and still not a verdict.

Its invariants exist because two fields describing one fact will eventually
disagree, and a reader then picks whichever suits them. The transcript and the
observation must agree about the recipient; the observation and the TLS detail
must agree about TLS.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError, SMTPState
from emailcheck.domain.smtp_protocol import (
    STAGE_ORDER,
    CleanupStatus,
    DialogueStage,
    SessionReport,
)
from emailcheck.domain.smtp_reply import SMTPReply
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSFailureReason, TLSOutcomeDetail


def observation(**overrides: object) -> RecipientObservation:
    fields: dict[str, object] = {
        "outcome": RecipientStageOutcome.ACCEPTED,
        "final_state": SMTPState.CLOSED,
        "reply": SMTPReply(code=250, diagnostic="recipient ok"),
        "recipients_attempted": 1,
    }
    fields.update(overrides)
    return RecipientObservation(**fields)  # type: ignore[arg-type]


def report(**overrides: object) -> SessionReport:
    fields: dict[str, object] = {
        "observation": observation(),
        "stage_reached": DialogueStage.CLEANUP,
        "tls": TLSOutcomeDetail(),
        "capabilities": Capabilities(),
        "cleanup": CleanupStatus.COMPLETED,
        "commands_issued": (
            SMTPCommand.EHLO,
            SMTPCommand.MAIL_FROM,
            SMTPCommand.RCPT_TO,
            SMTPCommand.RSET,
            SMTPCommand.QUIT,
        ),
    }
    fields.update(overrides)
    return SessionReport(**fields)  # type: ignore[arg-type]


# --- the ordinary case -----------------------------------------------------


def test_a_complete_report_describes_the_session() -> None:
    built = report()
    assert built.final_state is SMTPState.CLOSED
    assert built.no_message_data_sent is True
    assert built.summary["result"] == "accepted"
    assert built.summary["stage_reached"] == "cleanup"


def test_the_stage_order_covers_every_stage() -> None:
    assert set(STAGE_ORDER) == set(DialogueStage)
    assert STAGE_ORDER[0] is DialogueStage.CONNECTED
    assert STAGE_ORDER[-1] is DialogueStage.CLEANUP


# --- the invariants --------------------------------------------------------


def test_a_second_recipient_in_the_transcript_is_refused() -> None:
    """The product promise, checked once more where a report is assembled."""
    with pytest.raises(SMTPContractError, match="at most one RCPT TO"):
        report(
            commands_issued=(SMTPCommand.RCPT_TO, SMTPCommand.RCPT_TO),
            observation=observation(recipients_attempted=1),
        )


def test_a_second_starttls_in_the_transcript_is_refused() -> None:
    with pytest.raises(SMTPContractError, match="STARTTLS at most once"):
        report(
            commands_issued=(SMTPCommand.STARTTLS, SMTPCommand.STARTTLS, SMTPCommand.RCPT_TO),
            tls=TLSOutcomeDetail(negotiated=True),
            observation=observation(recipients_attempted=1, tls_used=True),
        )


def test_a_second_mail_from_in_the_transcript_is_refused() -> None:
    with pytest.raises(SMTPContractError, match="MAIL FROM at most once"):
        report(commands_issued=(SMTPCommand.MAIL_FROM, SMTPCommand.MAIL_FROM))


def test_the_transcript_and_the_observation_must_agree_about_the_recipient() -> None:
    with pytest.raises(SMTPContractError, match="disagree about the recipient"):
        report(commands_issued=(SMTPCommand.EHLO,), observation=observation(recipients_attempted=1))
    with pytest.raises(SMTPContractError, match="disagree about the recipient"):
        report(
            commands_issued=(SMTPCommand.RCPT_TO,),
            observation=observation(recipients_attempted=0, outcome=RecipientStageOutcome.ACCEPTED),
        )


def test_the_observation_and_the_tls_detail_must_agree() -> None:
    with pytest.raises(SMTPContractError, match="disagree about TLS"):
        report(tls=TLSOutcomeDetail(negotiated=True))
    with pytest.raises(SMTPContractError, match="disagree about TLS"):
        report(observation=observation(tls_used=True))


def test_cleanup_skipped_for_the_deadline_must_say_the_deadline_ran_out() -> None:
    """The 4C review found these two fields contradicting each other.

    `SKIPPED_DEADLINE` means the session budget stopped the cleanup, and
    `deadline_exhausted` is the field Phase 4D reads to tell this project's own
    bound apart from the network's. A report saying both at once is a report that
    lets a reader pick whichever suits them, so it cannot be built.
    """
    with pytest.raises(SMTPContractError, match="deadline_exhausted"):
        report(cleanup=CleanupStatus.SKIPPED_DEADLINE, deadline_exhausted=False)

    consistent = report(cleanup=CleanupStatus.SKIPPED_DEADLINE, deadline_exhausted=True)
    assert consistent.summary["cleanup"] == "skipped_deadline"
    assert consistent.summary["deadline_exhausted"] is True


@pytest.mark.parametrize(
    "cleanup",
    [CleanupStatus.COMPLETED, CleanupStatus.INCOMPLETE, CleanupStatus.NOT_ATTEMPTED],
)
def test_a_deadline_may_run_out_without_the_cleanup_being_the_place_it_showed(
    cleanup: CleanupStatus,
) -> None:
    """The implication is one-directional, deliberately.

    A budget spent part way through the dialogue never reaches cleanup at all,
    and one spent during `RSET` leaves it `INCOMPLETE`. Requiring the converse
    would make those reports unbuildable.
    """
    built = report(cleanup=cleanup, deadline_exhausted=True)
    assert built.deadline_exhausted is True


def test_a_report_must_carry_an_observation() -> None:
    for wrong in (None, "accepted", 250):
        with pytest.raises(SMTPContractError, match="recipient observation"):
            report(observation=wrong)


def test_a_negotiated_tls_session_has_no_failure_reason() -> None:
    with pytest.raises(ValueError, match="no failure reason"):
        TLSOutcomeDetail(negotiated=True, reason=TLSFailureReason.NOT_OFFERED)


# --- what it never says ----------------------------------------------------


def test_a_report_carries_no_status_vocabulary() -> None:
    rendered = repr(report()) + repr(report().summary)
    for forbidden in ("likely_deliverable", "temporary_unknown", "confidence", "verdict"):
        assert forbidden not in rendered


def test_no_tls_outcome_is_ever_about_the_target() -> None:
    for reason in TLSFailureReason:
        assert TLSOutcomeDetail(negotiated=False, reason=reason).is_about_the_target is False
    assert TLSOutcomeDetail(negotiated=True).is_about_the_target is False


def test_the_summary_is_structured_and_bounded() -> None:
    summary = report().summary
    assert set(summary) == {
        "result",
        "final_state",
        "basic_code",
        "enhanced_code",
        "tls_used",
        "recipients_attempted",
        "no_message_data_sent",
        "stage_reached",
        "tls_negotiated",
        "tls_reason",
        "cleanup",
        "starttls_advertised",
        "deadline_exhausted",
    }
    for value in summary.values():
        assert value is None or isinstance(value, str | int | bool)
