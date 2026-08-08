"""The Phase 4D mapping, against the table that was written before it.

`docs/status-model.md` section 7 is the specification. These tests are arranged
as the matrix it describes — every RCPT class, every enhanced code that changes
an answer, every pre-recipient failure, every TLS reason, the deadline, and each
cleanup category — so a row that stops being implemented fails on the row rather
than somewhere downstream.

The invariants at the end are the ones that would be silent if they broke. A
`252` becoming positive evidence, a `MAIL FROM 550` becoming a recipient
rejection, a TLS failure becoming mailbox invalidity: all three produce a
plausible-looking result, and all three would be wrong in the direction this
project must never be wrong in.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from emailcheck.application.smtp_evidence import (
    _CONNECT_REASONS,
    NON_TARGET_SMTP_REASONS,
    POSITIVE_RECIPIENT_REASONS,
    RECIPIENT_STAGE_REASONS,
    SMTP_EVIDENCE_RULESET,
    _connect_finding,
    _identifies_the_recipient,
    _is_about_the_target,
    _is_policy_refusal,
    map_connect_failure,
    map_session_evidence,
)
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPState
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_reply import (
    EnhancedStatusCode,
    ReplyDefect,
    ReplyParsed,
    SMTPReply,
    parse_reply,
)
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSFailureReason, TLSOutcomeDetail
from emailcheck.domain.smtp_transport import TransportFailure

OBSERVED_AT = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)

RECIPIENT_TRANSCRIPT = (
    SMTPCommand.EHLO,
    SMTPCommand.MAIL_FROM,
    SMTPCommand.RCPT_TO,
    SMTPCommand.RSET,
    SMTPCommand.QUIT,
)


def reply_of(*lines: str) -> SMTPReply:
    """Build a reply the way the dialogue does — through the Phase 4A parser.

    Constructing `SMTPReply` by hand would let a test assert on an enhanced code
    the parser would have dropped, so the matrix below exercises the same path
    production uses.
    """
    parsed = parse_reply(list(lines))
    assert isinstance(parsed, ReplyParsed), lines
    return parsed.reply


def recipient_report(
    *lines: str,
    cleanup: CleanupStatus = CleanupStatus.COMPLETED,
    deadline_exhausted: bool = False,
    tls: TLSOutcomeDetail | None = None,
) -> SessionReport:
    """A session that reached the recipient stage and got `lines` back."""
    reply = reply_of(*lines)
    first_digit = reply.code // 100
    outcome = {
        2: RecipientStageOutcome.ACCEPTED,
        4: RecipientStageOutcome.TEMPORARY_FAILURE,
    }.get(first_digit, RecipientStageOutcome.REJECTED)
    detail = tls or TLSOutcomeDetail()
    return SessionReport(
        observation=RecipientObservation(
            outcome=outcome,
            final_state=SMTPState.CLOSED,
            reply=reply,
            tls_used=detail.negotiated,
            recipients_attempted=1,
            elapsed_milliseconds=120,
        ),
        stage_reached=DialogueStage.CLEANUP,
        tls=detail,
        capabilities=Capabilities(),
        cleanup=cleanup,
        commands_issued=RECIPIENT_TRANSCRIPT,
        deadline_exhausted=deadline_exhausted,
    )


def pre_recipient_report(
    stage: DialogueStage,
    *,
    outcome: RecipientStageOutcome = RecipientStageOutcome.CONNECTION_ERROR,
    reply: SMTPReply | None = None,
    defect: ReplyDefect | None = None,
    tls: TLSOutcomeDetail | None = None,
    deadline_exhausted: bool = False,
) -> SessionReport:
    """A session that ended before the recipient stage."""
    detail = tls or TLSOutcomeDetail()
    return SessionReport(
        observation=RecipientObservation(
            outcome=outcome,
            final_state=SMTPState.CLOSED,
            reply=reply,
            defect=defect,
            tls_used=detail.negotiated,
            recipients_attempted=0,
            elapsed_milliseconds=45,
        ),
        stage_reached=stage,
        tls=detail,
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=(),
        deadline_exhausted=deadline_exhausted,
    )


def barrier_report(
    *,
    outcome: RecipientStageOutcome,
    lines: tuple[str, ...],
    recipients_attempted: int,
    stage: DialogueStage,
) -> SessionReport:
    """A report assembled field by field, so exactly one barrier refuses it.

    The two helpers above cannot build these shapes: `recipient_report` always
    sets the outcome, the count, and the stage consistently, and
    `pre_recipient_report` always uses `connection_error` with no recipient
    attempted. That is precisely why removing any one of the three barriers in
    `_recipient_reply` left the whole suite passing — every test satisfied at
    least two of them at once.
    """
    transcript = (SMTPCommand.EHLO, SMTPCommand.MAIL_FROM) + (
        (SMTPCommand.RCPT_TO,) if recipients_attempted else ()
    )
    return SessionReport(
        observation=RecipientObservation(
            outcome=outcome,
            final_state=SMTPState.CLOSED,
            reply=reply_of(*lines),
            recipients_attempted=recipients_attempted,
            elapsed_milliseconds=120,
        ),
        stage_reached=stage,
        tls=TLSOutcomeDetail(),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=transcript,
    )


def only(report: SessionReport) -> Evidence:
    """The one piece of evidence a session produces."""
    produced = map_session_evidence(report, observed_at=OBSERVED_AT)
    assert len(produced) == 1, produced
    return produced[0]


# --- the three barriers before a recipient rejection, pinned one by one -------
#
# `550 5.1.1` is the strongest evidence this project produces, and each of these
# reports carries one. Each is a legal `SessionReport`, and each is refused by
# exactly one barrier, so each test fails when that barrier alone is removed and
# passes when either of the other two is.


def test_the_outcome_barrier_alone_refuses_a_non_recipient_answer() -> None:
    """A `connection_error` is never a recipient answer, at any stage.

    The count and the stage both say "recipient", so nothing but the outcome
    check stands between this and `rcpt_rejected_address`.
    """
    report = barrier_report(
        outcome=RecipientStageOutcome.CONNECTION_ERROR,
        lines=("550 5.1.1 no such user",),
        recipients_attempted=1,
        stage=DialogueStage.CLEANUP,
    )
    evidence = only(report)

    assert evidence.reason not in RECIPIENT_STAGE_REASONS
    assert evidence.reason is not ReasonCode.RCPT_REJECTED_ADDRESS
    assert evidence.reason is ReasonCode.SMTP_POLICY_BLOCKED
    assert evidence.details["about_the_target"] is False
    assert evidence.details["recipient_stage"] is False


def test_the_recipient_count_barrier_alone_refuses_a_session_that_asked_nothing() -> None:
    """No `RCPT TO` was issued, so no reply can be an answer about the recipient.

    The outcome is `rejected` and the stage is `cleanup`, so both of the other
    barriers let this through.
    """
    report = barrier_report(
        outcome=RecipientStageOutcome.REJECTED,
        lines=("550 5.1.1 no such user",),
        recipients_attempted=0,
        stage=DialogueStage.CLEANUP,
    )
    evidence = only(report)

    assert evidence.reason not in RECIPIENT_STAGE_REASONS
    assert evidence.reason is not ReasonCode.RCPT_REJECTED_ADDRESS
    assert evidence.reason is ReasonCode.SMTP_POLICY_BLOCKED
    assert evidence.details["about_the_target"] is False
    assert evidence.details["recipients_attempted"] == 0


def test_the_stage_barrier_alone_refuses_a_session_that_never_got_there() -> None:
    """The dialogue ended at `MAIL FROM`, so the `550` refused the *sender*.

    The outcome is `rejected` and one recipient is recorded, so only the stage
    check separates this from the worst mistake this mapping could make.
    """
    report = barrier_report(
        outcome=RecipientStageOutcome.REJECTED,
        lines=("550 5.1.1 no such user",),
        recipients_attempted=1,
        stage=DialogueStage.MAIL_FROM,
    )
    evidence = only(report)

    assert evidence.reason not in RECIPIENT_STAGE_REASONS
    assert evidence.reason is not ReasonCode.RCPT_REJECTED_ADDRESS
    assert evidence.reason is ReasonCode.MAIL_FROM_REJECTED
    assert evidence.details["about_the_target"] is False


def test_all_three_barrier_shapes_are_legal_session_reports() -> None:
    """The tests above prove nothing if their inputs are unconstructible.

    `SessionReport` and `RecipientObservation` accept every one of them, which is
    what makes each barrier load-bearing rather than decorative.
    """
    shapes = (
        (RecipientStageOutcome.CONNECTION_ERROR, 1, DialogueStage.CLEANUP),
        (RecipientStageOutcome.REJECTED, 0, DialogueStage.CLEANUP),
        (RecipientStageOutcome.REJECTED, 1, DialogueStage.MAIL_FROM),
    )
    for outcome, attempted, stage in shapes:
        report = barrier_report(
            outcome=outcome,
            lines=("550 5.1.1 no such user",),
            recipients_attempted=attempted,
            stage=stage,
        )
        assert isinstance(report, SessionReport)
        assert report.observation.recipients_attempted == attempted


def test_a_real_recipient_answer_arrives_at_the_cleanup_stage() -> None:
    """The stage barrier must admit what the dialogue actually reports.

    `application/smtp_dialogue.py` records every completed recipient exchange at
    `cleanup`; `rcpt_to` is the stage a dialogue is *in* while the command is
    outstanding. A barrier admitting only `rcpt_to` would discard every recipient
    answer this project produces, so both are asserted here.
    """
    for stage in (DialogueStage.RCPT_TO, DialogueStage.CLEANUP):
        report = barrier_report(
            outcome=RecipientStageOutcome.REJECTED,
            lines=("550 5.1.1 no such user",),
            recipients_attempted=1,
            stage=stage,
        )
        evidence = only(report)
        assert evidence.reason is ReasonCode.RCPT_REJECTED_ADDRESS, stage
        assert evidence.details["about_the_target"] is True, stage


# --- the recipient stage: every class in the matrix -------------------------


@pytest.mark.parametrize(
    ("lines", "reason", "strength", "temporary"),
    [
        (("250 2.1.5 recipient ok",), ReasonCode.RCPT_ACCEPTED, EvidenceStrength.MODERATE, False),
        (("250 ok",), ReasonCode.RCPT_ACCEPTED, EvidenceStrength.MODERATE, False),
        (
            ("251 2.1.5 user not local; will forward",),
            ReasonCode.RCPT_FORWARDED,
            EvidenceStrength.MODERATE,
            False,
        ),
        (
            ("252 2.1.5 cannot verify user",),
            ReasonCode.RCPT_UNVERIFIABLE,
            EvidenceStrength.WEAK,
            False,
        ),
        (
            ("450 4.2.1 mailbox busy",),
            ReasonCode.SMTP_TEMPORARY_FAILURE,
            EvidenceStrength.MODERATE,
            True,
        ),
        (
            ("451 4.7.1 greylisted, try again",),
            ReasonCode.SMTP_TEMPORARY_FAILURE,
            EvidenceStrength.MODERATE,
            True,
        ),
        (
            ("450 4.1.1 recipient unknown right now",),
            ReasonCode.SMTP_TEMPORARY_FAILURE,
            EvidenceStrength.MODERATE,
            True,
        ),
        (
            ("452 4.2.2 insufficient storage",),
            ReasonCode.MAILBOX_FULL,
            EvidenceStrength.MODERATE,
            True,
        ),
        (
            ("550 5.1.1 no such user",),
            ReasonCode.RCPT_REJECTED_ADDRESS,
            EvidenceStrength.STRONG,
            False,
        ),
        (
            ("550 mailbox unavailable",),
            ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
            EvidenceStrength.WEAK,
            False,
        ),
        (
            ("550 5.1.0 other address status",),
            ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
            EvidenceStrength.WEAK,
            False,
        ),
        (
            ("550 5.7.1 policy rejection",),
            ReasonCode.RCPT_REJECTED_POLICY,
            EvidenceStrength.WEAK,
            False,
        ),
        (
            ("551 5.1.6 user not local",),
            ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
            EvidenceStrength.WEAK,
            False,
        ),
        (("552 5.2.2 mailbox full",), ReasonCode.MAILBOX_FULL, EvidenceStrength.MODERATE, True),
        (
            ("553 5.1.3 bad recipient address syntax",),
            ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
            EvidenceStrength.WEAK,
            False,
        ),
        (
            ("554 5.0.0 transaction failed",),
            ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
            EvidenceStrength.WEAK,
            False,
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_every_recipient_reply_maps_as_the_table_says(
    lines: tuple[str, ...], reason: ReasonCode, strength: EvidenceStrength, temporary: bool
) -> None:
    evidence = only(recipient_report(*lines))

    assert evidence.reason is reason
    assert evidence.strength is strength
    assert evidence.temporary is temporary
    assert evidence.layer is EvidenceLayer.SMTP
    assert evidence.details["recipient_stage"] is True


def test_the_enhanced_code_is_carried_as_metadata() -> None:
    """Kept for Phase 5, and read here only where the table says to read it."""
    evidence = only(recipient_report("451 4.7.1 greylisted, try again"))

    assert evidence.details["basic_code"] == 451
    assert evidence.details["enhanced_code"] == "4.7.1"
    # `4.7.1` is a policy subject and this is still only a temporary failure:
    # asserting greylisting from it would be a guess dressed as an observation.
    assert evidence.reason is ReasonCode.SMTP_TEMPORARY_FAILURE


def test_an_absent_enhanced_code_is_absent_rather_than_invented() -> None:
    evidence = only(recipient_report("550 mailbox unavailable"))

    assert evidence.details["basic_code"] == 550
    assert evidence.details["enhanced_code"] is None
    assert evidence.reason is ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE


def test_a_contradictory_enhanced_code_never_reaches_the_mapping() -> None:
    """Phase 4A drops it, so 4D never sees `250 5.1.1` and cannot act on one."""
    evidence = only(recipient_report("250 5.1.1 nonsense"))

    assert evidence.details["enhanced_code"] is None
    assert evidence.reason is ReasonCode.RCPT_ACCEPTED


def test_a_success_class_2_2_2_is_not_a_storage_failure() -> None:
    """`X.2.2` is a storage condition only on a class that carries failures."""
    evidence = only(recipient_report("250 2.2.2 ok"))

    assert evidence.reason is ReasonCode.RCPT_ACCEPTED


# --- 252, the branch the whole mapping is arranged around -------------------


def test_252_is_unverifiable_and_never_positive() -> None:
    evidence = only(recipient_report("252 2.1.5 cannot verify user"))

    assert evidence.reason is ReasonCode.RCPT_UNVERIFIABLE
    assert evidence.reason not in POSITIVE_RECIPIENT_REASONS
    assert evidence.reason is not ReasonCode.RCPT_ACCEPTED
    assert evidence.strength is EvidenceStrength.WEAK
    assert evidence.details["basic_code"] == 252


def test_252_and_250_share_an_outcome_and_not_a_reason() -> None:
    """The trap section 7.4 exists for, asserted from both ends.

    Gate 4C records both as `ACCEPTED`, so the observation cannot tell them
    apart. The mapping must, and only the basic code lets it.
    """
    unverifiable = recipient_report("252 2.1.5 cannot verify user")
    accepted = recipient_report("250 2.1.5 recipient ok")

    assert unverifiable.observation.outcome is accepted.observation.outcome
    assert unverifiable.observation.is_about_the_target is True

    assert only(unverifiable).reason is ReasonCode.RCPT_UNVERIFIABLE
    assert only(accepted).reason is ReasonCode.RCPT_ACCEPTED


def test_the_positive_set_differs_from_the_recipient_set_by_exactly_252() -> None:
    """Section 7.4 expressed as code, so the two cannot quietly converge."""
    assert POSITIVE_RECIPIENT_REASONS < RECIPIENT_STAGE_REASONS
    assert ReasonCode.RCPT_UNVERIFIABLE in RECIPIENT_STAGE_REASONS
    assert ReasonCode.RCPT_UNVERIFIABLE not in POSITIVE_RECIPIENT_REASONS
    assert set(POSITIVE_RECIPIENT_REASONS) == {
        ReasonCode.RCPT_ACCEPTED,
        ReasonCode.RCPT_FORWARDED,
    }


# --- before the recipient stage ---------------------------------------------


@pytest.mark.parametrize(
    ("stage", "outcome", "reply", "defect", "reason", "temporary"),
    [
        (
            DialogueStage.BANNER,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("421 4.3.2 service not available",),
            None,
            ReasonCode.SMTP_POLICY_BLOCKED,
            True,
        ),
        (
            DialogueStage.BANNER,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("554 5.7.1 no SMTP service here",),
            None,
            ReasonCode.SMTP_POLICY_BLOCKED,
            False,
        ),
        (
            DialogueStage.BANNER,
            RecipientStageOutcome.PROTOCOL_ERROR,
            None,
            ReplyDefect.MALFORMED_LINE,
            ReasonCode.SMTP_BANNER_INVALID,
            False,
        ),
        (
            DialogueStage.EHLO,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("450 4.3.2 try again later",),
            None,
            ReasonCode.SMTP_POLICY_BLOCKED,
            True,
        ),
        (
            DialogueStage.EHLO,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("502 5.5.1 command not implemented",),
            None,
            ReasonCode.SMTP_POLICY_BLOCKED,
            False,
        ),
        (
            DialogueStage.EHLO,
            RecipientStageOutcome.PROTOCOL_ERROR,
            None,
            ReplyDefect.MALFORMED_LINE,
            ReasonCode.SMTP_PROTOCOL_ERROR,
            False,
        ),
        (
            DialogueStage.EHLO_AFTER_TLS,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("550 5.7.0 refused after TLS",),
            None,
            ReasonCode.SMTP_POLICY_BLOCKED,
            False,
        ),
        (
            DialogueStage.MAIL_FROM,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("451 4.3.0 try later",),
            None,
            ReasonCode.MAIL_FROM_REJECTED,
            True,
        ),
        (
            DialogueStage.MAIL_FROM,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("550 5.7.1 sender denied",),
            None,
            ReasonCode.MAIL_FROM_REJECTED,
            False,
        ),
        (
            DialogueStage.RCPT_TO,
            RecipientStageOutcome.CONNECTION_ERROR,
            None,
            None,
            ReasonCode.SMTP_CONNECTION_TIMEOUT,
            True,
        ),
        (
            DialogueStage.RCPT_TO,
            RecipientStageOutcome.PROTOCOL_ERROR,
            None,
            ReplyDefect.MALFORMED_LINE,
            ReasonCode.SMTP_PROTOCOL_ERROR,
            False,
        ),
    ],
)
def test_every_pre_recipient_failure_maps_as_the_table_says(
    stage: DialogueStage,
    outcome: RecipientStageOutcome,
    reply: tuple[str, ...] | None,
    defect: ReplyDefect | None,
    reason: ReasonCode,
    temporary: bool,
) -> None:
    report = pre_recipient_report(
        stage,
        outcome=outcome,
        reply=reply_of(*reply) if reply is not None else None,
        defect=defect,
    )
    evidence = only(report)

    assert evidence.reason is reason
    assert evidence.temporary is temporary
    assert evidence.reason in NON_TARGET_SMTP_REASONS
    assert evidence.details["about_the_target"] is False
    assert evidence.details["recipient_stage"] is False
    assert evidence.details["recipients_attempted"] == 0


def test_an_internal_failure_is_never_about_anything_remote() -> None:
    report = pre_recipient_report(DialogueStage.EHLO, outcome=RecipientStageOutcome.INTERNAL_ERROR)
    evidence = only(report)

    assert evidence.reason is ReasonCode.INTERNAL_ERROR
    assert evidence.layer is EvidenceLayer.INTERNAL
    assert evidence.temporary is False


# --- TLS ---------------------------------------------------------------------


@pytest.mark.parametrize("tls_reason", list(TLSFailureReason))
def test_every_tls_failure_is_one_non_target_reason(tls_reason: TLSFailureReason) -> None:
    """Seven reasons, one decision, and never mailbox invalidity."""
    report = pre_recipient_report(
        DialogueStage.STARTTLS,
        outcome=RecipientStageOutcome.TLS_ERROR,
        tls=TLSOutcomeDetail(negotiated=False, reason=tls_reason),
    )
    evidence = only(report)

    assert evidence.reason is ReasonCode.SMTP_TLS_FAILURE
    assert evidence.reason in NON_TARGET_SMTP_REASONS
    assert evidence.reason not in RECIPIENT_STAGE_REASONS
    assert evidence.temporary is False
    # The reason survives as metadata, so an operator can tell the seven apart.
    assert evidence.details["tls_reason"] == tls_reason.value
    assert evidence.details["tls_negotiated"] is False


def test_a_negotiated_session_records_tls_without_it_changing_the_reason() -> None:
    over_tls = only(recipient_report("250 ok", tls=TLSOutcomeDetail(negotiated=True)))
    plaintext = only(recipient_report("250 ok"))

    assert over_tls.reason is plaintext.reason
    assert over_tls.details["tls_negotiated"] is True
    assert plaintext.details["tls_negotiated"] is False


# --- the deadline ------------------------------------------------------------


def test_a_deadline_mid_dialogue_is_this_projects_own_bound() -> None:
    report = pre_recipient_report(DialogueStage.MAIL_FROM, deadline_exhausted=True)
    evidence = only(report)

    assert evidence.reason is ReasonCode.SMTP_CONNECTION_TIMEOUT
    assert evidence.temporary is True
    assert evidence.details["deadline_exhausted"] is True
    assert evidence.details["about_the_target"] is False


def test_a_transport_timeout_and_a_deadline_are_distinguishable() -> None:
    """Same reason code, and the flag is what tells an operator which it was."""
    ours = map_connect_failure(
        TransportFailure.CONNECT_TIMEOUT, observed_at=OBSERVED_AT, deadline_exhausted=True
    )[0]
    theirs = map_connect_failure(TransportFailure.CONNECT_TIMEOUT, observed_at=OBSERVED_AT)[0]

    assert ours.reason is theirs.reason is ReasonCode.SMTP_CONNECTION_TIMEOUT
    assert ours.details["deadline_exhausted"] is True
    assert theirs.details["deadline_exhausted"] is False


def test_a_deadline_at_the_cleanup_boundary_keeps_the_recipient_answer() -> None:
    """The budget ran out after the server had already answered.

    The recipient's reply is the evidence; the deadline is metadata on it. If
    this ever inverts, an accepted recipient silently becomes a timeout.
    """
    report = recipient_report(
        "250 2.1.5 recipient ok",
        cleanup=CleanupStatus.SKIPPED_DEADLINE,
        deadline_exhausted=True,
    )
    evidence = only(report)

    assert evidence.reason is ReasonCode.RCPT_ACCEPTED
    assert evidence.details["deadline_exhausted"] is True
    assert evidence.details["cleanup"] == "skipped_deadline"


# --- cleanup -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("cleanup", "deadline_exhausted"),
    [
        (CleanupStatus.COMPLETED, False),
        (CleanupStatus.INCOMPLETE, False),
        (CleanupStatus.NOT_ATTEMPTED, False),
        (CleanupStatus.SKIPPED_DEADLINE, True),
    ],
)
def test_cleanup_is_metadata_and_never_changes_the_answer(
    cleanup: CleanupStatus, deadline_exhausted: bool
) -> None:
    """`RSET` and `QUIT` happen after the question was answered."""
    baseline = only(recipient_report("250 2.1.5 recipient ok"))
    varied = only(
        recipient_report(
            "250 2.1.5 recipient ok", cleanup=cleanup, deadline_exhausted=deadline_exhausted
        )
    )

    assert varied.reason is baseline.reason
    assert varied.strength is baseline.strength
    assert varied.temporary is baseline.temporary
    assert varied.details["cleanup"] == cleanup.value

    # Everything else must be untouched, not merely the reason. A mutation that
    # left the reason alone and flipped `about_the_target` on a failed cleanup
    # escaped an earlier version of this test, which compared only the three
    # fields above.
    ignored = {"cleanup", "deadline_exhausted"}
    assert {key: value for key, value in varied.details.items() if key not in ignored} == {
        key: value for key, value in baseline.details.items() if key not in ignored
    }


def test_a_failed_cleanup_after_a_rejection_keeps_the_rejection() -> None:
    evidence = only(recipient_report("550 5.1.1 no such user", cleanup=CleanupStatus.INCOMPLETE))

    assert evidence.reason is ReasonCode.RCPT_REJECTED_ADDRESS
    assert evidence.details["cleanup"] == "incomplete"


# --- connect failures --------------------------------------------------------


@pytest.mark.parametrize(
    ("failure", "reason", "layer", "temporary"),
    [
        (
            TransportFailure.CONNECT_TIMEOUT,
            ReasonCode.SMTP_CONNECTION_TIMEOUT,
            EvidenceLayer.SMTP,
            True,
        ),
        (
            TransportFailure.CONNECTION_REFUSED,
            ReasonCode.SMTP_CONNECTION_REFUSED,
            EvidenceLayer.SMTP,
            True,
        ),
        (
            TransportFailure.CONNECTION_RESET,
            ReasonCode.SMTP_CONNECTION_TIMEOUT,
            EvidenceLayer.SMTP,
            True,
        ),
        (
            TransportFailure.TLS_CERTIFICATE_INVALID,
            ReasonCode.SMTP_TLS_FAILURE,
            EvidenceLayer.SMTP,
            False,
        ),
        (
            TransportFailure.TLS_HOSTNAME_MISMATCH,
            ReasonCode.SMTP_TLS_FAILURE,
            EvidenceLayer.SMTP,
            False,
        ),
        (TransportFailure.TLS_TIMEOUT, ReasonCode.SMTP_TLS_FAILURE, EvidenceLayer.SMTP, False),
        (
            TransportFailure.LINE_TOO_LONG,
            ReasonCode.SMTP_PROTOCOL_ERROR,
            EvidenceLayer.SMTP,
            False,
        ),
        (
            TransportFailure.PEER_ADDRESS_MISMATCH,
            ReasonCode.UNSAFE_DESTINATION,
            EvidenceLayer.DNS,
            False,
        ),
        (
            TransportFailure.DESTINATION_DENIED_BY_POLICY,
            ReasonCode.UNSAFE_DESTINATION,
            EvidenceLayer.DNS,
            False,
        ),
        (TransportFailure.INTERNAL_ERROR, ReasonCode.INTERNAL_ERROR, EvidenceLayer.INTERNAL, False),
    ],
)
def test_a_connect_failure_maps_conservatively(
    failure: TransportFailure,
    reason: ReasonCode,
    layer: EvidenceLayer,
    temporary: bool,
) -> None:
    (evidence,) = map_connect_failure(failure, observed_at=OBSERVED_AT)

    assert evidence.reason is reason
    assert evidence.layer is layer
    assert evidence.temporary is temporary
    assert evidence.reason in NON_TARGET_SMTP_REASONS
    assert evidence.details["transport_failure"] == failure.value
    assert evidence.details["about_the_target"] is False


def test_every_transport_failure_is_mapped() -> None:
    """A new member must fail here rather than default to something plausible."""
    for failure in TransportFailure:
        (evidence,) = map_connect_failure(failure, observed_at=OBSERVED_AT)
        assert isinstance(evidence.reason, ReasonCode), failure


def test_the_connect_table_covers_the_failure_enum_exactly() -> None:
    """Coverage in both directions: no member unmapped, no key that is not one."""
    assert set(_CONNECT_REASONS) == set(TransportFailure)


def test_an_unmapped_failure_raises_rather_than_defaulting() -> None:
    """The *mechanism*, which coverage alone cannot pin.

    The test above passes whether the lookup is `table[failure]` or
    `table.get(failure, SMTP_CONNECTION_TIMEOUT)`, because the table is the same
    either way. This one distinguishes them: a defaulting lookup would quietly
    call an unknown failure a timeout, which is a plausible answer about a remote
    host derived from nothing.
    """
    unmapped = object()

    with pytest.raises(KeyError):
        _connect_finding(unmapped, deadline_exhausted=False)  # type: ignore[arg-type]


# --- the published sets are a partition, and the derivation fails closed ------


def every_reason_the_mapper_can_emit() -> set[ReasonCode]:
    """A corpus broad enough to reach every branch of the classifier."""
    emitted: set[ReasonCode] = set()

    for lines in (
        ("250 2.1.5 recipient ok",),
        ("251 2.1.5 will forward",),
        ("252 2.1.5 cannot verify user",),
        ("450 4.2.1 mailbox busy",),
        ("452 4.2.2 insufficient storage",),
        ("550 5.1.1 no such user",),
        ("550 5.7.1 policy rejection",),
        ("550 mailbox unavailable",),
    ):
        emitted.add(only(recipient_report(*lines)).reason)

    pre_recipient = (
        (DialogueStage.BANNER, RecipientStageOutcome.PROTOCOL_ERROR, None, ReplyDefect.EMPTY),
        (
            DialogueStage.EHLO,
            RecipientStageOutcome.PROTOCOL_ERROR,
            None,
            ReplyDefect.MALFORMED_LINE,
        ),
        (
            DialogueStage.BANNER,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("554 5.7.1 go away",),
            None,
        ),
        (
            DialogueStage.MAIL_FROM,
            RecipientStageOutcome.CONNECTION_ERROR,
            ("550 5.7.1 sender denied",),
            None,
        ),
        (DialogueStage.STARTTLS, RecipientStageOutcome.TLS_ERROR, None, None),
        (DialogueStage.EHLO, RecipientStageOutcome.INTERNAL_ERROR, None, None),
        (DialogueStage.EHLO, RecipientStageOutcome.CONNECTION_ERROR, None, None),
    )
    for stage, outcome, lines, defect in pre_recipient:
        report = pre_recipient_report(
            stage,
            outcome=outcome,
            reply=reply_of(*lines) if lines is not None else None,
            defect=defect,
        )
        emitted.add(only(report).reason)

    for failure in TransportFailure:
        emitted.add(map_connect_failure(failure, observed_at=OBSERVED_AT)[0].reason)

    return emitted


def test_the_two_published_sets_are_disjoint() -> None:
    """A reason in both would make `about_the_target` depend on which is read."""
    assert set(NON_TARGET_SMTP_REASONS & RECIPIENT_STAGE_REASONS) == set()


def test_every_reason_the_mapper_emits_is_in_exactly_one_published_set() -> None:
    """Missing from both is forbidden, and so is present in both.

    Missing from both is the dangerous one: `about_the_target` is derived from
    `RECIPIENT_STAGE_REASONS`, so an unclassified reason is silently non-target,
    and the sets stop describing what the mapper does without anything failing.
    """
    unclassified: list[ReasonCode] = []
    for reason in every_reason_the_mapper_can_emit():
        memberships = sum(
            (reason in NON_TARGET_SMTP_REASONS, reason in RECIPIENT_STAGE_REASONS),
        )
        if memberships != 1:
            unclassified.append(reason)
    assert unclassified == [], f"a reason is in neither set or in both: {unclassified}"


def test_every_declared_member_of_both_sets_is_actually_emitted() -> None:
    """The other direction: a set may not declare a reason the mapper never makes.

    A declared-but-dead member is how a set stops being a description of the code
    and becomes a wish about it.
    """
    emitted = every_reason_the_mapper_can_emit()
    declared = NON_TARGET_SMTP_REASONS | RECIPIENT_STAGE_REASONS

    assert declared - emitted == set(), f"declared but never emitted: {declared - emitted}"
    assert emitted - declared == set(), f"emitted but undeclared: {emitted - declared}"


def test_the_target_question_fails_closed_on_an_unclassified_reason() -> None:
    """The reason the derivation is written the way it is.

    `MX_AVAILABLE` is a published reason this mapper never emits, so it stands in
    for one added later and forgotten from both sets. Under the old form,
    `reason not in NON_TARGET_SMTP_REASONS`, it would be reported as evidence
    about the address.
    """
    stranger = ReasonCode.MX_AVAILABLE
    assert stranger not in NON_TARGET_SMTP_REASONS
    assert stranger not in RECIPIENT_STAGE_REASONS

    assert _is_about_the_target(stranger) is False


def test_the_target_detail_agrees_with_the_recipient_stage_detail() -> None:
    """Both derive from the same set, so they may not diverge on any input."""
    for lines in (("250 ok",), ("252 2.1.5 cannot verify",), ("550 5.1.1 no such user",)):
        evidence = only(recipient_report(*lines))
        assert evidence.details["about_the_target"] is evidence.details["recipient_stage"] is True

    for failure in TransportFailure:
        (evidence,) = map_connect_failure(failure, observed_at=OBSERVED_AT)
        assert evidence.details["about_the_target"] is False, failure
        assert evidence.details["recipient_stage"] is False, failure


@pytest.mark.parametrize(
    "reason",
    [
        ReasonCode.RCPT_UNVERIFIABLE,
        ReasonCode.RCPT_REJECTED_ADDRESS,
        ReasonCode.RCPT_REJECTED_POLICY,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ReasonCode.MAILBOX_FULL,
        ReasonCode.SMTP_TEMPORARY_FAILURE,
    ],
)
def test_no_negative_or_ambiguous_reason_is_positive_evidence(reason: ReasonCode) -> None:
    """Named one by one rather than left to the subset relation.

    `POSITIVE_RECIPIENT_REASONS < RECIPIENT_STAGE_REASONS` stays true if a
    rejection is added to the positive set and a different member is removed.
    """
    assert reason in RECIPIENT_STAGE_REASONS
    assert reason not in POSITIVE_RECIPIENT_REASONS


# --- what a caller may hand the connect entry point ---------------------------


@pytest.mark.parametrize("elapsed", [-1, -5, True, False, 12.0, "12", object()])
def test_map_connect_failure_refuses_an_unusable_elapsed_time(elapsed: object) -> None:
    """The session path refuses these through `RecipientObservation`.

    Two entry points into one module must not answer to two contracts. A boolean
    is refused despite `bool` being an `int`, because `True` would be recorded as
    one millisecond.
    """
    with pytest.raises(ValueError):
        map_connect_failure(
            TransportFailure.CONNECT_TIMEOUT,
            observed_at=OBSERVED_AT,
            elapsed_milliseconds=elapsed,  # type: ignore[arg-type]
        )


def test_map_connect_failure_accepts_no_timing_and_a_whole_number() -> None:
    for elapsed in (None, 0, 1, 45_000):
        (evidence,) = map_connect_failure(
            TransportFailure.CONNECT_TIMEOUT,
            observed_at=OBSERVED_AT,
            elapsed_milliseconds=elapsed,
        )
        assert evidence.details["elapsed_milliseconds"] == elapsed


@pytest.mark.parametrize(
    "observed_at",
    [None, "2026-08-08T12:00:00Z", 1_754_654_400, object(), datetime(2026, 8, 8, 12, 0)],
)
def test_both_entry_points_refuse_a_timestamp_that_is_not_aware(observed_at: object) -> None:
    """A naive datetime is the one that gets through review.

    It is a `datetime`, it prints plausibly, and it raises `TypeError` the first
    time Phase 5 compares it against an aware one from another producer.

    **Matched on the entry point's own message**, because `Evidence` refuses the
    same value a few lines later and a bare `pytest.raises(ValueError)` would
    pass with this check deleted. Two barriers are only two barriers if each is
    pinned by its own test, and the value type has its own in
    `tests/unit/domain/test_evidence.py`.
    """
    with pytest.raises(ValueError, match=r"^observed_at must"):
        map_connect_failure(TransportFailure.CONNECT_TIMEOUT, observed_at=observed_at)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"^observed_at must"):
        map_session_evidence(recipient_report("250 ok"), observed_at=observed_at)  # type: ignore[arg-type]


def test_a_non_utc_offset_is_accepted_because_it_is_still_orderable() -> None:
    """The requirement is an explicit offset, not one particular offset."""
    tokyo = datetime(2026, 8, 8, 21, 0, tzinfo=timezone(timedelta(hours=9)))

    (evidence,) = map_connect_failure(TransportFailure.CONNECT_TIMEOUT, observed_at=tokyo)

    assert evidence.observed_at == OBSERVED_AT


def test_map_connect_failure_refuses_arguments_of_the_wrong_type() -> None:
    with pytest.raises(ValueError):
        map_connect_failure("connect_timeout", observed_at=OBSERVED_AT)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        map_connect_failure(
            TransportFailure.CONNECT_TIMEOUT,
            observed_at=OBSERVED_AT,
            deadline_exhausted="yes",  # type: ignore[arg-type]
        )


# --- the enhanced-code helpers refuse on their own ---------------------------


def test_an_address_shaped_code_on_a_transient_class_is_not_a_rejection() -> None:
    """`_identifies_the_recipient` checks the class rather than assuming it.

    Three separate things already keep `4.1.1` away from this branch: the 4A
    parser drops an enhanced code contradicting the basic one, `SMTPReply`
    refuses to carry the contradiction, and the classifier reads `is_transient`
    first. None of them is a property of the helper, and a helper that turns
    `4.1.1` into the strongest evidence this project produces should refuse by
    itself.
    """
    assert _identifies_the_recipient(EnhancedStatusCode(5, 1, 1)) is True
    assert _identifies_the_recipient(EnhancedStatusCode(4, 1, 1)) is False
    assert _identifies_the_recipient(EnhancedStatusCode(2, 1, 1)) is False
    assert _identifies_the_recipient(None) is False


def test_a_transient_policy_code_is_not_a_permanent_policy_refusal() -> None:
    """`4.7.1` is greylisting far more often than it is a policy refusal."""
    assert _is_policy_refusal(EnhancedStatusCode(5, 7, 1)) is True
    assert _is_policy_refusal(EnhancedStatusCode(4, 7, 1)) is False
    assert _is_policy_refusal(None) is False


# --- the invariants ----------------------------------------------------------


def test_no_pre_recipient_failure_ever_produces_a_recipient_reason() -> None:
    """The single worst mistake this mapping could make, enumerated.

    Every stage, with and without a reply, with and without a deadline: none of
    them may produce a reason that describes the recipient.
    """
    replies = (None, reply_of("550 5.1.1 no such user"), reply_of("450 4.2.1 busy"))
    for stage in DialogueStage:
        if stage in {DialogueStage.RCPT_TO, DialogueStage.CLEANUP}:
            continue
        for reply in replies:
            for deadline_exhausted in (False, True):
                report = pre_recipient_report(
                    stage, reply=reply, deadline_exhausted=deadline_exhausted
                )
                evidence = only(report)
                assert evidence.reason not in RECIPIENT_STAGE_REASONS, (stage, reply)
                assert evidence.reason in NON_TARGET_SMTP_REASONS, (stage, reply)


def test_a_mail_from_rejection_is_never_a_recipient_rejection() -> None:
    """`550` at `MAIL FROM` looks exactly like `550` at `RCPT TO` and is not."""
    sender = only(
        pre_recipient_report(DialogueStage.MAIL_FROM, reply=reply_of("550 5.1.1 sender unknown"))
    )
    recipient = only(recipient_report("550 5.1.1 no such user"))

    assert sender.reason is ReasonCode.MAIL_FROM_REJECTED
    assert sender.reason is not ReasonCode.RCPT_REJECTED_ADDRESS
    assert sender.details["about_the_target"] is False
    # Even carrying the same enhanced code, they are different evidence.
    assert sender.details["enhanced_code"] == recipient.details["enhanced_code"] == "5.1.1"
    assert recipient.reason is ReasonCode.RCPT_REJECTED_ADDRESS


def test_a_banner_rejection_is_never_target_evidence() -> None:
    evidence = only(pre_recipient_report(DialogueStage.BANNER, reply=reply_of("550 5.1.1 go away")))

    assert evidence.reason is ReasonCode.SMTP_POLICY_BLOCKED
    assert evidence.details["about_the_target"] is False


def test_the_strongest_recipient_evidence_is_still_not_a_status() -> None:
    """`550 5.1.1` is the strongest thing this project produces, and it is evidence."""
    evidence = only(recipient_report("550 5.1.1 no such user"))

    assert evidence.strength is EvidenceStrength.STRONG
    assert isinstance(evidence, Evidence)
    rendered = repr(evidence)
    for vocabulary in ("likely_deliverable", "temporary_unknown", "confidence", "Verdict"):
        assert vocabulary not in rendered


@pytest.mark.parametrize(
    "lines",
    [
        ("250 2.1.5 recipient ok",),
        ("252 2.1.5 cannot verify user",),
        ("450 4.2.1 mailbox busy",),
        ("550 5.1.1 no such user",),
        ("550 5.7.1 policy rejection",),
    ],
)
def test_no_mapping_produces_a_status_or_a_risk_flag(lines: tuple[str, ...]) -> None:
    evidence = only(recipient_report(*lines))

    assert isinstance(evidence.reason, ReasonCode)
    assert evidence.layer in set(EvidenceLayer)
    assert evidence.strength in set(EvidenceStrength)
    assert not hasattr(evidence, "status")
    assert not hasattr(evidence, "confidence")
    assert not hasattr(evidence, "risk_flags")


def test_the_ruleset_version_is_recorded_on_every_piece_of_evidence() -> None:
    assert only(recipient_report("250 ok")).source_version == SMTP_EVIDENCE_RULESET
    assert (
        map_connect_failure(TransportFailure.CONNECT_TIMEOUT, observed_at=OBSERVED_AT)[
            0
        ].source_version
        == SMTP_EVIDENCE_RULESET
    )


# --- privacy -----------------------------------------------------------------

ECHOED = "550 5.1.1 <probe.target@recipient.test.example> unknown"


def test_a_reply_echoing_the_recipient_does_not_leak_it() -> None:
    """Ten surfaces, because one of them is the one Phase 6 will publish."""
    evidence = only(recipient_report(ECHOED))

    surfaces = [
        repr(evidence),
        str(evidence),
        repr(evidence.details),
        str(dict(evidence.details)),
        str(evidence.reason),
        str(evidence.details.get("diagnostic")),
    ]
    for surface in surfaces:
        assert "probe.target@recipient.test.example" not in surface
        assert "probe.target" not in surface
        assert "@" not in surface


def test_no_raw_reply_or_locally_issued_wire_text_survives_into_the_details() -> None:
    """What is stored is codes and flags, never this project's own transcript.

    The name is precise on purpose. The details carry no reply line, no command
    this project issued, no transcript, and no certificate — but see the test
    below for what a *server's* own prose may legitimately contain, which an
    earlier name for this test claimed it did not.
    """
    evidence = only(recipient_report("550 5.1.1 no such user", cleanup=CleanupStatus.INCOMPLETE))
    rendered = repr(evidence.details)

    for forbidden in ("RCPT TO", "MAIL FROM", "EHLO", "\r\n", "BEGIN CERTIFICATE"):
        assert forbidden not in rendered
    # The reply line itself is gone; only its parts survive, each in its own key.
    assert "550 5.1.1" not in rendered
    assert evidence.details["diagnostic"] == "no such user"
    assert evidence.details["basic_code"] == 550
    assert evidence.details["enhanced_code"] == "5.1.1"
    assert "commands_issued" not in evidence.details
    assert "transcript" not in evidence.details


def test_a_servers_own_prose_may_contain_command_words_and_that_is_not_a_leak() -> None:
    """The guarantee stated at the size of what holds.

    A server is free to write `RCPT TO is not allowed here`, and that text
    survives into the bounded diagnostic. It is remote prose, not a wire command:
    it is length-bounded, `@`-free, and stripped of control characters by the
    Phase 4A sanitizer, and it is the only thing that says *why* a server
    answered as it did. A test forbidding the string outright would assert
    something untrue and pass only by its fixture's wording.
    """
    evidence = only(recipient_report("550 RCPT TO is not allowed here"))

    assert evidence.details["diagnostic"] == "RCPT TO is not allowed here"
    assert evidence.reason is ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE
    # Bounded, address-free, and control-free is the whole of the promise.
    diagnostic = evidence.details["diagnostic"]
    assert isinstance(diagnostic, str)
    assert "@" not in diagnostic
    assert all(character.isprintable() for character in diagnostic)


def test_the_detail_values_are_all_safe_scalars() -> None:
    for report in (
        recipient_report("250 ok"),
        pre_recipient_report(DialogueStage.BANNER, reply=reply_of("421 4.3.2 busy")),
    ):
        for key, value in only(report).details.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, str | int | bool), key


def test_a_connect_failure_carries_no_peer_address() -> None:
    (evidence,) = map_connect_failure(
        TransportFailure.PEER_ADDRESS_MISMATCH, observed_at=OBSERVED_AT
    )
    rendered = repr(evidence)

    assert "93.184" not in rendered
    assert "@" not in rendered


# --- determinism -------------------------------------------------------------


def test_the_same_report_always_produces_the_same_evidence() -> None:
    report = recipient_report("550 5.1.1 no such user", cleanup=CleanupStatus.INCOMPLETE)

    first = map_session_evidence(report, observed_at=OBSERVED_AT)
    second = map_session_evidence(report, observed_at=OBSERVED_AT)

    assert first == second
    assert [dict(item.details) for item in first] == [dict(item.details) for item in second]
    assert [list(item.details) for item in first] == [list(item.details) for item in second]


def test_two_equal_reports_produce_equal_evidence() -> None:
    """Nothing depends on object identity or on set iteration order."""
    one = map_session_evidence(recipient_report("250 ok"), observed_at=OBSERVED_AT)
    other = map_session_evidence(recipient_report("250 ok"), observed_at=OBSERVED_AT)

    assert one == other


def test_the_detail_key_order_is_fixed() -> None:
    expected = [
        "stage_reached",
        "recipient_stage",
        "about_the_target",
        "basic_code",
        "enhanced_code",
        "diagnostic",
        "defect",
        "tls_negotiated",
        "tls_reason",
        "deadline_exhausted",
        "cleanup",
        "recipients_attempted",
        "no_message_data_sent",
        "elapsed_milliseconds",
    ]
    assert list(only(recipient_report("250 ok")).details) == expected


def test_the_primary_observation_is_the_first_item() -> None:
    """The documented ordering rule, asserted where a later gate would break it."""
    produced = map_session_evidence(recipient_report("250 ok"), observed_at=OBSERVED_AT)

    assert produced[0].reason in RECIPIENT_STAGE_REASONS
    assert len(produced) == 1


def test_the_promise_that_no_message_content_was_sent_reaches_the_evidence() -> None:
    assert only(recipient_report("250 ok")).details["no_message_data_sent"] is True
    assert (
        map_connect_failure(TransportFailure.CONNECT_TIMEOUT, observed_at=OBSERVED_AT)[0].details[
            "no_message_data_sent"
        ]
        is True
    )


def test_the_timestamp_is_the_callers_and_not_a_clocks() -> None:
    """A mapper that read a clock would not be a pure function."""
    other = datetime(2020, 1, 1, tzinfo=UTC)

    assert only(recipient_report("250 ok")).observed_at == OBSERVED_AT
    assert (
        map_session_evidence(recipient_report("250 ok"), observed_at=other)[0].observed_at is other
    )


def test_a_temporary_reply_is_never_converted_into_a_rejection() -> None:
    """The basic class outranks an address-shaped enhanced code.

    `450 4.1.1` reads like `550 5.1.1` one component at a time, and it is a
    transient failure: RFC 3463 class 4 says so, and `docs/requirements.md`
    section 17 makes "temporary failures are not converted to invalid" a quality
    target. A mutation that read the subject and detail before the class turned
    this into the strongest evidence this project produces, and no row in the
    matrix noticed until this one existed.
    """
    for lines in (
        ("450 4.1.1 recipient unknown right now",),
        ("451 4.1.1 try again",),
        ("452 4.1.1 not now",),
    ):
        evidence = only(recipient_report(*lines))
        assert evidence.reason is ReasonCode.SMTP_TEMPORARY_FAILURE, lines
        assert evidence.reason is not ReasonCode.RCPT_REJECTED_ADDRESS
        assert evidence.temporary is True
        assert evidence.strength is not EvidenceStrength.STRONG


def test_an_enhanced_code_is_only_read_where_the_table_reads_one() -> None:
    """Sanity on the branch order: `252` outranks `X.2.2`, which outranks class."""
    assert only(recipient_report("252 2.1.5 cannot verify")).reason is ReasonCode.RCPT_UNVERIFIABLE
    assert only(recipient_report("452 4.2.2 no room")).reason is ReasonCode.MAILBOX_FULL
    assert only(recipient_report("452 4.3.1 no room")).reason is ReasonCode.SMTP_TEMPORARY_FAILURE


def test_a_reply_defect_is_carried_for_a_protocol_error() -> None:
    evidence = only(
        pre_recipient_report(
            DialogueStage.EHLO,
            outcome=RecipientStageOutcome.PROTOCOL_ERROR,
            defect=ReplyDefect.TOO_MANY_LINES,
        )
    )

    assert evidence.reason is ReasonCode.SMTP_PROTOCOL_ERROR
    assert evidence.details["defect"] == "too_many_lines"


def test_an_enhanced_status_value_is_the_published_string() -> None:
    assert EnhancedStatusCode(5, 1, 1).value == "5.1.1"
    assert only(recipient_report("550 5.1.1 no such user")).details["enhanced_code"] == "5.1.1"


# --- the mapper is pure, and inspected for it --------------------------------

MAPPER = (
    Path(__file__).resolve().parents[3] / "src" / "emailcheck" / "application" / "smtp_evidence.py"
)

#: Anything that could reach the network, a clock, or storage. A mapping that
#: acquired one of these would stop being a function of its input.
FORBIDDEN_IMPORTS = frozenset(
    {
        "socket",
        "asyncio",
        "ssl",
        "smtplib",
        "dns",
        "dnspython",
        "http",
        "urllib",
        "requests",
        "time",
        "random",
        "os",
        "pathlib",
        "sqlite3",
    }
)

#: Collaborators that would make this an orchestration step rather than a
#: mapping. `RiskFlag` is here too: Phase 4D produces no risk flag, because risk
#: is orthogonal to deliverability and nothing an SMTP reply says is one.
FORBIDDEN_NAMES = frozenset(
    {
        "ProviderFamily",
        "SMTPTransport",
        "SMTPConnection",
        "SMTPProber",
        "RateLimiter",
        "RateLimitLease",
        "Clock",
        "MonotonicClock",
        "SMTPDialogue",
        "SMTPProbeService",
        "SMTPConnector",
        "Status",
        "Verdict",
        "Confidence",
        "RiskFlag",
        "aggregate_evidence",
    }
)


def _mapper_tree() -> ast.Module:
    return ast.parse(MAPPER.read_text(encoding="utf-8"))


def test_the_mapper_imports_nothing_that_could_reach_the_world() -> None:
    offences: list[str] = []
    for node in ast.walk(_mapper_tree()):
        if isinstance(node, ast.Import):
            offences.extend(
                f"{alias.name}:{node.lineno}"
                for alias in node.names
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] in FORBIDDEN_IMPORTS
        ):
            offences.append(f"{node.module}:{node.lineno}")
    assert offences == [], f"the evidence mapper imports something impure: {offences}"


def test_the_mapper_names_no_collaborator_it_should_not_have() -> None:
    offences: list[str] = []
    for node in ast.walk(_mapper_tree()):
        for attribute in ("id", "attr", "name"):
            value = getattr(node, attribute, None)
            if isinstance(value, str) and value in FORBIDDEN_NAMES:
                offences.append(f"{value}:{node.lineno}")
        if isinstance(node, ast.ImportFrom | ast.Import):
            offences.extend(
                f"{alias.name}:{node.lineno}"
                for alias in node.names
                if alias.name in FORBIDDEN_NAMES
            )
    assert offences == [], f"the evidence mapper depends on a collaborator: {offences}"


def test_the_mapper_defines_no_coroutine_and_awaits_nothing() -> None:
    """A pure mapping has nothing to wait for."""
    for node in ast.walk(_mapper_tree()):
        assert not isinstance(node, ast.AsyncFunctionDef | ast.Await | ast.AsyncWith)


def test_the_mapper_reads_no_ambient_state() -> None:
    """No environment, no import-time file reads, no global mutation."""
    source = MAPPER.read_text(encoding="utf-8")
    for forbidden in ("environ", "getenv", "open(", "monotonic", "now(", "utcnow"):
        assert forbidden not in source, forbidden


def test_the_mapper_names_no_provider() -> None:
    """A behavioural test cannot enumerate the providers it has not thought of.

    The dialogue's own inspection already covers every module with `smtp` in its
    name, which includes this one; asserted here as well so the property is
    visible where the mapping lives.
    """
    providers = ("google", "gmail", "microsoft", "outlook", "yahoo", "proton", "zoho", "icloud")
    source = MAPPER.read_text(encoding="utf-8").lower()
    found = [provider for provider in providers if provider in source]
    assert found == [], f"the evidence mapper names a provider: {found}"


def test_the_mapper_produces_no_final_status_object() -> None:
    """It returns evidence. Building a verdict here would be Phase 5 in disguise."""
    import inspect as inspection

    from emailcheck.application import smtp_evidence

    for name, value in vars(smtp_evidence).items():
        if inspection.isclass(value) and value.__module__ == smtp_evidence.__name__:
            assert "Verdict" not in name
            assert "Status" not in name
    signature = inspection.signature(map_session_evidence)
    assert str(signature.return_annotation) == "tuple[Evidence, ...]"
