"""The two items Phase 4D deferred to Phase 5, closed before aggregation.

`docs/status-model.md` section 7.6 records both:

- `RecipientStageOutcome` extension was silent. A member added to that enum fell
  through every named branch and was reported as `smtp_connection_timeout`;
- `LINE_TOO_LONG` and `TOTAL_LIMIT_EXCEEDED` map by entry point.

They belong here rather than in Phase 4E for the same reason: neither changes a
verdict until something is weighing verdicts, and Phase 5 is that thing.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from emailcheck.application.aggregate import aggregate_evidence, is_about_the_target
from emailcheck.application.smtp_evidence import (
    NON_TARGET_SMTP_REASONS,
    _require_known_outcome,
    map_connect_failure,
    map_session_evidence,
)
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPState
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSOutcomeDetail
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.domain.verdict import Status

OBSERVED_AT = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)

SOURCE = Path("src/emailcheck/application/smtp_evidence.py")


def lost_connection_report() -> SessionReport:
    """A dialogue that ended with no reply — how a bounded read arrives here.

    `SessionReport` carries no `TransportFailure`, which is the 4C contract this
    whole stop condition is a consequence of, so an over-long line and a reset
    connection reach this module in exactly the same shape.
    """
    return SessionReport(
        observation=RecipientObservation(
            outcome=RecipientStageOutcome.CONNECTION_ERROR,
            final_state=SMTPState.CLOSED,
            reply=None,
            tls_used=False,
            recipients_attempted=0,
            elapsed_milliseconds=45,
        ),
        stage_reached=DialogueStage.EHLO,
        tls=TLSOutcomeDetail(),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=(),
        deadline_exhausted=False,
    )


# --- 0A: RecipientStageOutcome exhaustiveness -------------------------------


def test_every_outcome_the_enum_publishes_is_recognised() -> None:
    """The guard admits exactly today's members, and complains about nothing."""
    for outcome in RecipientStageOutcome:
        _require_known_outcome(outcome)


def test_an_unrecognised_outcome_fails_loudly_rather_than_becoming_a_timeout() -> None:
    """The regression this stop condition exists for.

    A new member used to fall through every branch, miss the
    `_RECIPIENT_ANSWERS` barrier, and be reported as `smtp_connection_timeout` —
    temporary, non-target, and entirely invented. There is no way to add an enum
    member at run time, so the guard is exercised with a value that is not one:
    the failure mode is identical, and it is the *loudness* being asserted.
    """
    with pytest.raises(AssertionError):
        _require_known_outcome("some_outcome_added_in_a_later_gate")  # type: ignore[arg-type]


def report_with_outcome(outcome: RecipientStageOutcome) -> SessionReport:
    """A session report carrying an arbitrary outcome.

    `RecipientObservation` validates the recipient count, the elapsed time, and
    the reply-versus-outcome pairing, but it does not check that `outcome` is a
    member of the enum. That is what makes the test below possible: an outcome
    the classifier has never heard of is constructible today, and it stands in
    for the enum member a later gate adds.
    """
    return SessionReport(
        observation=RecipientObservation(
            outcome=outcome,
            final_state=SMTPState.CLOSED,
            reply=None,
            tls_used=False,
            recipients_attempted=0,
            elapsed_milliseconds=45,
        ),
        stage_reached=DialogueStage.RCPT_TO,
        tls=TLSOutcomeDetail(),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=(),
        deadline_exhausted=False,
    )


def test_the_mapper_itself_refuses_an_outcome_it_does_not_recognise() -> None:
    """The guard wired in, not merely present.

    A guard that exists and is never called is exactly the shape this project
    keeps finding, and it is what a mutation found here: deleting the
    `_require_known_outcome(...)` line from `_classify` left the entire suite
    passing while an unrecognised outcome went back to being reported as
    `smtp_connection_timeout` — temporary, non-target, and invented.

    So the property is asserted through the public entry point, on a report that
    is constructible today.
    """
    with pytest.raises(AssertionError):
        map_session_evidence(
            report_with_outcome("some_outcome_added_in_a_later_gate"),  # type: ignore[arg-type]
            observed_at=OBSERVED_AT,
        )


def test_every_published_outcome_still_maps_through_the_public_entry_point() -> None:
    """The other half: the guard refuses nothing it should admit."""
    for outcome in RecipientStageOutcome:
        if outcome in {
            # These two carry their own construction invariants — a reply and a
            # defect respectively — and the rest of the matrix covers them.
            RecipientStageOutcome.ACCEPTED,
            RecipientStageOutcome.REJECTED,
            RecipientStageOutcome.PROTOCOL_ERROR,
        }:
            continue
        (evidence,) = map_session_evidence(report_with_outcome(outcome), observed_at=OBSERVED_AT)
        assert evidence.reason in ReasonCode


@pytest.mark.inspection
def test_the_exhaustiveness_guard_is_called_before_any_branch_decides() -> None:
    """Read out of the syntax tree, because position is what makes it total.

    A guard called at the bottom of `_classify` would be a guard every `return`
    above it skips. It is the first statement after the observation is bound,
    and this fixes that.
    """
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    classify = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_classify"
    )
    calls = [
        node.lineno
        for node in ast.walk(classify)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_require_known_outcome"
    ]
    assert len(calls) == 1

    returns = [node.lineno for node in ast.walk(classify) if isinstance(node, ast.Return)]
    assert calls[0] < min(returns)


@pytest.mark.inspection
def test_the_exhaustiveness_guard_uses_assert_never_rather_than_a_default() -> None:
    """Read out of the syntax tree, because a default is what this forbids.

    `.get(outcome, SMTP_CONNECTION_TIMEOUT)` and `case _: return _pre_recipient`
    both satisfy every behavioural test above while restoring exactly the
    silence the stop condition names. Only the mechanism distinguishes them, so
    the mechanism is what is asserted — the same argument that pinned
    `_CONNECT_REASONS`.
    """
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    guard = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_require_known_outcome"
    )
    calls = {
        node.func.id
        for node in ast.walk(guard)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "assert_never" in calls

    matches = [node for node in ast.walk(guard) if isinstance(node, ast.Match)]
    assert len(matches) == 1
    named = {
        node.attr
        for node in ast.walk(matches[0])
        if isinstance(node, ast.Attribute) and node.value.__class__ is ast.Name
    }
    assert {outcome.name for outcome in RecipientStageOutcome} <= named


@pytest.mark.inspection
def test_the_guard_is_not_the_dispatch_so_the_4d_barriers_survive() -> None:
    """A `match` that routed the outcome would delete a reviewed barrier.

    `_recipient_reply` checks `outcome not in _RECIPIENT_ANSWERS` as the first of
    the three barriers between a `MAIL FROM 550` and a recipient rejection, and
    that check is pinned by a test which fails when it alone is removed. A
    dispatching `match` would send `CONNECTION_ERROR` to the pre-recipient path
    directly, making the check unreachable and its test vacuous.

    So the guard must return `None` and decide nothing — asserted here, because
    "tidy this up into the dispatch" is exactly the edit someone makes later.
    """
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    guard = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_require_known_outcome"
    )
    assert isinstance(guard.returns, ast.Constant)
    assert guard.returns.value is None
    for node in ast.walk(guard):
        if isinstance(node, ast.Return):
            assert node.value is None


# --- 0B: the LINE_TOO_LONG entry-point difference ---------------------------


BOUNDED_READ_FAILURES = (
    TransportFailure.LINE_TOO_LONG,
    TransportFailure.TOTAL_LIMIT_EXCEEDED,
)


@pytest.mark.parametrize("failure", BOUNDED_READ_FAILURES)
def test_a_bounded_read_through_the_connect_entry_point_is_a_protocol_error(
    failure: TransportFailure,
) -> None:
    """Decision B: the difference is kept, as entry-point provenance.

    Here the caller *knows* which bound was reached, so the evidence says so.
    """
    (evidence,) = map_connect_failure(failure, observed_at=OBSERVED_AT)

    assert evidence.reason is ReasonCode.SMTP_PROTOCOL_ERROR
    assert evidence.temporary is False
    assert evidence.details["transport_failure"] == failure.value


def test_a_bounded_read_reached_mid_dialogue_is_a_connection_timeout() -> None:
    """The other entry point, and the reason the two differ.

    A `SessionReport` carries no `TransportFailure` — a reviewed 4C contract —
    so the session path cannot know a bound was reached rather than the peer
    going away. It reports the conservative reading of what it *can* see, which
    is a lost connection, and that one is retryable.
    """
    (evidence,) = map_session_evidence(lost_connection_report(), observed_at=OBSERVED_AT)

    assert evidence.reason is ReasonCode.SMTP_CONNECTION_TIMEOUT
    assert evidence.temporary is True


def test_the_two_readings_differ_only_in_ways_that_cannot_reach_a_verdict() -> None:
    """What makes decision B safe, asserted rather than argued.

    The two entry points produce different reason codes and different
    permanence, and permanence is not cosmetic — it separates `temporary_unknown`
    from `unknown`. What must hold is the bound on how far the difference can
    travel: **neither reading is ever about the target and neither can ever
    produce `invalid`**, so no entry point can turn a bounded read into a
    statement about someone's mailbox.
    """
    (through_connect,) = map_connect_failure(
        TransportFailure.LINE_TOO_LONG, observed_at=OBSERVED_AT
    )
    (mid_dialogue,) = map_session_evidence(lost_connection_report(), observed_at=OBSERVED_AT)

    assert through_connect.reason is not mid_dialogue.reason
    for evidence in (through_connect, mid_dialogue):
        assert evidence.reason in NON_TARGET_SMTP_REASONS
        assert is_about_the_target(evidence) is False
        assert evidence.details["about_the_target"] is False
        assert aggregate_evidence((evidence,)).status is not Status.INVALID


def test_the_documented_difference_in_status_is_the_one_that_is_implemented() -> None:
    """Pinned end to end, so the collapse cannot happen by accident either.

    An edit that made the two agree would change one of these statuses, and an
    edit that widened either into target evidence would change both. Recording
    the difference in a document is not the same as fixing it.
    """
    (through_connect,) = map_connect_failure(
        TransportFailure.TOTAL_LIMIT_EXCEEDED, observed_at=OBSERVED_AT
    )
    (mid_dialogue,) = map_session_evidence(lost_connection_report(), observed_at=OBSERVED_AT)

    assert aggregate_evidence((through_connect,)).status is Status.UNKNOWN
    assert aggregate_evidence((mid_dialogue,)).status is Status.TEMPORARY_UNKNOWN
