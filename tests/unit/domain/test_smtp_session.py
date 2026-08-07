"""The state machine, and the three things it must refuse.

One `RCPT TO` per session, no plaintext after a TLS failure, and no message
transaction at all. Each is tested against the type rather than against a
convention, because a convention is what the application layer forgets.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from emailcheck.domain.dns import HostName
from emailcheck.domain.mail_route import CandidateStatus, RouteCandidate, RouteSource
from emailcheck.domain.smtp_contract import (
    SMTPCommand,
    SMTPContractError,
    SMTPState,
    allowed_commands,
)
from emailcheck.domain.smtp_destination import ApprovedDestination, ConfirmedPeer
from emailcheck.domain.smtp_session import (
    MAX_RECIPIENTS_PER_SESSION,
    CommandPermitted,
    CommandRefusal,
    CommandRefused,
    SMTPSession,
    begin_session,
)
from emailcheck.security.destination import DestinationDecision

PUBLIC_ADDRESS = "93.184.216.34"


def peer() -> ConfirmedPeer:
    approved = ApprovedDestination(host=HostName("mx.example.com"), address=PUBLIC_ADDRESS)
    return ConfirmedPeer(approved=approved, peer_address=PUBLIC_ADDRESS)


def permitted(session: SMTPSession, command: SMTPCommand) -> SMTPSession:
    outcome = session.issue(command)
    assert isinstance(outcome, CommandPermitted), f"{command} refused from {session.state}"
    return outcome.session


def refused(session: SMTPSession, command: SMTPCommand) -> CommandRefusal:
    outcome = session.issue(command)
    assert isinstance(outcome, CommandRefused), f"{command} permitted from {session.state}"
    assert outcome.session == session, "a refusal must not advance the session"
    return outcome.reason


def greeted() -> SMTPSession:
    return begin_session(peer()).observe_banner()


def at_mail_from() -> SMTPSession:
    session = permitted(greeted(), SMTPCommand.EHLO)
    return permitted(session, SMTPCommand.MAIL_FROM)


# --- the ordinary path -----------------------------------------------------


def test_the_plain_path_reaches_the_recipient_stage_and_closes() -> None:
    session = begin_session(peer())
    assert session.state is SMTPState.CONNECTING

    session = session.observe_banner()
    assert session.state is SMTPState.BANNER_RECEIVED

    session = permitted(session, SMTPCommand.EHLO)
    assert session.state is SMTPState.EHLO_COMPLETED

    session = permitted(session, SMTPCommand.MAIL_FROM)
    assert session.state is SMTPState.MAIL_FROM_ACCEPTED

    session = permitted(session, SMTPCommand.RCPT_TO)
    assert session.state is SMTPState.RCPT_RESULT_RECEIVED
    assert session.reached_recipient_stage is True

    session = permitted(session, SMTPCommand.RSET)
    assert session.state is SMTPState.RESET_COMPLETED

    session = permitted(session, SMTPCommand.QUIT)
    assert session.state is SMTPState.CLOSED


def test_a_session_cannot_exist_without_a_confirmed_peer() -> None:
    """The destination policy ran three times before this type could be built."""
    assert "peer" in SMTPSession.__dataclass_fields__
    with pytest.raises(TypeError):
        SMTPSession()  # type: ignore[call-arg]


# --- exactly one RCPT TO ---------------------------------------------------


def test_a_second_rcpt_is_refused() -> None:
    """The product promise, enforced by the session and not by convention."""
    session = permitted(at_mail_from(), SMTPCommand.RCPT_TO)
    assert refused(session, SMTPCommand.RCPT_TO) is CommandRefusal.RECIPIENT_LIMIT_REACHED


def test_a_second_rcpt_is_refused_even_after_a_reset() -> None:
    """RSET clears a transaction in SMTP. It does not buy a second recipient."""
    session = permitted(at_mail_from(), SMTPCommand.RCPT_TO)
    session = permitted(session, SMTPCommand.RSET)
    assert refused(session, SMTPCommand.RCPT_TO) is CommandRefusal.RECIPIENT_LIMIT_REACHED
    assert refused(session, SMTPCommand.MAIL_FROM) is CommandRefusal.NOT_ALLOWED_IN_STATE


def test_the_state_table_alone_forbids_a_second_recipient() -> None:
    """The other half of the pair, asserted directly on the table.

    A mutation check found that removing this barrier changed no test result,
    because the counter caught it anyway. Two barriers are only two barriers if
    each one is pinned on its own.
    """
    assert SMTPCommand.RCPT_TO not in allowed_commands(SMTPState.RCPT_RESULT_RECEIVED)
    assert SMTPCommand.RCPT_TO not in allowed_commands(SMTPState.RESET_COMPLETED)
    reachable_with_rcpt = {
        state for state in SMTPState if SMTPCommand.RCPT_TO in allowed_commands(state)
    }
    assert reachable_with_rcpt == {SMTPState.MAIL_FROM_ACCEPTED}


def test_the_recipient_limit_does_not_depend_on_the_state_table() -> None:
    """Both barriers are independent: the counter refuses from any state.

    If a future edit made `RCPT TO` allowed from `MAIL_FROM_ACCEPTED` again
    after one was already sent, the count would still refuse it.
    """
    used = SMTPSession(
        peer=peer(),
        state=SMTPState.MAIL_FROM_ACCEPTED,
        recipients_attempted=MAX_RECIPIENTS_PER_SESSION,
    )
    assert SMTPCommand.RCPT_TO in allowed_commands(used.state)
    assert refused(used, SMTPCommand.RCPT_TO) is CommandRefusal.RECIPIENT_LIMIT_REACHED


def test_a_session_cannot_be_constructed_with_two_recipients_already_used() -> None:
    with pytest.raises(SMTPContractError, match="more than one recipient"):
        SMTPSession(peer=peer(), state=SMTPState.RCPT_RESULT_RECEIVED, recipients_attempted=2)


def test_no_reachable_state_allows_a_second_recipient() -> None:
    """Exhaustive: from every state, with one recipient used, RCPT is refused."""
    for state in SMTPState:
        session = SMTPSession(peer=peer(), state=state, recipients_attempted=1)
        outcome = session.issue(SMTPCommand.RCPT_TO)
        assert isinstance(outcome, CommandRefused), state
        assert session.recipients_attempted == 1


def test_a_permitted_rcpt_increments_the_count_exactly_once() -> None:
    session = at_mail_from()
    assert session.recipients_attempted == 0
    session = permitted(session, SMTPCommand.RCPT_TO)
    assert session.recipients_attempted == 1


# --- STARTTLS --------------------------------------------------------------


def test_starttls_requires_a_completed_ehlo() -> None:
    assert refused(greeted(), SMTPCommand.STARTTLS) is CommandRefusal.NOT_ALLOWED_IN_STATE


def test_after_tls_only_ehlo_may_be_issued() -> None:
    """The session is reset by the handshake and must be re-introduced."""
    session = permitted(greeted(), SMTPCommand.EHLO)
    session = permitted(session, SMTPCommand.STARTTLS)

    assert session.state is SMTPState.TLS_NEGOTIATED
    assert session.tls_active is True
    assert session.permitted_commands == frozenset({SMTPCommand.EHLO, SMTPCommand.QUIT})
    assert refused(session, SMTPCommand.MAIL_FROM) is CommandRefusal.NOT_ALLOWED_IN_STATE
    assert refused(session, SMTPCommand.RCPT_TO) is CommandRefusal.NOT_ALLOWED_IN_STATE


def test_the_second_ehlo_reaches_a_distinct_state() -> None:
    session = permitted(greeted(), SMTPCommand.EHLO)
    session = permitted(session, SMTPCommand.STARTTLS)
    session = permitted(session, SMTPCommand.EHLO)

    assert session.state is SMTPState.EHLO_COMPLETED_AFTER_TLS
    assert session.used_tls is True
    session = permitted(session, SMTPCommand.MAIL_FROM)
    assert session.state is SMTPState.MAIL_FROM_ACCEPTED


def test_starttls_is_issued_at_most_once() -> None:
    session = permitted(greeted(), SMTPCommand.EHLO)
    session = permitted(session, SMTPCommand.STARTTLS)
    session = permitted(session, SMTPCommand.EHLO)
    assert refused(session, SMTPCommand.STARTTLS) is CommandRefusal.STARTTLS_ALREADY_ATTEMPTED


def test_no_state_permits_a_second_starttls() -> None:
    for state in SMTPState:
        session = SMTPSession(peer=peer(), state=state, starttls_attempts=1, tls_active=True)
        outcome = session.issue(SMTPCommand.STARTTLS)
        assert isinstance(outcome, CommandRefused), state


def test_a_failed_handshake_does_not_fall_back_to_plaintext() -> None:
    """The whole point of the FAILED state: there is no way back."""
    session = permitted(greeted(), SMTPCommand.EHLO)
    session = permitted(session, SMTPCommand.STARTTLS)
    session = session.fail()

    assert session.state is SMTPState.FAILED
    assert session.permitted_commands == frozenset({SMTPCommand.QUIT})
    assert refused(session, SMTPCommand.MAIL_FROM) is CommandRefusal.NOT_ALLOWED_IN_STATE
    assert refused(session, SMTPCommand.EHLO) is CommandRefusal.NOT_ALLOWED_IN_STATE
    assert refused(session, SMTPCommand.RCPT_TO) is CommandRefusal.NOT_ALLOWED_IN_STATE
    assert refused(session, SMTPCommand.STARTTLS) is CommandRefusal.STARTTLS_ALREADY_ATTEMPTED


def test_failed_leads_only_to_closed() -> None:
    session = SMTPSession(peer=peer(), state=SMTPState.FAILED)
    for command in SMTPCommand:
        outcome = session.issue(command)
        if isinstance(outcome, CommandPermitted):
            assert outcome.command is SMTPCommand.QUIT
            assert outcome.session.state is SMTPState.CLOSED


# --- nothing may follow a close --------------------------------------------


def test_a_closed_session_issues_nothing() -> None:
    session = SMTPSession(peer=peer(), state=SMTPState.CLOSED)
    assert session.permitted_commands == frozenset()
    for command in SMTPCommand:
        assert refused(session, command) is CommandRefusal.SESSION_CLOSED


def test_closing_is_idempotent_and_failing_a_closed_session_changes_nothing() -> None:
    session = SMTPSession(peer=peer(), state=SMTPState.CLOSED)
    assert session.close().state is SMTPState.CLOSED
    assert session.fail().state is SMTPState.CLOSED


# --- no command before the banner ------------------------------------------


@pytest.mark.parametrize("state", [SMTPState.DISCONNECTED, SMTPState.CONNECTING])
def test_nothing_may_be_issued_before_the_greeting(state: SMTPState) -> None:
    session = SMTPSession(peer=peer(), state=state)
    assert session.permitted_commands == frozenset()


def test_a_banner_is_observed_only_while_connecting() -> None:
    session = permitted(greeted(), SMTPCommand.EHLO)
    with pytest.raises(SMTPContractError, match="only observed while connecting"):
        session.observe_banner()


# --- immutability ----------------------------------------------------------


def test_a_session_is_never_mutated() -> None:
    """Every transition returns a new value, so a failure cannot half-advance one."""
    original = at_mail_from()
    snapshot = (original.state, original.recipients_attempted, original.starttls_attempts)

    original.issue(SMTPCommand.RCPT_TO)
    original.issue(SMTPCommand.QUIT)
    original.fail()
    original.close()

    assert (original.state, original.recipients_attempted, original.starttls_attempts) == snapshot


def test_a_refusal_returns_the_same_session() -> None:
    session = permitted(at_mail_from(), SMTPCommand.RCPT_TO)
    outcome = session.issue(SMTPCommand.RCPT_TO)
    assert isinstance(outcome, CommandRefused)
    assert outcome.session is session


# --- the peer is checked at run time, not only by mypy ---------------------


def approved_only() -> ApprovedDestination:
    return ApprovedDestination(host=HostName("mx.example.com"), address=PUBLIC_ADDRESS)


@pytest.mark.parametrize(
    ("forged", "label"),
    [
        (None, "None"),
        (approved_only(), "an ApprovedDestination, skipping the peer check"),
        (("mx.example.com", 25), "a host/port tuple"),
        (object(), "a bare object"),
        (PUBLIC_ADDRESS, "an address string"),
        (
            RouteCandidate(
                host=HostName("mx.example.com"),
                preference=10,
                source=RouteSource.MX,
                status=CandidateStatus.USABLE,
                decisions=(
                    DestinationDecision(
                        allowed=True, address=PUBLIC_ADDRESS, version=4, deny_reason=None
                    ),
                ),
            ),
            "a RouteCandidate",
        ),
    ],
)
def test_a_session_refuses_anything_that_is_not_a_confirmed_peer(
    forged: object, label: str
) -> None:
    """The annotation was not enough: every one of these used to construct.

    `peer=<ApprovedDestination>` is the dangerous one — it is the value 4B will
    already be holding, and accepting it skips the post-connect check entirely.
    """
    with pytest.raises(SMTPContractError, match="requires a ConfirmedPeer"):
        SMTPSession(peer=forged)  # type: ignore[arg-type]


def test_a_confirmed_peer_is_accepted() -> None:
    session = SMTPSession(peer=peer())
    assert session.peer.peer_address == PUBLIC_ADDRESS


def test_replace_cannot_swap_the_peer_for_something_else() -> None:
    """`replace` re-runs `__post_init__`, so the check applies to it too."""
    session = begin_session(peer())
    for forged in (None, object(), approved_only(), ("host", 25)):
        with pytest.raises(SMTPContractError, match="requires a ConfirmedPeer"):
            replace(session, peer=forged)


def test_every_transition_keeps_a_confirmed_peer() -> None:
    """A transition rebuilds the session, so the invariant is rechecked."""
    session = at_mail_from()
    for step in (
        lambda s: permitted(s, SMTPCommand.RCPT_TO),
        lambda s: permitted(s, SMTPCommand.RSET),
        lambda s: s.fail(),
        lambda s: s.close(),
    ):
        session = step(session)
        assert isinstance(session.peer, ConfirmedPeer)
