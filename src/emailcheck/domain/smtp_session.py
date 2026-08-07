"""The state machine, as a value that refuses what it must refuse.

A session is immutable. Issuing a command returns either a permission carrying
the session that results, or a typed refusal. Nothing mutates in place, so a
session cannot be half-advanced by a failure part way through.

Two guarantees are worth stating plainly, because they are the ones the product
promises:

- **at most one `RCPT TO` per session.** The state table already gives
  `RCPT_RESULT_RECEIVED` no way to issue another, and the counter refuses one
  even if a future state edit were to allow it. Two independent reasons, because
  a single one becomes a single edit away from gone;
- **no plaintext fallback after TLS fails.** A failure moves to `FAILED`, from
  which only `QUIT` is permitted, and `FAILED` is never left except by closing.
  There is no transition back to a state that can issue `MAIL FROM`.

A session also cannot exist without a `ConfirmedPeer`, so the destination policy
has necessarily run three times before any command is permitted.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from emailcheck.domain.smtp_contract import (
    SMTPCommand,
    SMTPContractError,
    SMTPState,
    allowed_commands,
)
from emailcheck.domain.smtp_destination import ConfirmedPeer

#: `docs/requirements.md` section 9: one requested recipient per session.
MAX_RECIPIENTS_PER_SESSION: Final = 1

#: `docs/smtp-state-machine.md` section 4: send STARTTLS only once.
MAX_STARTTLS_ATTEMPTS: Final = 1


class CommandRefusal(StrEnum):
    """Why a command may not be issued now."""

    NOT_ALLOWED_IN_STATE = "not_allowed_in_state"
    RECIPIENT_LIMIT_REACHED = "recipient_limit_reached"
    STARTTLS_ALREADY_ATTEMPTED = "starttls_already_attempted"
    SESSION_CLOSED = "session_closed"


#: Where each command leaves the session once the server has accepted it. The
#: table is keyed by the state the command was issued from, because `EHLO` means
#: something different before and after TLS.
_NEXT_STATE: Final[dict[tuple[SMTPState, SMTPCommand], SMTPState]] = {
    (SMTPState.BANNER_RECEIVED, SMTPCommand.EHLO): SMTPState.EHLO_COMPLETED,
    (SMTPState.EHLO_COMPLETED, SMTPCommand.STARTTLS): SMTPState.TLS_NEGOTIATED,
    (SMTPState.TLS_NEGOTIATED, SMTPCommand.EHLO): SMTPState.EHLO_COMPLETED_AFTER_TLS,
    (SMTPState.EHLO_COMPLETED, SMTPCommand.MAIL_FROM): SMTPState.MAIL_FROM_ACCEPTED,
    (SMTPState.EHLO_COMPLETED_AFTER_TLS, SMTPCommand.MAIL_FROM): SMTPState.MAIL_FROM_ACCEPTED,
    (SMTPState.MAIL_FROM_ACCEPTED, SMTPCommand.RCPT_TO): SMTPState.RCPT_RESULT_RECEIVED,
    (SMTPState.EHLO_COMPLETED, SMTPCommand.RSET): SMTPState.RESET_COMPLETED,
    (SMTPState.EHLO_COMPLETED_AFTER_TLS, SMTPCommand.RSET): SMTPState.RESET_COMPLETED,
    (SMTPState.MAIL_FROM_ACCEPTED, SMTPCommand.RSET): SMTPState.RESET_COMPLETED,
    (SMTPState.RCPT_RESULT_RECEIVED, SMTPCommand.RSET): SMTPState.RESET_COMPLETED,
}


@dataclass(frozen=True, slots=True)
class SMTPSession:
    """One recipient-stage session with a peer that has already been judged."""

    peer: ConfirmedPeer
    state: SMTPState = SMTPState.CONNECTING
    recipients_attempted: int = 0
    starttls_attempts: int = 0
    tls_active: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.peer, ConfirmedPeer):
            # The annotation alone was not enough. A review built
            # `SMTPSession(peer=approved_destination)` and it succeeded, which
            # skips the post-connect check entirely — and `peer=None` and a bare
            # tuple worked too. mypy rejects all three, but mypy checks `src`
            # only and `Any` launders any of them, so the type is checked here
            # as well. Every other value in this project validates itself; this
            # is the one where forgetting to means talking to an unchecked peer.
            raise SMTPContractError(
                "a session requires a ConfirmedPeer, so the destination policy has run "
                "against the DNS answer, the approved address, and the actual peer"
            )
        if self.recipients_attempted < 0 or self.starttls_attempts < 0:
            raise SMTPContractError("a session counter cannot be negative")
        if self.recipients_attempted > MAX_RECIPIENTS_PER_SESSION:
            raise SMTPContractError("a session cannot have attempted more than one recipient")
        if self.starttls_attempts > MAX_STARTTLS_ATTEMPTS:
            raise SMTPContractError("a session cannot have attempted STARTTLS more than once")
        if self.tls_active and self.starttls_attempts == 0:
            raise SMTPContractError("TLS cannot be active without a STARTTLS attempt")

    # --- what may happen next ---------------------------------------------

    @property
    def permitted_commands(self) -> frozenset[SMTPCommand]:
        """The commands that would be accepted right now, limits included."""
        return frozenset(
            command for command in allowed_commands(self.state) if self.refusal(command) is None
        )

    def refusal(self, command: SMTPCommand) -> CommandRefusal | None:
        """Why `command` would be refused now, or None if it would be issued."""
        if self.state is SMTPState.CLOSED:
            return CommandRefusal.SESSION_CLOSED
        if command is SMTPCommand.RCPT_TO and self.recipients_attempted >= (
            MAX_RECIPIENTS_PER_SESSION
        ):
            # Checked before the state table on purpose: the limit is the
            # product promise, and it must not depend on the table being right.
            return CommandRefusal.RECIPIENT_LIMIT_REACHED
        if command is SMTPCommand.STARTTLS and self.starttls_attempts >= MAX_STARTTLS_ATTEMPTS:
            return CommandRefusal.STARTTLS_ALREADY_ATTEMPTED
        if command not in allowed_commands(self.state):
            return CommandRefusal.NOT_ALLOWED_IN_STATE
        return None

    # --- transitions -------------------------------------------------------

    def issue(self, command: SMTPCommand) -> CommandOutcome:
        """Ask to issue `command`, and get the session that would result.

        The returned session is the state *after* the server accepts. A refusal
        or a failure from the server is reported with `fail`, and a `QUIT` with
        `close`, so a rejected command never silently advances the session.
        """
        refusal = self.refusal(command)
        if refusal is not None:
            return CommandRefused(command=command, reason=refusal, session=self)

        counted = self
        if command is SMTPCommand.RCPT_TO:
            counted = replace(counted, recipients_attempted=counted.recipients_attempted + 1)
        elif command is SMTPCommand.STARTTLS:
            counted = replace(counted, starttls_attempts=counted.starttls_attempts + 1)

        if command is SMTPCommand.QUIT:
            closed = replace(counted, state=SMTPState.CLOSED)
            return CommandPermitted(command=command, session=closed)

        next_state = _NEXT_STATE[(self.state, command)]
        advanced = replace(counted, state=next_state)
        if command is SMTPCommand.STARTTLS:
            # The handshake has succeeded by the time this state is reached, and
            # everything agreed before it is discarded: the session is
            # re-introduced with EHLO before anything else is permitted.
            advanced = replace(advanced, tls_active=True)
        return CommandPermitted(command=command, session=advanced)

    def observe_banner(self) -> SMTPSession:
        """The greeting was a usable reply. This is the only way out of connecting."""
        if self.state is not SMTPState.CONNECTING:
            raise SMTPContractError("a banner is only observed while connecting")
        return replace(self, state=SMTPState.BANNER_RECEIVED)

    def fail(self) -> SMTPSession:
        """Something went wrong. Only `QUIT` remains, and TLS never falls back.

        A failed STARTTLS lands here like any other failure, and there is no
        transition from `FAILED` to a state that can issue `MAIL FROM`, so the
        session cannot quietly continue in plaintext.
        """
        if self.state is SMTPState.CLOSED:
            return self
        return replace(self, state=SMTPState.FAILED)

    def close(self) -> SMTPSession:
        """The stream is gone. Nothing further may be issued."""
        return replace(self, state=SMTPState.CLOSED)

    # --- reporting ---------------------------------------------------------

    @property
    def reached_recipient_stage(self) -> bool:
        return self.recipients_attempted > 0

    @property
    def used_tls(self) -> bool:
        return self.tls_active


@dataclass(frozen=True, slots=True)
class CommandPermitted:
    """The command may be issued. `session` is where it leaves the session."""

    command: SMTPCommand
    session: SMTPSession


@dataclass(frozen=True, slots=True)
class CommandRefused:
    """The command may not be issued. `session` is unchanged."""

    command: SMTPCommand
    reason: CommandRefusal
    session: SMTPSession


CommandOutcome = CommandPermitted | CommandRefused


def begin_session(peer: ConfirmedPeer) -> SMTPSession:
    """Start a session with a peer that has passed all three policy checks."""
    return SMTPSession(peer=peer, state=SMTPState.CONNECTING)
