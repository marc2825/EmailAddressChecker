"""The commands this project may issue, and the states it may be in.

Everything the SMTP layer is allowed to do is named here. The set is closed on
purpose: a command this enum does not have cannot be encoded, because the
encoder in `smtp_command.py` has one function per member and no function that
takes a command name.

`docs/smtp-state-machine.md` is the specification. ADR 0003 records why this
project owns a small state machine instead of using a mail-sending library, and
ADR 0008 records the gate that keeps it small.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class SMTPContractError(ValueError):
    """An SMTP value was built from data that violates its invariants.

    This is a programmer error inside this project. Remote data that cannot be
    used is reported as a typed reply failure or a recipient-stage outcome.
    """


class SMTPState(StrEnum):
    """Where a session is. The list is `docs/smtp-state-machine.md` section 2.

    There is deliberately no state for a message transaction body, an
    authenticated session, or a queued transfer. A state that does not exist
    cannot be reached by a bug.
    """

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    BANNER_RECEIVED = "banner_received"
    EHLO_COMPLETED = "ehlo_completed"
    TLS_NEGOTIATED = "tls_negotiated"
    EHLO_COMPLETED_AFTER_TLS = "ehlo_completed_after_tls"
    MAIL_FROM_ACCEPTED = "mail_from_accepted"
    RCPT_RESULT_RECEIVED = "rcpt_result_received"
    RESET_COMPLETED = "reset_completed"
    CLOSED = "closed"
    FAILED = "failed"


class SMTPCommand(StrEnum):
    """Every command this project may issue. There are no others.

    `docs/requirements.md` section 2 publishes this list as the meaning of "no
    email is sent". Adding a member here is a change to that public promise and
    needs a security review and an ADR, not a commit.
    """

    EHLO = "EHLO"
    STARTTLS = "STARTTLS"
    MAIL_FROM = "MAIL FROM"
    RCPT_TO = "RCPT TO"
    RSET = "RSET"
    QUIT = "QUIT"


#: The complete allowed set, for tests and for callers that need to assert it.
ALLOWED_COMMANDS: Final[frozenset[SMTPCommand]] = frozenset(SMTPCommand)

#: RFC 5321 section 4.5.3.1.4: a command line is at most 512 octets including
#: the terminating CRLF. The encoder refuses anything longer rather than letting
#: a server decide how to fold it.
MAX_COMMAND_LINE_BYTES: Final = 512

#: The only line terminator SMTP has. The encoder appends it; nothing else may.
COMMAND_TERMINATOR: Final = "\r\n"


#: Which commands may be issued from each state. A state that is absent permits
#: nothing at all.
#:
#: Three rules are visible in the table and are the reason it is data rather
#: than a chain of conditionals:
#:
#: - `TLS_NEGOTIATED` permits `EHLO` and `QUIT`. `EHLO` is the only way forward,
#:   so the session is re-introduced after TLS before anything else happens, and
#:   `QUIT` is there so an upgraded session can be ended politely rather than by
#:   dropping the socket. `QUIT` leads nowhere: no state reachable from it can
#:   issue `MAIL FROM`;
#: - `RCPT_RESULT_RECEIVED` does not permit `RCPT TO`, so a second recipient has
#:   no state to be issued from;
#: - `RESET_COMPLETED` permits only `QUIT`, so `RSET` cannot start a second
#:   transaction in a session that already observed its one recipient.
_ALLOWED_BY_STATE: Final[dict[SMTPState, frozenset[SMTPCommand]]] = {
    SMTPState.DISCONNECTED: frozenset(),
    SMTPState.CONNECTING: frozenset(),
    SMTPState.BANNER_RECEIVED: frozenset({SMTPCommand.EHLO, SMTPCommand.QUIT}),
    SMTPState.EHLO_COMPLETED: frozenset(
        {
            SMTPCommand.STARTTLS,
            SMTPCommand.MAIL_FROM,
            SMTPCommand.RSET,
            SMTPCommand.QUIT,
        }
    ),
    SMTPState.TLS_NEGOTIATED: frozenset({SMTPCommand.EHLO, SMTPCommand.QUIT}),
    SMTPState.EHLO_COMPLETED_AFTER_TLS: frozenset(
        {SMTPCommand.MAIL_FROM, SMTPCommand.RSET, SMTPCommand.QUIT}
    ),
    SMTPState.MAIL_FROM_ACCEPTED: frozenset(
        {SMTPCommand.RCPT_TO, SMTPCommand.RSET, SMTPCommand.QUIT}
    ),
    SMTPState.RCPT_RESULT_RECEIVED: frozenset({SMTPCommand.RSET, SMTPCommand.QUIT}),
    SMTPState.RESET_COMPLETED: frozenset({SMTPCommand.QUIT}),
    SMTPState.FAILED: frozenset({SMTPCommand.QUIT}),
    SMTPState.CLOSED: frozenset(),
}


def allowed_commands(state: SMTPState) -> frozenset[SMTPCommand]:
    """Return the commands permitted from `state`, which may be none."""
    return _ALLOWED_BY_STATE[state]


#: States from which no further command may be issued.
TERMINAL_STATES: Final[frozenset[SMTPState]] = frozenset({SMTPState.CLOSED})
