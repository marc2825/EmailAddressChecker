"""Turning typed values into wire bytes, and nothing else.

There are six functions, one per allowed command, and none of them takes a
command name. That is the design: a caller cannot ask for a command the enum
does not have, because there is no parameter through which to ask.

Every function is pure. Nothing here opens a socket, reads a clock, or touches
configuration; `bytes` come back and a later gate decides what to do with them.

The CRLF is appended here and only here. Each input type already refuses CR,
LF, and NUL at construction, and `_terminate` checks again on the assembled
line, so a command line carrying a second line is unrepresentable rather than
merely unlikely.
"""

from __future__ import annotations

from emailcheck.domain.address import NormalizedAddress, has_control_character
from emailcheck.domain.smtp_contract import (
    COMMAND_TERMINATOR,
    MAX_COMMAND_LINE_BYTES,
    SMTPCommand,
    SMTPContractError,
)
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender


def _terminate(line: str) -> bytes:
    """Append the one line terminator SMTP has, after checking the line is one.

    This runs even though every caller passes text assembled from validated
    values. The check is cheap, and the failure it guards against — a second
    command smuggled into an argument — is the one this project must never
    have.
    """
    if has_control_character(line):
        raise SMTPContractError("an SMTP command line cannot contain a control character")
    encoded = f"{line}{COMMAND_TERMINATOR}".encode("ascii", errors="strict")
    if len(encoded) > MAX_COMMAND_LINE_BYTES:
        raise SMTPContractError("an SMTP command line exceeds the maximum length")
    return encoded


def encode_ehlo(identity: EhloIdentity) -> bytes:
    """`EHLO <fqdn>`: introduce this project by a name that resolves back to it."""
    return _terminate(f"{SMTPCommand.EHLO.value} {identity.value}")


def encode_starttls() -> bytes:
    """`STARTTLS`: request the upgrade. It takes no argument, so it takes none here."""
    return _terminate(SMTPCommand.STARTTLS.value)


def encode_mail_from(sender: EnvelopeSender) -> bytes:
    """`MAIL FROM:<...>`: declare the managed return path.

    No ESMTP parameters are appended. `SIZE` would describe a message, and this
    project has none; `AUTH=` would assert an identity it does not have.
    """
    return _terminate(f"{SMTPCommand.MAIL_FROM.value}:<{sender.path}>")


def encode_rcpt_to(address: NormalizedAddress) -> bytes:
    """`RCPT TO:<...>`: name the one recipient being observed.

    The argument is a `NormalizedAddress` and nothing else, so the local part is
    exactly what the user submitted: Phase 1 promises it is never rewritten, and
    re-normalizing here would probe a different mailbox than the one asked
    about.
    """
    return _terminate(f"{SMTPCommand.RCPT_TO.value}:<{address.smtp_target}>")


def encode_rset() -> bytes:
    """`RSET`: abandon the transaction before closing, as a courtesy."""
    return _terminate(SMTPCommand.RSET.value)


def encode_quit() -> bytes:
    """`QUIT`: end the session politely rather than dropping the connection."""
    return _terminate(SMTPCommand.QUIT.value)
