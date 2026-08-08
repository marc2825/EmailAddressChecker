"""The only thing a connection will accept, and why it cannot be anything else.

Gate 4B published no way to write a byte. Gate 4C needs one, and the obvious
shape — `write(payload: bytes)` on the connection port — is the arbitrary-command
API this whole design exists to prevent. Once it exists, any caller holding a
connection can put any verb on the wire, and the closed enum, the six encoders,
and the scanner all become advisory.

So the capability is a *type* rather than a method signature. `WireCommand` is
the only argument the connection takes, there are exactly six functions that
produce one, and each of them calls the matching encoder in `smtp_command.py`.

The constructor is not the barrier — Python has no private one — so the value
checks itself:

- `command` is an `SMTPCommand`, which has six members and no seventh;
- `payload` is exactly one CRLF-terminated line, within the 512-octet limit,
  carrying no other CR, LF, or NUL;
- **the verb in the bytes is the verb the value claims.** `WireCommand(EHLO,
  b"DATA\\r\\n")` does not construct.

That last check is what makes the type mean something. Without it the value
would be a label attached to arbitrary bytes, which is the same hole with more
ceremony.

**What this type does not do is constrain the argument.** The verb is checked;
what follows it is not. `WireCommand(RCPT_TO, b"RCPT TO:<a@b>,<c@d>\\r\\n")` and
`WireCommand(MAIL_FROM, b"MAIL FROM:<x@y> AUTH=<victim>\\r\\n")` both construct,
and neither is anything an encoder produces. So the property "every wire line is
one of the six encoders' output" rests on three layers rather than on this one:

1. `WireCommand` — one bounded line, and the declared verb;
2. the six factories below — the only argument forms production approves,
   each built from typed values by the matching encoder;
3. an inspection test — production code constructs a `WireCommand` only through
   those factories, so the raw constructor has no production caller.

Closing the argument grammar in the type as well is possible and is not done
here: it would mean a per-command parser, and ADR 0008's rule is that a document
claiming more than the code does is worse than one claiming less. The claim is
therefore stated at the size of what is actually enforced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.smtp_command import (
    encode_ehlo,
    encode_mail_from,
    encode_quit,
    encode_rcpt_to,
    encode_rset,
    encode_starttls,
)
from emailcheck.domain.smtp_contract import (
    COMMAND_TERMINATOR,
    MAX_COMMAND_LINE_BYTES,
    SMTPCommand,
    SMTPContractError,
)
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender

_TERMINATOR: Final = COMMAND_TERMINATOR.encode("ascii")

#: The bytes that separate a verb from its argument. `MAIL FROM:<x>` uses the
#: colon and `EHLO host` uses the space, so a verb ends at whichever comes first.
_ARGUMENT_SEPARATORS: Final = (b" ", b":")


def _verb_of(payload: bytes) -> str:
    """Read the verb a receiving server would read, so it can be compared.

    Deliberately the same rule as `scripts/check_forbidden_smtp.py`: the first
    token, up to a space or a colon. Two places reading a command line the same
    way is the point — the scanner refuses the fourteen forbidden verbs
    statically, and this refuses anything the enum does not name at run time.
    """
    line = payload.removesuffix(_TERMINATOR)
    cut = len(line)
    for separator in _ARGUMENT_SEPARATORS:
        found = line.find(separator)
        if found >= 0:
            cut = min(cut, found)
    # `MAIL FROM` and `RCPT TO` are two words, so the comparison is done on the
    # whole head rather than only the first word; `_matches` handles that.
    return line[:cut].decode("ascii", errors="replace").upper()


@dataclass(frozen=True, slots=True)
class WireCommand:
    """One encoded command line, bound to the enum member it encodes.

    Build one with the six functions below. Nothing else in this project
    constructs one, and an inspection test fixes that.
    """

    command: SMTPCommand
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.command, SMTPCommand):
            raise SMTPContractError("a wire command must name a member of the closed command set")
        if not isinstance(self.payload, bytes):
            raise SMTPContractError("a wire command payload must be bytes")
        if not self.payload.endswith(_TERMINATOR):
            raise SMTPContractError("a wire command must end with one CRLF")
        if len(self.payload) > MAX_COMMAND_LINE_BYTES:
            raise SMTPContractError("a wire command exceeds the maximum command line length")
        line = self.payload.removesuffix(_TERMINATOR)
        for forbidden in (b"\r", b"\n", b"\x00"):
            if forbidden in line:
                raise SMTPContractError("a wire command is exactly one line")
        if not line:
            raise SMTPContractError("a wire command cannot be empty")
        expected = self.command.value.upper()
        head = line.decode("ascii", errors="replace").upper()
        if not (
            head == expected or head.startswith(f"{expected} ") or head.startswith(f"{expected}:")
        ):
            # The label must describe the bytes. Otherwise the type is a
            # decoration on arbitrary content, and a caller could smuggle any
            # verb past a port that accepts only `WireCommand`.
            raise SMTPContractError("a wire command payload must begin with the command it names")

    @property
    def verb(self) -> str:
        """The verb a receiving server would read from these bytes."""
        return _verb_of(self.payload)


def ehlo(identity: EhloIdentity) -> WireCommand:
    """`EHLO`, introducing this project by its configured name."""
    return WireCommand(command=SMTPCommand.EHLO, payload=encode_ehlo(identity))


def starttls() -> WireCommand:
    """`STARTTLS`, requesting the upgrade. It carries no argument."""
    return WireCommand(command=SMTPCommand.STARTTLS, payload=encode_starttls())


def mail_from(sender: EnvelopeSender) -> WireCommand:
    """`MAIL FROM`, with the operator-configured reverse path and nothing else."""
    return WireCommand(command=SMTPCommand.MAIL_FROM, payload=encode_mail_from(sender))


def rcpt_to(address: NormalizedAddress) -> WireCommand:
    """`RCPT TO`, naming the one recipient this session observes.

    The local part is exactly what was submitted. Phase 1 promises it is never
    rewritten, and probing a rewritten form would answer about a different
    mailbox than the one asked about.
    """
    return WireCommand(command=SMTPCommand.RCPT_TO, payload=encode_rcpt_to(address))


def rset() -> WireCommand:
    """`RSET`, abandoning the transaction before the connection is closed."""
    return WireCommand(command=SMTPCommand.RSET, payload=encode_rset())


def quit_session() -> WireCommand:
    """`QUIT`, ending the session politely rather than dropping the socket."""
    return WireCommand(command=SMTPCommand.QUIT, payload=encode_quit())
