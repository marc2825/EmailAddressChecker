"""The type that is the entire write capability.

Gate 4B's connection could not write. Gate 4C's can, and what stops that from
being an arbitrary-command API is this value: six factories, a closed enum, and
a payload that is checked to be the command it claims to be.

These tests are the ones that matter if `WireCommand` ever stops meaning
anything. A label attached to arbitrary bytes would pass a port that accepts
"only a `WireCommand`" while putting any verb at all on the wire.
"""

from __future__ import annotations

import pytest

from emailcheck.domain import smtp_wire as wire
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_contract import (
    ALLOWED_COMMANDS,
    MAX_COMMAND_LINE_BYTES,
    SMTPCommand,
    SMTPContractError,
)
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender
from emailcheck.domain.smtp_wire import WireCommand

EHLO = EhloIdentity(host=HostName("probe.sender.test.example"))


def target(text: str = "probe.target@recipient.test.example"):  # type: ignore[no-untyped-def]
    accepted = parse_address(RawAddressInput(value=text))
    assert isinstance(accepted, AddressAccepted)
    return accepted.address


SENDER = EnvelopeSender(address=target("verify@sender.test.example"))


# --- the six, and only the six ---------------------------------------------


def test_there_is_one_factory_per_allowed_command() -> None:
    """Six factories, six enum members, and no way to ask for a seventh."""
    produced = {
        wire.ehlo(EHLO).command,
        wire.starttls().command,
        wire.mail_from(SENDER).command,
        wire.rcpt_to(target()).command,
        wire.rset().command,
        wire.quit_session().command,
    }
    assert produced == set(ALLOWED_COMMANDS)
    assert len(produced) == 6


def test_no_factory_takes_a_command_name() -> None:
    """The reason the set is closed: there is no parameter to name one through."""
    import inspect

    for name in ("ehlo", "starttls", "mail_from", "rcpt_to", "rset", "quit_session"):
        signature = inspect.signature(getattr(wire, name))
        for parameter in signature.parameters.values():
            assert parameter.annotation not in {"str", "bytes", "SMTPCommand"}, name


@pytest.mark.parametrize(
    ("built", "expected"),
    [
        (wire.ehlo(EHLO), b"EHLO probe.sender.test.example\r\n"),
        (wire.starttls(), b"STARTTLS\r\n"),
        (wire.mail_from(SENDER), b"MAIL FROM:<verify@sender.test.example>\r\n"),
        (wire.rcpt_to(target()), b"RCPT TO:<probe.target@recipient.test.example>\r\n"),
        (wire.rset(), b"RSET\r\n"),
        (wire.quit_session(), b"QUIT\r\n"),
    ],
)
def test_each_factory_produces_the_encoder_output(built: WireCommand, expected: bytes) -> None:
    assert built.payload == expected


def test_every_payload_is_exactly_one_terminated_line() -> None:
    for built in (
        wire.ehlo(EHLO),
        wire.starttls(),
        wire.mail_from(SENDER),
        wire.rcpt_to(target()),
        wire.rset(),
        wire.quit_session(),
    ):
        assert built.payload.endswith(b"\r\n")
        assert built.payload.count(b"\r\n") == 1
        assert b"\x00" not in built.payload
        assert len(built.payload) <= MAX_COMMAND_LINE_BYTES


def test_the_recipient_local_part_is_not_rewritten() -> None:
    """Phase 1 promises it; probing a rewritten form asks about another mailbox."""
    submitted = "Mixed.Case+tag@recipient.test.example"
    built = wire.rcpt_to(target(submitted))
    assert built.payload == f"RCPT TO:<{submitted}>\r\n".encode("ascii")


# --- the payload must be the command it claims -----------------------------


@pytest.mark.parametrize(
    ("command", "payload", "label"),
    [
        (SMTPCommand.EHLO, b"DATA\r\n", "a message-content command wearing an EHLO label"),
        (SMTPCommand.QUIT, b"VRFY someone\r\n", "recipient enumeration under a QUIT label"),
        (SMTPCommand.RSET, b"AUTH PLAIN abcdef\r\n", "authentication under an RSET label"),
        (SMTPCommand.EHLO, b"HELO host.example\r\n", "the greeting this project does not have"),
        (SMTPCommand.MAIL_FROM, b"RCPT TO:<a@b.example>\r\n", "one allowed command as another"),
        (SMTPCommand.EHLO, b"EHLOSOMETHING host\r\n", "a prefix that is not the verb"),
    ],
)
def test_a_payload_that_is_not_its_command_is_refused(
    command: SMTPCommand, payload: bytes, label: str
) -> None:
    """This check is what makes the type mean anything at all.

    Without it a `WireCommand` is a decoration on arbitrary bytes, and a port
    accepting only `WireCommand` would accept any verb on the wire.
    """
    with pytest.raises(SMTPContractError, match="begin with the command it names"):
        WireCommand(command=command, payload=payload)


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        (b"EHLO host.example", "no terminator"),
        (b"EHLO host.example\n", "a bare LF rather than CRLF"),
        (b"EHLO a.example\r\nRSET\r\n", "two command lines in one payload"),
        (b"EHLO a.example\x00\r\n", "a NUL inside the line"),
        (b"\r\n", "an empty command"),
        (b"EHLO " + b"x" * MAX_COMMAND_LINE_BYTES + b"\r\n", "beyond the line limit"),
    ],
)
def test_a_payload_that_is_not_one_line_is_refused(payload: bytes, label: str) -> None:
    with pytest.raises(SMTPContractError):
        WireCommand(command=SMTPCommand.EHLO, payload=payload)


@pytest.mark.parametrize("command", ["EHLO", None, 25, b"EHLO", object()])
def test_the_command_must_be_a_member_of_the_closed_enum(command: object) -> None:
    with pytest.raises(SMTPContractError):
        WireCommand(command=command, payload=b"EHLO host.example\r\n")  # type: ignore[arg-type]


@pytest.mark.parametrize("payload", ["EHLO host.example\r\n", None, 25, bytearray(b"EHLO a\r\n")])
def test_the_payload_must_be_bytes(payload: object) -> None:
    with pytest.raises(SMTPContractError):
        WireCommand(command=SMTPCommand.EHLO, payload=payload)  # type: ignore[arg-type]


def test_the_verb_is_read_the_way_a_server_reads_it() -> None:
    """The same rule the forbidden-command scanner uses, applied at run time."""
    assert wire.ehlo(EHLO).verb == "EHLO"
    assert wire.mail_from(SENDER).verb == "MAIL"
    assert wire.rcpt_to(target()).verb == "RCPT"
    assert wire.quit_session().verb == "QUIT"


@pytest.mark.inspection
def test_production_code_builds_wire_commands_only_through_the_factories() -> None:
    """The raw constructor stays validating, and nothing outside this module uses it."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    factory_module = root / "domain" / "smtp_wire.py"
    callers: list[str] = []
    for module in sorted(root.rglob("*.py")):
        if module == factory_module:
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "WireCommand"
            ):
                callers.append(f"{module.name}:{node.lineno}")
    assert callers == [], f"WireCommand built outside its factories: {callers}"
