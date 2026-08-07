"""The command set is closed, and the encoder has no way to widen it.

The tests that matter here are the negative ones. A test that `EHLO` encodes
correctly proves the happy path works; a test that there is no function taking a
command name proves the layer cannot be talked into something else.
"""

from __future__ import annotations

import inspect

import pytest

from emailcheck.domain import smtp_command
from emailcheck.domain.address import (
    AddressAccepted,
    NormalizedAddress,
    RawAddressInput,
    parse_address,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_command import (
    encode_ehlo,
    encode_mail_from,
    encode_quit,
    encode_rcpt_to,
    encode_rset,
    encode_starttls,
)
from emailcheck.domain.smtp_contract import (
    ALLOWED_COMMANDS,
    COMMAND_TERMINATOR,
    MAX_COMMAND_LINE_BYTES,
    SMTPCommand,
    SMTPContractError,
    SMTPState,
    allowed_commands,
)
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender

# The names this project must never be able to issue. Written out because a
# test file is exactly where they may appear.
FORBIDDEN = (
    "DATA",
    "BDAT",
    "AUTH",
    "VRFY",
    "EXPN",
    "SEND",
    "SOML",
    "SAML",
    "TURN",
    "ATRN",
    "ETRN",
    "BURL",
    "XCLIENT",
    "XFORWARD",
)

IDENTITY = EhloIdentity(host=HostName("probe.example.net"))


def address(text: str) -> NormalizedAddress:
    parsed = parse_address(RawAddressInput(text))
    assert isinstance(parsed, AddressAccepted)
    return parsed.address


# --- the closed set --------------------------------------------------------


def test_the_command_enum_holds_exactly_the_published_six() -> None:
    assert {command.value for command in SMTPCommand} == {
        "EHLO",
        "STARTTLS",
        "MAIL FROM",
        "RCPT TO",
        "RSET",
        "QUIT",
    }


@pytest.mark.parametrize("name", FORBIDDEN)
def test_no_forbidden_command_is_a_member(name: str) -> None:
    assert name not in {command.name for command in SMTPCommand}
    assert name not in {command.value for command in SMTPCommand}
    with pytest.raises(ValueError):
        SMTPCommand(name)


def test_allowed_commands_is_the_whole_enum() -> None:
    assert frozenset(SMTPCommand) == ALLOWED_COMMANDS


def test_no_state_permits_a_command_outside_the_enum() -> None:
    for state in SMTPState:
        assert allowed_commands(state) <= ALLOWED_COMMANDS


def test_every_state_has_an_entry() -> None:
    """A missing entry would raise at run time in the middle of a session."""
    for state in SMTPState:
        assert isinstance(allowed_commands(state), frozenset)


def test_there_is_no_message_transaction_state() -> None:
    values = {state.value for state in SMTPState}
    for forbidden in ("data", "body", "content", "authenticated", "transaction_body"):
        assert forbidden not in values


# --- the encoder has no name parameter -------------------------------------


ENCODERS = (
    encode_ehlo,
    encode_starttls,
    encode_mail_from,
    encode_rcpt_to,
    encode_rset,
    encode_quit,
)


def test_the_module_exports_one_encoder_per_command_and_no_dispatcher() -> None:
    public = {
        name
        for name, value in vars(smtp_command).items()
        if not name.startswith("_")
        and inspect.isfunction(value)
        and value.__module__ == smtp_command.__name__
    }
    assert public == {
        "encode_ehlo",
        "encode_starttls",
        "encode_mail_from",
        "encode_rcpt_to",
        "encode_rset",
        "encode_quit",
    }


@pytest.mark.parametrize("encoder", ENCODERS, ids=lambda f: f.__name__)
def test_no_encoder_accepts_a_command_name(encoder: object) -> None:
    """There is no parameter through which to ask for a forbidden command."""
    signature = inspect.signature(encoder)  # type: ignore[arg-type]
    for parameter in signature.parameters.values():
        assert parameter.annotation is not str, parameter
        assert parameter.name not in {"command", "verb", "name", "line", "raw"}


@pytest.mark.parametrize("encoder", ENCODERS, ids=lambda f: f.__name__)
def test_every_encoder_returns_bytes(encoder: object) -> None:
    signature = inspect.signature(encoder)  # type: ignore[arg-type]
    assert signature.return_annotation == "bytes"


def test_no_encoder_takes_a_plain_string() -> None:
    """Typed values only: a `str` parameter is where injection gets in."""
    for encoder in ENCODERS:
        for parameter in inspect.signature(encoder).parameters.values():
            assert parameter.annotation not in {"str", str, "bytes", bytes}


# --- what the encoders produce ---------------------------------------------


def test_each_command_encodes_to_its_wire_form() -> None:
    assert encode_ehlo(IDENTITY) == b"EHLO probe.example.net\r\n"
    assert encode_starttls() == b"STARTTLS\r\n"
    assert encode_mail_from(EnvelopeSender(address=address("probe@example.net"))) == (
        b"MAIL FROM:<probe@example.net>\r\n"
    )
    assert encode_rcpt_to(address("user@example.com")) == b"RCPT TO:<user@example.com>\r\n"
    assert encode_rset() == b"RSET\r\n"
    assert encode_quit() == b"QUIT\r\n"


def test_the_null_sender_is_expressible() -> None:
    assert encode_mail_from(EnvelopeSender.null()) == b"MAIL FROM:<>\r\n"


ALL_ENCODED = (
    encode_ehlo(IDENTITY),
    encode_starttls(),
    encode_mail_from(EnvelopeSender.null()),
    encode_mail_from(EnvelopeSender(address=address("probe@example.net"))),
    encode_rcpt_to(address("user@example.com")),
    encode_rset(),
    encode_quit(),
)


@pytest.mark.parametrize("encoded", ALL_ENCODED, ids=lambda b: b.decode().strip())
def test_every_command_is_exactly_one_line(encoded: bytes) -> None:
    """The invariant an injection would break: one command, one line."""
    assert encoded.endswith(b"\r\n")
    assert encoded.count(b"\r\n") == 1
    assert encoded.count(b"\r") == 1
    assert encoded.count(b"\n") == 1
    assert b"\x00" not in encoded
    assert len(encoded) <= MAX_COMMAND_LINE_BYTES


@pytest.mark.parametrize("encoded", ALL_ENCODED, ids=lambda b: b.decode().strip())
def test_no_encoded_command_is_a_forbidden_one(encoded: bytes) -> None:
    verb = encoded.decode("ascii").split(COMMAND_TERMINATOR)[0].split(" ")[0].split(":")[0]
    assert verb.upper() not in FORBIDDEN


def test_the_local_part_is_not_rewritten() -> None:
    """Phase 1 promises it, and only the receiving server knows it is the same."""
    encoded = encode_rcpt_to(address("Support+Billing.Case@Example.COM"))
    assert encoded == b"RCPT TO:<Support+Billing.Case@example.com>\r\n"


@pytest.mark.parametrize(
    "text",
    [
        "user@example.com",
        "USER@example.com",
        "user+tag@example.com",
        "first.last@example.com",
        "u@example.com",
        "user@xn--mnchen-3ya.de",
    ],
)
def test_a_valid_address_never_produces_a_second_line(text: str) -> None:
    encoded = encode_rcpt_to(address(text))
    assert encoded.count(b"\r\n") == 1


# --- what the encoders refuse ----------------------------------------------


def test_the_address_boundary_already_keeps_every_real_line_under_the_cap() -> None:
    """The longest address Phase 1 accepts still leaves 246 octets of headroom.

    So the encoder's own length guard is a second barrier, not the working one.
    Recording the arithmetic here means a future change to `ADDRESS_MAX_LENGTH`
    that removes the headroom fails a test rather than a server.
    """
    longest = "a" * 64 + "@" + "b" * 60 + "." + "c" * 60 + "." + "d" * 59 + ".example"
    assert len(longest) == 254
    encoded = encode_rcpt_to(address(longest))
    assert len(encoded) == len(longest) + len("RCPT TO:<>\r\n")
    assert len(encoded) < MAX_COMMAND_LINE_BYTES


def test_an_over_long_command_line_is_refused() -> None:
    """The second barrier, exercised directly because nothing valid reaches it."""
    with pytest.raises(SMTPContractError, match="maximum length"):
        smtp_command._terminate("EHLO " + "a" * MAX_COMMAND_LINE_BYTES)


@pytest.mark.parametrize(
    "line",
    [
        "EHLO probe.example.net\r\nDATA",
        "EHLO probe.example.net\r",
        "EHLO probe.example.net\n",
        "EHLO probe\x00.example.net",
        "RCPT TO:<a@b.example>\r\nRCPT TO:<c@d.example>",
    ],
)
def test_a_line_carrying_a_second_command_is_refused(line: str) -> None:
    """The guard the whole encoder exists for, tested on the assembled line."""
    with pytest.raises(SMTPContractError, match="control character"):
        smtp_command._terminate(line)


def test_an_ehlo_identity_must_be_fully_qualified() -> None:
    with pytest.raises(SMTPContractError, match="fully qualified"):
        EhloIdentity(host=HostName("localhost"))


@pytest.mark.parametrize(
    "text",
    ["localhost", "", "probe.example.net\r\nDATA", "probe example net", "-bad.example"],
)
def test_an_unusable_ehlo_identity_is_refused(text: str) -> None:
    assert EhloIdentity.parse(text) is None


def test_an_ehlo_identity_normalizes_the_way_a_host_name_does() -> None:
    identity = EhloIdentity.parse("Probe.Example.NET.")
    assert identity is not None
    assert identity.value == "probe.example.net"
