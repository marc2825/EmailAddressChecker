"""Property and fuzz-style checks over deterministically generated input.

No `random` seeding is used: every case is derived from a digest of its index,
so a failure reproduces exactly from the reported input.
"""

import hashlib
from collections.abc import Iterator

import pytest

from emailcheck.domain.address import (
    AddressAccepted,
    AddressRejected,
    RawAddressInput,
    has_control_character,
    parse_address,
)

FUZZ_ALPHABET = "abcXYZ019.@+-_[]<>,;\"'\\ \t\r\n\x00héμ😀!#$%&*/=?^`{|}~:()"
CONTROL_CHARACTERS = "\r\n\x00\x07\x0b\x1b\x7f\x85"


def deterministic_inputs(count: int, alphabet: str = FUZZ_ALPHABET) -> Iterator[str]:
    for index in range(count):
        digest = hashlib.sha256(f"emailcheck-address-fuzz-{index}".encode()).digest()
        length = digest[0] % 31
        yield "".join(alphabet[byte % len(alphabet)] for byte in digest[1 : 1 + length])


def test_parsing_arbitrary_input_always_returns_a_result() -> None:
    for text in deterministic_inputs(600):
        result = parse_address(RawAddressInput(text))
        assert isinstance(result, AddressAccepted | AddressRejected), text


def test_an_accepted_target_is_never_injectable() -> None:
    """The invariant the SMTP command encoder depends on."""
    for text in deterministic_inputs(600):
        result = parse_address(RawAddressInput(text))
        if isinstance(result, AddressAccepted):
            target = result.address.smtp_target
            assert not has_control_character(target), text
            assert "\r" not in target and "\n" not in target, text
            assert target.count("@") == 1, text


def test_input_with_an_interior_control_character_is_never_accepted() -> None:
    for control in CONTROL_CHARACTERS:
        for text in (
            f"user{control}@example.com",
            f"user@exam{control}ple.com",
            f"us{control}er@example.com",
            f"user@example.com{control}RCPT TO:<x@example.net>",
        ):
            result = parse_address(RawAddressInput(text))
            assert isinstance(result, AddressRejected), repr(text)


def test_accepted_input_keeps_the_local_part_verbatim() -> None:
    for text in deterministic_inputs(600):
        result = parse_address(RawAddressInput(text))
        if isinstance(result, AddressAccepted):
            assert result.address.local_part.value in text, text


def test_an_accepted_domain_is_always_lowercase_ascii() -> None:
    for text in deterministic_inputs(600):
        result = parse_address(RawAddressInput(text))
        if isinstance(result, AddressAccepted):
            ascii_form = result.address.domain.ascii_form
            assert ascii_form == ascii_form.lower(), text
            assert ascii_form.isascii(), text


def test_parsing_is_idempotent_over_the_normalized_target() -> None:
    """Re-parsing a target yields the same target.

    Only `unicode_form` may differ, because an encoded domain no longer carries
    the text the user typed. Everything a port acts on is stable.
    """
    for text in deterministic_inputs(600):
        first = parse_address(RawAddressInput(text))
        if isinstance(first, AddressAccepted):
            second = parse_address(RawAddressInput(first.address.smtp_target))
            assert isinstance(second, AddressAccepted), text
            assert second.address.smtp_target == first.address.smtp_target, text
            assert second.address.local_part == first.address.local_part, text
            assert second.address.domain.ascii_form == first.address.domain.ascii_form, text


def test_surrounding_whitespace_does_not_change_the_outcome() -> None:
    for text in deterministic_inputs(300):
        bare = parse_address(RawAddressInput(text))
        padded = parse_address(RawAddressInput(f"  {text}\t"))
        if isinstance(bare, AddressAccepted):
            assert isinstance(padded, AddressAccepted), text
            assert padded.address == bare.address, text
        else:
            assert isinstance(padded, AddressRejected), text


@pytest.mark.parametrize(
    "payload",
    [
        "user@example.com\r\nMAIL FROM:<attacker@example.net>",
        "user@example.com\nRCPT TO:<victim@example.net>",
        "user@example.com\rQUIT",
        "user\r\n.\r\n@example.com",
        "user@example.com\x00@example.net",
    ],
)
def test_command_injection_payloads_are_rejected(payload: str) -> None:
    assert isinstance(parse_address(RawAddressInput(payload)), AddressRejected)


def test_a_rejected_result_never_echoes_control_characters() -> None:
    for text in deterministic_inputs(600):
        result = parse_address(RawAddressInput(text))
        if isinstance(result, AddressRejected):
            assert not has_control_character(result.redacted_input), text
