"""Invariants of the address value types, redaction, and the port boundary."""

import dataclasses
from typing import get_type_hints

import pytest

from emailcheck.domain.address import (
    CANONICALIZATION_VERSION,
    AddressAccepted,
    AddressContractError,
    DomainName,
    LocalPart,
    NormalizedAddress,
    RawAddressInput,
    has_control_character,
    parse_address,
    redact_address_text,
)
from emailcheck.domain.dns import HostName
from emailcheck.ports.dns import DNSResolver
from emailcheck.ports.smtp import SMTPProber


def build(text: str) -> NormalizedAddress:
    result = parse_address(RawAddressInput(text))
    assert isinstance(result, AddressAccepted)
    return result.address


# --- the local part is never rewritten ------------------------------------


@pytest.mark.parametrize(
    "local",
    [
        "User",
        "USER",
        "uSeR.NaMe",
        "user+tag",
        "user+TAG+second",
        "first.last",
        "f.i.r.s.t",
        "user-name_2026",
        "a!#$%&'*+-/=?^_`{|}~",
    ],
)
def test_local_part_is_passed_through_unchanged(local: str) -> None:
    address = build(f"{local}@Example.COM")
    assert address.local_part.value == local
    assert address.smtp_target == f"{local}@example.com"


def test_dots_and_plus_tags_are_not_stripped() -> None:
    """No provider-specific normalization: only the receiving server decides."""
    address = build("First.Last+news@gmail.com")
    assert address.local_part.value == "First.Last+news"
    assert "." in address.local_part.value
    assert "+" in address.local_part.value


# --- programmer errors raise, user input does not -------------------------


@pytest.mark.parametrize(
    "value",
    ["", "user\r\n", "us er", ".user", "user.", "us..er", "a" * 65, "héllo", "user\x00"],
)
def test_local_part_rejects_unusable_text(value: str) -> None:
    with pytest.raises(AddressContractError):
        LocalPart(value)


@pytest.mark.parametrize(
    "ascii_form",
    [
        "",
        "Example.com",
        "example..com",
        "example.com.",
        "ex_ample.com",
        "-example.com",
        "example-.com",
        f"{'a' * 64}.com",
        "example.com\r\n",
        "münchen.de",
    ],
)
def test_domain_name_rejects_an_unusable_ascii_form(ascii_form: str) -> None:
    with pytest.raises(AddressContractError):
        DomainName(unicode_form=ascii_form, ascii_form=ascii_form)


def test_domain_name_rejects_control_characters_in_the_submitted_form() -> None:
    with pytest.raises(AddressContractError):
        DomainName(unicode_form="example.com\n", ascii_form="example.com")


@pytest.mark.parametrize(
    ("unicode_form", "ascii_form"),
    [
        # The pair that motivated this check: display one domain, probe another.
        ("attacker.example", "victim.example"),
        ("example.com", "example.net"),
        ("münchen.de", "example.com"),
        ("example.com", "xn--mnchen-3ya.de"),
        ("münchen.de", "xn--wgv71a119e.jp"),
        ("sub.example.com", "example.com"),
        ("example.com", "sub.example.com"),
        # A domain that cannot be encoded at all may not be paired with anything.
        ("😀.example", "example.com"),
    ],
)
def test_domain_name_rejects_two_unrelated_domains(unicode_form: str, ascii_form: str) -> None:
    with pytest.raises(AddressContractError):
        DomainName(unicode_form=unicode_form, ascii_form=ascii_form)


@pytest.mark.parametrize(
    ("unicode_form", "ascii_form"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("ExAmPle.Com", "example.com"),
        ("sub.Domain.Example.COM", "sub.domain.example.com"),
        ("localhost", "localhost"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("MÜNCHEN.de", "xn--mnchen-3ya.de"),
        ("日本語.jp", "xn--wgv71a119e.jp"),
        ("straße.de", "xn--strae-oqa.de"),
        ("münchen.example.com", "xn--mnchen-3ya.example.com"),
    ],
)
def test_domain_name_accepts_a_matching_pair(unicode_form: str, ascii_form: str) -> None:
    domain = DomainName(unicode_form=unicode_form, ascii_form=ascii_form)
    assert domain.ascii_form == ascii_form
    assert domain.unicode_form == unicode_form


def test_normalized_address_rejects_an_over_long_combination() -> None:
    local = LocalPart("a" * 64)
    long_domain = ".".join(["b" * 63, "b" * 63, "b" * 62])
    domain = DomainName(unicode_form=long_domain, ascii_form=long_domain)
    with pytest.raises(AddressContractError):
        NormalizedAddress(local_part=local, domain=domain)


def test_parsing_user_input_never_raises() -> None:
    """User mistakes are results, not exceptions."""
    for text in ["", "@", "a@b@c", "user\x00@example.com", "\r\n", "user@[192.0.2.1]"]:
        parse_address(RawAddressInput(text))


# --- immutability ---------------------------------------------------------


def test_value_types_are_frozen() -> None:
    address = build("user@example.com")
    for target, field in (
        (address, "local_part"),
        (address.local_part, "value"),
        (address.domain, "ascii_form"),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(target, field, "mutated")


# --- the control-character predicate --------------------------------------


# Pinned directly, with the expected answer written out, because the property
# tests use this predicate as their oracle. If it were wrong there, both the
# parser and the assertion would agree and hide the fault.
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("user@example.com", False),
        ("", False),
        ("plain text with spaces", False),
        ("tilde ~ and backtick `", False),
        ("héllo", False),
        ("日本語", False),
        ("\x00", True),
        ("a\x00b", True),
        ("\r", True),
        ("\n", True),
        ("\r\n", True),
        ("\t", True),
        ("\x07", True),
        ("\x1b", True),
        ("\x1f", True),
        ("\x7f", True),
        ("\x80", True),
        ("\x85", True),
        ("\x9f", True),
        ("\xa0", False),
        ("\u2028", False),
        (" ", False),
    ],
)
def test_has_control_character_table(text: str, expected: bool) -> None:
    assert has_control_character(text) is expected


def test_has_control_character_covers_every_c0_and_c1_code_point() -> None:
    for code in [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0)]:
        assert has_control_character(chr(code)) is True, hex(code)
    for code in (0x20, 0x41, 0x7E, 0xA0, 0xA1, 0x2028, 0x3000):
        assert has_control_character(chr(code)) is False, hex(code)


# --- redaction ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("alice@example.com", "a***@example.com"),
        ("a@example.com", "*@example.com"),
        ("@example.com", "*@example.com"),
        ("no-at-sign", "***"),
        ("", "***"),
    ],
)
def test_redaction_matches_the_documented_examples(text: str, expected: str) -> None:
    assert redact_address_text(text) == expected


def test_redaction_drops_control_characters() -> None:
    redacted = redact_address_text("ali\r\nce@example.com")
    assert "\r" not in redacted
    assert "\n" not in redacted


@pytest.mark.parametrize(
    "text", ["alice@example.com", "bob.smith+tag@example.org", "x@example.net"]
)
def test_redaction_never_contains_the_complete_local_part(text: str) -> None:
    local = text.split("@")[0]
    redacted = redact_address_text(text)
    assert redacted.count("@") == 1
    assert redacted.split("@")[0] != local
    assert len(redacted.split("@")[0].replace("*", "")) <= 1


def test_normalized_address_exposes_a_redacted_form() -> None:
    assert build("alice@example.com").redacted == "a***@example.com"


def test_raw_input_exposes_a_redacted_form() -> None:
    assert RawAddressInput(" alice@example.com").redacted == "a***@example.com"


# --- correlation material -------------------------------------------------


def test_hmac_material_is_deterministic_and_versioned() -> None:
    first = build("User@Example.com")
    second = build("  User@example.COM  ")
    assert first.hmac_material == second.hmac_material
    assert first.hmac_material == f"{CANONICALIZATION_VERSION}:User@example.com"


def test_hmac_material_separates_addresses_differing_only_in_local_case() -> None:
    assert build("User@example.com").hmac_material != build("user@example.com").hmac_material


# --- the port boundary ----------------------------------------------------


def test_raw_input_cannot_be_used_as_an_smtp_target() -> None:
    raw = RawAddressInput("user@example.com")
    assert not hasattr(raw, "smtp_target")
    assert not hasattr(raw, "local_part")


def test_the_smtp_port_accepts_only_a_validated_address() -> None:
    hints = get_type_hints(SMTPProber.probe_recipient)
    assert hints["address"] is NormalizedAddress


@pytest.mark.parametrize("method", ["query_mx", "query_a", "query_aaaa"])
def test_the_dns_port_accepts_only_validated_values(method: str) -> None:
    """No external I/O port may take raw text, whatever the query is."""
    hints = get_type_hints(getattr(DNSResolver, method))
    parameters = {name: hint for name, hint in hints.items() if name != "return"}
    assert parameters
    for name, hint in parameters.items():
        assert hint in {HostName, NormalizedAddress}, f"{method}({name}) accepts {hint}"
        assert hint is not str
