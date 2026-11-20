"""Parsing decisions for every case listed in `docs/requirements.md`."""

import pytest

from emailcheck.domain.address import (
    ADDRESS_MAX_LENGTH,
    DOMAIN_MAX_LENGTH,
    LOCAL_PART_MAX_LENGTH,
    AddressAccepted,
    AddressParseResult,
    AddressRejected,
    AddressSyntaxIssue,
    RawAddressInput,
    RejectionKind,
    ascii_domain_issue,
    encode_domain_ascii,
    parse_address,
)
from emailcheck.domain.reasons import ReasonCode


def parse(text: str) -> AddressParseResult:
    return parse_address(RawAddressInput(text))


def accepted(text: str) -> AddressAccepted:
    result = parse(text)
    assert isinstance(result, AddressAccepted), f"expected acceptance, got {result}"
    return result


def rejected(text: str) -> AddressRejected:
    result = parse(text)
    assert isinstance(result, AddressRejected), f"expected rejection, got {result}"
    return result


def domain_of_length(total: int) -> str:
    """Build a syntactically valid ASCII domain of exactly `total` characters."""
    labels: list[str] = []
    remaining = total
    while remaining > 64:
        labels.append("a" * 63)
        remaining -= 64  # label plus the separating dot
    labels.append("a" * remaining)
    domain = ".".join(labels)
    assert len(domain) == total
    return domain


# --- accepted forms -------------------------------------------------------


def test_valid_simple_mailbox() -> None:
    address = accepted("user@example.com").address
    assert address.local_part.value == "user"
    assert address.domain.ascii_form == "example.com"
    assert address.smtp_target == "user@example.com"


def test_uppercase_local_part_is_preserved() -> None:
    address = accepted("User.NAME@example.com").address
    assert address.local_part.value == "User.NAME"
    assert address.smtp_target == "User.NAME@example.com"


def test_domain_is_lowercased() -> None:
    address = accepted("user@ExAmPle.COM").address
    assert address.domain.ascii_form == "example.com"
    assert address.local_part.value == "user"


def test_plus_tag_is_preserved() -> None:
    assert accepted("user+news-2026@example.com").address.local_part.value == "user+news-2026"


def test_dots_in_local_part_are_preserved() -> None:
    assert accepted("first.middle.last@example.com").address.local_part.value == "first.middle.last"


@pytest.mark.parametrize(
    ("text", "expected_ascii"),
    [
        ("user@münchen.de", "xn--mnchen-3ya.de"),
        ("user@MÜNCHEN.de", "xn--mnchen-3ya.de"),
        ("user@日本語.jp", "xn--wgv71a119e.jp"),
        # Non-transitional IDNA 2008 encodes the sharp s instead of folding it
        # to "ss", which would be a different domain. See ADR 0005.
        ("user@straße.de", "xn--strae-oqa.de"),
    ],
)
def test_idn_domain_conversion(text: str, expected_ascii: str) -> None:
    address = accepted(text).address
    assert address.domain.ascii_form == expected_ascii
    assert address.domain.is_internationalized is True


def test_ascii_domain_is_not_marked_internationalized() -> None:
    assert accepted("user@Example.com").address.domain.is_internationalized is False


def test_unicode_domain_input_is_retained_for_display() -> None:
    address = accepted("user@münchen.de").address
    assert address.domain.unicode_form == "münchen.de"


@pytest.mark.parametrize(
    "text",
    [
        "a!#$%&'*+-/=?^_`{|}~@example.com",
        "user@localhost",
        "user@sub.domain.example.com",
        "user@xn--mnchen-3ya.de",
        "0user9@example123.com",
    ],
)
def test_supported_forms_are_accepted(text: str) -> None:
    accepted(text)


@pytest.mark.parametrize(
    "domain",
    ["localhost", "mailhost", "123.123.123.123", "192.0.2.1", "example.123"],
)
def test_single_label_and_numeric_domains_stay_dns_names(domain: str) -> None:
    """ADR 0005 judgments 4 and 11, stated as specification after issue #2.

    These are letter-digit-hyphen labels, so the grammar accepts them, and the
    parser is not the layer with evidence about them: DNS answers for the name
    (a numeric top-level label has no delegation, so the real answer is
    NXDOMAIN) and the destination policy refuses loopback and private answers.
    What this pins is that nothing is *reinterpreted*: an unbracketed dotted
    quad is never rewritten into the address literal `[192.0.2.1]`, which is a
    different, unsupported form, and the domain is kept exactly as a name.
    """
    address = accepted(f"user@{domain}").address

    assert address.domain.ascii_form == domain
    assert address.smtp_target == f"user@{domain}"
    literal = rejected(f"user@[{domain}]")
    assert literal.issue is AddressSyntaxIssue.DOMAIN_LITERAL
    assert literal.kind is RejectionKind.UNSUPPORTED


@pytest.mark.parametrize(
    "text",
    [
        "  user@example.com  ",
        "\tuser@example.com\t",
        "user@example.com\n",
        "\r\nuser@example.com\r\n",
    ],
)
def test_surrounding_interface_whitespace_is_trimmed(text: str) -> None:
    """ADR 0005 judgment 1: framing whitespace is not an injection attempt."""
    assert accepted(text).address.smtp_target == "user@example.com"


# --- rejected forms -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "issue"),
    [
        # empty and framing
        ("", AddressSyntaxIssue.EMPTY_INPUT),
        ("   ", AddressSyntaxIssue.EMPTY_INPUT),
        # CRLF injection and control characters
        ("user@example.com\r\nRCPT TO:<evil@example.net>", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("user\r\n@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("us\ner@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("user@exam\rple.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("user\x00@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("user@example.com\x00", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("us\x07er@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("us\x1ber@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("us\x7fer@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        ("us\x85er@example.com", AddressSyntaxIssue.CONTROL_CHARACTER),
        # display names and lists
        ("John Doe <john@example.com>", AddressSyntaxIssue.DISPLAY_NAME_FORM),
        ('"John Doe" <john@example.com>', AddressSyntaxIssue.DISPLAY_NAME_FORM),
        ("<user@example.com>", AddressSyntaxIssue.DISPLAY_NAME_FORM),
        ("a@example.com,b@example.net", AddressSyntaxIssue.ADDRESS_LIST),
        ("a@example.com, b@example.net", AddressSyntaxIssue.ADDRESS_LIST),
        ("a@example.com;b@example.net", AddressSyntaxIssue.ADDRESS_LIST),
        # envelope structure
        ("user.example.com", AddressSyntaxIssue.MISSING_AT),
        ("a@b@example.com", AddressSyntaxIssue.MULTIPLE_AT),
        ("user@@example.com", AddressSyntaxIssue.MULTIPLE_AT),
        ("@example.com", AddressSyntaxIssue.MISSING_LOCAL_PART),
        ("user@", AddressSyntaxIssue.MISSING_DOMAIN),
        # local part
        (".user@example.com", AddressSyntaxIssue.LOCAL_PART_LEADING_DOT),
        ("user.@example.com", AddressSyntaxIssue.LOCAL_PART_TRAILING_DOT),
        ("us..er@example.com", AddressSyntaxIssue.LOCAL_PART_CONSECUTIVE_DOTS),
        ("us er@example.com", AddressSyntaxIssue.LOCAL_PART_INVALID_CHARACTER),
        ("us(er@example.com", AddressSyntaxIssue.LOCAL_PART_INVALID_CHARACTER),
        ("us:er@example.com", AddressSyntaxIssue.LOCAL_PART_INVALID_CHARACTER),
        # domain
        ("user@example.com.", AddressSyntaxIssue.DOMAIN_EMPTY_LABEL),
        ("user@example..com", AddressSyntaxIssue.DOMAIN_EMPTY_LABEL),
        ("user@.example.com", AddressSyntaxIssue.DOMAIN_EMPTY_LABEL),
        ("user@ex_ample.com", AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER),
        ("user@exa mple.com", AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER),
        ("user@-example.com", AddressSyntaxIssue.DOMAIN_HYPHEN_POSITION),
        ("user@example-.com", AddressSyntaxIssue.DOMAIN_HYPHEN_POSITION),
        ("user@😀.example", AddressSyntaxIssue.DOMAIN_IDNA_FAILURE),
        # A bracket on one side only is a broken domain, not an address literal.
        ("user@example.com]", AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER),
        ("user@[example.com", AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER),
    ],
)
def test_invalid_inputs_are_reported_with_a_specific_issue(
    text: str, issue: AddressSyntaxIssue
) -> None:
    result = rejected(text)
    assert result.issue is issue
    assert result.kind is RejectionKind.INVALID
    assert result.reason is ReasonCode.INVALID_SYNTAX


@pytest.mark.parametrize(
    ("text", "issue", "reason"),
    [
        (
            '"john doe"@example.com',
            AddressSyntaxIssue.QUOTED_LOCAL_PART,
            ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ),
        (
            '"a@b"@example.com',
            AddressSyntaxIssue.QUOTED_LOCAL_PART,
            ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ),
        (
            r'"escaped\"quote"@example.com',
            AddressSyntaxIssue.QUOTED_LOCAL_PART,
            ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ),
        (
            "user@[192.0.2.1]",
            AddressSyntaxIssue.DOMAIN_LITERAL,
            ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ),
        (
            "user@[IPv6:2001:db8::1]",
            AddressSyntaxIssue.DOMAIN_LITERAL,
            ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ),
        (
            "héllo@example.com",
            AddressSyntaxIssue.UNICODE_LOCAL_PART,
            ReasonCode.UNSUPPORTED_SMTPUTF8,
        ),
        (
            "日本@example.com",
            AddressSyntaxIssue.UNICODE_LOCAL_PART,
            ReasonCode.UNSUPPORTED_SMTPUTF8,
        ),
        (
            "μμ@example.com",
            AddressSyntaxIssue.UNICODE_LOCAL_PART,
            ReasonCode.UNSUPPORTED_SMTPUTF8,
        ),
        (
            "user@[127.0.0.1]",
            AddressSyntaxIssue.DOMAIN_LITERAL,
            ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ),
    ],
)
def test_unsupported_forms_are_not_reported_as_invalid(
    text: str, issue: AddressSyntaxIssue, reason: ReasonCode
) -> None:
    """Unsupported input must resolve to `unknown` later, never to `invalid`."""
    result = rejected(text)
    assert result.issue is issue
    assert result.kind is RejectionKind.UNSUPPORTED
    assert result.reason is reason
    assert result.reason is not ReasonCode.INVALID_SYNTAX


# Written as escapes on purpose: these characters are invisible in an editor,
# and a reviewer must be able to see exactly which one each case uses.
@pytest.mark.parametrize(
    ("name", "local"),
    [
        ("no-break space U+00A0", "user\u00a0name"),
        ("zero width space U+200B", "user\u200bname"),
        ("right-to-left override U+202E", "user\u202ename"),
        ("left-to-right mark U+200E", "user\u200ename"),
        ("line separator U+2028", "user\u2028name"),
        ("paragraph separator U+2029", "user\u2029name"),
        ("ideographic space U+3000", "user\u3000name"),
        ("soft hyphen U+00AD", "user\u00adname"),
        ("C1 control U+0085", "user\u0085name"),
        ("leading no-break space", "\u00a0user"),
        ("trailing zero width space", "user\u200b"),
    ],
)
def test_invisible_and_separator_characters_are_invalid_not_unsupported(
    name: str, local: str
) -> None:
    """These are never a mailbox name, so they break the grammar outright.

    Reporting them as an unsupported SMTPUTF8 form would imply the address might
    be fine on a server this MVP cannot talk to, which is not true.
    """
    result = rejected(f"{local}@example.com")
    assert result.kind is RejectionKind.INVALID, name
    assert result.reason is ReasonCode.INVALID_SYNTAX, name
    assert result.issue in {
        AddressSyntaxIssue.LOCAL_PART_DISALLOWED_UNICODE,
        AddressSyntaxIssue.CONTROL_CHARACTER,
    }, name


IGNORED_BY_UTS46 = [
    ("zero width space U+200B", chr(0x200B)),
    ("soft hyphen U+00AD", chr(0x00AD)),
    ("byte order mark U+FEFF", chr(0xFEFF)),
    ("word joiner U+2060", chr(0x2060)),
    ("mongolian vowel separator U+180E", chr(0x180E)),
    ("combining grapheme joiner U+034F", chr(0x034F)),
    ("variation selector U+FE0F", chr(0xFE0F)),
]


@pytest.mark.parametrize(("name", "char"), IGNORED_BY_UTS46)
def test_a_character_uts46_would_delete_makes_the_domain_invalid(name: str, char: str) -> None:
    """Issue #3: UTS-46 maps these to nothing, so `exam?ple.com` became `example.com`.

    A different domain would be looked up than the one submitted, the failure
    ADR 0005 rejected IDNA 2003 for. The local part already treats invisible
    characters as invalid (judgment 9); the domain now does too (judgment 12).
    """
    result = rejected(f"user@exam{char}ple.com")
    assert result.kind is RejectionKind.INVALID, name
    assert result.reason is ReasonCode.INVALID_SYNTAX, name
    assert result.issue is AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER, name
    assert encode_domain_ascii(f"exam{char}ple.com") is None, name


@pytest.mark.parametrize(("name", "char"), IGNORED_BY_UTS46)
def test_operator_host_names_refuse_the_same_characters(name: str, char: str) -> None:
    """Blocks and allowlists share the encoder, so they cannot match a lookalike."""
    from emailcheck.domain.dns import HostName

    with pytest.raises(ValueError):
        HostName.canonical(f"exam{char}ple.com")


def test_uts46_mappings_that_keep_a_character_still_apply() -> None:
    """Only deletion is refused; documented mappings such as U+3002 stay (ADR 0005)."""
    ideographic_full_stop, fullwidth_e = chr(0x3002), chr(0xFF45)
    assert encode_domain_ascii(f"example{ideographic_full_stop}com") == "example.com"
    assert encode_domain_ascii(f"{fullwidth_e}xample.com") == "example.com"


@pytest.mark.parametrize("local", ["usér", "日本語", "μμ", "Ωmega", "naïve.user", "café+tag"])
def test_ordinary_non_ascii_local_parts_stay_unsupported(local: str) -> None:
    """A real Unicode mailbox name is outside MVP support, not invalid."""
    result = rejected(f"{local}@example.com")
    assert result.kind is RejectionKind.UNSUPPORTED
    assert result.issue is AddressSyntaxIssue.UNICODE_LOCAL_PART
    assert result.reason is ReasonCode.UNSUPPORTED_SMTPUTF8


def test_domain_grammar_violation_outranks_an_unsupported_local_part() -> None:
    """ADR 0005 judgment 7, matching status-model aggregation precedence."""
    result = rejected("héllo@ex_ample.com")
    assert result.kind is RejectionKind.INVALID
    assert result.issue is AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER


# --- length limits --------------------------------------------------------


def test_local_part_at_maximum_length_is_accepted() -> None:
    address = accepted(f"{'a' * LOCAL_PART_MAX_LENGTH}@example.com").address
    assert len(address.local_part.value) == LOCAL_PART_MAX_LENGTH


def test_local_part_one_past_maximum_is_invalid() -> None:
    result = rejected(f"{'a' * (LOCAL_PART_MAX_LENGTH + 1)}@example.com")
    assert result.issue is AddressSyntaxIssue.LOCAL_PART_TOO_LONG


def test_domain_label_at_maximum_length_is_accepted() -> None:
    accepted(f"user@{'a' * 63}.com")


def test_domain_label_one_past_maximum_is_invalid() -> None:
    result = rejected(f"user@{'a' * 64}.com")
    assert result.issue is AddressSyntaxIssue.DOMAIN_LABEL_TOO_LONG


def test_domain_at_maximum_length_is_accepted() -> None:
    """Checked through the helper because no accepted address can carry it.

    A 253 character domain needs a local part and an "@" as well, which puts the
    mailbox over the 254 octet limit, so `parse_address` would report
    `address_too_long` before this boundary could be observed. The one-past
    case below is reachable, because the domain is validated first.
    """
    assert ascii_domain_issue(domain_of_length(DOMAIN_MAX_LENGTH)) is None


def test_domain_one_past_maximum_is_invalid() -> None:
    result = rejected(f"user@{domain_of_length(DOMAIN_MAX_LENGTH + 1)}")
    assert result.issue is AddressSyntaxIssue.DOMAIN_TOO_LONG


def test_address_at_maximum_length_is_accepted() -> None:
    local = "a" * LOCAL_PART_MAX_LENGTH
    domain = domain_of_length(ADDRESS_MAX_LENGTH - LOCAL_PART_MAX_LENGTH - 1)
    address = accepted(f"{local}@{domain}").address
    assert len(address.smtp_target) == ADDRESS_MAX_LENGTH


def test_address_one_past_maximum_is_invalid() -> None:
    local = "a" * LOCAL_PART_MAX_LENGTH
    domain = domain_of_length(ADDRESS_MAX_LENGTH - LOCAL_PART_MAX_LENGTH)
    result = rejected(f"{local}@{domain}")
    assert result.issue is AddressSyntaxIssue.ADDRESS_TOO_LONG


# --- completeness ---------------------------------------------------------


def test_every_syntax_issue_is_reachable_through_the_parser() -> None:
    """No issue may exist that parsing can never produce."""
    cases = [
        "",
        "user\x00@example.com",
        "John Doe <john@example.com>",
        "a@example.com,b@example.net",
        '"john doe"@example.com',
        "user.example.com",
        "a@b@example.com",
        "@example.com",
        "user@",
        "user@[192.0.2.1]",
        "héllo@example.com",
        "user\u200bname@example.com",
        f"{'a' * 65}@example.com",
        ".user@example.com",
        "user.@example.com",
        "us..er@example.com",
        "us er@example.com",
        "user@example..com",
        "user@ex_ample.com",
        "user@-example.com",
        f"user@{'a' * 64}.com",
        f"user@{domain_of_length(DOMAIN_MAX_LENGTH + 1)}",
        "user@😀.example",
        f"{'a' * 64}@{domain_of_length(ADDRESS_MAX_LENGTH - 64)}",
    ]
    produced = {rejected(case).issue for case in cases}
    assert produced == set(AddressSyntaxIssue)
