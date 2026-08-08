"""Reading an EHLO reply, and refusing to read anything into it.

The parser answers one question — was `STARTTLS` advertised — and records the
rest as opaque names. The tests that matter are the ones where a keyword *looks*
like something: a lookalike, a substring, a parameter, and an `X-` extension all
have to produce no behaviour at all.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.smtp_capabilities import (
    MAX_KEYWORD_LENGTH,
    MAX_KEYWORDS,
    Capabilities,
    parse_capabilities,
)

GREETING = "250-mx.test.example at your service"


def parse(*keyword_lines: str) -> Capabilities:
    return parse_capabilities([GREETING, *keyword_lines])


# --- the one keyword this gate acts on -------------------------------------


def test_starttls_is_found_when_advertised() -> None:
    assert parse("250-STARTTLS", "250 ENHANCEDSTATUSCODES").supports_starttls is True


def test_starttls_is_absent_when_not_advertised() -> None:
    assert parse("250-SIZE 1000", "250 8BITMIME").supports_starttls is False


@pytest.mark.parametrize(
    "keyword",
    ["starttls", "StartTls", "STARTTLS", "sTaRtTlS"],
)
def test_the_keyword_is_case_insensitive(keyword: str) -> None:
    """RFC 5321 keywords are case-insensitive, and servers exercise that."""
    assert parse(f"250 {keyword}").supports_starttls is True


@pytest.mark.parametrize(
    ("keyword", "label"),
    [
        ("STARTTLSX", "a longer keyword that starts the same way"),
        ("XSTARTTLS", "a longer keyword that ends the same way"),
        ("START", "a prefix"),
        ("TLS", "a suffix"),
        ("STARTTLS-PLEASE", "a hyphenated relative"),
        ("NOSTARTTLS", "a negation that contains it"),
    ],
)
def test_a_lookalike_keyword_is_not_starttls(keyword: str, label: str) -> None:
    """Token boundaries, not substrings. A substring match would upgrade blind."""
    assert parse(f"250 {keyword}").supports_starttls is False, label


def test_a_keyword_with_parameters_is_still_the_keyword() -> None:
    assert parse("250 STARTTLS SOMEPARAM=1").supports_starttls is True


def test_a_duplicate_keyword_collapses() -> None:
    capabilities = parse("250-STARTTLS", "250-STARTTLS", "250 STARTTLS")
    assert capabilities.supports_starttls is True
    assert capabilities.keywords == frozenset({"STARTTLS"})


def test_the_greeting_line_is_not_a_keyword() -> None:
    """The first line is the server's name, and it is not an extension."""
    capabilities = parse_capabilities(["250 mx.test.example at your service"])
    assert capabilities.keywords == frozenset()
    assert capabilities.supports_starttls is False


# --- everything else is ignored, deliberately ------------------------------


def test_an_unknown_extension_is_recorded_and_does_nothing() -> None:
    capabilities = parse("250-CHUNKING", "250-SMTPUTF8", "250 DSN")
    assert capabilities.advertises("CHUNKING")
    assert capabilities.supports_starttls is False


def test_a_provider_specific_extension_triggers_no_behaviour() -> None:
    """`X-` keywords are a better fingerprint than an MX name, and are not used.

    `docs/architecture.md` keeps provider identity as metadata that never
    decides anything, and an extension keyword would be the same decision made
    somewhere less visible.
    """
    capabilities = parse("250-XCLIENTLIKE", "250-X-SOMEVENDOR", "250 XANYTHING")
    assert capabilities.supports_starttls is False
    assert capabilities.size_limit is None


@pytest.mark.parametrize(
    "line",
    ["", "   ", "250", "not a line at all", "\t", "250-" + "!" * 10],
)
def test_a_malformed_keyword_line_contributes_nothing(line: str) -> None:
    """Robust by ignoring rather than by guessing. Nothing here can fail."""
    capabilities = parse(line)
    assert capabilities.supports_starttls is False


def test_an_over_long_keyword_is_dropped() -> None:
    capabilities = parse("250 " + "A" * (MAX_KEYWORD_LENGTH + 1))
    assert capabilities.keywords == frozenset()


def test_the_keyword_count_is_bounded() -> None:
    """A server describing itself in 500 keywords is not describing itself."""
    capabilities = parse_capabilities(
        [GREETING, *[f"250-KEYWORD{index}" for index in range(MAX_KEYWORDS + 50)]]
    )
    assert len(capabilities.keywords) <= MAX_KEYWORDS


# --- SIZE is metadata ------------------------------------------------------


def test_size_is_read_as_a_number() -> None:
    assert parse("250 SIZE 35882577").size_limit == 35882577


@pytest.mark.parametrize("parameters", ["", "unlimited", "-1", "1.5", "9" * 30])
def test_an_unusable_size_is_no_size(parameters: str) -> None:
    assert parse(f"250 SIZE {parameters}".strip()).size_limit is None


def test_anything_after_the_size_number_is_ignored() -> None:
    """`SIZE <number>` is the whole grammar; trailing junk is not read as more."""
    assert parse("250 SIZE 1024 and some words").size_limit == 1024


def test_size_changes_nothing_about_starttls() -> None:
    """It is recorded, and nothing reads it. This project transmits no message."""
    capabilities = parse("250-SIZE 10", "250 STARTTLS")
    assert capabilities.size_limit == 10
    assert capabilities.supports_starttls is True


# --- the empty case --------------------------------------------------------


def test_no_lines_at_all_is_an_empty_capability_set() -> None:
    capabilities = parse_capabilities([])
    assert capabilities.keywords == frozenset()
    assert capabilities.supports_starttls is False
