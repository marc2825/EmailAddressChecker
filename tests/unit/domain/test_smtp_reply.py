"""Reading a reply without trusting it, and without keeping it.

A reply is written by a remote operator, often echoes the address that was
asked about, and ends up near logs and API responses. So these tests are mostly
about what does *not* survive parsing.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.address import has_control_character
from emailcheck.domain.smtp_reply import (
    _ADDRESS_LIKE,
    MAX_DIAGNOSTIC_LENGTH,
    MAX_DIAGNOSTIC_SOURCE_LENGTH,
    MAX_REPLY_LINE_BYTES,
    MAX_REPLY_LINES,
    REDACTED_MARKER,
    EnhancedStatusCode,
    ReplyClass,
    ReplyDefect,
    ReplyMalformed,
    ReplyParsed,
    SMTPReply,
    parse_reply,
    sanitize_diagnostic,
)


def parsed(lines: list[str]) -> SMTPReply:
    outcome = parse_reply(lines)
    assert isinstance(outcome, ReplyParsed), outcome
    return outcome.reply


def defect(lines: list[str]) -> ReplyDefect:
    outcome = parse_reply(lines)
    assert isinstance(outcome, ReplyMalformed), outcome
    return outcome.defect


# --- ordinary replies ------------------------------------------------------


def test_a_single_line_reply_parses() -> None:
    reply = parsed(["250 OK"])
    assert reply.code == 250
    assert reply.enhanced is None
    assert reply.diagnostic == "OK"
    assert reply.line_count == 1


def test_a_multiline_reply_parses() -> None:
    reply = parsed(
        [
            "250-mx.example.com greets you",
            "250-SIZE 52428800",
            "250-STARTTLS",
            "250 HELP",
        ]
    )
    assert reply.code == 250
    assert reply.line_count == 4
    assert "STARTTLS" in reply.diagnostic


def test_an_enhanced_code_is_extracted_when_it_is_valid() -> None:
    reply = parsed(["550 5.1.1 Recipient address rejected"])
    assert reply.code == 550
    assert reply.enhanced is not None
    assert reply.enhanced.value == "5.1.1"
    assert reply.diagnostic == "Recipient address rejected"


def test_the_two_550_meanings_stay_distinguishable() -> None:
    """`5.1.1` and `5.7.1` share a basic code and mean different things."""
    missing = parsed(["550 5.1.1 unknown"])
    policy = parsed(["550 5.7.1 blocked"])
    ambiguous = parsed(["550 no"])

    assert missing.enhanced is not None and missing.enhanced.value == "5.1.1"
    assert policy.enhanced is not None and policy.enhanced.value == "5.7.1"
    assert ambiguous.enhanced is None
    assert missing.code == policy.code == ambiguous.code == 550


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (250, ReplyClass.POSITIVE_COMPLETION),
        (354, ReplyClass.POSITIVE_INTERMEDIATE),
        (450, ReplyClass.TRANSIENT_NEGATIVE),
        (550, ReplyClass.PERMANENT_NEGATIVE),
    ],
)
def test_the_reply_class_is_the_first_digit_named(code: int, expected: ReplyClass) -> None:
    assert parsed([f"{code} text"]).reply_class is expected


def test_transient_and_permanent_are_not_the_same_question() -> None:
    assert parsed(["450 later"]).is_transient is True
    assert parsed(["450 later"]).is_permanent is False
    assert parsed(["550 no"]).is_permanent is True


# --- an enhanced code that contradicts the basic code is dropped ------------


@pytest.mark.parametrize(
    "line",
    ["250 5.1.1 confusing", "550 2.0.0 confusing", "450 5.1.1 confusing", "250 4.7.1 confusing"],
)
def test_an_inconsistent_enhanced_code_is_ignored_not_trusted(line: str) -> None:
    """Taking the enhanced half would turn an acceptance into a rejection."""
    reply = parsed([line])
    assert reply.enhanced is None


@pytest.mark.parametrize(
    "text", ["5.1", "5.1.1.1", "6.1.1", "x.1.1", "5..1", "5.1.", "51.1", "5.1.1234"]
)
def test_a_malformed_enhanced_code_is_not_extracted(text: str) -> None:
    reply = parsed([f"550 {text} text"])
    assert reply.enhanced is None


def test_an_enhanced_status_class_must_be_a_real_one() -> None:
    with pytest.raises(ValueError, match="status class"):
        EnhancedStatusCode(status_class=3, subject=0, detail=0)


# --- malformed replies are typed, not raised -------------------------------


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        ([], ReplyDefect.EMPTY),
        (["nonsense"], ReplyDefect.MALFORMED_LINE),
        (["25 OK"], ReplyDefect.MALFORMED_LINE),
        (["1000 OK"], ReplyDefect.MALFORMED_LINE),
        (["100 OK"], ReplyDefect.CODE_OUT_OF_RANGE),
        (["600 OK"], ReplyDefect.CODE_OUT_OF_RANGE),
        (["250-first", "550 second"], ReplyDefect.INCONSISTENT_CODE),
        (["250-first"], ReplyDefect.NOT_TERMINATED),
        (["250-a", "250-b"], ReplyDefect.NOT_TERMINATED),
        (["250 first", "250 second"], ReplyDefect.MALFORMED_LINE),
        ([f"250-{i}" for i in range(MAX_REPLY_LINES)] + ["250 end"], ReplyDefect.TOO_MANY_LINES),
        (["250 " + "x" * MAX_REPLY_LINE_BYTES], ReplyDefect.LINE_TOO_LONG),
    ],
)
def test_a_malformed_reply_is_reported_not_raised(lines: list[str], expected: ReplyDefect) -> None:
    assert defect(lines) is expected


def test_a_code_change_mid_reply_cannot_hide_a_rejection() -> None:
    """`250-` then `550` is two replies. Guessing which one was meant is worse."""
    assert defect(["250-greeting", "250-more", "550 actually no"]) is (
        ReplyDefect.INCONSISTENT_CODE
    )


def test_parsing_never_raises_on_arbitrary_bounded_text() -> None:
    hostile = [
        "\x00\x01\x02",
        "250",
        "-250 x",
        "250\tOK",
        "  250 OK",
        "250" + "-" * 10,
        "999 x",
        "2 5 0",
    ]
    for line in hostile:
        outcome = parse_reply([line])
        assert isinstance(outcome, ReplyParsed | ReplyMalformed)


# --- what does not survive -------------------------------------------------


def test_an_echoed_address_is_removed_from_the_diagnostic() -> None:
    """Servers echo the recipient. That must not put it in a log line."""
    reply = parsed(["550 5.1.1 <user@example.com>: Recipient address rejected"])
    assert "user@example.com" not in reply.diagnostic
    assert "@" not in reply.diagnostic
    assert REDACTED_MARKER in reply.diagnostic
    assert "Recipient address rejected" in reply.diagnostic


@pytest.mark.parametrize(
    "echoed",
    [
        "user@example.com",
        "<user@example.com>",
        "Support+Billing@example.com",
        "user@[192.0.2.1]",
        '"quoted local"@example.com',
        "user@example.com,other@example.com",
    ],
)
def test_no_form_of_an_echoed_address_survives(echoed: str) -> None:
    reply = parsed([f"550 5.1.1 {echoed} unknown"])
    assert "@" not in reply.diagnostic


def test_a_control_character_never_survives_into_a_diagnostic() -> None:
    reply = parsed(["550 5.1.1 bad\x00\x07\x1b[31m recipient"])
    assert not has_control_character(reply.diagnostic)


def test_a_diagnostic_is_bounded() -> None:
    reply = parsed(["550 5.1.1 " + "x " * 500])
    assert len(reply.diagnostic) <= MAX_DIAGNOSTIC_LENGTH


def test_the_sanitizer_collapses_whitespace_and_trims() -> None:
    assert sanitize_diagnostic("  a\t\tb   c  ") == "a b c"


def test_a_reply_refuses_to_hold_a_control_character() -> None:
    with pytest.raises(ValueError, match="control character"):
        SMTPReply(code=250, diagnostic="line one\r\nline two")


def test_a_reply_refuses_an_impossible_code() -> None:
    for code in (0, 100, 199, 600, 999):
        with pytest.raises(ValueError, match="between 200 and 599"):
            SMTPReply(code=code)


def test_a_reply_refuses_an_enhanced_code_from_another_class() -> None:
    with pytest.raises(ValueError, match="agree with the basic code"):
        SMTPReply(code=250, enhanced=EnhancedStatusCode(status_class=5, subject=1, detail=1))


# --- nothing here decides anything -----------------------------------------


def test_a_reply_carries_no_status_and_no_verdict() -> None:
    fields = set(SMTPReply.__dataclass_fields__)
    for forbidden in ("status", "verdict", "deliverable", "valid", "confidence", "reason"):
        assert forbidden not in fields


def test_250_and_550_are_numbers_at_this_layer() -> None:
    """No property named after a conclusion exists to be read by mistake."""
    for code in (250, 550):
        reply = parsed([f"{code} text"])
        assert not hasattr(reply, "is_deliverable")
        assert not hasattr(reply, "mailbox_exists")
        assert not hasattr(reply, "status")


# --- the work the sanitizer does is bounded, not just its output -----------


@pytest.mark.parametrize("size", [1024, 2048, 4096, 8192, MAX_REPLY_LINES * MAX_REPLY_LINE_BYTES])
def test_only_a_bounded_prefix_is_ever_examined(size: int) -> None:
    """The algorithmic bound, asserted without a clock.

    The input is padded so that everything the sanitizer may look at is
    whitespace except the last ten characters of the allowed prefix. If the
    bound were removed, the run past it would collapse into the result and give
    120 characters instead of 10 — so this fails on the behaviour, not on a
    timing threshold that flakes on a loaded CI machine.

    Comparing `sanitize(text)` to `sanitize(text[:bound])` would *not* work: with
    the bound in place both sides are the same call, so the assertion holds
    whether or not the bound exists.
    """
    visible = 10
    text = " " * (MAX_DIAGNOSTIC_SOURCE_LENGTH - visible) + "A" * size
    assert len(text) > MAX_DIAGNOSTIC_SOURCE_LENGTH
    assert sanitize_diagnostic(text) == "A" * visible


@pytest.mark.parametrize("size", [1024, 2048, 4096, 8192])
def test_the_bound_holds_for_the_shape_that_was_quadratic(size: int) -> None:
    """A long run with no `@` and no whitespace: the worst case for the old rule."""
    visible = 4
    text = " " * (MAX_DIAGNOSTIC_SOURCE_LENGTH - visible) + "y" * size
    assert sanitize_diagnostic(text) == "y" * visible


def test_a_maximal_legal_reply_produces_a_bounded_diagnostic() -> None:
    """40 lines of 2048 bytes is legal input. It must stay cheap."""
    run = "y" * (MAX_REPLY_LINE_BYTES - 5)
    lines = [f"250-{run}"] * (MAX_REPLY_LINES - 1) + [f"250 {run}"]
    reply = parsed(lines)
    assert len(reply.diagnostic) <= MAX_DIAGNOSTIC_LENGTH


def test_the_address_pattern_cannot_backtrack_across_an_at_sign() -> None:
    """`\\S*@\\S*` was quadratic because `\\S*` could eat an `@` and give it back.

    Excluding `@` from both sides is what makes each position cost O(1).
    """
    assert "@" not in _ADDRESS_LIKE.pattern.replace("[^\\s@]", "").replace("@", "", 1)
    assert _ADDRESS_LIKE.pattern == r"[^\s@]*@[^\s@]*"


def test_truncation_does_not_weaken_redaction() -> None:
    """An address inside the examined prefix is still removed."""
    text = "550 5.1.1 <user@example.com> " + "y" * 5000
    assert "@" not in sanitize_diagnostic(text)


# --- exactly what the sanitizer promises -----------------------------------


@pytest.mark.parametrize(
    "echoed",
    [
        "user@example.com",
        "<user@example.com>",
        "RCPT TO:<user@example.com>",
        '"user@example.com"',
        "user@example.com,other@example.com",
        "Support+Secret@example.com",
    ],
)
def test_the_guarantee_a_token_containing_an_at_sign_is_removed(echoed: str) -> None:
    assert "@" not in sanitize_diagnostic(f"5.1.1 {echoed} unknown")


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("user%40example.com", "percent-encoded"),
        ("user\uff20example.com", "a fullwidth at sign"),
        ("Support+Secret", "a local part on its own"),
        ("example.com", "a domain on its own"),
    ],
)
def test_the_non_guarantee_these_forms_are_documented_as_surviving(text: str, label: str) -> None:
    """Not a bug: the sanitizer is not an RFC parser or a general PII scrubber.

    Pinned so the documented guarantee and the behavior cannot drift apart. If
    a future change starts catching one of these, update ADR 0008 too.
    """
    assert sanitize_diagnostic(text) == text, label


def test_a_spaced_at_sign_loses_the_at_but_keeps_the_parts() -> None:
    """The literal `@` still goes; the local part and domain do not.

    This is the sharpest illustration of the boundary, so it is pinned on its
    own rather than lumped in with the forms that survive whole.
    """
    result = sanitize_diagnostic("user @ example.com")
    assert "@" not in result
    assert "user" in result
    assert "example.com" in result
