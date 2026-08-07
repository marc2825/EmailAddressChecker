"""Remote replies, as structured values rather than as text.

A reply is the most attacker-influenced input this project handles: a remote
operator writes it, it often echoes the address that was asked about, and it
ends up near logs and API responses. So the text is not kept. What is kept is
the basic code, a valid enhanced code when there is one, and a bounded
diagnostic with the addresses removed.

`docs/smtp-state-machine.md` section 5 is the specification. Nothing here
decides what a code means for deliverability: `250` and `550` are numbers at
this layer, and `docs/status-model.md` section 4 gives Phase 5 the job of
weighing them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.address import has_control_character

#: RFC 5321 section 4.5.3.1.5: a reply line is at most 512 octets. Servers
#: exceed it, so the cap is generous, but it is a cap.
MAX_REPLY_LINE_BYTES: Final = 2048

#: A reply longer than this is a tarpit or a bug, not information.
MAX_REPLY_LINES: Final = 40

#: What survives into evidence. Long enough for "mailbox unavailable", short
#: enough that nobody stores a paragraph of remote prose.
MAX_DIAGNOSTIC_LENGTH: Final = 120

#: How much remote text the sanitizer is allowed to look at.
#:
#: This bound is the point. A reply may legally be 40 lines of 2048 bytes, and
#: sanitizing all 80 KB to produce 120 characters let a tarpit spend this
#: project's CPU: the output cap bounded the answer but not the work. Everything
#: past this prefix cannot reach a 120-character diagnostic anyway, so it is
#: dropped before any pattern runs. Generous enough that a real diagnostic is
#: never truncated by it, since redaction can only shorten the text.
MAX_DIAGNOSTIC_SOURCE_LENGTH: Final = 512

#: Replaces a token containing an ASCII `@`. A server that echoes the recipient
#: must not thereby put it in a log line.
REDACTED_MARKER: Final = "[redacted]"

#: RFC 5321 section 4.2: exactly three digits, then a space, a hyphen for a
#: continuation, or the end of the line. The separator is not optional-and-then-
#: anything: without that, `"1000 OK"` reads as code 100 with the text `"0 OK"`.
_REPLY_LINE: Final = re.compile(r"^(?P<code>\d{3})(?:(?P<separator>[ -])(?P<text>.*))?$", re.DOTALL)

#: RFC 3463. The lookahead matters: without it `5.1.1.1` yields `5.1.1`, which
#: is a different and entirely made-up status.
_ENHANCED: Final = re.compile(
    r"^(?P<class>[245])\.(?P<subject>\d{1,3})\.(?P<detail>\d{1,3})(?=\s|$)"
)
#: A whitespace-delimited token containing an ASCII `@`.
#:
#: Written as `[^\s@]*@[^\s@]*` rather than `\S*@\S*`. The two match the same
#: tokens, but `\S*` can consume an `@` and then backtrack over it, which makes
#: the search quadratic in the length of a run without one: 8000 characters took
#: 58 ms, and doubling the length quadrupled the time. Excluding `@` from both
#: sides removes the ambiguity, so each position is tried once.
_ADDRESS_LIKE: Final = re.compile(r"[^\s@]*@[^\s@]*")
_WHITESPACE: Final = re.compile(r"\s+")


class ReplyDefect(StrEnum):
    """Why a reply could not be read. Each is an observation, not a crash."""

    EMPTY = "empty"
    LINE_TOO_LONG = "line_too_long"
    TOO_MANY_LINES = "too_many_lines"
    MALFORMED_LINE = "malformed_line"
    CODE_OUT_OF_RANGE = "code_out_of_range"
    INCONSISTENT_CODE = "inconsistent_code"
    NOT_TERMINATED = "not_terminated"


class ReplyClass(StrEnum):
    """The first digit, named. Still not a verdict."""

    POSITIVE_COMPLETION = "positive_completion"
    POSITIVE_INTERMEDIATE = "positive_intermediate"
    TRANSIENT_NEGATIVE = "transient_negative"
    PERMANENT_NEGATIVE = "permanent_negative"


@dataclass(frozen=True, slots=True)
class EnhancedStatusCode:
    """An RFC 3463 status code, kept only when it is structurally valid."""

    status_class: int
    subject: int
    detail: int

    def __post_init__(self) -> None:
        if self.status_class not in {2, 4, 5}:
            raise ValueError("an enhanced status class must be 2, 4, or 5")
        if not 0 <= self.subject <= 999 or not 0 <= self.detail <= 999:
            raise ValueError("an enhanced status subject and detail must be within three digits")

    @property
    def value(self) -> str:
        return f"{self.status_class}.{self.subject}.{self.detail}"


def sanitize_diagnostic(text: str) -> str:
    """Return the part of a reply that is safe to keep.

    **What this guarantees**, and nothing beyond it:

    - a whitespace-delimited token containing a literal ASCII `@` is replaced,
      so `user@example.com` and `<user@example.com>` do not survive;
    - a literal ASCII `@` never appears in the result;
    - control and format characters are removed, so the text cannot break a log
      line or reorder the text around it;
    - the result is at most `MAX_DIAGNOSTIC_LENGTH` characters.

    **What it does not guarantee.** It is not an RFC mailbox parser and not a
    general PII scrubber. A local part on its own (`Support+Secret`), a domain
    on its own, a spaced form (`user @ example.com`), a percent-encoded form
    (`user%40example.com`), and a fullwidth at sign (U+FF20 rather than U+0040) all
    survive. `docs/requirements.md` section 16 requires that ordinary logs carry
    no *complete* address, which this meets; it does not make remote text safe
    in general, and a raw SMTP reply must never be written to an ordinary log.

    The work is bounded before any of it starts: only the first
    `MAX_DIAGNOSTIC_SOURCE_LENGTH` characters are examined, because nothing past
    them could reach a 120-character result. Without that bound, a legal 80 KB
    reply cost 153 ms of CPU to produce 120 characters.
    """
    bounded = text[:MAX_DIAGNOSTIC_SOURCE_LENGTH]
    without_addresses = _ADDRESS_LIKE.sub(REDACTED_MARKER, bounded)
    printable = "".join(
        character
        for character in without_addresses
        if character.isprintable() or character in " \t"
    )
    collapsed = _WHITESPACE.sub(" ", printable).strip()
    if len(collapsed) > MAX_DIAGNOSTIC_LENGTH:
        return collapsed[:MAX_DIAGNOSTIC_LENGTH].rstrip()
    return collapsed


@dataclass(frozen=True, slots=True)
class SMTPReply:
    """One complete reply, reduced to what may be published.

    The remote text is gone by the time this exists. `diagnostic` is bounded and
    redacted, and `docs/requirements.md` section 11 forbids returning the raw
    form in any public response.
    """

    code: int
    enhanced: EnhancedStatusCode | None = None
    diagnostic: str = ""
    line_count: int = 1

    def __post_init__(self) -> None:
        if not 200 <= self.code <= 599:
            raise ValueError("an SMTP reply code must be between 200 and 599")
        if self.line_count < 1:
            raise ValueError("a reply has at least one line")
        if has_control_character(self.diagnostic):
            raise ValueError("a diagnostic cannot contain a control character")
        if len(self.diagnostic) > MAX_DIAGNOSTIC_LENGTH:
            raise ValueError("a diagnostic exceeds the maximum length")
        if self.enhanced is not None and self.enhanced.status_class != self.code // 100:
            raise ValueError("an enhanced status class must agree with the basic code")

    @property
    def reply_class(self) -> ReplyClass:
        return {
            2: ReplyClass.POSITIVE_COMPLETION,
            3: ReplyClass.POSITIVE_INTERMEDIATE,
            4: ReplyClass.TRANSIENT_NEGATIVE,
            5: ReplyClass.PERMANENT_NEGATIVE,
        }[self.code // 100]

    @property
    def is_transient(self) -> bool:
        return self.code // 100 == 4

    @property
    def is_permanent(self) -> bool:
        return self.code // 100 == 5


@dataclass(frozen=True, slots=True)
class ReplyParsed:
    reply: SMTPReply


@dataclass(frozen=True, slots=True)
class ReplyMalformed:
    """The reply could not be read. This is never mailbox evidence."""

    defect: ReplyDefect


ReplyOutcome = ReplyParsed | ReplyMalformed


def parse_reply(lines: list[str]) -> ReplyOutcome:
    """Read a single or multiline reply into a value, or report why not.

    Every line must carry the same code, which RFC 5321 requires and which a
    server splitting one reply into two would violate. Taking the last code and
    ignoring the rest would let a `250-` prelude hide a `550` conclusion, or the
    reverse, so a disagreement is a defect rather than a preference.
    """
    if not lines:
        return ReplyMalformed(defect=ReplyDefect.EMPTY)
    if len(lines) > MAX_REPLY_LINES:
        return ReplyMalformed(defect=ReplyDefect.TOO_MANY_LINES)

    code: int | None = None
    texts: list[str] = []
    terminated = False

    for index, raw in enumerate(lines):
        if len(raw.encode("utf-8", errors="replace")) > MAX_REPLY_LINE_BYTES:
            return ReplyMalformed(defect=ReplyDefect.LINE_TOO_LONG)
        line = raw.rstrip("\r\n")
        match = _REPLY_LINE.match(line)
        if match is None:
            return ReplyMalformed(defect=ReplyDefect.MALFORMED_LINE)

        line_code = int(match.group("code"))
        if not 200 <= line_code <= 599:
            return ReplyMalformed(defect=ReplyDefect.CODE_OUT_OF_RANGE)
        if code is None:
            code = line_code
        elif line_code != code:
            return ReplyMalformed(defect=ReplyDefect.INCONSISTENT_CODE)

        separator = match.group("separator")
        text = match.group("text") or ""
        if separator == "-":
            if index == len(lines) - 1:
                return ReplyMalformed(defect=ReplyDefect.NOT_TERMINATED)
        else:
            if index != len(lines) - 1:
                # A terminating line before the end means these are two replies,
                # not one, and guessing which the caller wanted is how a `250`
                # gets attributed to a command that received a `550`.
                return ReplyMalformed(defect=ReplyDefect.MALFORMED_LINE)
            terminated = True
        texts.append(text)

    if code is None or not terminated:
        return ReplyMalformed(defect=ReplyDefect.NOT_TERMINATED)

    enhanced, remainder = _read_enhanced(texts[0], code)
    diagnostic = sanitize_diagnostic(" ".join([remainder, *texts[1:]]))
    return ReplyParsed(
        reply=SMTPReply(
            code=code,
            enhanced=enhanced,
            diagnostic=diagnostic,
            line_count=len(lines),
        )
    )


def _read_enhanced(text: str, code: int) -> tuple[EnhancedStatusCode | None, str]:
    """Return the enhanced code and the text that follows it.

    An enhanced code whose class contradicts the basic code is dropped rather
    than trusted: `250 5.1.1` describes nothing real, and taking the enhanced
    half would turn an acceptance into a rejection. When it is dropped, the
    text is returned whole, so nothing is silently sliced off a diagnostic.
    """
    stripped = text.strip()
    match = _ENHANCED.match(stripped)
    if match is None:
        return None, text
    try:
        enhanced = EnhancedStatusCode(
            status_class=int(match.group("class")),
            subject=int(match.group("subject")),
            detail=int(match.group("detail")),
        )
    except ValueError:
        return None, text
    if enhanced.status_class != code // 100:
        return None, text
    return enhanced, stripped[match.end() :]
