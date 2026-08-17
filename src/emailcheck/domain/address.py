"""Safe address input boundary and conservative mailbox syntax.

Phase 1 owns the only path from untrusted text to a value that a later DNS or
SMTP port will accept. `RawAddressInput` is deliberately inert: it carries the
submitted text and a redacted display form, and offers no conversion to an SMTP
target. The typed values below can only be built from text that already
satisfies the invariants, so raw input cannot reach a port without passing
through `parse_address`.

Problems in user input are returned as `AddressRejected`, never raised.
Constructing a value type from text that violates an invariant is a programmer
error and raises `AddressContractError`.

No DNS, SMTP, dataset, or network behavior belongs in this module.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import idna

from emailcheck.domain.reasons import ReasonCode

LOCAL_PART_MAX_LENGTH: Final = 64
DOMAIN_LABEL_MAX_LENGTH: Final = 63
DOMAIN_MAX_LENGTH: Final = 253
ADDRESS_MAX_LENGTH: Final = 254

#: Version of the canonicalization used for HMAC material. Bump this when the
#: normalized target form changes, so stored correlations stay comparable.
CANONICALIZATION_VERSION: Final = "1"

#: Only ASCII whitespace is treated as user-interface framing. Other Unicode
#: spaces are left in place so they are rejected as disallowed characters
#: rather than silently accepted as separators.
_UI_WHITESPACE: Final = " \t\r\n\v\f"

#: RFC 5322 atext. The local part is a dot-atom: atext runs joined by ".".
_ATEXT: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
)
_LOCAL_PART_CHARS: Final = _ATEXT | {"."}
_DOMAIN_LABEL_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

#: Unicode categories that are never a mailbox name, whatever SMTPUTF8 allows:
#: controls (Cc), formatting and bidirectional overrides (Cf), and the space and
#: line separators (Zs, Zl, Zp). These are invisible or act as separators, so
#: treating them as an unsupported-but-plausible address would be wrong.
_DISALLOWED_UNICODE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zs", "Zl", "Zp"})

_MAX_REDACTED_DOMAIN_LENGTH: Final = 63


class AddressContractError(ValueError):
    """A value type was constructed from text that violates its invariants.

    This is a programmer error. User input never reaches it: `parse_address`
    classifies bad input into a result instead.
    """


class AddressSyntaxIssue(StrEnum):
    """The specific observation that made an address unusable.

    Aggregation reads this instead of re-parsing text, so members are stable and
    describe one cause each.
    """

    EMPTY_INPUT = "empty_input"
    CONTROL_CHARACTER = "control_character"
    DISPLAY_NAME_FORM = "display_name_form"
    ADDRESS_LIST = "address_list"
    QUOTED_LOCAL_PART = "quoted_local_part"
    MISSING_AT = "missing_at"
    MULTIPLE_AT = "multiple_at"
    MISSING_LOCAL_PART = "missing_local_part"
    MISSING_DOMAIN = "missing_domain"
    DOMAIN_LITERAL = "domain_literal"
    UNICODE_LOCAL_PART = "unicode_local_part"
    LOCAL_PART_DISALLOWED_UNICODE = "local_part_disallowed_unicode"
    LOCAL_PART_TOO_LONG = "local_part_too_long"
    LOCAL_PART_LEADING_DOT = "local_part_leading_dot"
    LOCAL_PART_TRAILING_DOT = "local_part_trailing_dot"
    LOCAL_PART_CONSECUTIVE_DOTS = "local_part_consecutive_dots"
    LOCAL_PART_INVALID_CHARACTER = "local_part_invalid_character"
    DOMAIN_EMPTY_LABEL = "domain_empty_label"
    DOMAIN_INVALID_CHARACTER = "domain_invalid_character"
    DOMAIN_HYPHEN_POSITION = "domain_hyphen_position"
    DOMAIN_LABEL_TOO_LONG = "domain_label_too_long"
    DOMAIN_TOO_LONG = "domain_too_long"
    DOMAIN_IDNA_FAILURE = "domain_idna_failure"
    ADDRESS_TOO_LONG = "address_too_long"


class RejectionKind(StrEnum):
    """Whether the input broke the supported grammar or fell outside it.

    `INVALID` is target-specific evidence that the address cannot be delivered
    as written. `UNSUPPORTED` means this MVP cannot judge the form at all, and
    must resolve to `unknown` later, never to an optimistic or a hard verdict.
    """

    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


_ISSUE_CLASSIFICATION: Final[dict[AddressSyntaxIssue, tuple[RejectionKind, ReasonCode]]] = {
    AddressSyntaxIssue.EMPTY_INPUT: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.CONTROL_CHARACTER: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DISPLAY_NAME_FORM: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.ADDRESS_LIST: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.QUOTED_LOCAL_PART: (
        RejectionKind.UNSUPPORTED,
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ),
    AddressSyntaxIssue.MISSING_AT: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.MULTIPLE_AT: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.MISSING_LOCAL_PART: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.MISSING_DOMAIN: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_LITERAL: (
        RejectionKind.UNSUPPORTED,
        ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
    ),
    AddressSyntaxIssue.UNICODE_LOCAL_PART: (
        RejectionKind.UNSUPPORTED,
        ReasonCode.UNSUPPORTED_SMTPUTF8,
    ),
    AddressSyntaxIssue.LOCAL_PART_DISALLOWED_UNICODE: (
        RejectionKind.INVALID,
        ReasonCode.INVALID_SYNTAX,
    ),
    AddressSyntaxIssue.LOCAL_PART_TOO_LONG: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.LOCAL_PART_LEADING_DOT: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.LOCAL_PART_TRAILING_DOT: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.LOCAL_PART_CONSECUTIVE_DOTS: (
        RejectionKind.INVALID,
        ReasonCode.INVALID_SYNTAX,
    ),
    AddressSyntaxIssue.LOCAL_PART_INVALID_CHARACTER: (
        RejectionKind.INVALID,
        ReasonCode.INVALID_SYNTAX,
    ),
    AddressSyntaxIssue.DOMAIN_EMPTY_LABEL: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_HYPHEN_POSITION: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_LABEL_TOO_LONG: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_TOO_LONG: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.DOMAIN_IDNA_FAILURE: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
    AddressSyntaxIssue.ADDRESS_TOO_LONG: (RejectionKind.INVALID, ReasonCode.INVALID_SYNTAX),
}


def _is_control_character(char: str) -> bool:
    code = ord(char)
    return code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F


def has_control_character(text: str) -> bool:
    """Report CR, LF, NUL, and other C0/C1 control characters anywhere in `text`."""
    return any(_is_control_character(char) for char in text)


def redact_address_text(text: str) -> str:
    """Return a bounded display form that never contains a complete local part.

    Control characters are dropped so a redacted value is always safe to write
    to a log or an API response. Framing whitespace is removed first, so the
    same address redacts identically whether or not it arrived padded.
    """
    printable = "".join(char for char in text.strip(_UI_WHITESPACE) if char.isprintable())
    local, separator, domain = printable.rpartition("@")
    if not separator:
        return "***"
    masked_local = f"{local[0]}***" if len(local) >= 2 else "*"
    shown_domain = domain[:_MAX_REDACTED_DOMAIN_LENGTH] if domain else "***"
    return f"{masked_local}@{shown_domain}"


def local_part_issue(value: str) -> AddressSyntaxIssue | None:
    """Return why `value` is not a supported ASCII dot-atom local part, or None.

    A non-ASCII local part is normally reported as unsupported, because this MVP
    does not implement SMTPUTF8 and cannot judge such an address. Invisible and
    separator characters are the exception: they are never part of a mailbox
    name under any grammar, so they are a grammar violation rather than a form
    this project merely declines to handle.
    """
    if not value:
        return AddressSyntaxIssue.MISSING_LOCAL_PART
    non_ascii = [char for char in value if ord(char) > 0x7F]
    if non_ascii:
        if any(unicodedata.category(char) in _DISALLOWED_UNICODE_CATEGORIES for char in non_ascii):
            return AddressSyntaxIssue.LOCAL_PART_DISALLOWED_UNICODE
        return AddressSyntaxIssue.UNICODE_LOCAL_PART
    if len(value) > LOCAL_PART_MAX_LENGTH:
        return AddressSyntaxIssue.LOCAL_PART_TOO_LONG
    if value.startswith("."):
        return AddressSyntaxIssue.LOCAL_PART_LEADING_DOT
    if value.endswith("."):
        return AddressSyntaxIssue.LOCAL_PART_TRAILING_DOT
    if ".." in value:
        return AddressSyntaxIssue.LOCAL_PART_CONSECUTIVE_DOTS
    if any(char not in _LOCAL_PART_CHARS for char in value):
        return AddressSyntaxIssue.LOCAL_PART_INVALID_CHARACTER
    return None


def ascii_domain_issue(value: str) -> AddressSyntaxIssue | None:
    """Return why `value` is not a usable lowercase ASCII DNS domain, or None.

    Structural problems are reported before the total-length limit so the most
    specific cause wins.
    """
    if not value:
        return AddressSyntaxIssue.MISSING_DOMAIN
    if any(ord(char) > 0x7F for char in value):
        return AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER
    for label in value.split("."):
        if not label:
            return AddressSyntaxIssue.DOMAIN_EMPTY_LABEL
        if any(char not in _DOMAIN_LABEL_CHARS for char in label):
            return AddressSyntaxIssue.DOMAIN_INVALID_CHARACTER
        if label.startswith("-") or label.endswith("-"):
            return AddressSyntaxIssue.DOMAIN_HYPHEN_POSITION
        if len(label) > DOMAIN_LABEL_MAX_LENGTH:
            return AddressSyntaxIssue.DOMAIN_LABEL_TOO_LONG
    if len(value) > DOMAIN_MAX_LENGTH:
        return AddressSyntaxIssue.DOMAIN_TOO_LONG
    return None


@dataclass(frozen=True, slots=True)
class RawAddressInput:
    """Untrusted text exactly as submitted.

    This type intentionally offers no SMTP target. Only `parse_address` can turn
    it into a value that a DNS or SMTP port accepts.
    """

    value: str

    @property
    def redacted(self) -> str:
        return redact_address_text(self.value)


@dataclass(frozen=True, slots=True)
class LocalPart:
    """A validated ASCII dot-atom local part, preserved exactly as submitted.

    Case, dots, and plus tags are never rewritten: two local parts differing
    only in case may be different mailboxes, and only the receiving server knows.
    """

    value: str

    def __post_init__(self) -> None:
        issue = local_part_issue(self.value)
        if issue is not None:
            raise AddressContractError(f"unusable local part: {issue.value}")


@dataclass(frozen=True, slots=True)
class DomainName:
    """A mail domain in both the submitted form and the encoded ASCII form.

    `ascii_form` is what DNS and SMTP use. `unicode_form` is kept only so a
    later interface can display what the user typed.

    The two fields must describe the same domain: `ascii_form` has to be exactly
    what encoding `unicode_form` produces. Without that check a caller could
    display one domain while a probe contacted another.
    """

    unicode_form: str
    ascii_form: str

    def __post_init__(self) -> None:
        if has_control_character(self.unicode_form):
            raise AddressContractError("domain input contains a control character")
        issue = ascii_domain_issue(self.ascii_form)
        if issue is not None:
            raise AddressContractError(f"unusable domain: {issue.value}")
        encoded, encoding_issue = _encode_domain(self.unicode_form)
        if encoding_issue is not None:
            raise AddressContractError(f"domain input cannot be encoded: {encoding_issue.value}")
        if encoded != self.ascii_form:
            raise AddressContractError("domain input does not encode to the given ASCII form")

    @property
    def is_internationalized(self) -> bool:
        return self.unicode_form.lower() != self.ascii_form


@dataclass(frozen=True, slots=True)
class NormalizedAddress:
    """One validated mailbox that later ports may act on."""

    local_part: LocalPart
    domain: DomainName

    def __post_init__(self) -> None:
        if len(self.smtp_target) > ADDRESS_MAX_LENGTH:
            raise AddressContractError("address exceeds the maximum length")

    @property
    def smtp_target(self) -> str:
        """The envelope recipient. Guaranteed free of CR, LF, NUL, and controls."""
        return f"{self.local_part.value}@{self.domain.ascii_form}"

    @property
    def redacted(self) -> str:
        return redact_address_text(self.smtp_target)

    @property
    def hmac_material(self) -> str:
        """Deterministic input for correlation hashing.

        Key management and the HMAC itself belong to a later Phase; this only
        fixes what is hashed.
        """
        return f"{CANONICALIZATION_VERSION}:{self.smtp_target}"


@dataclass(frozen=True, slots=True)
class AddressAccepted:
    """The input is one supported mailbox."""

    address: NormalizedAddress


@dataclass(frozen=True, slots=True)
class AddressRejected:
    """The input cannot be used, with enough detail to classify it later."""

    kind: RejectionKind
    issue: AddressSyntaxIssue
    reason: ReasonCode
    redacted_input: str


AddressParseResult = AddressAccepted | AddressRejected


def _reject(issue: AddressSyntaxIssue, redacted_input: str) -> AddressRejected:
    kind, reason = _ISSUE_CLASSIFICATION[issue]
    return AddressRejected(kind=kind, issue=issue, reason=reason, redacted_input=redacted_input)


def _closing_quote_index(text: str) -> int | None:
    """Index of the quote closing a leading quoted string, honoring backslashes."""
    escaped = False
    for index, char in enumerate(text[1:], start=1):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index
    return None


def encode_domain_ascii(domain: str) -> str | None:
    """The canonical ASCII form of `domain`, or `None` when it has none.

    The **public** name for Phase 1's encoder, exported because two other places
    need the identical answer and were not getting it. `application/admin.py`
    stored whatever an operator typed, so `EXAMPLE.TEST`, `example.test.`, and
    `bücher.test` were three different blocks and a route spelled any other way
    walked past all of them; `composition.py`'s lab destination allowlist has
    exactly the same problem to avoid. The final system audit found the first.

    One encoder, so a domain has one identity everywhere: the address parser,
    the mail route, the destination policy, an operator's kill switch, and a lab
    allowlist all compare the same string. A second `.lower()` somewhere else is
    the bug this exists to prevent, and it is why this is a shared function
    rather than three implementations that agree today.
    """
    encoded, issue = _encode_domain(domain)
    return None if issue is not None else encoded


def _encode_domain(domain: str) -> tuple[str, AddressSyntaxIssue | None]:
    """Return the lowercase ASCII form of `domain`.

    A domain that is already ASCII is only lowercased, so the reported cause
    stays specific. A domain with non-ASCII characters goes through IDNA, whose
    failures are reported as one cause because the library does not expose a
    stable machine-readable code.
    """
    if any(ord(char) > 0x7F for char in domain):
        try:
            encoded = idna.encode(domain, uts46=True, transitional=False)
        except UnicodeError:
            # idna.IDNAError derives from UnicodeError. The library's message is
            # never surfaced: only this project's own issue vocabulary is.
            return "", AddressSyntaxIssue.DOMAIN_IDNA_FAILURE
        return encoded.decode("ascii"), None
    return domain.lower(), None


def parse_address(raw: RawAddressInput) -> AddressParseResult:
    """Classify one submitted address into an accepted value or a typed rejection.

    The order of checks is deliberate. Framing problems come first because a
    malformed envelope cannot be split reliably. The domain is then validated
    before the local part, so a domain that breaks the supported grammar
    outranks a local part that is merely outside MVP support, matching the
    aggregation precedence in `docs/status-model.md`.
    """
    redacted = raw.redacted
    text = raw.value.strip(_UI_WHITESPACE)

    if not text:
        return _reject(AddressSyntaxIssue.EMPTY_INPUT, redacted)
    if has_control_character(text):
        return _reject(AddressSyntaxIssue.CONTROL_CHARACTER, redacted)

    if text.startswith('"'):
        closing = _closing_quote_index(text)
        if closing is not None and text[closing + 1 : closing + 2] == "@":
            return _reject(AddressSyntaxIssue.QUOTED_LOCAL_PART, redacted)
    if "<" in text or ">" in text:
        return _reject(AddressSyntaxIssue.DISPLAY_NAME_FORM, redacted)
    if "," in text or ";" in text:
        return _reject(AddressSyntaxIssue.ADDRESS_LIST, redacted)

    at_count = text.count("@")
    if at_count == 0:
        return _reject(AddressSyntaxIssue.MISSING_AT, redacted)
    if at_count > 1:
        return _reject(AddressSyntaxIssue.MULTIPLE_AT, redacted)

    local_text, _, domain_text = text.partition("@")
    if not local_text:
        return _reject(AddressSyntaxIssue.MISSING_LOCAL_PART, redacted)
    if not domain_text:
        return _reject(AddressSyntaxIssue.MISSING_DOMAIN, redacted)
    if domain_text.startswith("[") and domain_text.endswith("]"):
        return _reject(AddressSyntaxIssue.DOMAIN_LITERAL, redacted)

    ascii_domain, encoding_issue = _encode_domain(domain_text)
    if encoding_issue is not None:
        return _reject(encoding_issue, redacted)
    domain_problem = ascii_domain_issue(ascii_domain)
    if domain_problem is not None:
        return _reject(domain_problem, redacted)

    local_problem = local_part_issue(local_text)
    if local_problem is not None:
        return _reject(local_problem, redacted)

    if len(f"{local_text}@{ascii_domain}") > ADDRESS_MAX_LENGTH:
        return _reject(AddressSyntaxIssue.ADDRESS_TOO_LONG, redacted)

    return AddressAccepted(
        address=NormalizedAddress(
            local_part=LocalPart(local_text),
            domain=DomainName(unicode_form=domain_text, ascii_form=ascii_domain),
        )
    )
