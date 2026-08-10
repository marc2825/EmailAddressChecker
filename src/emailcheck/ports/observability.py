"""Where an operator finds out that something went wrong here.

Phase 5 stop condition 5: `internal_error` resolves to `unknown`, and `unknown`
is a non-answer a caller sees constantly — so a failure of this project's own
must not disappear into it. It leads tier 4 precisely so it is the reason a
verdict *names*, and that is only useful if something is listening.

**This port carries no target data.** An event names a reason code, a
recipient *domain* at most, and a bounded category. Never a local part, never a
complete address, never remote text, never an exception message, and never a
principal identifier — `docs/requirements.md` section 16 forbids a full address
in ordinary logs, and an account identifier in a log line is the correlation
handle an HMAC exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from emailcheck.domain.reasons import ReasonCode

#: Bounded, because an event is written to a log an attacker may be able to
#: influence the volume of.
MAX_DETAIL_LENGTH: Final = 120


class OperatorEventKind(StrEnum):
    """What happened. Operational vocabulary, never a deliverability status."""

    #: A failure of this project's own reached the verdict.
    INTERNAL_ERROR = "internal_error"
    #: Capacity refused the request before any work began.
    ADMISSION_REFUSED = "admission_refused"
    #: The verification-total deadline expired.
    DEADLINE_EXCEEDED = "deadline_exceeded"
    #: This project's own pacing refused the request.
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class OperatorEvent:
    """One thing an operator needs to know, with nothing about the user in it."""

    kind: OperatorEventKind
    #: The published reason, when the event came from a verdict.
    reason: ReasonCode | None = None
    #: The recipient's domain. Analytics aggregate by domain and reason
    #: (`docs/requirements.md` section 16), and a domain is not a mailbox.
    domain: str | None = None
    #: A bounded category this project chose. Never remote text and never an
    #: exception message.
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperatorEventKind):
            raise ValueError("an operator event must name a published kind")
        if self.reason is not None and not isinstance(self.reason, ReasonCode):
            raise ValueError("an operator event reason must be a published reason code")
        for field_name in ("domain", "detail"):
            value = getattr(self, field_name)
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"an operator event {field_name} must be a string")
            if "@" in value:
                # The same shape check `rate_limit_key` makes, for the same
                # reason: no field of an event may be a mailbox.
                raise ValueError(f"an operator event {field_name} may not carry an address")
            if len(value) > MAX_DETAIL_LENGTH:
                raise ValueError(f"an operator event {field_name} is too long")


class OperatorSink(Protocol):
    def record(self, event: OperatorEvent) -> None:
        """Report one operational event. Must not raise."""
        ...
