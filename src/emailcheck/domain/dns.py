"""Typed DNS observations.

Everything a resolver can report is a value here: an answer, a failure, a TTL,
or CNAME metadata. Nothing in this module imports a DNS library, so the mail
route decision can be tested without a resolver and a library exception can
never reach a caller.

A record from DNS is remote data, not trusted input. An MX exchange is validated
the same way an address domain is before it becomes a `HostName`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.address import ascii_domain_issue

#: Requirements section 13. Caps are policy, not protocol truth.
POSITIVE_TTL_CAP_SECONDS: Final = 24 * 60 * 60
NEGATIVE_TTL_CAP_SECONDS: Final = 3 * 60 * 60

#: Used when a resolver reports no usable TTL. Short on purpose: a wrong guess
#: should expire quickly rather than pin a bad answer for hours.
DEFAULT_TTL_SECONDS: Final = 60

#: A chain longer than this is treated as unusable rather than followed.
MAX_CNAME_CHAIN_LENGTH: Final = 8

#: RFC 7505: one MX, preference 0, exchange is the root.
NULL_MX_EXCHANGE: Final = "."


class DNSContractError(ValueError):
    """A DNS value was built from data that violates its invariants.

    This is a programmer error inside an adapter. Remote data that cannot be
    used is reported as a typed failure or anomaly instead.
    """


class DNSFailure(StrEnum):
    """Why a lookup produced no usable answer.

    Five separate things can go wrong and they must not be confused:

    - the name or record authoritatively does not exist (`NXDOMAIN`,
      `NO_RECORDS`), the only failures that may support a hard verdict;
    - the resolver could not answer now (`SERVFAIL`, `TIMEOUT`, `REFUSED`);
    - the answer itself was unusable (`MALFORMED`);
    - this project failed (`INTERNAL_ERROR`), which is never evidence about
      the domain being checked.
    """

    NXDOMAIN = "nxdomain"
    NO_RECORDS = "no_records"
    SERVFAIL = "servfail"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    MALFORMED = "malformed"
    INTERNAL_ERROR = "internal_error"

    @property
    def is_temporary(self) -> bool:
        """Whether one bounded retry is worthwhile."""
        return self in {DNSFailure.SERVFAIL, DNSFailure.TIMEOUT, DNSFailure.REFUSED}

    @property
    def is_authoritative_absence(self) -> bool:
        """Whether the answer proves the name or record does not exist.

        Only this may contribute to `no_mail_route`. A malformed answer or an
        internal failure proves nothing about the domain.
        """
        return self in {DNSFailure.NXDOMAIN, DNSFailure.NO_RECORDS}

    @property
    def is_internal(self) -> bool:
        """Whether this project, not the domain, is at fault."""
        return self is DNSFailure.INTERNAL_ERROR


@dataclass(frozen=True, slots=True)
class HostName:
    """A validated ASCII DNS host name in its canonical form.

    Built from remote data, so it is validated with the same letter-digit-hyphen
    rules an address domain uses. The presentation trailing dot is removed and
    the name is lowercased, so two spellings of one host compare equal.
    """

    value: str

    def __post_init__(self) -> None:
        issue = ascii_domain_issue(self.value)
        if issue is not None:
            raise DNSContractError(f"unusable host name: {issue.value}")

    @classmethod
    def normalize(cls, text: str) -> HostName | None:
        """Return a canonical host name, or None when the text is unusable.

        Remote data uses this instead of the constructor: a malformed exchange
        is an observation to record, not a crash.
        """
        candidate = text.strip().rstrip(".").lower()
        if not candidate or ascii_domain_issue(candidate) is not None:
            return None
        return cls(candidate)


@dataclass(frozen=True, slots=True)
class MXRecord:
    """One MX answer exactly as served, before any usability judgment."""

    preference: int
    exchange: str

    @property
    def is_root_exchange(self) -> bool:
        return self.exchange.strip() == NULL_MX_EXCHANGE

    @property
    def is_null_mx(self) -> bool:
        """RFC 7505 form only: preference 0 and the root as exchange."""
        return self.preference == 0 and self.is_root_exchange


@dataclass(frozen=True, slots=True)
class CNAMEChain:
    """Safe metadata about a CNAME chain: names only, bounded in length."""

    names: tuple[HostName, ...] = ()
    truncated: bool = False

    @property
    def length(self) -> int:
        return len(self.names)


def _is_whole_seconds(value: object) -> bool:
    """Accept only a real integer count of seconds.

    `bool` is excluded even though it is an `int` subclass, and `float` and
    `str` are excluded outright: a TTL arrives from remote data and must be
    normalized before it becomes a value.
    """
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class TTL:
    """A record lifetime, both as served and as this project will honor it.

    This type accepts only already-normalized values. `apply_ttl_policy` does
    the normalizing; anything missing, negative, or of the wrong type is turned
    into the short default there rather than being stored here.
    """

    authoritative_seconds: int | None
    applied_seconds: int
    positive: bool

    def __post_init__(self) -> None:
        if not _is_whole_seconds(self.applied_seconds):
            raise DNSContractError("applied TTL must be a whole number of seconds")
        if self.applied_seconds < 0:
            raise DNSContractError("applied TTL cannot be negative")
        if not isinstance(self.positive, bool):
            raise DNSContractError("TTL polarity must be a bool")
        cap = POSITIVE_TTL_CAP_SECONDS if self.positive else NEGATIVE_TTL_CAP_SECONDS
        if self.applied_seconds > cap:
            raise DNSContractError("applied TTL exceeds the configured cap")
        if self.authoritative_seconds is None:
            return
        if not _is_whole_seconds(self.authoritative_seconds):
            raise DNSContractError("authoritative TTL must be a whole number of seconds")
        if self.authoritative_seconds < 0:
            raise DNSContractError("a negative authoritative TTL is not a served value")
        if self.applied_seconds > self.authoritative_seconds:
            raise DNSContractError("applied TTL cannot exceed the served TTL")

    @property
    def was_supplied(self) -> bool:
        return self.authoritative_seconds is not None

    @property
    def was_capped(self) -> bool:
        return (
            self.authoritative_seconds is not None
            and self.applied_seconds < self.authoritative_seconds
        )


def apply_ttl_policy(
    authoritative_seconds: object,
    *,
    positive: bool,
    positive_cap_seconds: int = POSITIVE_TTL_CAP_SECONDS,
    negative_cap_seconds: int = NEGATIVE_TTL_CAP_SECONDS,
    default_seconds: int = DEFAULT_TTL_SECONDS,
) -> TTL:
    """Normalize a served TTL into a value the rest of the system can trust.

    A missing, negative, or wrongly typed TTL falls back to a short default
    rather than to the cap, so a broken answer is re-checked soon; such a value
    is not recorded as authoritative, because it was never a usable served TTL.
    A served TTL of zero is honored as zero: the server asked for no caching.
    """
    cap = positive_cap_seconds if positive else negative_cap_seconds
    if not _is_whole_seconds(authoritative_seconds) or authoritative_seconds < 0:  # type: ignore[operator]
        return TTL(
            authoritative_seconds=None,
            applied_seconds=min(default_seconds, cap),
            positive=positive,
        )
    served = int(authoritative_seconds)  # type: ignore[call-overload]
    return TTL(
        authoritative_seconds=served,
        applied_seconds=min(served, cap),
        positive=positive,
    )


@dataclass(frozen=True, slots=True)
class MXLookup:
    """The result of asking for MX records.

    Exactly one of an answer or a typed failure. A lookup that reports neither
    would leave a caller guessing what happened, so it cannot be built.
    """

    records: tuple[MXRecord, ...] = ()
    failure: DNSFailure | None = None
    ttl: TTL | None = None
    cname_chain: CNAMEChain = CNAMEChain()

    def __post_init__(self) -> None:
        if self.records and self.failure is not None:
            raise DNSContractError("a lookup cannot both answer and fail")
        if not self.records and self.failure is None:
            raise DNSContractError("a lookup must carry either records or a failure")

    @property
    def succeeded(self) -> bool:
        return self.failure is None


@dataclass(frozen=True, slots=True)
class AddressLookup:
    """The result of asking for A or AAAA records.

    Addresses stay as text here. Judging them is the destination policy's job,
    so no code can mistake "resolved" for "allowed". As with `MXLookup`,
    exactly one of an answer or a typed failure is required.
    """

    addresses: tuple[str, ...] = ()
    failure: DNSFailure | None = None
    ttl: TTL | None = None
    cname_chain: CNAMEChain = CNAMEChain()

    def __post_init__(self) -> None:
        if self.addresses and self.failure is not None:
            raise DNSContractError("a lookup cannot both answer and fail")
        if not self.addresses and self.failure is None:
            raise DNSContractError("a lookup must carry either addresses or a failure")

    @property
    def succeeded(self) -> bool:
        return self.failure is None


class DNSRecordType(StrEnum):
    """The record types this project asks for."""

    MX = "mx"
    A = "a"
    AAAA = "aaaa"


@dataclass(frozen=True, slots=True)
class DNSCacheKey:
    """What identifies one cached DNS answer.

    A validated host name and a record type, never a free string. MX, A, and
    AAAA answers for one host therefore cannot overwrite each other, and the
    key carries no local part and no complete address.
    """

    host: HostName
    record_type: DNSRecordType

    def __str__(self) -> str:
        return f"{self.record_type.value}:{self.host.value}"
