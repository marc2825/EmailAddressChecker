"""Deciding what DNS said about a domain's mail route.

Pure policy: it takes observations and returns a classification. It performs no
lookups, so every branch is reachable in a test without a resolver.

Two rules shape everything here. A hard-invalid result must have very high
precision, so only a standards-compliant Null MX or a proven absence of any
route produces one. And an MX host that cannot be used is not the same as a
domain that cannot receive mail, so the two are reported separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from emailcheck.domain.dns import TTL, DNSFailure, HostName, MXRecord
from emailcheck.domain.evidence import EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.security.destination import DestinationDecision


class RouteSource(StrEnum):
    """Where a candidate came from."""

    MX = "mx"
    IMPLICIT_MX = "implicit_mx"


class CandidateStatus(StrEnum):
    """Whether one host could be used as a destination, and why not.

    `NO_ADDRESSES` is reserved for a proven absence: both families answered
    authoritatively that there is nothing. A malformed answer or an internal
    failure gets its own status, because neither proves anything about the host.
    """

    USABLE = "usable"
    NO_ADDRESSES = "no_addresses"
    ADDRESSES_DENIED = "addresses_denied"
    TEMPORARY_FAILURE = "temporary_failure"
    MALFORMED_RESPONSE = "malformed_response"
    INTERNAL_ERROR = "internal_error"


class RouteAnomaly(StrEnum):
    """A configuration that is not a valid route and not proof of no mail.

    Each one drops the offending record and is reported, so a misconfigured
    domain resolves to `unknown` instead of being called invalid.
    """

    NULL_MX_WITH_OTHER_RECORDS = "null_mx_with_other_records"
    ROOT_EXCHANGE_NONZERO_PREFERENCE = "root_exchange_nonzero_preference"
    EMPTY_EXCHANGE = "empty_exchange"
    MALFORMED_EXCHANGE = "malformed_exchange"
    NEGATIVE_PREFERENCE = "negative_preference"


class MailRouteOutcome(StrEnum):
    """What the DNS layer concluded about the domain."""

    MX_ROUTE = "mx_route"
    IMPLICIT_MX_ROUTE = "implicit_mx_route"
    NULL_MX = "null_mx"
    NO_MAIL_ROUTE = "no_mail_route"
    DOMAIN_NOT_FOUND = "domain_not_found"
    TEMPORARY_FAILURE = "temporary_failure"
    CONFIGURATION_ANOMALY = "configuration_anomaly"
    UNSAFE_DESTINATION = "unsafe_destination"
    INTERNAL_ERROR = "internal_error"


_OUTCOME_REASONS: dict[MailRouteOutcome, ReasonCode] = {
    MailRouteOutcome.MX_ROUTE: ReasonCode.MX_AVAILABLE,
    MailRouteOutcome.IMPLICIT_MX_ROUTE: ReasonCode.IMPLICIT_MX_AVAILABLE,
    MailRouteOutcome.NULL_MX: ReasonCode.NULL_MX,
    MailRouteOutcome.NO_MAIL_ROUTE: ReasonCode.NO_MAIL_ROUTE,
    MailRouteOutcome.DOMAIN_NOT_FOUND: ReasonCode.DOMAIN_NXDOMAIN,
    MailRouteOutcome.TEMPORARY_FAILURE: ReasonCode.DNS_TEMPORARY_FAILURE,
    MailRouteOutcome.CONFIGURATION_ANOMALY: ReasonCode.MX_CONFIGURATION_ANOMALY,
    MailRouteOutcome.UNSAFE_DESTINATION: ReasonCode.UNSAFE_DESTINATION,
    # This project failed. It is never evidence about the domain, so it must
    # not be reported as a configuration anomaly of theirs.
    MailRouteOutcome.INTERNAL_ERROR: ReasonCode.INTERNAL_ERROR,
}

#: Outcomes that later aggregation may treat as target-specific hard evidence.
#: Everything else must resolve to `unknown` or `temporary_unknown`.
HARD_INVALID_OUTCOMES: frozenset[MailRouteOutcome] = frozenset(
    {
        MailRouteOutcome.NULL_MX,
        MailRouteOutcome.NO_MAIL_ROUTE,
        MailRouteOutcome.DOMAIN_NOT_FOUND,
    }
)


def reason_for(outcome: MailRouteOutcome) -> ReasonCode:
    return _OUTCOME_REASONS[outcome]


def strength_for(outcome: MailRouteOutcome) -> EvidenceStrength:
    if outcome in HARD_INVALID_OUTCOMES:
        return EvidenceStrength.STRONG
    if outcome in {MailRouteOutcome.MX_ROUTE, MailRouteOutcome.IMPLICIT_MX_ROUTE}:
        return EvidenceStrength.MODERATE
    return EvidenceStrength.WEAK


@dataclass(frozen=True, slots=True)
class RouteCandidate:
    """One host that mail for the domain could be delivered to.

    The status and the address decisions must agree. A `USABLE` candidate is a
    promise that Phase 4 has somewhere to connect, so it must carry at least one
    allowed address, and no other status may carry one.
    """

    host: HostName
    preference: int
    source: RouteSource
    status: CandidateStatus
    decisions: tuple[DestinationDecision, ...] = ()

    def __post_init__(self) -> None:
        allowed = self.allowed_addresses
        if self.status is CandidateStatus.USABLE:
            if not allowed:
                raise ValueError("a usable candidate must have at least one allowed address")
            return
        if allowed:
            raise ValueError(f"a {self.status.value} candidate cannot have an allowed address")
        if self.status is CandidateStatus.ADDRESSES_DENIED and not self.decisions:
            raise ValueError("a denied candidate must name the addresses that were refused")
        if self.status is CandidateStatus.NO_ADDRESSES and self.decisions:
            raise ValueError("a candidate with no addresses cannot carry address decisions")

    @property
    def allowed_addresses(self) -> tuple[str, ...]:
        return tuple(d.address for d in self.decisions if d.allowed)

    @property
    def denied_addresses(self) -> tuple[str, ...]:
        return tuple(d.address for d in self.decisions if not d.allowed)


@dataclass(frozen=True, slots=True)
class MXClassification:
    """MX answers split into what is usable and what is merely odd."""

    null_mx: bool
    usable: tuple[MXRecord, ...]
    anomalies: tuple[RouteAnomaly, ...]

    @property
    def has_usable_records(self) -> bool:
        return bool(self.usable)


@dataclass(frozen=True, slots=True)
class MailRoute:
    """The DNS layer's report for one domain.

    This is evidence, not a verdict. It never states that a mailbox exists;
    `mx_route` only means mail for the domain has somewhere to go.
    """

    domain: str
    outcome: MailRouteOutcome
    candidates: tuple[RouteCandidate, ...] = ()
    anomalies: tuple[RouteAnomaly, ...] = ()
    ttl: TTL | None = None

    @property
    def reason(self) -> ReasonCode:
        """The public code for this outcome.

        Derived rather than stored, so a route cannot claim one outcome and
        report the reason code of another.
        """
        return reason_for(self.outcome)

    @property
    def is_hard_invalid(self) -> bool:
        return self.outcome in HARD_INVALID_OUTCOMES

    @property
    def is_temporary(self) -> bool:
        return self.outcome is MailRouteOutcome.TEMPORARY_FAILURE

    @property
    def is_internal_error(self) -> bool:
        return self.outcome is MailRouteOutcome.INTERNAL_ERROR

    @property
    def connectable_candidates(self) -> tuple[RouteCandidate, ...]:
        """Candidates a later Phase may attempt, in preference order.

        A Null MX or any other routeless outcome yields nothing, so no later
        code can select a destination from a domain that refuses mail. The
        allowed-address check is redundant with the candidate invariant and is
        kept as a second barrier: Phase 4 opens sockets from this list.
        """
        if self.outcome not in {MailRouteOutcome.MX_ROUTE, MailRouteOutcome.IMPLICIT_MX_ROUTE}:
            return ()
        return tuple(
            candidate
            for candidate in self.candidates
            if candidate.status is CandidateStatus.USABLE and candidate.allowed_addresses
        )


def sort_mx_records(records: tuple[MXRecord, ...]) -> tuple[MXRecord, ...]:
    """Order by preference, keeping every host at an equal preference.

    `sorted` is stable, so hosts sharing a preference keep the order the
    resolver served them in rather than being collapsed or reordered.
    """
    return tuple(sorted(records, key=lambda record: record.preference))


def classify_mx_records(records: tuple[MXRecord, ...]) -> MXClassification:
    """Split MX answers into a Null MX, usable records, and anomalies.

    A Null MX counts only in its RFC 7505 form and only when it is the whole
    answer. Anything else that cannot be used is dropped and reported, because
    a broken record is not a statement that the domain refuses mail.
    """
    anomalies: list[RouteAnomaly] = []
    usable: list[MXRecord] = []
    null_mx_records = [record for record in records if record.is_null_mx]

    for record in records:
        if record.is_null_mx:
            continue
        if record.preference < 0:
            anomalies.append(RouteAnomaly.NEGATIVE_PREFERENCE)
            continue
        if record.is_root_exchange:
            anomalies.append(RouteAnomaly.ROOT_EXCHANGE_NONZERO_PREFERENCE)
            continue
        if not record.exchange.strip():
            anomalies.append(RouteAnomaly.EMPTY_EXCHANGE)
            continue
        if HostName.normalize(record.exchange) is None:
            anomalies.append(RouteAnomaly.MALFORMED_EXCHANGE)
            continue
        usable.append(record)

    if null_mx_records and len(records) > len(null_mx_records):
        # A domain that refuses mail must not also advertise a mail host.
        anomalies.append(RouteAnomaly.NULL_MX_WITH_OTHER_RECORDS)
        return MXClassification(null_mx=False, usable=tuple(usable), anomalies=_dedupe(anomalies))

    return MXClassification(
        null_mx=bool(null_mx_records),
        usable=tuple(sort_mx_records(tuple(usable))),
        anomalies=_dedupe(anomalies),
    )


def _dedupe(anomalies: list[RouteAnomaly]) -> tuple[RouteAnomaly, ...]:
    seen: dict[RouteAnomaly, None] = {}
    for anomaly in anomalies:
        seen.setdefault(anomaly, None)
    return tuple(seen)


def classify_host_result(
    *,
    a_failure: DNSFailure | None,
    aaaa_failure: DNSFailure | None,
    decisions: tuple[DestinationDecision, ...],
) -> CandidateStatus:
    """Decide what one host's A and AAAA answers mean.

    `NO_ADDRESSES` requires a proven absence on both families. Anything else
    that produced no usable address keeps its own status, so a malformed answer
    or an internal failure can never be mistaken for "this host does not exist".

    An internal failure outranks a temporary one: a defect in this project is
    worth surfacing rather than hiding behind a retry hint.
    """
    if any(decision.allowed for decision in decisions):
        return CandidateStatus.USABLE

    failures = [failure for failure in (a_failure, aaaa_failure) if failure is not None]
    if any(failure.is_internal for failure in failures):
        return CandidateStatus.INTERNAL_ERROR
    if any(failure.is_temporary for failure in failures):
        return CandidateStatus.TEMPORARY_FAILURE
    if any(not failure.is_authoritative_absence for failure in failures):
        return CandidateStatus.MALFORMED_RESPONSE
    if decisions:
        return CandidateStatus.ADDRESSES_DENIED
    return CandidateStatus.NO_ADDRESSES


#: What one unusable host means for the domain when nothing better is available.
#: No entry is a hard-invalid outcome: a host that cannot be reached is not the
#: domain declaring that it accepts no mail.
_UNUSABLE_STATUS_OUTCOMES: dict[CandidateStatus, MailRouteOutcome] = {
    CandidateStatus.INTERNAL_ERROR: MailRouteOutcome.INTERNAL_ERROR,
    CandidateStatus.TEMPORARY_FAILURE: MailRouteOutcome.TEMPORARY_FAILURE,
    CandidateStatus.MALFORMED_RESPONSE: MailRouteOutcome.CONFIGURATION_ANOMALY,
    CandidateStatus.ADDRESSES_DENIED: MailRouteOutcome.UNSAFE_DESTINATION,
    CandidateStatus.NO_ADDRESSES: MailRouteOutcome.CONFIGURATION_ANOMALY,
}

#: The order in which competing unusable statuses are reported.
_UNUSABLE_PRECEDENCE: tuple[CandidateStatus, ...] = (
    CandidateStatus.INTERNAL_ERROR,
    CandidateStatus.TEMPORARY_FAILURE,
    CandidateStatus.MALFORMED_RESPONSE,
    CandidateStatus.ADDRESSES_DENIED,
    CandidateStatus.NO_ADDRESSES,
)


def decide_outcome(
    *,
    mx_failure: DNSFailure | None,
    classification: MXClassification | None,
    candidates: tuple[RouteCandidate, ...],
    implicit_status: CandidateStatus | None,
) -> MailRouteOutcome:
    """Choose the outcome from everything observed.

    Order matters. An internal failure is reported as ours, a temporary
    resolver failure never becomes a permanent answer, and `no_mail_route` is
    claimed only when both address families proved an absence.
    """
    if mx_failure is not None:
        if mx_failure.is_internal:
            return MailRouteOutcome.INTERNAL_ERROR
        if mx_failure.is_temporary:
            return MailRouteOutcome.TEMPORARY_FAILURE
        if mx_failure is DNSFailure.NXDOMAIN:
            return MailRouteOutcome.DOMAIN_NOT_FOUND
        if mx_failure is DNSFailure.MALFORMED:
            return MailRouteOutcome.CONFIGURATION_ANOMALY

    if classification is not None and classification.null_mx:
        return MailRouteOutcome.NULL_MX

    usable = [c for c in candidates if c.status is CandidateStatus.USABLE]
    if usable:
        sources = {c.source for c in usable}
        if RouteSource.MX in sources:
            return MailRouteOutcome.MX_ROUTE
        return MailRouteOutcome.IMPLICIT_MX_ROUTE

    if candidates:
        # Hosts were published but none can be used. Never hard-invalid: the
        # domain still advertises somewhere to deliver.
        statuses = {c.status for c in candidates}
        for status in _UNUSABLE_PRECEDENCE:
            if status in statuses:
                return _UNUSABLE_STATUS_OUTCOMES[status]
        return MailRouteOutcome.CONFIGURATION_ANOMALY

    if classification is not None and classification.anomalies and not classification.usable:
        return MailRouteOutcome.CONFIGURATION_ANOMALY

    if implicit_status is None:
        # No MX and no implicit lookup was made; nothing was observed at all.
        return MailRouteOutcome.CONFIGURATION_ANOMALY
    if implicit_status is CandidateStatus.NO_ADDRESSES:
        # The only hard-invalid path here: both families proved an absence.
        return MailRouteOutcome.NO_MAIL_ROUTE
    return _UNUSABLE_STATUS_OUTCOMES[implicit_status]
