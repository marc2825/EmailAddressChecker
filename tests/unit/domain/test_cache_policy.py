"""How long a verdict may be reused, row by row against section 13.

ADR 0015 composes an aggregated verdict's lifetime from the per-class defaults
`docs/requirements.md` section 13 publishes. This is that table, tested as a
table — and, more importantly, tested for the cases section 13 does **not**
price, where the answer must be "do not cache" rather than a default.

The verdicts here are built by the real `aggregate_evidence` from real
`Evidence`, so a row cannot assert a reason the aggregator would not have
produced or a `reason_codes` ordering it does not use.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.domain.cache_policy import (
    DNS_GOVERNED_REASONS,
    RISK_ONLY_REASONS,
    SECTION_13_TTL_SECONDS,
    decision_relevant_reasons,
    verdict_ttl_seconds,
)
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode

OBSERVED_AT = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)

HOUR = 3600
MINUTE = 60


def evidence(
    reason: ReasonCode,
    *,
    layer: EvidenceLayer = EvidenceLayer.SMTP,
    strength: EvidenceStrength = EvidenceStrength.MODERATE,
    temporary: bool = False,
) -> Evidence:
    return Evidence(
        layer=layer,
        reason=reason,
        strength=strength,
        observed_at=OBSERVED_AT,
        temporary=temporary,
    )


def route(reason: ReasonCode = ReasonCode.MX_AVAILABLE) -> Evidence:
    return evidence(reason, layer=EvidenceLayer.DNS)


def ttl(*items: Evidence, route_ttl: int | None = 24 * HOUR) -> int | None:
    return verdict_ttl_seconds(aggregate_evidence(items), route_ttl_seconds=route_ttl)


# --- the section 13 table ---------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (ReasonCode.RCPT_ACCEPTED, 6 * HOUR),
        (ReasonCode.RCPT_FORWARDED, 6 * HOUR),
        (ReasonCode.RCPT_REJECTED_ADDRESS, 1 * HOUR),
        (ReasonCode.SMTP_TEMPORARY_FAILURE, 10 * MINUTE),
        (ReasonCode.MAILBOX_FULL, 10 * MINUTE),
        (ReasonCode.RCPT_REJECTED_POLICY, 30 * MINUTE),
        (ReasonCode.SMTP_POLICY_BLOCKED, 30 * MINUTE),
        (ReasonCode.SMTP_CONNECTION_TIMEOUT, 5 * MINUTE),
        (ReasonCode.ACCEPT_ALL_SUSPECTED, 7 * 24 * HOUR),
    ],
    ids=lambda value: value.value if isinstance(value, ReasonCode) else str(value),
)
def test_each_priced_class_matches_section_13(reason: ReasonCode, expected: int) -> None:
    assert SECTION_13_TTL_SECONDS[reason] == expected


def test_an_accepted_recipient_is_bounded_by_its_own_class_and_its_route() -> None:
    """The composition, in the case it exists for.

    `rcpt_accepted` is priced at six hours and the route it was obtained
    through has its own TTL. The shorter wins, because an acceptance is only as
    current as the exchanger it was obtained from.
    """
    assert ttl(route(), evidence(ReasonCode.RCPT_ACCEPTED), route_ttl=24 * HOUR) == 6 * HOUR
    assert ttl(route(), evidence(ReasonCode.RCPT_ACCEPTED), route_ttl=300) == 300


def test_a_temporary_failure_expires_soonest_of_the_priced_classes() -> None:
    """Section 13's asymmetry, preserved rather than smoothed.

    A temporary condition is worth ten minutes and an acceptance six hours; the
    ordering is the specification's, not this module's.
    """
    temporary = ttl(
        route(),
        evidence(ReasonCode.SMTP_TEMPORARY_FAILURE, temporary=True),
        route_ttl=24 * HOUR,
    )
    accepted = ttl(route(), evidence(ReasonCode.RCPT_ACCEPTED), route_ttl=24 * HOUR)
    assert temporary is not None and accepted is not None
    assert temporary < accepted


# --- DNS-governed reasons read the record's own TTL -------------------------


@pytest.mark.parametrize("reason", sorted(DNS_GOVERNED_REASONS, key=lambda item: item.value))
def test_a_dns_reason_is_priced_by_the_records_own_ttl(reason: ReasonCode) -> None:
    """Section 13 prices DNS by the served TTL under a cap, and Phase 2's
    `apply_ttl_policy` already applied that cap. Re-deriving it here would be a
    second policy to keep in step."""
    assert ttl(route(reason), route_ttl=1800) == 1800


@pytest.mark.parametrize("reason", sorted(DNS_GOVERNED_REASONS, key=lambda item: item.value))
def test_a_dns_reason_with_no_route_ttl_is_not_cacheable(reason: ReasonCode) -> None:
    """A DNS-governed reason with nothing to read is uncacheable rather than
    assumed fresh."""
    assert ttl(route(reason), route_ttl=None) is None


def test_a_served_ttl_of_zero_survives_aggregation() -> None:
    """The server asked for no caching, and that request is not rounded up."""
    assert ttl(route(), evidence(ReasonCode.RCPT_ACCEPTED), route_ttl=0) is None


# --- what section 13 does not price -----------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        ReasonCode.RCPT_UNVERIFIABLE,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ReasonCode.SMTP_CONNECTION_REFUSED,
        ReasonCode.SMTP_BANNER_INVALID,
        ReasonCode.SMTP_PROTOCOL_ERROR,
        ReasonCode.SMTP_TLS_FAILURE,
        ReasonCode.MAIL_FROM_REJECTED,
        ReasonCode.UNSAFE_DESTINATION,
    ],
    ids=lambda value: value.value,
)
def test_an_unpriced_reason_makes_the_verdict_uncacheable(reason: ReasonCode) -> None:
    """ADR 0015's deliberate cost, asserted rather than left implicit.

    `252` and a bare `550` are common answers, and not caching them means
    re-probing. Inventing a duration section 13 never wrote is the alternative,
    and that is how a cache policy becomes an unreviewed deliverability rule.
    """
    assert ttl(route(), evidence(reason)) is None


@pytest.mark.parametrize(
    "reason",
    [
        ReasonCode.INVALID_SYNTAX,
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ReasonCode.UNSUPPORTED_SMTPUTF8,
    ],
    ids=lambda value: value.value,
)
def test_a_syntax_verdict_is_not_cached_and_costs_nothing_to_recompute(
    reason: ReasonCode,
) -> None:
    assert ttl(evidence(reason, layer=EvidenceLayer.SYNTAX), route_ttl=None) is None


def test_an_internal_error_is_never_cached_at_any_position() -> None:
    """A failure of ours is not an observation about the address, and storing
    one would serve our outage to the next caller."""
    assert ttl(route(), evidence(ReasonCode.INTERNAL_ERROR)) is None
    assert (
        ttl(
            route(),
            evidence(ReasonCode.RCPT_ACCEPTED),
            evidence(ReasonCode.INTERNAL_ERROR),
        )
        is None
    )


def test_an_empty_verdict_is_not_cached() -> None:
    assert ttl(route_ttl=None) is None


# --- risk-only reasons decide nothing, and time nothing ---------------------


@pytest.mark.parametrize("reason", sorted(RISK_ONLY_REASONS, key=lambda item: item.value))
def test_a_risk_flag_neither_shortens_nor_lengthens_a_verdict(reason: ReasonCode) -> None:
    """Section 13 governs passive datasets by data version rather than by
    duration, and a risk flag never changes a status — so letting one move the
    lifetime would be a timing rule derived from an observation with no bearing
    on the answer."""
    without = ttl(route(), evidence(ReasonCode.RCPT_ACCEPTED))
    with_flag = ttl(
        route(),
        evidence(ReasonCode.RCPT_ACCEPTED),
        evidence(reason, layer=EvidenceLayer.PASSIVE_CLASSIFICATION),
    )
    assert without == with_flag == 6 * HOUR


def test_a_verdict_resting_only_on_risk_evidence_is_not_cached() -> None:
    verdict = aggregate_evidence(
        (
            evidence(
                ReasonCode.DISPOSABLE_DOMAIN,
                layer=EvidenceLayer.PASSIVE_CLASSIFICATION,
            ),
        )
    )
    assert decision_relevant_reasons(verdict) == ()
    assert verdict_ttl_seconds(verdict, route_ttl_seconds=3600) is None


# --- the composition rule itself --------------------------------------------


def test_the_shortest_decision_relevant_lifetime_wins() -> None:
    """Stated as the property rather than inferred from one pairing."""
    verdict = aggregate_evidence(
        (
            route(),
            evidence(ReasonCode.SMTP_TEMPORARY_FAILURE, temporary=True),
            evidence(ReasonCode.RCPT_REJECTED_POLICY),
        )
    )
    lifetime = verdict_ttl_seconds(verdict, route_ttl_seconds=24 * HOUR)
    priced = [
        SECTION_13_TTL_SECONDS[reason]
        for reason in decision_relevant_reasons(verdict)
        if reason in SECTION_13_TTL_SECONDS
    ]
    assert lifetime == min(priced)


def test_the_lifetime_does_not_depend_on_evidence_order() -> None:
    """The aggregation is order-independent, and so is this."""
    items = (route(), evidence(ReasonCode.RCPT_ACCEPTED))
    assert ttl(*items) == ttl(*reversed(items))
