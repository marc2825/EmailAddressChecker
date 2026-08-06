"""The pure route decision: MX classification, host classification, outcomes."""

import pytest

from emailcheck.domain.dns import DNSFailure, HostName, MXRecord
from emailcheck.domain.evidence import EvidenceStrength
from emailcheck.domain.mail_route import (
    HARD_INVALID_OUTCOMES,
    CandidateStatus,
    MailRoute,
    MailRouteOutcome,
    RouteAnomaly,
    RouteCandidate,
    RouteSource,
    classify_host_result,
    classify_mx_records,
    decide_outcome,
    reason_for,
    sort_mx_records,
    strength_for,
)
from emailcheck.domain.reasons import ReasonCode
from emailcheck.security.destination import DestinationDecision, DestinationDenyReason

ALLOWED = DestinationDecision(allowed=True, address="93.184.216.34", version=4, deny_reason=None)
DENIED = DestinationDecision(
    allowed=False, address="127.0.0.1", version=4, deny_reason=DestinationDenyReason.LOOPBACK
)


def mx(preference: int, exchange: str) -> MXRecord:
    return MXRecord(preference=preference, exchange=exchange)


def candidate(
    host: str,
    status: CandidateStatus,
    *,
    preference: int = 10,
    source: RouteSource = RouteSource.MX,
) -> RouteCandidate:
    """Build a candidate whose decisions match its status."""
    if status is CandidateStatus.USABLE:
        decisions = (ALLOWED,)
    elif status is CandidateStatus.ADDRESSES_DENIED:
        decisions = (DENIED,)
    else:
        decisions = ()
    return RouteCandidate(
        host=HostName(host),
        preference=preference,
        source=source,
        status=status,
        decisions=decisions,
    )


# --- ordering -------------------------------------------------------------


def test_mx_records_are_sorted_by_preference() -> None:
    records = (mx(30, "c.example.com"), mx(10, "a.example.com"), mx(20, "b.example.com"))
    assert [r.exchange for r in sort_mx_records(records)] == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


def test_hosts_sharing_a_preference_are_all_kept_in_served_order() -> None:
    records = (mx(10, "b.example.com"), mx(10, "a.example.com"), mx(5, "first.example.com"))
    ordered = sort_mx_records(records)
    assert [r.exchange for r in ordered] == [
        "first.example.com",
        "b.example.com",
        "a.example.com",
    ]
    assert len(ordered) == 3


# --- MX classification ----------------------------------------------------


def test_a_single_mx_is_usable() -> None:
    result = classify_mx_records((mx(10, "mx.example.com"),))
    assert result.null_mx is False
    assert result.has_usable_records is True
    assert result.anomalies == ()


def test_a_standards_compliant_null_mx_is_recognized() -> None:
    result = classify_mx_records((mx(0, "."),))
    assert result.null_mx is True
    assert result.usable == ()
    assert result.anomalies == ()


def test_duplicate_null_mx_records_are_still_one_refusal() -> None:
    """Two identical Null MX answers say the same thing once."""
    result = classify_mx_records((mx(0, "."), mx(0, ".")))
    assert result.null_mx is True
    assert result.usable == ()


def test_null_mx_alongside_a_real_mx_is_an_anomaly_not_a_refusal() -> None:
    result = classify_mx_records((mx(0, "."), mx(10, "mx.example.com")))
    assert result.null_mx is False
    assert RouteAnomaly.NULL_MX_WITH_OTHER_RECORDS in result.anomalies
    assert [r.exchange for r in result.usable] == ["mx.example.com"]


def test_a_root_exchange_with_a_nonzero_preference_is_not_null_mx() -> None:
    result = classify_mx_records((mx(10, "."),))
    assert result.null_mx is False
    assert result.usable == ()
    assert RouteAnomaly.ROOT_EXCHANGE_NONZERO_PREFERENCE in result.anomalies


@pytest.mark.parametrize(
    ("record", "anomaly"),
    [
        (mx(10, ""), RouteAnomaly.EMPTY_EXCHANGE),
        (mx(10, "   "), RouteAnomaly.EMPTY_EXCHANGE),
        (mx(10, "mx..example.com"), RouteAnomaly.MALFORMED_EXCHANGE),
        (mx(10, "-mx.example.com"), RouteAnomaly.MALFORMED_EXCHANGE),
        (mx(10, "mx host.example.com"), RouteAnomaly.MALFORMED_EXCHANGE),
        (mx(-5, "mx.example.com"), RouteAnomaly.NEGATIVE_PREFERENCE),
    ],
)
def test_malformed_records_are_dropped_and_reported(
    record: MXRecord, anomaly: RouteAnomaly
) -> None:
    result = classify_mx_records((record,))
    assert result.usable == ()
    assert anomaly in result.anomalies
    assert result.null_mx is False


def test_a_malformed_record_does_not_discard_a_usable_sibling() -> None:
    result = classify_mx_records((mx(10, "mx..example.com"), mx(20, "mx2.example.com")))
    assert [r.exchange for r in result.usable] == ["mx2.example.com"]
    assert RouteAnomaly.MALFORMED_EXCHANGE in result.anomalies


# --- host classification: only a proven absence is an absence -------------


@pytest.mark.parametrize(
    ("a_failure", "aaaa_failure", "expected"),
    [
        # The row the independent review found wrong: a malformed answer is not
        # proof that the host has no address.
        (DNSFailure.MALFORMED, DNSFailure.NO_RECORDS, CandidateStatus.MALFORMED_RESPONSE),
        (DNSFailure.NO_RECORDS, DNSFailure.MALFORMED, CandidateStatus.MALFORMED_RESPONSE),
        (DNSFailure.MALFORMED, DNSFailure.TIMEOUT, CandidateStatus.TEMPORARY_FAILURE),
        (DNSFailure.INTERNAL_ERROR, DNSFailure.NO_RECORDS, CandidateStatus.INTERNAL_ERROR),
        (DNSFailure.INTERNAL_ERROR, DNSFailure.TIMEOUT, CandidateStatus.INTERNAL_ERROR),
        (DNSFailure.REFUSED, DNSFailure.NO_RECORDS, CandidateStatus.TEMPORARY_FAILURE),
        (DNSFailure.SERVFAIL, DNSFailure.NO_RECORDS, CandidateStatus.TEMPORARY_FAILURE),
        (DNSFailure.TIMEOUT, DNSFailure.NO_RECORDS, CandidateStatus.TEMPORARY_FAILURE),
        # Only this pair proves an absence.
        (DNSFailure.NO_RECORDS, DNSFailure.NO_RECORDS, CandidateStatus.NO_ADDRESSES),
        (DNSFailure.NXDOMAIN, DNSFailure.NO_RECORDS, CandidateStatus.NO_ADDRESSES),
        (DNSFailure.NXDOMAIN, DNSFailure.NXDOMAIN, CandidateStatus.NO_ADDRESSES),
    ],
)
def test_host_failures_are_classified_without_guessing(
    a_failure: DNSFailure, aaaa_failure: DNSFailure, expected: CandidateStatus
) -> None:
    status = classify_host_result(a_failure=a_failure, aaaa_failure=aaaa_failure, decisions=())
    assert status is expected


def test_a_safe_address_beats_any_failure_on_the_other_family() -> None:
    status = classify_host_result(
        a_failure=None, aaaa_failure=DNSFailure.MALFORMED, decisions=(ALLOWED,)
    )
    assert status is CandidateStatus.USABLE


def test_only_denied_addresses_is_an_unsafe_host_not_an_absent_one() -> None:
    status = classify_host_result(
        a_failure=None, aaaa_failure=DNSFailure.NO_RECORDS, decisions=(DENIED,)
    )
    assert status is CandidateStatus.ADDRESSES_DENIED


def test_a_denied_address_beside_a_temporary_failure_stays_retryable() -> None:
    """A retry may still produce a usable address on the other family."""
    status = classify_host_result(
        a_failure=None, aaaa_failure=DNSFailure.TIMEOUT, decisions=(DENIED,)
    )
    assert status is CandidateStatus.TEMPORARY_FAILURE


# --- outcome --------------------------------------------------------------


def test_nxdomain_and_servfail_are_different_outcomes() -> None:
    """The distinction that decides invalid against temporary_unknown."""
    nx = decide_outcome(
        mx_failure=DNSFailure.NXDOMAIN,
        classification=None,
        candidates=(),
        implicit_status=None,
    )
    servfail = decide_outcome(
        mx_failure=DNSFailure.SERVFAIL,
        classification=None,
        candidates=(),
        implicit_status=None,
    )
    assert nx is MailRouteOutcome.DOMAIN_NOT_FOUND
    assert servfail is MailRouteOutcome.TEMPORARY_FAILURE
    assert nx in HARD_INVALID_OUTCOMES
    assert servfail not in HARD_INVALID_OUTCOMES


@pytest.mark.parametrize("failure", [DNSFailure.SERVFAIL, DNSFailure.TIMEOUT, DNSFailure.REFUSED])
def test_temporary_resolver_failures_never_become_permanent(failure: DNSFailure) -> None:
    outcome = decide_outcome(
        mx_failure=failure, classification=None, candidates=(), implicit_status=None
    )
    assert outcome is MailRouteOutcome.TEMPORARY_FAILURE
    assert outcome not in HARD_INVALID_OUTCOMES


def test_an_internal_failure_on_the_mx_query_is_reported_as_ours() -> None:
    outcome = decide_outcome(
        mx_failure=DNSFailure.INTERNAL_ERROR,
        classification=None,
        candidates=(),
        implicit_status=None,
    )
    assert outcome is MailRouteOutcome.INTERNAL_ERROR
    assert reason_for(outcome) is ReasonCode.INTERNAL_ERROR
    assert outcome not in HARD_INVALID_OUTCOMES


def test_a_usable_mx_candidate_gives_an_mx_route() -> None:
    outcome = decide_outcome(
        mx_failure=None,
        classification=classify_mx_records((mx(10, "mx.example.com"),)),
        candidates=(candidate("mx.example.com", CandidateStatus.USABLE),),
        implicit_status=None,
    )
    assert outcome is MailRouteOutcome.MX_ROUTE


def test_one_usable_host_is_enough_even_when_another_fails() -> None:
    outcome = decide_outcome(
        mx_failure=None,
        classification=classify_mx_records((mx(10, "a.example.com"), mx(20, "b.example.com"))),
        candidates=(
            candidate("a.example.com", CandidateStatus.TEMPORARY_FAILURE),
            candidate("b.example.com", CandidateStatus.USABLE),
        ),
        implicit_status=None,
    )
    assert outcome is MailRouteOutcome.MX_ROUTE


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (CandidateStatus.INTERNAL_ERROR, MailRouteOutcome.INTERNAL_ERROR),
        (CandidateStatus.TEMPORARY_FAILURE, MailRouteOutcome.TEMPORARY_FAILURE),
        (CandidateStatus.MALFORMED_RESPONSE, MailRouteOutcome.CONFIGURATION_ANOMALY),
        (CandidateStatus.ADDRESSES_DENIED, MailRouteOutcome.UNSAFE_DESTINATION),
        (CandidateStatus.NO_ADDRESSES, MailRouteOutcome.CONFIGURATION_ANOMALY),
    ],
)
def test_an_unusable_mx_host_never_makes_the_address_invalid(
    status: CandidateStatus, expected: MailRouteOutcome
) -> None:
    outcome = decide_outcome(
        mx_failure=None,
        classification=classify_mx_records((mx(10, "mx.example.com"),)),
        candidates=(candidate("mx.example.com", status),),
        implicit_status=None,
    )
    assert outcome is expected
    assert outcome not in HARD_INVALID_OUTCOMES


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (CandidateStatus.USABLE, MailRouteOutcome.IMPLICIT_MX_ROUTE),
        (CandidateStatus.INTERNAL_ERROR, MailRouteOutcome.INTERNAL_ERROR),
        (CandidateStatus.TEMPORARY_FAILURE, MailRouteOutcome.TEMPORARY_FAILURE),
        (CandidateStatus.MALFORMED_RESPONSE, MailRouteOutcome.CONFIGURATION_ANOMALY),
        (CandidateStatus.ADDRESSES_DENIED, MailRouteOutcome.UNSAFE_DESTINATION),
    ],
)
def test_the_implicit_path_is_hard_invalid_only_on_a_proven_absence(
    status: CandidateStatus, expected: MailRouteOutcome
) -> None:
    candidates = (
        (candidate("example.com", status, preference=0, source=RouteSource.IMPLICIT_MX),)
        if status is not CandidateStatus.NO_ADDRESSES
        else ()
    )
    outcome = decide_outcome(
        mx_failure=None,
        classification=classify_mx_records(()),
        candidates=candidates,
        implicit_status=status,
    )
    assert outcome is expected
    assert outcome not in HARD_INVALID_OUTCOMES


def test_no_mx_and_a_proven_absence_of_addresses_is_hard_invalid() -> None:
    outcome = decide_outcome(
        mx_failure=None,
        classification=classify_mx_records(()),
        candidates=(),
        implicit_status=CandidateStatus.NO_ADDRESSES,
    )
    assert outcome is MailRouteOutcome.NO_MAIL_ROUTE
    assert outcome in HARD_INVALID_OUTCOMES


# --- reason and strength mapping ------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (MailRouteOutcome.MX_ROUTE, ReasonCode.MX_AVAILABLE),
        (MailRouteOutcome.IMPLICIT_MX_ROUTE, ReasonCode.IMPLICIT_MX_AVAILABLE),
        (MailRouteOutcome.NULL_MX, ReasonCode.NULL_MX),
        (MailRouteOutcome.NO_MAIL_ROUTE, ReasonCode.NO_MAIL_ROUTE),
        (MailRouteOutcome.DOMAIN_NOT_FOUND, ReasonCode.DOMAIN_NXDOMAIN),
        (MailRouteOutcome.TEMPORARY_FAILURE, ReasonCode.DNS_TEMPORARY_FAILURE),
        (MailRouteOutcome.CONFIGURATION_ANOMALY, ReasonCode.MX_CONFIGURATION_ANOMALY),
        (MailRouteOutcome.UNSAFE_DESTINATION, ReasonCode.UNSAFE_DESTINATION),
        (MailRouteOutcome.INTERNAL_ERROR, ReasonCode.INTERNAL_ERROR),
    ],
)
def test_every_outcome_maps_to_a_public_reason(
    outcome: MailRouteOutcome, reason: ReasonCode
) -> None:
    assert reason_for(outcome) is reason


def test_every_outcome_has_a_reason_and_a_strength() -> None:
    for outcome in MailRouteOutcome:
        assert reason_for(outcome) in set(ReasonCode)
        assert strength_for(outcome) in set(EvidenceStrength)


def test_only_hard_invalid_outcomes_are_strong() -> None:
    for outcome in MailRouteOutcome:
        if outcome in HARD_INVALID_OUTCOMES:
            assert strength_for(outcome) is EvidenceStrength.STRONG, outcome
        else:
            assert strength_for(outcome) is not EvidenceStrength.STRONG, outcome


def test_a_route_cannot_report_the_reason_of_another_outcome() -> None:
    """The reason is derived, so a mismatch is not expressible."""
    for outcome in MailRouteOutcome:
        assert MailRoute(domain="example.com", outcome=outcome).reason is reason_for(outcome)

    with pytest.raises(TypeError):
        MailRoute(  # type: ignore[call-arg]
            domain="example.com",
            outcome=MailRouteOutcome.NULL_MX,
            reason=ReasonCode.MX_AVAILABLE,
        )


# --- candidate invariants -------------------------------------------------


def test_a_usable_candidate_must_have_an_allowed_address() -> None:
    with pytest.raises(ValueError, match="allowed address"):
        RouteCandidate(
            host=HostName("mx.example.com"),
            preference=10,
            source=RouteSource.MX,
            status=CandidateStatus.USABLE,
            decisions=(DENIED,),
        )
    with pytest.raises(ValueError, match="allowed address"):
        RouteCandidate(
            host=HostName("mx.example.com"),
            preference=10,
            source=RouteSource.MX,
            status=CandidateStatus.USABLE,
        )


@pytest.mark.parametrize(
    "status",
    [
        CandidateStatus.ADDRESSES_DENIED,
        CandidateStatus.NO_ADDRESSES,
        CandidateStatus.TEMPORARY_FAILURE,
        CandidateStatus.MALFORMED_RESPONSE,
        CandidateStatus.INTERNAL_ERROR,
    ],
)
def test_only_a_usable_candidate_may_carry_an_allowed_address(status: CandidateStatus) -> None:
    with pytest.raises(ValueError, match="cannot have an allowed address"):
        RouteCandidate(
            host=HostName("mx.example.com"),
            preference=10,
            source=RouteSource.MX,
            status=status,
            decisions=(ALLOWED,),
        )


def test_a_denied_candidate_must_name_what_was_refused() -> None:
    with pytest.raises(ValueError, match="addresses that were refused"):
        RouteCandidate(
            host=HostName("mx.example.com"),
            preference=10,
            source=RouteSource.MX,
            status=CandidateStatus.ADDRESSES_DENIED,
        )


def test_a_candidate_with_no_addresses_carries_no_decisions() -> None:
    with pytest.raises(ValueError, match="cannot carry address decisions"):
        RouteCandidate(
            host=HostName("mx.example.com"),
            preference=10,
            source=RouteSource.MX,
            status=CandidateStatus.NO_ADDRESSES,
            decisions=(DENIED,),
        )


# --- a route never offers a destination it should not ---------------------


@pytest.mark.parametrize(
    "outcome",
    [
        MailRouteOutcome.NULL_MX,
        MailRouteOutcome.NO_MAIL_ROUTE,
        MailRouteOutcome.DOMAIN_NOT_FOUND,
        MailRouteOutcome.TEMPORARY_FAILURE,
        MailRouteOutcome.CONFIGURATION_ANOMALY,
        MailRouteOutcome.UNSAFE_DESTINATION,
        MailRouteOutcome.INTERNAL_ERROR,
    ],
)
def test_a_routeless_outcome_offers_no_candidate_to_connect_to(
    outcome: MailRouteOutcome,
) -> None:
    route = MailRoute(
        domain="example.com",
        outcome=outcome,
        candidates=(candidate("mx.example.com", CandidateStatus.USABLE),),
    )
    assert route.connectable_candidates == ()


def test_a_route_only_offers_usable_candidates() -> None:
    route = MailRoute(
        domain="example.com",
        outcome=MailRouteOutcome.MX_ROUTE,
        candidates=(
            candidate("a.example.com", CandidateStatus.USABLE, preference=10),
            candidate("b.example.com", CandidateStatus.ADDRESSES_DENIED, preference=20),
            candidate("c.example.com", CandidateStatus.TEMPORARY_FAILURE, preference=30),
        ),
    )
    assert [c.host.value for c in route.connectable_candidates] == ["a.example.com"]


def test_every_connectable_candidate_carries_an_address_to_connect_to() -> None:
    """What Phase 4 relies on when it opens a socket."""
    route = MailRoute(
        domain="example.com",
        outcome=MailRouteOutcome.MX_ROUTE,
        candidates=(
            candidate("a.example.com", CandidateStatus.USABLE),
            candidate("b.example.com", CandidateStatus.ADDRESSES_DENIED, preference=20),
        ),
    )
    for entry in route.connectable_candidates:
        assert entry.allowed_addresses


def test_a_candidate_separates_allowed_from_denied_addresses() -> None:
    entry = RouteCandidate(
        host=HostName("mx.example.com"),
        preference=10,
        source=RouteSource.MX,
        status=CandidateStatus.USABLE,
        decisions=(ALLOWED, DENIED),
    )
    assert entry.allowed_addresses == ("93.184.216.34",)
    assert entry.denied_addresses == ("127.0.0.1",)
