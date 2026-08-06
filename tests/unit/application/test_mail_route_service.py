"""The mail-route use case, driven by a fake resolver.

No test here touches a real resolver: `tests/conftest.py` fails any socket use,
and the fake below answers from a dictionary.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from emailcheck.application.mail_route import MailRouteService
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.dns import (
    AddressLookup,
    CNAMEChain,
    DNSFailure,
    HostName,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)
from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.mail_route import (
    CandidateStatus,
    MailRouteOutcome,
    RouteAnomaly,
    RouteSource,
)
from emailcheck.domain.reasons import ReasonCode
from emailcheck.security.destination import DestinationDenyReason


@dataclass
class FakeClock:
    current: datetime = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


@dataclass
class FakeResolver:
    """Answers from fixed tables. Anything unlisted is an authoritative absence."""

    mx: dict[str, MXLookup] = field(default_factory=dict)
    a: dict[str, AddressLookup] = field(default_factory=dict)
    aaaa: dict[str, AddressLookup] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def query_mx(self, domain: HostName) -> MXLookup:
        self.calls.append(("mx", domain.value))
        return self.mx.get(domain.value, MXLookup(failure=DNSFailure.NO_RECORDS))

    async def query_a(self, host: HostName) -> AddressLookup:
        self.calls.append(("a", host.value))
        return self.a.get(host.value, AddressLookup(failure=DNSFailure.NO_RECORDS))

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        self.calls.append(("aaaa", host.value))
        return self.aaaa.get(host.value, AddressLookup(failure=DNSFailure.NO_RECORDS))


def service(resolver: FakeResolver) -> MailRouteService:
    return MailRouteService(resolver=resolver, clock=FakeClock())


def address(text: str) -> object:
    parsed = parse_address(RawAddressInput(text))
    assert isinstance(parsed, AddressAccepted)
    return parsed.address


def mx_answer(*records: tuple[int, str], ttl: int | None = 3600) -> MXLookup:
    return MXLookup(
        records=tuple(MXRecord(preference=p, exchange=e) for p, e in records),
        ttl=apply_ttl_policy(ttl, positive=True),
    )


def a_answer(*addresses: str) -> AddressLookup:
    return AddressLookup(addresses=addresses, ttl=apply_ttl_policy(300, positive=True))


# --- MX routes ------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_single_mx_with_a_public_address_is_a_route() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com."))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.MX_ROUTE
    assert route.reason is ReasonCode.MX_AVAILABLE
    assert [c.host.value for c in route.connectable_candidates] == ["mx.example.com"]
    assert route.is_hard_invalid is False


@pytest.mark.asyncio
async def test_candidates_are_ordered_by_preference() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((30, "c.example.com"), (10, "a.example.com"), (20, "b.exa"))},
        a={
            "a.example.com": a_answer("93.184.216.34"),
            "b.exa": a_answer("93.184.216.35"),
            "c.example.com": a_answer("93.184.216.36"),
        },
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert [c.host.value for c in route.connectable_candidates] == [
        "a.example.com",
        "b.exa",
        "c.example.com",
    ]


@pytest.mark.asyncio
async def test_hosts_sharing_a_preference_are_all_kept() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "a.example.com"), (10, "b.example.com"))},
        a={
            "a.example.com": a_answer("93.184.216.34"),
            "b.example.com": a_answer("93.184.216.35"),
        },
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert len(route.connectable_candidates) == 2


@pytest.mark.asyncio
async def test_a_trailing_dot_in_an_exchange_is_normalized() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "MX.Example.COM."))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert route.connectable_candidates[0].host.value == "mx.example.com"


# --- Null MX --------------------------------------------------------------


@pytest.mark.asyncio
async def test_null_mx_is_hard_invalid_and_offers_no_destination() -> None:
    resolver = FakeResolver(mx={"example.com": mx_answer((0, "."))})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.NULL_MX
    assert route.reason is ReasonCode.NULL_MX
    assert route.is_hard_invalid is True
    assert route.connectable_candidates == ()
    assert route.candidates == ()


@pytest.mark.asyncio
async def test_null_mx_stops_before_any_address_lookup() -> None:
    """Nothing may be resolved for a domain that refuses mail."""
    resolver = FakeResolver(mx={"example.com": mx_answer((0, "."))})
    await service(resolver).resolve_domain(HostName("example.com"))
    assert resolver.calls == [("mx", "example.com")]


@pytest.mark.asyncio
async def test_null_mx_beside_a_real_mx_is_an_anomaly_and_keeps_routing() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((0, "."), (10, "mx.example.com"))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.MX_ROUTE
    assert RouteAnomaly.NULL_MX_WITH_OTHER_RECORDS in route.anomalies
    assert route.is_hard_invalid is False


@pytest.mark.asyncio
async def test_only_malformed_mx_records_give_a_configuration_anomaly() -> None:
    resolver = FakeResolver(mx={"example.com": mx_answer((10, "mx..example.com"), (20, ""))})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.CONFIGURATION_ANOMALY
    assert route.reason is ReasonCode.MX_CONFIGURATION_ANOMALY
    assert route.is_hard_invalid is False
    assert route.connectable_candidates == ()


# --- implicit MX ----------------------------------------------------------


@pytest.mark.asyncio
async def test_no_mx_with_an_a_record_is_an_implicit_route() -> None:
    resolver = FakeResolver(a={"example.com": a_answer("93.184.216.34")})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.IMPLICIT_MX_ROUTE
    assert route.reason is ReasonCode.IMPLICIT_MX_AVAILABLE
    assert route.connectable_candidates[0].source is RouteSource.IMPLICIT_MX


@pytest.mark.asyncio
async def test_no_mx_with_only_an_aaaa_record_is_an_implicit_route() -> None:
    resolver = FakeResolver(aaaa={"example.com": a_answer("2606:4700:4700::1111")})
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert route.outcome is MailRouteOutcome.IMPLICIT_MX_ROUTE


@pytest.mark.asyncio
async def test_no_mx_with_both_families_keeps_every_address() -> None:
    resolver = FakeResolver(
        a={"example.com": a_answer("93.184.216.34")},
        aaaa={"example.com": a_answer("2606:4700:4700::1111")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert route.outcome is MailRouteOutcome.IMPLICIT_MX_ROUTE
    assert route.candidates[0].allowed_addresses == ("93.184.216.34", "2606:4700:4700::1111")


@pytest.mark.asyncio
async def test_implicit_lookup_only_happens_when_no_mx_exists() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    await service(resolver).resolve_domain(HostName("example.com"))
    assert ("a", "example.com") not in resolver.calls


# --- absence and failure --------------------------------------------------


@pytest.mark.asyncio
async def test_no_mx_and_no_addresses_is_no_mail_route() -> None:
    resolver = FakeResolver()
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.NO_MAIL_ROUTE
    assert route.reason is ReasonCode.NO_MAIL_ROUTE
    assert route.is_hard_invalid is True


@pytest.mark.asyncio
async def test_nxdomain_is_reported_as_the_domain_not_existing() -> None:
    resolver = FakeResolver(mx={"example.com": MXLookup(failure=DNSFailure.NXDOMAIN)})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.DOMAIN_NOT_FOUND
    assert route.reason is ReasonCode.DOMAIN_NXDOMAIN
    assert route.is_hard_invalid is True
    assert route.is_temporary is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [DNSFailure.SERVFAIL, DNSFailure.TIMEOUT, DNSFailure.REFUSED])
async def test_temporary_failures_never_become_invalid(failure: DNSFailure) -> None:
    resolver = FakeResolver(mx={"example.com": MXLookup(failure=failure)})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.TEMPORARY_FAILURE
    assert route.reason is ReasonCode.DNS_TEMPORARY_FAILURE
    assert route.is_hard_invalid is False
    assert route.is_temporary is True


@pytest.mark.asyncio
async def test_nxdomain_and_servfail_differ_end_to_end() -> None:
    nx = await service(
        FakeResolver(mx={"example.com": MXLookup(failure=DNSFailure.NXDOMAIN)})
    ).resolve_domain(HostName("example.com"))
    servfail = await service(
        FakeResolver(mx={"example.com": MXLookup(failure=DNSFailure.SERVFAIL)})
    ).resolve_domain(HostName("example.com"))

    assert nx.reason is not servfail.reason
    assert nx.is_hard_invalid and not servfail.is_hard_invalid


@pytest.mark.asyncio
async def test_a_temporary_failure_on_one_mx_host_does_not_invalidate_the_domain() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "slow.example.com"), (20, "ok.example.com"))},
        a={
            "slow.example.com": AddressLookup(failure=DNSFailure.TIMEOUT),
            "ok.example.com": a_answer("93.184.216.34"),
        },
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.MX_ROUTE
    assert route.is_hard_invalid is False
    statuses = {c.host.value: c.status for c in route.candidates}
    assert statuses["slow.example.com"] is CandidateStatus.TEMPORARY_FAILURE
    assert statuses["ok.example.com"] is CandidateStatus.USABLE


@pytest.mark.asyncio
async def test_every_mx_host_failing_temporarily_stays_temporary() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": AddressLookup(failure=DNSFailure.SERVFAIL)},
        aaaa={"mx.example.com": AddressLookup(failure=DNSFailure.SERVFAIL)},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert route.outcome is MailRouteOutcome.TEMPORARY_FAILURE
    assert route.is_hard_invalid is False


# --- the implicit A/AAAA state matrix --------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("a_lookup", "aaaa_lookup", "expected"),
    [
        # The row the independent review found wrong. A malformed answer is not
        # proof of absence, so it must not reach `no_mail_route`.
        (
            AddressLookup(failure=DNSFailure.MALFORMED),
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            MailRouteOutcome.CONFIGURATION_ANOMALY,
        ),
        (
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            AddressLookup(failure=DNSFailure.MALFORMED),
            MailRouteOutcome.CONFIGURATION_ANOMALY,
        ),
        (
            AddressLookup(failure=DNSFailure.MALFORMED),
            AddressLookup(failure=DNSFailure.TIMEOUT),
            MailRouteOutcome.TEMPORARY_FAILURE,
        ),
        (
            AddressLookup(failure=DNSFailure.INTERNAL_ERROR),
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            MailRouteOutcome.INTERNAL_ERROR,
        ),
        (
            AddressLookup(failure=DNSFailure.REFUSED),
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            MailRouteOutcome.TEMPORARY_FAILURE,
        ),
        (
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            MailRouteOutcome.NO_MAIL_ROUTE,
        ),
        (
            a_answer("93.184.216.34"),
            AddressLookup(failure=DNSFailure.MALFORMED),
            MailRouteOutcome.IMPLICIT_MX_ROUTE,
        ),
        (
            a_answer("127.0.0.1"),
            AddressLookup(failure=DNSFailure.NO_RECORDS),
            MailRouteOutcome.UNSAFE_DESTINATION,
        ),
    ],
)
async def test_the_implicit_route_matrix(
    a_lookup: AddressLookup, aaaa_lookup: AddressLookup, expected: MailRouteOutcome
) -> None:
    resolver = FakeResolver(a={"example.com": a_lookup}, aaaa={"example.com": aaaa_lookup})
    route = await service(resolver).resolve_domain(HostName("example.com"))
    assert route.outcome is expected


@pytest.mark.asyncio
async def test_a_malformed_address_answer_is_never_hard_invalid() -> None:
    """Stated separately because it is the defect this matrix was added for."""
    resolver = FakeResolver(
        a={"example.com": AddressLookup(failure=DNSFailure.MALFORMED)},
        aaaa={"example.com": AddressLookup(failure=DNSFailure.NO_RECORDS)},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is not MailRouteOutcome.NO_MAIL_ROUTE
    assert route.is_hard_invalid is False
    assert route.reason is not ReasonCode.NO_MAIL_ROUTE


@pytest.mark.asyncio
async def test_an_internal_failure_is_reported_as_ours_not_the_domains() -> None:
    resolver = FakeResolver(mx={"example.com": MXLookup(failure=DNSFailure.INTERNAL_ERROR)})
    dns_service = service(resolver)
    route = await dns_service.resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.INTERNAL_ERROR
    assert route.reason is ReasonCode.INTERNAL_ERROR
    assert route.reason is not ReasonCode.MX_CONFIGURATION_ANOMALY
    assert route.is_hard_invalid is False
    assert dns_service.evidence(route).details["internal_error"] is True


@pytest.mark.asyncio
async def test_an_mx_host_that_answers_malformed_never_invalidates_the_address() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": AddressLookup(failure=DNSFailure.MALFORMED)},
        aaaa={"mx.example.com": AddressLookup(failure=DNSFailure.NO_RECORDS)},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.is_hard_invalid is False
    assert route.candidates[0].status is CandidateStatus.MALFORMED_RESPONSE


# --- destination policy applied to answers --------------------------------


@pytest.mark.asyncio
async def test_an_mx_pointing_only_at_loopback_is_unsafe_not_invalid() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": a_answer("127.0.0.1")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.UNSAFE_DESTINATION
    assert route.reason is ReasonCode.UNSAFE_DESTINATION
    assert route.is_hard_invalid is False
    assert route.connectable_candidates == ()
    assert route.candidates[0].denied_addresses == ("127.0.0.1",)


@pytest.mark.asyncio
async def test_a_cname_chain_ending_at_a_forbidden_address_is_refused() -> None:
    """Only the address matters: a chain cannot launder a private destination."""
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mail.example.com"))},
        a={
            "mail.example.com": AddressLookup(
                addresses=("10.0.0.5",),
                ttl=apply_ttl_policy(300, positive=True),
                cname_chain=CNAMEChain(
                    names=(HostName("intranet.example.com"), HostName("internal.example.com"))
                ),
            )
        },
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.UNSAFE_DESTINATION
    assert route.candidates[0].decisions[0].deny_reason is DestinationDenyReason.PRIVATE


@pytest.mark.asyncio
async def test_a_host_with_both_safe_and_unsafe_addresses_keeps_only_the_safe_ones() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": a_answer("127.0.0.1", "93.184.216.34", "10.0.0.1")},
    )
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.MX_ROUTE
    candidate = route.connectable_candidates[0]
    assert candidate.allowed_addresses == ("93.184.216.34",)
    assert set(candidate.denied_addresses) == {"127.0.0.1", "10.0.0.1"}


@pytest.mark.asyncio
async def test_an_implicit_route_to_a_metadata_address_is_refused() -> None:
    resolver = FakeResolver(a={"example.com": a_answer("169.254.169.254")})
    route = await service(resolver).resolve_domain(HostName("example.com"))

    assert route.outcome is MailRouteOutcome.UNSAFE_DESTINATION
    assert route.candidates[0].decisions[0].deny_reason is DestinationDenyReason.METADATA


# --- the address boundary and evidence ------------------------------------


@pytest.mark.asyncio
async def test_resolving_uses_only_the_domain_of_an_address() -> None:
    """The local part must never reach a resolver."""
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    await service(resolver).resolve(address("User.Name+tag@Example.COM"))  # type: ignore[arg-type]
    assert all("user" not in name.lower() for _kind, name in resolver.calls)
    assert resolver.calls[0] == ("mx", "example.com")


@pytest.mark.asyncio
async def test_evidence_carries_the_reason_and_a_fixed_timestamp() -> None:
    resolver = FakeResolver(mx={"example.com": mx_answer((0, "."))})
    dns_service = service(resolver)
    route = await dns_service.resolve_domain(HostName("example.com"))
    evidence = dns_service.evidence(route)

    assert evidence.layer is EvidenceLayer.DNS
    assert evidence.reason is ReasonCode.NULL_MX
    assert evidence.temporary is False
    assert evidence.observed_at == FakeClock().current
    assert evidence.details["null_mx"] is True


@pytest.mark.asyncio
async def test_evidence_marks_a_temporary_failure_as_temporary() -> None:
    resolver = FakeResolver(mx={"example.com": MXLookup(failure=DNSFailure.SERVFAIL)})
    dns_service = service(resolver)
    evidence = dns_service.evidence(await dns_service.resolve_domain(HostName("example.com")))
    assert evidence.temporary is True


@pytest.mark.asyncio
async def test_evidence_never_carries_an_address_or_raw_text() -> None:
    resolver = FakeResolver(
        mx={"example.com": mx_answer((10, "mx.example.com"))},
        a={"mx.example.com": a_answer("93.184.216.34")},
    )
    dns_service = service(resolver)
    evidence = dns_service.evidence(await dns_service.resolve_domain(HostName("example.com")))
    rendered = str(evidence.details)
    assert "93.184.216.34" not in rendered
    assert "@" not in rendered
