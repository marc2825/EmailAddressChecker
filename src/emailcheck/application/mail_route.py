"""Resolving a mail route for one validated address.

This is the only place the query order lives: MX first, implicit A/AAAA only
when no MX exists at all. Every address a resolver returns is passed through the
destination policy before it can become a candidate, so nothing downstream ever
sees an address that was not judged.

No socket is opened here and none may be: this Phase produces evidence, and
Phase 4 owns connecting.
"""

from __future__ import annotations

from dataclasses import dataclass

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.dns import TTL, DNSFailure, HostName, MXRecord
from emailcheck.domain.evidence import Evidence, EvidenceLayer
from emailcheck.domain.mail_route import (
    CandidateStatus,
    MailRoute,
    MailRouteOutcome,
    RouteAnomaly,
    RouteCandidate,
    RouteSource,
    classify_host_result,
    classify_mx_records,
    decide_outcome,
    strength_for,
)
from emailcheck.ports.clock import Clock
from emailcheck.ports.dns import DNSResolver
from emailcheck.security.destination import DestinationDecision, evaluate_destinations


@dataclass(frozen=True, slots=True)
class MailRouteService:
    """Application service that turns DNS answers into route evidence."""

    resolver: DNSResolver
    clock: Clock

    async def resolve(self, address: NormalizedAddress) -> MailRoute:
        """Resolve the mail route for the address's domain.

        The local part is never used for a lookup: only the domain identifies a
        route, and passing more than that to a resolver would leak the mailbox.
        """
        domain = HostName(address.domain.ascii_form)
        return await self.resolve_domain(domain)

    async def resolve_domain(self, domain: HostName) -> MailRoute:
        mx_lookup = await self.resolver.query_mx(domain)

        if mx_lookup.failure is not None and mx_lookup.failure is not DNSFailure.NO_RECORDS:
            outcome = decide_outcome(
                mx_failure=mx_lookup.failure,
                classification=None,
                candidates=(),
                implicit_status=None,
            )
            return self._route(domain, outcome, (), (), mx_lookup.ttl)

        classification = classify_mx_records(mx_lookup.records)

        if classification.null_mx:
            return self._route(
                domain,
                MailRouteOutcome.NULL_MX,
                (),
                classification.anomalies,
                mx_lookup.ttl,
            )

        if classification.has_usable_records:
            candidates = await self._mx_candidates(classification.usable)
            outcome = decide_outcome(
                mx_failure=None,
                classification=classification,
                candidates=candidates,
                implicit_status=None,
            )
            return self._route(domain, outcome, candidates, classification.anomalies, mx_lookup.ttl)

        if classification.anomalies:
            # MX records exist but none is usable. Implicit MX does not apply,
            # because the domain did publish mail routing.
            return self._route(
                domain,
                MailRouteOutcome.CONFIGURATION_ANOMALY,
                (),
                classification.anomalies,
                mx_lookup.ttl,
            )

        decisions, status = await self._host_addresses(domain)
        candidates = self._implicit_candidates(domain, decisions, status)
        outcome = decide_outcome(
            mx_failure=None,
            classification=classification,
            candidates=candidates,
            implicit_status=status,
        )
        return self._route(domain, outcome, candidates, classification.anomalies, mx_lookup.ttl)

    async def _mx_candidates(self, records: tuple[MXRecord, ...]) -> tuple[RouteCandidate, ...]:
        candidates: list[RouteCandidate] = []
        for record in records:
            host = HostName.normalize(record.exchange)
            if host is None:  # pragma: no cover - classification already filtered these
                continue
            decisions, status = await self._host_addresses(host)
            candidates.append(
                RouteCandidate(
                    host=host,
                    preference=record.preference,
                    source=RouteSource.MX,
                    status=status,
                    decisions=decisions,
                )
            )
        return tuple(candidates)

    def _implicit_candidates(
        self,
        domain: HostName,
        decisions: tuple[DestinationDecision, ...],
        status: CandidateStatus,
    ) -> tuple[RouteCandidate, ...]:
        """Build the implicit-MX candidate, if the host produced anything at all.

        A proven absence yields no candidate: there is nothing to describe, and
        the outcome comes from the status instead.
        """
        if status is CandidateStatus.NO_ADDRESSES:
            return ()
        return (
            RouteCandidate(
                host=domain,
                preference=0,
                source=RouteSource.IMPLICIT_MX,
                status=status,
                decisions=decisions,
            ),
        )

    async def _host_addresses(
        self, host: HostName
    ) -> tuple[tuple[DestinationDecision, ...], CandidateStatus]:
        """Resolve one host's addresses and judge every one of them.

        The classification itself is pure domain policy, so the rule that only
        a proven absence counts as an absence is tested without a resolver. The
        policy runs on every returned address, including any reached through a
        CNAME chain, because the answer is what a connection would use.
        """
        a_lookup = await self.resolver.query_a(host)
        aaaa_lookup = await self.resolver.query_aaaa(host)

        decisions = evaluate_destinations(a_lookup.addresses + aaaa_lookup.addresses)
        status = classify_host_result(
            a_failure=a_lookup.failure,
            aaaa_failure=aaaa_lookup.failure,
            decisions=decisions,
        )
        if status is CandidateStatus.NO_ADDRESSES:
            # The invariant on the candidate forbids carrying decisions here,
            # and by definition there are none to carry.
            return (), status
        return decisions, status

    def _route(
        self,
        domain: HostName,
        outcome: MailRouteOutcome,
        candidates: tuple[RouteCandidate, ...],
        anomalies: tuple[RouteAnomaly, ...],
        ttl: TTL | None,
    ) -> MailRoute:
        return MailRoute(
            domain=domain.value,
            outcome=outcome,
            candidates=candidates,
            anomalies=anomalies,
            ttl=ttl,
        )

    def evidence(self, route: MailRoute) -> Evidence:
        """Express a route as one immutable observation for later aggregation."""
        return Evidence(
            layer=EvidenceLayer.DNS,
            reason=route.reason,
            strength=strength_for(route.outcome),
            observed_at=self.clock.now(),
            temporary=route.is_temporary,
            details={
                "outcome": route.outcome.value,
                "candidate_count": len(route.connectable_candidates),
                "anomaly_count": len(route.anomalies),
                "null_mx": route.outcome is MailRouteOutcome.NULL_MX,
                "internal_error": route.is_internal_error,
            },
        )
