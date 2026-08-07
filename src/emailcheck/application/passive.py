"""Classifying an address without contacting anyone.

This service reads datasets and the Phase 2 route. It opens no socket, changes
no DNS result, and never returns a status: what it produces is risk metadata and
evidence for Phase 5 to aggregate.

The route is optional. Passive classification of the address itself works
without DNS; only provider inference needs MX host names.
"""

from __future__ import annotations

from dataclasses import dataclass

from emailcheck.classification.matchers import (
    infer_provider_family,
    match_domain_list,
    match_role,
)
from emailcheck.classification.repository import PassiveDatasets
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.dns import HostName
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.mail_route import MailRoute, MailRouteOutcome, RouteSource
from emailcheck.domain.passive import PassiveClassification
from emailcheck.domain.reasons import ReasonCode
from emailcheck.ports.clock import Clock


def mx_hosts_for_provider(route: MailRoute | None) -> tuple[HostName, ...]:
    """Return the host names provider inference may look at.

    Only MX-sourced candidates qualify. An implicit route means the domain
    published no MX at all, and its own A record says nothing about who runs its
    mail. A Null MX, a malformed exchange, and a dropped record never became a
    candidate in Phase 2, so they cannot reach here either.
    """
    if route is None:
        return ()
    if route.outcome is not MailRouteOutcome.MX_ROUTE:
        return ()
    return tuple(
        candidate.host for candidate in route.candidates if candidate.source is RouteSource.MX
    )


@dataclass(frozen=True, slots=True)
class PassiveClassifier:
    """Application service producing passive risk metadata."""

    datasets: PassiveDatasets
    clock: Clock

    def classify(
        self, address: NormalizedAddress, route: MailRoute | None = None
    ) -> PassiveClassification:
        """Classify one address against the loaded dataset snapshot.

        Each signal is computed independently, so a domain can be free-mail
        without being disposable, and a role local part is recorded whatever the
        domain turns out to be.
        """
        # `ascii_form` is already validated, so this only carries the guarantee
        # into the classification's own type: a `HostName` cannot be an address.
        domain = HostName(address.domain.ascii_form)
        return PassiveClassification(
            domain=domain,
            role=match_role(address.local_part, self.datasets.roles),
            disposable=match_domain_list(
                domain, self.datasets.disposable, self.datasets.disposable_overrides
            ),
            free_mail=match_domain_list(domain, self.datasets.free_mail),
            provider=infer_provider_family(mx_hosts_for_provider(route), self.datasets.providers),
            route_anomaly=_has_route_anomaly(route),
        )

    def evidence(self, classification: PassiveClassification) -> tuple[Evidence, ...]:
        """Express a classification as risk-only observations.

        Every item is `WEAK` and non-temporary. `docs/status-model.md` records
        that a passive risk list is not confidence evidence, so nothing here may
        move a status on its own.
        """
        observed_at = self.clock.now()
        return tuple(
            Evidence(
                layer=EvidenceLayer.PASSIVE_CLASSIFICATION,
                reason=reason,
                strength=EvidenceStrength.WEAK,
                observed_at=observed_at,
                temporary=False,
                source_version=_version_for(classification, reason),
                details=classification.details,
            )
            for reason in classification.reason_codes
        )


def _has_route_anomaly(route: MailRoute | None) -> bool:
    """Whether Phase 2 saw a configuration this layer should flag.

    The mapping is to a risk flag only. `docs/status-model.md` keeps risk
    separate from status, so noting the anomaly here cannot change what the
    route already concluded.
    """
    if route is None:
        return False
    return bool(route.anomalies) or route.outcome is MailRouteOutcome.CONFIGURATION_ANOMALY


def _version_for(classification: PassiveClassification, reason: ReasonCode) -> str | None:
    versions = classification.dataset_versions
    if reason is ReasonCode.DISPOSABLE_DOMAIN:
        return versions.get("disposable")
    if reason is ReasonCode.ROLE_ACCOUNT:
        return versions.get("role")
    if reason is ReasonCode.FREE_MAIL:
        return versions.get("free_mail")
    return None
