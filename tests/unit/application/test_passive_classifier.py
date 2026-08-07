"""The passive classification service, and the invariants that bound it."""

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from dataset_fixtures import (
    domain_dataset_text,
    override_dataset_text,
    provider_dataset_text,
    role_dataset_text,
)
from emailcheck.application.passive import PassiveClassifier, mx_hosts_for_provider
from emailcheck.classification.datasets import (
    load_domain_dataset,
    load_override_dataset,
    load_provider_dataset,
    load_role_dataset,
)
from emailcheck.classification.repository import PassiveDatasets
from emailcheck.domain.address import (
    AddressAccepted,
    RawAddressInput,
    has_control_character,
    parse_address,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.evidence import EvidenceLayer, EvidenceStrength
from emailcheck.domain.mail_route import (
    CandidateStatus,
    MailRoute,
    MailRouteOutcome,
    RouteAnomaly,
    RouteCandidate,
    RouteSource,
)
from emailcheck.domain.passive import (
    PASSIVE_REASON_CODES,
    PASSIVE_RISK_FLAGS,
    PassiveClassification,
    ProviderFamily,
)
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import RiskFlag
from emailcheck.security.destination import DestinationDecision

ALLOWED = DestinationDecision(allowed=True, address="93.184.216.34", version=4, deny_reason=None)


@dataclass
class FixedClock:
    current: datetime = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


def datasets(
    *,
    disposable: tuple[str, ...] = ("throwaway.example",),
    free_mail: tuple[str, ...] = ("consumer-mail.example",),
    roles: tuple[str, ...] = ("support", "info", "postmaster"),
    providers: tuple[tuple[str, str], ...] = (("google", "provider-a.example"),),
    not_disposable: tuple[tuple[str, str], ...] = (),
    disposable_override: tuple[tuple[str, str], ...] = (),
) -> PassiveDatasets:
    return PassiveDatasets(
        disposable=load_domain_dataset(
            domain_dataset_text("disposable_domains", *disposable, version="disposable-1"),
            kind="disposable_domains",
        ),
        free_mail=load_domain_dataset(
            domain_dataset_text("free_mail_domains", *free_mail, version="free-1"),
            kind="free_mail_domains",
        ),
        roles=load_role_dataset(role_dataset_text(*roles, version="role-1")),
        providers=load_provider_dataset(provider_dataset_text(*providers, version="provider-1")),
        disposable_overrides=load_override_dataset(
            override_dataset_text(not_disposable=not_disposable, disposable=disposable_override)
        ),
    )


def classifier(**kwargs: object) -> PassiveClassifier:
    return PassiveClassifier(datasets=datasets(**kwargs), clock=FixedClock())  # type: ignore[arg-type]


def address(text: str) -> object:
    parsed = parse_address(RawAddressInput(text))
    assert isinstance(parsed, AddressAccepted)
    return parsed.address


def mx_route(*hosts: str, outcome: MailRouteOutcome = MailRouteOutcome.MX_ROUTE) -> MailRoute:
    return MailRoute(
        domain="example.com",
        outcome=outcome,
        candidates=tuple(
            RouteCandidate(
                host=HostName(host),
                preference=10 * (index + 1),
                source=RouteSource.MX,
                status=CandidateStatus.USABLE,
                decisions=(ALLOWED,),
            )
            for index, host in enumerate(hosts)
        ),
    )


# --- the four signals are independent --------------------------------------


def test_a_plain_address_raises_nothing() -> None:
    result = classifier().classify(address("person@legitimate.example"))  # type: ignore[arg-type]
    assert result.risk_flags == frozenset()
    assert result.reason_codes == ()
    assert result.is_disposable is False
    assert result.is_free_mail is False


def test_a_role_on_a_free_mail_domain_records_both() -> None:
    result = classifier().classify(address("support@consumer-mail.example"))  # type: ignore[arg-type]
    assert result.risk_flags == {RiskFlag.ROLE_ACCOUNT, RiskFlag.FREE_MAIL}
    assert set(result.reason_codes) == {ReasonCode.ROLE_ACCOUNT, ReasonCode.FREE_MAIL}


def test_disposable_and_free_mail_can_coexist() -> None:
    service = classifier(disposable=("both.example",), free_mail=("both.example",))
    result = service.classify(address("person@both.example"))  # type: ignore[arg-type]
    assert result.is_disposable is True
    assert result.is_free_mail is True


def test_a_disposable_domain_is_not_free_mail_by_default() -> None:
    result = classifier().classify(address("person@throwaway.example"))  # type: ignore[arg-type]
    assert result.is_disposable is True
    assert result.is_free_mail is False


def test_a_company_domain_hosted_by_a_big_provider_is_not_free_mail() -> None:
    """Free-mail is membership of the domain, never of whoever hosts its mail."""
    service = classifier()
    result = service.classify(
        address("person@company.example"),  # type: ignore[arg-type]
        mx_route("mx.provider-a.example"),
    )
    assert result.provider_family is ProviderFamily.GOOGLE
    assert result.is_free_mail is False
    assert RiskFlag.FREE_MAIL not in result.risk_flags


# --- provider inference uses only usable MX hosts --------------------------


def test_provider_inference_reads_mx_hosts() -> None:
    result = classifier().classify(
        address("person@company.example"),  # type: ignore[arg-type]
        mx_route("alt.provider-a.example"),
    )
    assert result.provider_family is ProviderFamily.GOOGLE


@pytest.mark.parametrize(
    "outcome",
    [
        MailRouteOutcome.NULL_MX,
        MailRouteOutcome.IMPLICIT_MX_ROUTE,
        MailRouteOutcome.NO_MAIL_ROUTE,
        MailRouteOutcome.CONFIGURATION_ANOMALY,
        MailRouteOutcome.TEMPORARY_FAILURE,
        MailRouteOutcome.DOMAIN_NOT_FOUND,
        MailRouteOutcome.UNSAFE_DESTINATION,
        MailRouteOutcome.INTERNAL_ERROR,
    ],
)
def test_no_route_outcome_other_than_an_mx_route_feeds_provider_inference(
    outcome: MailRouteOutcome,
) -> None:
    """A Null MX has no provider, and an implicit route published no MX at all."""
    route = mx_route("mx.provider-a.example", outcome=outcome)
    assert mx_hosts_for_provider(route) == ()

    result = classifier().classify(address("person@company.example"), route)  # type: ignore[arg-type]
    assert result.provider_family is ProviderFamily.UNKNOWN


def test_an_implicit_route_candidate_is_never_used_for_provider_inference() -> None:
    route = MailRoute(
        domain="example.com",
        outcome=MailRouteOutcome.IMPLICIT_MX_ROUTE,
        candidates=(
            RouteCandidate(
                host=HostName("provider-a.example"),
                preference=0,
                source=RouteSource.IMPLICIT_MX,
                status=CandidateStatus.USABLE,
                decisions=(ALLOWED,),
            ),
        ),
    )
    assert mx_hosts_for_provider(route) == ()


def test_classification_without_a_route_still_works() -> None:
    result = classifier().classify(address("support@throwaway.example"))  # type: ignore[arg-type]
    assert result.is_role_account is True
    assert result.is_disposable is True
    assert result.provider_family is ProviderFamily.UNKNOWN


# --- route anomalies map to a risk flag, never to a status ------------------


def test_a_route_anomaly_becomes_a_risk_flag() -> None:
    route = MailRoute(
        domain="example.com",
        outcome=MailRouteOutcome.MX_ROUTE,
        candidates=mx_route("mx.provider-a.example").candidates,
        anomalies=(RouteAnomaly.NULL_MX_WITH_OTHER_RECORDS,),
    )
    result = classifier().classify(address("person@company.example"), route)  # type: ignore[arg-type]

    assert RiskFlag.DOMAIN_CONFIGURATION_ANOMALY in result.risk_flags
    # The route keeps the outcome it already had.
    assert route.outcome is MailRouteOutcome.MX_ROUTE
    assert route.reason is ReasonCode.MX_AVAILABLE


def test_classifying_does_not_change_the_route() -> None:
    route = mx_route("mx.provider-a.example")
    before = (route.outcome, route.reason, route.candidates, route.is_hard_invalid)
    classifier().classify(address("support@throwaway.example"), route)  # type: ignore[arg-type]
    assert (route.outcome, route.reason, route.candidates, route.is_hard_invalid) == before


# --- overrides -------------------------------------------------------------


def test_an_override_clears_a_disposable_flag() -> None:
    service = classifier(not_disposable=(("throwaway.example", "reported false positive"),))
    result = service.classify(address("person@throwaway.example"))  # type: ignore[arg-type]

    assert result.is_disposable is False
    assert RiskFlag.DISPOSABLE not in result.risk_flags
    assert result.disposable is not None
    assert result.disposable.overridden is True
    assert result.disposable.override_reason == "reported false positive"


# --- evidence --------------------------------------------------------------


def test_evidence_is_risk_only_and_carries_its_dataset_version() -> None:
    service = classifier()
    result = service.classify(address("support@throwaway.example"))  # type: ignore[arg-type]
    evidence = service.evidence(result)

    assert {item.reason for item in evidence} == {
        ReasonCode.ROLE_ACCOUNT,
        ReasonCode.DISPOSABLE_DOMAIN,
    }
    for item in evidence:
        assert item.layer is EvidenceLayer.PASSIVE_CLASSIFICATION
        assert item.strength is EvidenceStrength.WEAK
        assert item.temporary is False
        assert item.observed_at == FixedClock().current
    versions = {item.reason: item.source_version for item in evidence}
    assert versions[ReasonCode.ROLE_ACCOUNT] == "role-1"
    assert versions[ReasonCode.DISPOSABLE_DOMAIN] == "disposable-1"


def test_a_clean_address_produces_no_evidence() -> None:
    service = classifier()
    assert service.evidence(service.classify(address("person@legitimate.example"))) == ()  # type: ignore[arg-type]


def test_evidence_never_carries_an_address_or_local_part() -> None:
    service = classifier()
    result = service.classify(address("Support+Billing@throwaway.example"))  # type: ignore[arg-type]
    rendered = repr(service.evidence(result))

    assert "@" not in rendered
    assert "Support+Billing" not in rendered
    assert "Billing" not in rendered
    assert "throwaway.example" in rendered  # the domain is not the address


def test_the_matched_role_is_the_dataset_category_not_the_submitted_text() -> None:
    result = classifier().classify(address("Support+Billing@company.example"))  # type: ignore[arg-type]
    assert result.role is not None
    assert result.role.name.value == "support"


# --- invariants ------------------------------------------------------------


def test_passive_classification_only_uses_risk_only_reason_codes() -> None:
    """None of these may become hard-invalid or optimistic evidence."""
    service = classifier(disposable=("x.example",), free_mail=("x.example",))
    result = service.classify(address("support@x.example"))  # type: ignore[arg-type]

    assert set(result.reason_codes) <= PASSIVE_REASON_CODES
    for code in result.reason_codes:
        assert code not in {
            ReasonCode.INVALID_SYNTAX,
            ReasonCode.DOMAIN_NXDOMAIN,
            ReasonCode.NULL_MX,
            ReasonCode.NO_MAIL_ROUTE,
        }


def test_passive_classification_only_raises_passive_risk_flags() -> None:
    service = classifier(disposable=("x.example",), free_mail=("x.example",))
    route = MailRoute(
        domain="x.example",
        outcome=MailRouteOutcome.CONFIGURATION_ANOMALY,
        anomalies=(RouteAnomaly.MALFORMED_EXCHANGE,),
    )
    result = service.classify(address("support@x.example"), route)  # type: ignore[arg-type]

    assert result.risk_flags == PASSIVE_RISK_FLAGS
    assert RiskFlag.ACCEPT_ALL_SUSPECTED not in result.risk_flags
    assert RiskFlag.PROVIDER_OPAQUE not in result.risk_flags


def test_a_provider_family_never_raises_a_risk_flag() -> None:
    """Provider identity is metadata; it is not a risk and not a verdict."""
    result = classifier().classify(
        address("person@company.example"),  # type: ignore[arg-type]
        mx_route("mx.provider-a.example"),
    )
    assert result.provider_family is ProviderFamily.GOOGLE
    assert result.risk_flags == frozenset()
    assert result.reason_codes == ()


def test_the_same_input_and_snapshot_give_the_same_answer() -> None:
    service = classifier()
    target = address("support@throwaway.example")
    route = mx_route("mx.provider-a.example")

    first = service.classify(target, route)  # type: ignore[arg-type]
    second = service.classify(target, route)  # type: ignore[arg-type]
    assert first == second
    assert first.details == second.details


def test_every_answer_is_traceable_to_a_dataset_version() -> None:
    result = classifier().classify(
        address("support@throwaway.example"),  # type: ignore[arg-type]
        mx_route("mx.provider-a.example"),
    )
    assert result.dataset_versions == {
        "role": "role-1",
        "disposable": "disposable-1",
        "free_mail": "free-1",
        "provider": "provider-1",
    }


def test_a_classification_never_reports_a_status() -> None:
    """There is no status field to report: this layer cannot express one."""
    result = classifier().classify(address("support@throwaway.example"))  # type: ignore[arg-type]
    fields = set(PassiveClassification.__dataclass_fields__)
    assert "status" not in fields
    assert "deliverable" not in fields
    assert not hasattr(result, "status")


# --- what an override may and may not change -------------------------------


def test_an_override_changes_disposable_membership_and_nothing_else() -> None:
    """The correction is scoped to one list, in both directions."""
    plain = classifier()
    forced_off = classifier(not_disposable=(("throwaway.example", "real company"),))
    forced_on = classifier(disposable_override=(("consumer-mail.example", "seen offering it"),))
    target = address("support@throwaway.example")
    other = address("support@consumer-mail.example")

    assert plain.classify(target).is_disposable is True  # type: ignore[arg-type]
    assert forced_off.classify(target).is_disposable is False  # type: ignore[arg-type]
    assert forced_on.classify(other).is_disposable is True  # type: ignore[arg-type]

    for service, subject in ((forced_off, target), (forced_on, other)):
        overridden = service.classify(subject)  # type: ignore[arg-type]
        untouched = plain.classify(subject)  # type: ignore[arg-type]
        assert overridden.is_role_account == untouched.is_role_account
        assert overridden.is_free_mail == untouched.is_free_mail
        assert overridden.provider_family == untouched.provider_family
        assert overridden.route_anomaly == untouched.route_anomaly
        assert overridden.role == untouched.role
        assert overridden.free_mail == untouched.free_mail


def test_an_override_cannot_reach_a_status_or_a_verdict() -> None:
    """An override moves a risk flag. There is nothing else for it to move."""
    service = classifier(not_disposable=(("throwaway.example", "real company"),))
    result = service.classify(address("support@throwaway.example"))  # type: ignore[arg-type]

    assert not hasattr(result, "status")
    assert not hasattr(result, "verdict")
    assert not hasattr(result, "confidence")
    assert result.risk_flags <= PASSIVE_RISK_FLAGS
    assert set(result.reason_codes) <= PASSIVE_REASON_CODES
    assert result.disposable is not None
    assert result.disposable.overridden is True
    # The reason travels as text on the match, never as a reason code.
    assert result.disposable.override_reason == "real company"
    assert ReasonCode.DISPOSABLE_DOMAIN not in result.reason_codes


def test_an_override_reason_reaches_no_evidence_detail() -> None:
    """Operator prose stays out of the published detail map."""
    service = classifier(not_disposable=(("throwaway.example", "internal ticket OPS-4412"),))
    result = service.classify(address("support@throwaway.example"))  # type: ignore[arg-type]
    assert "OPS-4412" not in repr(result.details)


# --- every string that reaches evidence ------------------------------------


def evidence_strings(service: PassiveClassifier, subject: object, route: object = None) -> set[str]:
    """Every string reachable from a classification and its evidence."""
    result = service.classify(subject, route)  # type: ignore[arg-type]
    collected: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, str):
            collected.add(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(key)
                walk(item)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                walk(item)
        elif hasattr(value, "__dataclass_fields__"):
            for name in value.__dataclass_fields__:
                walk(getattr(value, name))

    walk(result)
    walk(result.details)
    walk(result.dataset_versions)
    for item in service.evidence(result):
        walk(item)
    return collected


def test_no_string_reaching_evidence_carries_a_control_character() -> None:
    service = classifier()
    for value in evidence_strings(
        service, address("Support+Billing@throwaway.example"), mx_route("mx.provider-a.example")
    ):
        assert not has_control_character(value), repr(value)


def test_no_string_reaching_evidence_carries_an_address_or_local_part() -> None:
    service = classifier()
    values = evidence_strings(
        service, address("Support+Billing@throwaway.example"), mx_route("mx.provider-a.example")
    )
    for value in values:
        assert "@" not in value, repr(value)
        assert "Support+Billing" not in value, repr(value)
        assert "Billing" not in value, repr(value)
    # The domain is present and is not the address.
    assert "throwaway.example" in values
