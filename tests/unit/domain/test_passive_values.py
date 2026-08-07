"""What a passive classification is structurally unable to hold.

Phase 1 and Phase 2 closed the same gap in their own values: a field typed as
`str` will eventually be handed the wrong string, and the wrong string here is
the submitted address. These tests are about what cannot be constructed at all,
not about what the service happens to pass today.
"""

import pytest

from emailcheck.domain.dns import DNSContractError, HostName
from emailcheck.domain.passive import (
    ROLE_NAME_MAX_LENGTH,
    DomainListMatch,
    PassiveClassification,
    PassiveContractError,
    ProviderFamily,
    RoleMatch,
    RoleName,
)

DOMAIN = HostName("example.com")


def classification(**kwargs: object) -> PassiveClassification:
    return PassiveClassification(domain=DOMAIN, **kwargs)  # type: ignore[arg-type]


# --- the domain is a host name, not text -----------------------------------


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("Support+Billing@example.com", "a complete address"),
        ("person@example.com", "a complete address"),
        ("@example.com", "a bare at sign"),
        ("example.com\r\nHELO evil", "CRLF"),
        ("example.com\n", "LF"),
        ("example.com\r", "CR"),
        ("example.com\x00", "NUL"),
        ("example.com\t", "tab"),
        ("", "empty"),
        (" example.com", "leading space"),
        ("example.com.", "a trailing dot, which normalization removes"),
        ("EXAMPLE.COM", "upper case, which normalization lowers"),
        ("ex ample.com", "an inner space"),
        ("example..com", "an empty label"),
        ("-example.com", "a leading hyphen"),
        ("example.com-", "a trailing hyphen"),
        ("ex_ample.com", "an underscore"),
        ("[192.0.2.1]", "an address literal"),
        ("münchen.de", "an unencoded IDN"),
        ("a" * 64 + ".example", "an over-long label"),
    ],
)
def test_a_classification_domain_cannot_be_built_from_unusable_text(value: str, label: str) -> None:
    with pytest.raises(DNSContractError):
        PassiveClassification(domain=HostName(value))


@pytest.mark.parametrize(
    ("submitted", "expected"),
    [
        ("EXAMPLE.COM", "example.com"),
        ("Example.Com.", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
    ],
)
def test_domain_normalization_matches_the_existing_rule(submitted: str, expected: str) -> None:
    """`HostName.normalize` is the Phase 2 rule; no second one was written."""
    host = HostName.normalize(submitted)
    assert host is not None
    assert host.value == expected


def test_the_domain_that_reaches_evidence_is_the_validated_one() -> None:
    result = classification()
    assert result.details["domain"] == DOMAIN.value
    assert isinstance(result.domain, HostName)


# --- the role name is a dataset identifier, not submitted text -------------


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("Support+Billing.SECRET", "the submitted local part"),
        ("support+billing", "a tag"),
        ("support+", "a bare tag separator"),
        ("Support", "upper case"),
        ("SUPPORT", "upper case"),
        ("support@example.com", "a complete address"),
        ("support@", "an at sign"),
        ("support\r\nRCPT TO:<x>", "CRLF"),
        ("support\n", "LF"),
        ("support\r", "CR"),
        ("support\x00", "NUL"),
        ("support\x1b", "an escape"),
        ("supporté", "non-ASCII"),
        ("support\u200b", "a zero width space"),
        ("", "empty"),
        (" support", "a leading space"),
        ("support ", "a trailing space"),
        (".support", "a leading dot"),
        ("support.", "a trailing dot"),
        ("sup..port", "consecutive dots"),
        ("x" * (ROLE_NAME_MAX_LENGTH + 1), "over length"),
    ],
)
def test_a_role_name_cannot_be_built_from_submitted_text(value: str, label: str) -> None:
    with pytest.raises((PassiveContractError, ValueError)):
        RoleName(value)


@pytest.mark.parametrize("value", ["support", "admin", "postmaster", "info.desk", "no-reply"])
def test_a_canonical_role_identifier_is_accepted(value: str) -> None:
    assert RoleName(value).value == value


def test_a_role_match_cannot_hold_a_raw_string() -> None:
    """The field is typed, and the type validates; neither alone is enough."""
    with pytest.raises((PassiveContractError, ValueError)):
        RoleMatch(name=RoleName("Support+Billing.SECRET"), dataset_version="v1")


def test_the_submitted_local_part_cannot_reach_details_or_repr() -> None:
    result = classification(role=RoleMatch(name=RoleName("support"), dataset_version="v1"))

    assert result.details["role_name"] == "support"
    rendered = repr(result)
    assert "Support+Billing" not in rendered
    assert "@" not in rendered
    assert "SECRET" not in rendered


# --- nothing here can carry a control character ----------------------------


def test_no_string_in_a_classification_can_break_a_line() -> None:
    result = PassiveClassification(
        domain=DOMAIN,
        role=RoleMatch(name=RoleName("support"), dataset_version="v1"),
        disposable=DomainListMatch(
            matched=False,
            dataset_version="v1",
            overridden=True,
            override_reason="reported false positive",
        ),
        free_mail=DomainListMatch(matched=True, dataset_version="v1"),
        route_anomaly=True,
    )
    rendered = repr(result) + repr(result.details) + repr(result.dataset_versions)

    for forbidden in ("\r", "\n", "\x00"):
        assert forbidden not in rendered
    assert "@" not in rendered


def test_a_provider_family_is_still_metadata_after_all_of_this() -> None:
    """None of the new invariants gave this layer a way to reach a verdict."""
    for family in ProviderFamily:
        assert family.value not in {"invalid", "likely_deliverable", "risky"}
