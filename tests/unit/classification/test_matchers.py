"""Role, domain-list, and provider matching."""

import pytest

from dataset_fixtures import (
    domain_dataset_text,
    override_dataset_text,
    provider_dataset_text,
    role_dataset_text,
)
from emailcheck.classification.datasets import (
    load_domain_dataset,
    load_override_dataset,
    load_provider_dataset,
    load_role_dataset,
)
from emailcheck.classification.matchers import (
    infer_provider_family,
    match_domain_list,
    match_role,
    role_comparison_form,
)
from emailcheck.domain.address import LocalPart
from emailcheck.domain.dns import HostName
from emailcheck.domain.passive import ProviderFamily, ProviderInferenceReason

ROLES = load_role_dataset(
    role_dataset_text("admin", "administrator", "info", "postmaster", "support", "webmaster")
)
DISPOSABLE = load_domain_dataset(
    domain_dataset_text("disposable_domains", "throwaway.example", "münchen-temp.example"),
    kind="disposable_domains",
)
FREE_MAIL = load_domain_dataset(
    domain_dataset_text("free_mail_domains", "consumer-mail.example"),
    kind="free_mail_domains",
)
PROVIDERS = load_provider_dataset(
    provider_dataset_text(
        ("google", "provider-a.example"),
        ("google", "mx.provider-a.example"),
        ("microsoft", "provider-b.example"),
    )
)


# --- role matching ---------------------------------------------------------


@pytest.mark.parametrize(
    "local",
    ["support", "Support", "SUPPORT", "SuPpOrT", "administrator", "postmaster", "webmaster"],
)
def test_a_role_matches_regardless_of_case(local: str) -> None:
    match = match_role(LocalPart(local), ROLES)
    assert match is not None
    assert match.name.value == local.lower()
    assert match.dataset_version == ROLES.metadata.version


@pytest.mark.parametrize(
    ("local", "expected"),
    [
        ("support+billing", "support"),
        ("Support+News", "support"),
        ("info+2026+x", "info"),
    ],
)
def test_a_tag_is_dropped_for_comparison_only(local: str, expected: str) -> None:
    match = match_role(LocalPart(local), ROLES)
    assert match is not None
    assert match.name.value == expected
    # Phase 1 promises the value itself is untouched.
    assert LocalPart(local).value == local


@pytest.mark.parametrize(
    "local",
    [
        "mysupport",
        "supportive",
        "support-team",
        "team-support",
        "support.desk",
        "info.desk",
        "sales2",
        "suport",
        "adminx",
        "xadmin",
        "webmasters",
        "the.admin",
    ],
)
def test_a_near_miss_is_not_a_role(local: str) -> None:
    """Exact match only: a substring rule would flag personal mailboxes."""
    assert match_role(LocalPart(local), ROLES) is None


def test_a_local_part_that_is_only_a_tag_is_not_a_role() -> None:
    assert match_role(LocalPart("+tag"), ROLES) is None


def test_the_comparison_form_keeps_dots() -> None:
    assert role_comparison_form(LocalPart("first.last")) == "first.last"
    assert role_comparison_form(LocalPart("First.Last+tag")) == "first.last"


def test_unicode_local_parts_never_reach_role_matching() -> None:
    """Phase 1 rejects them as unsupported, so a `LocalPart` cannot hold one."""
    from emailcheck.domain.address import AddressContractError

    with pytest.raises(AddressContractError):
        LocalPart("supporté")


# --- domain lists ----------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "expected"),
    [("throwaway.example", True), ("legitimate.example", False)],
)
def test_disposable_membership(domain: str, expected: bool) -> None:
    assert match_domain_list(HostName(domain), DISPOSABLE).matched is expected


def test_an_idn_dataset_entry_matches_the_encoded_domain() -> None:
    """The dataset stored a Unicode name; an address arrives already encoded."""
    encoded = "xn--mnchen-temp-zhb.example"
    assert DISPOSABLE.contains(encoded) or "münchen-temp.example" not in DISPOSABLE.domains
    stored = next(domain for domain in DISPOSABLE.domains if domain.startswith("xn--"))
    assert match_domain_list(HostName(stored), DISPOSABLE).matched is True


def test_free_mail_and_disposable_are_independent() -> None:
    """A free-mail domain need not be disposable, and the reverse."""
    free_only = match_domain_list(HostName("consumer-mail.example"), FREE_MAIL)
    disposable_only = match_domain_list(HostName("throwaway.example"), DISPOSABLE)

    assert free_only.matched is True
    assert match_domain_list(HostName("consumer-mail.example"), DISPOSABLE).matched is False
    assert disposable_only.matched is True
    assert match_domain_list(HostName("throwaway.example"), FREE_MAIL).matched is False


def test_a_result_carries_the_dataset_version_that_answered() -> None:
    assert match_domain_list(HostName("throwaway.example"), DISPOSABLE).dataset_version == "test-1"


# --- overrides -------------------------------------------------------------


def test_a_not_disposable_override_beats_a_dataset_match() -> None:
    overrides = load_override_dataset(
        override_dataset_text(not_disposable=(("throwaway.example", "reported false positive"),))
    )
    result = match_domain_list(HostName("throwaway.example"), DISPOSABLE, overrides)

    assert result.matched is False
    assert result.overridden is True
    assert result.override_reason == "reported false positive"


def test_a_disposable_override_adds_a_domain_the_dataset_missed() -> None:
    overrides = load_override_dataset(
        override_dataset_text(
            disposable=(("missed.example", "observed offering throwaway mailboxes"),)
        )
    )
    result = match_domain_list(HostName("missed.example"), DISPOSABLE, overrides)

    assert result.matched is True
    assert result.overridden is True


def test_an_unrelated_override_changes_nothing() -> None:
    overrides = load_override_dataset(
        override_dataset_text(not_disposable=(("other.example", "unrelated"),))
    )
    result = match_domain_list(HostName("throwaway.example"), DISPOSABLE, overrides)
    assert result.matched is True
    assert result.overridden is False


# --- provider inference ----------------------------------------------------


def hosts(*names: str) -> tuple[HostName, ...]:
    return tuple(HostName(name) for name in names)


def test_a_suffix_matches_on_a_label_boundary() -> None:
    result = infer_provider_family(hosts("aspmx.mx.provider-a.example"), PROVIDERS)
    assert result.family is ProviderFamily.GOOGLE
    assert result.reason is ProviderInferenceReason.MATCHED


def test_the_host_may_equal_the_suffix() -> None:
    assert infer_provider_family(hosts("provider-a.example"), PROVIDERS).family is (
        ProviderFamily.GOOGLE
    )


@pytest.mark.parametrize(
    "host",
    [
        "provider-a.example.evil.test",
        "notprovider-a.example",
        "xprovider-a.example",
        "provider-a.example.attacker.example",
        "fake-provider-a.example",
    ],
)
def test_a_lookalike_host_is_never_attributed_to_the_provider(host: str) -> None:
    result = infer_provider_family(hosts(host), PROVIDERS)
    assert result.family is ProviderFamily.OTHER
    assert result.matched_suffix is None


def test_several_hosts_of_one_family_stay_that_family() -> None:
    result = infer_provider_family(
        hosts("alt1.mx.provider-a.example", "alt2.mx.provider-a.example"), PROVIDERS
    )
    assert result.family is ProviderFamily.GOOGLE


def test_mx_order_cannot_change_the_answer() -> None:
    """Matching is set-based, so preference order is irrelevant."""
    forward = infer_provider_family(
        hosts("alt1.mx.provider-a.example", "alt2.provider-a.example"), PROVIDERS
    )
    reverse = infer_provider_family(
        hosts("alt2.provider-a.example", "alt1.mx.provider-a.example"), PROVIDERS
    )
    assert forward == reverse


def test_two_families_are_reported_as_unknown_not_guessed() -> None:
    result = infer_provider_family(
        hosts("mx.provider-a.example", "mx.provider-b.example"), PROVIDERS
    )
    assert result.family is ProviderFamily.UNKNOWN
    assert result.reason is ProviderInferenceReason.AMBIGUOUS


def test_no_hosts_is_unknown_not_other() -> None:
    result = infer_provider_family((), PROVIDERS)
    assert result.family is ProviderFamily.UNKNOWN
    assert result.reason is ProviderInferenceReason.NO_MX_HOSTS


def test_an_empty_dataset_reports_unknown_with_its_reason() -> None:
    empty = load_provider_dataset(provider_dataset_text())
    result = infer_provider_family(hosts("mx.provider-a.example"), empty)
    assert result.family is ProviderFamily.UNKNOWN
    assert result.reason is ProviderInferenceReason.NO_DATASET


def test_a_host_matching_nothing_is_other() -> None:
    result = infer_provider_family(hosts("mx.unaffiliated.example"), PROVIDERS)
    assert result.family is ProviderFamily.OTHER
    assert result.reason is ProviderInferenceReason.NO_MATCH


def test_the_most_specific_suffix_is_reported() -> None:
    result = infer_provider_family(hosts("a.mx.provider-a.example"), PROVIDERS)
    assert result.matched_suffix == "mx.provider-a.example"
