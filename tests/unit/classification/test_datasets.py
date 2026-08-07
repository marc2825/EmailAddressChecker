"""The dataset loader fails closed on anything it cannot trust."""

import pytest

from dataset_fixtures import (
    METADATA_BLOCK,
    domain_dataset_text,
    override_dataset_text,
    provider_dataset_text,
    role_dataset_text,
)
from emailcheck.classification.datasets import (
    MAX_DATASET_ENTRIES,
    REQUIRED_METADATA_FIELDS,
    DatasetError,
    load_domain_dataset,
    load_override_dataset,
    load_provider_dataset,
    load_role_dataset,
    normalize_dataset_domain,
)
from emailcheck.domain.passive import ProviderFamily


def disposable(*domains: str, version: str = "test-1") -> str:
    return domain_dataset_text("disposable_domains", *domains, version=version)


# --- normalization matches the address layer -------------------------------


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  example.com  ", "example.com"),
        ("example.com.", "example.com"),
        ("Example.Com.", "example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("MÜNCHEN.de", "xn--mnchen-3ya.de"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
    ],
)
def test_entries_normalize_the_way_addresses_do(entry: str, expected: str) -> None:
    assert normalize_dataset_domain(entry) == expected


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "   ",
        ".",
        "not a host",
        "ex_ample.com",
        "-example.com",
        "example..com",
        "192.0.2.1",
        "10.0.0.1",
        "[192.0.2.1]",
        "😀.example",
    ],
)
def test_unusable_entries_are_rejected(entry: str) -> None:
    with pytest.raises(DatasetError):
        normalize_dataset_domain(entry)


# --- structural validation -------------------------------------------------


def test_a_valid_domain_dataset_loads() -> None:
    dataset = load_domain_dataset(disposable("a.example", "b.example"), kind="disposable_domains")
    assert dataset.size == 2
    assert dataset.contains("a.example")
    assert dataset.metadata.version == "test-1"


def test_an_unknown_schema_version_is_refused() -> None:
    text = disposable("a.example").replace("schema_version = 1", "schema_version = 99")
    with pytest.raises(DatasetError, match="schema version"):
        load_domain_dataset(text, kind="disposable_domains")


def test_a_missing_schema_version_is_refused() -> None:
    text = disposable("a.example").replace("schema_version = 1\n", "")
    with pytest.raises(DatasetError, match="schema version"):
        load_domain_dataset(text, kind="disposable_domains")


def test_the_wrong_kind_of_dataset_is_refused() -> None:
    with pytest.raises(DatasetError, match="expected"):
        load_domain_dataset(disposable("a.example"), kind="free_mail_domains")


def test_invalid_toml_is_refused() -> None:
    with pytest.raises(DatasetError, match="valid TOML"):
        load_domain_dataset("schema_version = = 1", kind="disposable_domains")


@pytest.mark.parametrize("field", REQUIRED_METADATA_FIELDS)
def test_every_metadata_field_is_required(field: str) -> None:
    text = disposable("a.example")
    lines = [line for line in text.splitlines() if not line.startswith(f"{field} =")]
    with pytest.raises(DatasetError, match="missing required fields"):
        load_domain_dataset("\n".join(lines), kind="disposable_domains")


def test_an_unknown_metadata_field_is_refused() -> None:
    text = disposable("a.example").replace(
        'maintainer = "tests"', 'maintainer = "tests"\nconfidence = "very high"'
    )
    with pytest.raises(DatasetError, match="unknown fields"):
        load_domain_dataset(text, kind="disposable_domains")


def test_a_duplicate_entry_is_refused() -> None:
    with pytest.raises(DatasetError, match="duplicate"):
        load_domain_dataset(disposable("a.example", "A.Example."), kind="disposable_domains")


def test_entries_differing_only_by_unicode_normalization_are_duplicates() -> None:
    """Composed and decomposed forms encode to the same domain."""
    text = domain_dataset_text("disposable_domains", "münchen.de", "münchen.de")
    with pytest.raises(DatasetError, match="duplicate"):
        load_domain_dataset(text, kind="disposable_domains")


def test_a_non_string_entry_is_refused() -> None:
    text = f'schema_version = 1\nkind = "disposable_domains"\ndomains = [1, 2]\n{METADATA_BLOCK}'
    with pytest.raises(DatasetError, match="must be a string"):
        load_domain_dataset(text, kind="disposable_domains")


def test_a_non_list_entries_field_is_refused() -> None:
    text = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = "a.example"\n{METADATA_BLOCK}'
    )
    with pytest.raises(DatasetError, match="must be a list"):
        load_domain_dataset(text, kind="disposable_domains")


def test_an_oversized_dataset_is_refused() -> None:
    entries = ",\n".join(f'"host{index}.example"' for index in range(MAX_DATASET_ENTRIES + 1))
    text = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = [{entries}]\n{METADATA_BLOCK}'
    )
    with pytest.raises(DatasetError, match="more entries"):
        load_domain_dataset(text, kind="disposable_domains")


# --- role dataset ----------------------------------------------------------


def test_a_role_dataset_lower_cases_its_entries() -> None:
    dataset = load_role_dataset(role_dataset_text("Support", "INFO"))
    assert dataset.contains("support")
    assert dataset.contains("info")


@pytest.mark.parametrize("entry", ["", "   ", "sup port", "héllo", "user\r\n"])
def test_a_role_entry_must_be_a_usable_local_part(entry: str) -> None:
    with pytest.raises(DatasetError):
        load_role_dataset(role_dataset_text(entry))


def test_a_duplicate_role_entry_is_refused() -> None:
    with pytest.raises(DatasetError, match="duplicate"):
        load_role_dataset(role_dataset_text("support", "SUPPORT"))


# --- provider dataset ------------------------------------------------------


def test_a_provider_dataset_loads_typed_patterns() -> None:
    dataset = load_provider_dataset(provider_dataset_text(("google", "mx.provider-a.example")))
    assert dataset.size == 1
    assert dataset.patterns[0].family is ProviderFamily.GOOGLE


def test_a_wildcard_suffix_is_refused() -> None:
    with pytest.raises(DatasetError, match=r"[Ww]ildcard"):
        load_provider_dataset(provider_dataset_text(("google", "*.provider-a.example")))


def test_an_unknown_provider_family_is_refused() -> None:
    with pytest.raises(DatasetError, match="unknown provider family"):
        load_provider_dataset(provider_dataset_text(("acme", "mx.provider-a.example")))


@pytest.mark.parametrize("family", ["unknown", "other"])
def test_a_pattern_cannot_map_to_an_unresolved_family(family: str) -> None:
    with pytest.raises(DatasetError, match="cannot map"):
        load_provider_dataset(provider_dataset_text((family, "mx.provider-a.example")))


def test_a_conflicting_provider_mapping_is_refused() -> None:
    text = provider_dataset_text(
        ("google", "mx.provider-a.example"), ("microsoft", "mx.provider-a.example")
    )
    with pytest.raises(DatasetError, match="conflicting"):
        load_provider_dataset(text)


def test_a_duplicate_provider_suffix_is_refused() -> None:
    text = provider_dataset_text(
        ("google", "mx.provider-a.example"), ("google", "MX.Provider-A.Example.")
    )
    with pytest.raises(DatasetError, match="duplicate"):
        load_provider_dataset(text)


def test_a_provider_row_with_unknown_columns_is_refused() -> None:
    text = provider_dataset_text(("google", "mx.provider-a.example")).replace(
        'evidence = "fixture"', 'evidence = "fixture"\npriority = 1'
    )
    with pytest.raises(DatasetError, match="unknown columns"):
        load_provider_dataset(text)


def test_a_provider_row_missing_a_column_is_refused() -> None:
    text = f"""
schema_version = 1
kind = "provider_mx_patterns"
[[patterns]]
family = "google"
evidence = "fixture"
{METADATA_BLOCK}
"""
    with pytest.raises(DatasetError, match="missing columns"):
        load_provider_dataset(text)


# --- overrides -------------------------------------------------------------


def test_overrides_load_with_their_reasons() -> None:
    dataset = load_override_dataset(
        override_dataset_text(
            not_disposable=(("wrongly-listed.example", "reported 2026-08-07, real company"),),
            disposable=(("missed.example", "seen offering throwaway mailboxes"),),
        )
    )
    assert dataset.override_for("wrongly-listed.example") == (
        False,
        "reported 2026-08-07, real company",
    )
    assert dataset.override_for("missed.example")[0] is True  # type: ignore[index]
    assert dataset.override_for("unlisted.example") is None


def test_a_domain_cannot_be_corrected_in_both_directions() -> None:
    text = override_dataset_text(
        not_disposable=(("both.example", "not a throwaway service"),),
        disposable=(("both.example", "is a throwaway service"),),
    )
    with pytest.raises(DatasetError, match="both directions"):
        load_override_dataset(text)


def test_an_override_must_record_why_it_exists() -> None:
    with pytest.raises(DatasetError, match="why it exists"):
        load_override_dataset(override_dataset_text(not_disposable=(("x.example", "   "),)))


def test_a_duplicate_override_is_refused() -> None:
    text = override_dataset_text(
        not_disposable=(("dup.example", "first"), ("DUP.Example.", "second")),
    )
    with pytest.raises(DatasetError, match="duplicate override"):
        load_override_dataset(text)
