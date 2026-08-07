"""The dataset document schema is closed, and every typo lands on an error.

A dataset file is remote-authored data that decides what this project publishes
about somebody's domain. Three of the files this repository ships are
legitimately empty, so a mistake that produces an empty dataset is the dangerous
one: it looks exactly like the intended state. These tests fix the two ways a
typo can be caught -- a missing required array, or an unknown field -- so that
neither can be silently absorbed.
"""

import pytest

from dataset_fixtures import METADATA_BLOCK, domain_dataset_text, override_dataset_text
from emailcheck.classification.datasets import (
    MAX_METADATA_VALUE_LENGTH,
    DatasetError,
    DatasetMetadata,
    OverrideTarget,
    load_domain_dataset,
    load_override_dataset,
    load_provider_dataset,
    load_role_dataset,
)

# --- a missing entries array is an error, not an empty dataset -------------


MISSING_KEY_DOCUMENTS = {
    "disposable": (
        f'schema_version = 1\nkind = "disposable_domains"\n{METADATA_BLOCK}',
        lambda text: load_domain_dataset(text, kind="disposable_domains"),
        "domains",
    ),
    "free_mail": (
        f'schema_version = 1\nkind = "free_mail_domains"\n{METADATA_BLOCK}',
        lambda text: load_domain_dataset(text, kind="free_mail_domains"),
        "domains",
    ),
    "role": (
        f'schema_version = 1\nkind = "role_local_parts"\n{METADATA_BLOCK}',
        load_role_dataset,
        "local_parts",
    ),
    "provider": (
        f'schema_version = 1\nkind = "provider_mx_patterns"\n{METADATA_BLOCK}',
        load_provider_dataset,
        "patterns",
    ),
}


@pytest.mark.parametrize("name", sorted(MISSING_KEY_DOCUMENTS))
def test_a_missing_entries_array_is_refused(name: str) -> None:
    """Before this was enforced, every one of these loaded with size 0."""
    text, load, key = MISSING_KEY_DOCUMENTS[name]
    with pytest.raises(DatasetError, match=f"declares no '{key}' array"):
        load(text)


@pytest.mark.parametrize(
    ("kind", "typo", "correct"),
    [
        ("disposable_domains", "domians", "domains"),
        ("free_mail_domains", "domians", "domains"),
    ],
)
def test_a_misspelled_entries_key_is_refused(kind: str, typo: str, correct: str) -> None:
    text = f'schema_version = 1\nkind = "{kind}"\n{typo} = []\n{METADATA_BLOCK}'
    with pytest.raises(DatasetError) as caught:
        load_domain_dataset(text, kind=kind)
    # Either failure mode is acceptable; silence is not.
    assert typo in str(caught.value) or correct in str(caught.value)


def test_a_misspelled_role_key_is_refused() -> None:
    text = f'schema_version = 1\nkind = "role_local_parts"\nlocal_part = []\n{METADATA_BLOCK}'
    with pytest.raises(DatasetError):
        load_role_dataset(text)


def test_a_misspelled_provider_key_is_refused() -> None:
    text = f'schema_version = 1\nkind = "provider_mx_patterns"\npattern = []\n{METADATA_BLOCK}'
    with pytest.raises(DatasetError):
        load_provider_dataset(text)


def test_an_explicitly_empty_array_is_valid() -> None:
    """An empty dataset is a legitimate state and must stay expressible."""
    text = f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\n{METADATA_BLOCK}'
    dataset = load_domain_dataset(text, kind="disposable_domains")
    assert dataset.size == 0


def test_a_populated_dataset_still_loads() -> None:
    dataset = load_domain_dataset(
        domain_dataset_text("disposable_domains", "throwaway.example"),
        kind="disposable_domains",
    )
    assert dataset.size == 1


@pytest.mark.parametrize("value", ['"throwaway.example"', "42", "true", "{ a = 1 }"])
def test_an_entries_array_of_the_wrong_type_is_refused(value: str) -> None:
    text = f'schema_version = 1\nkind = "disposable_domains"\ndomains = {value}\n{METADATA_BLOCK}'
    with pytest.raises(DatasetError, match="must be a list"):
        load_domain_dataset(text, kind="disposable_domains")


def test_a_missing_array_and_an_empty_array_are_distinguishable() -> None:
    """The whole point: these two must not produce the same result."""
    empty = f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\n{METADATA_BLOCK}'
    missing = f'schema_version = 1\nkind = "disposable_domains"\n{METADATA_BLOCK}'

    assert load_domain_dataset(empty, kind="disposable_domains").size == 0
    with pytest.raises(DatasetError):
        load_domain_dataset(missing, kind="disposable_domains")


# --- unknown top-level fields ---------------------------------------------


def test_an_unknown_top_level_field_is_refused() -> None:
    text = (
        'schema_version = 1\nkind = "disposable_domains"\ndomains = []\nsurprise = "x"\n'
        f"{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="unknown top-level fields"):
        load_domain_dataset(text, kind="disposable_domains")


def test_an_unknown_top_level_table_is_refused() -> None:
    text = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\n{METADATA_BLOCK}'
        '\n[extra]\nkey = "value"\n'
    )
    with pytest.raises(DatasetError, match="unknown top-level fields"):
        load_domain_dataset(text, kind="disposable_domains")


def test_one_dataset_kind_cannot_borrow_another_kinds_array() -> None:
    """`patterns` in a domain file is a mistake, not a field to ignore."""
    text = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\npatterns = []\n'
        f"{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="unknown top-level fields"):
        load_domain_dataset(text, kind="disposable_domains")


def test_the_closed_document_schema_matches_the_closed_metadata_table() -> None:
    """Both levels fail closed; neither ignores what it does not recognize."""
    document_typo = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\nlicence = "x"\n'
        f"{METADATA_BLOCK}"
    )
    metadata_typo = (
        f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\n'
        f'{METADATA_BLOCK}\nlicence = "x"\n'
    )
    for text in (document_typo, metadata_typo):
        with pytest.raises(DatasetError, match="unknown"):
            load_domain_dataset(text, kind="disposable_domains")


# --- metadata values reach evidence, so they are validated -----------------


BASE_METADATA = {
    "name": "test",
    "source_url": "https://example.invalid/list",
    "license": "test fixture, not redistributed",
    "version": "test-1",
    "retrieved_at": "2026-08-07",
    "checksum": "sha256:fixture",
    "normalization": "trim, lower-case, IDNA",
    "update_frequency": "never; fixture",
    "maintainer": "tests",
}


def toml_quote(value: str) -> str:
    """Quote `value` as a TOML basic string, escaping what cannot be literal.

    Test sources hold escape sequences, never literal control characters, so
    the file stays greppable and an editor cannot silently drop one.
    """
    escaped = []
    for char in value:
        if char in '"\\':
            escaped.append(f"\\{char}")
        elif char == "\r":
            escaped.append("\\r")
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\t":
            escaped.append("\\t")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def metadata_with(field: str, value: str) -> str:
    """A disposable dataset whose metadata `field` carries exactly `value`."""
    values = dict(BASE_METADATA) | {field: value}
    block = "\n".join(f"{name} = {toml_quote(item)}" for name, item in values.items())
    return f'schema_version = 1\nkind = "disposable_domains"\ndomains = []\n\n[metadata]\n{block}\n'


@pytest.mark.parametrize(
    ("field", "value", "label"),
    [
        ("version", "v1\r\nX-Injected: yes", "CRLF"),
        ("version", "v1\nsecond line", "LF"),
        ("version", "v1\rsecond line", "CR"),
        ("version", "v1\x00truncated", "NUL"),
        ("source_url", "https://example.invalid/\u202elist", "bidi override"),
        ("source_url", "https://example.invalid/\u200blist", "zero width space"),
        ("name", "list\u2066nested\u2069", "bidi isolate"),
        ("license", "MIT\x1b[31m", "escape sequence"),
        ("license", "MIT\ttabbed", "tab"),
        ("normalization", "first\u2028second", "line separator"),
        ("normalization", "first\u2029second", "paragraph separator"),
        ("update_frequency", "weekly\x85next", "C1 next line"),
        ("checksum", "sha256:" + "a" * MAX_METADATA_VALUE_LENGTH, "over length"),
        ("maintainer", "x" * (MAX_METADATA_VALUE_LENGTH + 1), "over length"),
    ],
)
def test_an_unusable_metadata_value_is_refused(field: str, value: str, label: str) -> None:
    with pytest.raises(DatasetError, match=f"metadata field '{field}'"):
        load_domain_dataset(metadata_with(field, value), kind="disposable_domains")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "1.4.2"),
        ("version", "v2026.08.07-1"),
        ("version", "9f2c1e0d4b7a6f3e8c5d2a1b0e9f8c7d6a5b4c3d"),
        ("source_url", "https://example.invalid/lists/disposable.txt?ref=v1#section-2"),
        ("license", "CC-BY-SA-4.0"),
        ("license", "Apache-2.0 WITH LLVM-exception"),
        ("checksum", "sha256:9f2c1e0d4b7a6f3e8c5d2a1b0e9f8c7d6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d"),
        ("retrieved_at", "2026-08-07T12:30:00+00:00"),
        ("normalization", "trim, drop trailing dot, IDNA/UTS-46 to ASCII, lower-case"),
        ("maintainer", "project maintainers"),
        ("name", "disposable_domains"),
        ("update_frequency", "weekly, on review"),
        ("version", "x" * MAX_METADATA_VALUE_LENGTH),
    ],
)
def test_an_ordinary_metadata_value_is_accepted(field: str, value: str) -> None:
    dataset = load_domain_dataset(metadata_with(field, value), kind="disposable_domains")
    assert getattr(dataset.metadata, field) == value


def test_metadata_validation_is_a_property_of_the_value_not_of_the_loader() -> None:
    """A directly built metadata value is checked the same way a loaded one is."""
    fields = {name: "ok" for name in DatasetMetadata.__dataclass_fields__}
    fields["version"] = "v1\r\nX-Injected: yes"
    with pytest.raises(DatasetError, match="metadata field 'version'"):
        DatasetMetadata(**fields)


def test_a_dataset_error_does_not_quote_the_parser() -> None:
    """A library's wording is not this project's vocabulary."""
    with pytest.raises(DatasetError) as caught:
        load_domain_dataset("schema_version = 1\nkind = = =\n", kind="disposable_domains")
    message = str(caught.value)
    assert message == "dataset file is not valid TOML"
    assert "line" not in message
    assert "char" not in message


def test_no_dataset_error_message_can_break_a_line() -> None:
    """An error message is written to a log, so it stays on one line."""
    hostile = 'schema_version = 1\nkind = "disposable_domains"\ndomains = ["a\\r\\nb.example"]\n'
    with pytest.raises(DatasetError) as caught:
        load_domain_dataset(hostile + METADATA_BLOCK, kind="disposable_domains")
    assert "\r" not in str(caught.value)
    assert "\n" not in str(caught.value)


# --- overrides: names, target, and the rejected legacy schema --------------


def test_the_new_override_names_load() -> None:
    dataset = load_override_dataset(
        override_dataset_text(
            not_disposable=(("wrongly-listed.example", "real company, reported"),),
            disposable=(("missed.example", "observed offering throwaway mailboxes"),),
        )
    )
    assert dataset.target is OverrideTarget.DISPOSABLE
    assert dataset.override_for("wrongly-listed.example") == (False, "real company, reported")
    assert dataset.override_for("missed.example") == (
        True,
        "observed offering throwaway mailboxes",
    )


@pytest.mark.parametrize("legacy", ["allow", "deny"])
def test_the_legacy_override_schema_is_refused_by_name(legacy: str) -> None:
    """`allow` and `deny` read as a delivery decision, so they are gone."""
    text = (
        'schema_version = 1\nkind = "overrides"\ntarget = "disposable"\n'
        "not_disposable = []\ndisposable = []\n"
        f'{legacy} = [{{ domain = "x.example", reason = "legacy" }}]\n{METADATA_BLOCK}'
    )
    with pytest.raises(DatasetError, match="were renamed"):
        load_override_dataset(text)


def test_a_legacy_only_override_file_is_refused_rather_than_read_as_empty() -> None:
    text = (
        'schema_version = 1\nkind = "overrides"\ntarget = "disposable"\n'
        f"allow = []\ndeny = []\n{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="were renamed"):
        load_override_dataset(text)


def test_an_override_file_must_name_its_target() -> None:
    text = (
        'schema_version = 1\nkind = "overrides"\n'
        f"not_disposable = []\ndisposable = []\n{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="must name the classification"):
        load_override_dataset(text)


@pytest.mark.parametrize("target", ["free_mail", "role", "provider", "", "DISPOSABLE"])
def test_an_unsupported_override_target_is_refused(target: str) -> None:
    """Free-mail overrides are not implemented, so such a file must not load."""
    with pytest.raises(DatasetError, match="unsupported override target"):
        load_override_dataset(override_dataset_text(target=target))


def test_both_override_arrays_are_mandatory() -> None:
    text = (
        'schema_version = 1\nkind = "overrides"\ntarget = "disposable"\n'
        f"not_disposable = []\n{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="declares no 'disposable' array"):
        load_override_dataset(text)


def test_an_unknown_override_field_is_refused() -> None:
    text = (
        'schema_version = 1\nkind = "overrides"\ntarget = "disposable"\n'
        f"not_disposable = []\ndisposable = []\nfree_mail = []\n{METADATA_BLOCK}"
    )
    with pytest.raises(DatasetError, match="unknown top-level fields"):
        load_override_dataset(text)
