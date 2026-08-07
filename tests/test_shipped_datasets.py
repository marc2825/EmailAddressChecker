"""The datasets this repository actually ships.

These read files from `data/passive/`. That is not a network access and not a
runtime download: the files are in the repository, and the load is explicit.
"""

from pathlib import Path

import pytest

from emailcheck.classification.datasets import (
    DatasetError,
    load_domain_dataset,
    load_provider_dataset,
    load_role_dataset,
    read_text,
)
from emailcheck.classification.repository import load_passive_datasets

DATA_DIRECTORY = Path(__file__).resolve().parents[1] / "data" / "passive"


def test_every_shipped_dataset_loads() -> None:
    datasets = load_passive_datasets(DATA_DIRECTORY)
    assert datasets.roles.size > 0


def test_the_role_dataset_ships_populated_with_its_provenance() -> None:
    datasets = load_passive_datasets(DATA_DIRECTORY)
    metadata = datasets.roles.metadata

    assert datasets.roles.size >= 18
    assert "EmailChecker" in metadata.source_url
    assert metadata.license
    assert metadata.version
    assert metadata.maintainer


@pytest.mark.parametrize(
    "local_part",
    [
        "admin",
        "administrator",
        "billing",
        "contact",
        "help",
        "hello",
        "info",
        "marketing",
        "noc",
        "office",
        "postmaster",
        "privacy",
        "sales",
        "security",
        "support",
        "webmaster",
        "abuse",
        "hostmaster",
    ],
)
def test_the_role_dataset_covers_every_name_the_work_order_listed(local_part: str) -> None:
    datasets = load_passive_datasets(DATA_DIRECTORY)
    assert datasets.roles.contains(local_part)


@pytest.mark.parametrize("name", ["disposable", "free_mail", "providers"])
def test_the_lists_without_verified_provenance_ship_empty(name: str) -> None:
    """A licence was not invented, so these carry no entries.

    `data/passive/README.md` records why, and what must be established before
    any of them is populated. If this test starts failing, a dataset was added
    and its provenance needs reviewing.
    """
    datasets = load_passive_datasets(DATA_DIRECTORY)
    assert getattr(datasets, name).size == 0


def test_an_empty_dataset_still_declares_full_metadata() -> None:
    datasets = load_passive_datasets(DATA_DIRECTORY)
    for dataset in (datasets.disposable, datasets.free_mail, datasets.providers):
        assert dataset.metadata.name
        assert dataset.metadata.version
        assert dataset.metadata.normalization


def test_no_dataset_claims_a_licence_it_does_not_have() -> None:
    """An empty list must not assert a third-party licence."""
    datasets = load_passive_datasets(DATA_DIRECTORY)
    for dataset in (datasets.disposable, datasets.free_mail, datasets.providers):
        assert dataset.metadata.license.lower().startswith("none")
        assert dataset.metadata.source_url == "none selected"


# --- the example files are valid, so the format is demonstrable ------------


@pytest.mark.parametrize(
    ("filename", "kind"),
    [
        ("disposable_domains.toml.example", "disposable_domains"),
        ("free_mail_domains.toml.example", "free_mail_domains"),
    ],
)
def test_the_example_domain_files_parse(filename: str, kind: str) -> None:
    dataset = load_domain_dataset(read_text(DATA_DIRECTORY / filename), kind=kind)
    assert dataset.size > 0


def test_the_example_provider_file_parses() -> None:
    dataset = load_provider_dataset(read_text(DATA_DIRECTORY / "provider_mx_patterns.toml.example"))
    assert dataset.size > 0
    for pattern in dataset.patterns:
        assert pattern.evidence


def test_example_files_use_reserved_names_only() -> None:
    """Illustrative data must not name a real domain."""
    for filename in ("disposable_domains.toml.example", "free_mail_domains.toml.example"):
        dataset = load_domain_dataset(
            read_text(DATA_DIRECTORY / filename), kind=filename.split(".")[0]
        )
        for domain in dataset.domains:
            assert domain.endswith((".example", ".invalid", ".test")), domain


# --- failing closed --------------------------------------------------------


def test_a_missing_directory_is_an_error_not_an_empty_result() -> None:
    with pytest.raises(DatasetError, match="directory not found"):
        load_passive_datasets(DATA_DIRECTORY / "does-not-exist")


def test_a_missing_file_is_an_error_not_an_empty_list(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="not found"):
        load_passive_datasets(tmp_path)


def test_a_malformed_file_fails_the_load(tmp_path: Path) -> None:
    for name in (
        "disposable_domains.toml",
        "free_mail_domains.toml",
        "role_local_parts.toml",
        "provider_mx_patterns.toml",
        "overrides.toml",
    ):
        (tmp_path / name).write_text((DATA_DIRECTORY / name).read_text(), encoding="utf-8")
    (tmp_path / "role_local_parts.toml").write_text("schema_version = 1\n", encoding="utf-8")

    with pytest.raises(DatasetError):
        load_passive_datasets(tmp_path)


def test_loading_the_role_file_twice_gives_the_same_snapshot() -> None:
    first = load_role_dataset(read_text(DATA_DIRECTORY / "role_local_parts.toml"))
    second = load_role_dataset(read_text(DATA_DIRECTORY / "role_local_parts.toml"))
    assert first == second
