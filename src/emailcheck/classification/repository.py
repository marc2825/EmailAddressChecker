"""Loading a set of passive datasets from a directory, on request.

Nothing is read at import time. A caller names a directory and gets a bundle or
an error; a program that never classifies never touches the filesystem, and a
malformed file fails the load rather than degrading a later answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from emailcheck.classification.datasets import (
    EMPTY_DOMAIN_DATASET,
    EMPTY_LOCAL_PART_DATASET,
    EMPTY_OVERRIDE_DATASET,
    EMPTY_PROVIDER_DATASET,
    DatasetError,
    DomainDataset,
    LocalPartDataset,
    OverrideDataset,
    ProviderPatternDataset,
    load_domain_dataset,
    load_override_dataset,
    load_provider_dataset,
    load_role_dataset,
    read_text,
)

DISPOSABLE_FILE: Final = "disposable_domains.toml"
FREE_MAIL_FILE: Final = "free_mail_domains.toml"
ROLE_FILE: Final = "role_local_parts.toml"
PROVIDER_FILE: Final = "provider_mx_patterns.toml"
OVERRIDE_FILE: Final = "overrides.toml"


@dataclass(frozen=True, slots=True)
class PassiveDatasets:
    """Every dataset the passive layer uses, loaded from one snapshot."""

    disposable: DomainDataset = EMPTY_DOMAIN_DATASET
    free_mail: DomainDataset = EMPTY_DOMAIN_DATASET
    roles: LocalPartDataset = EMPTY_LOCAL_PART_DATASET
    providers: ProviderPatternDataset = EMPTY_PROVIDER_DATASET
    disposable_overrides: OverrideDataset = EMPTY_OVERRIDE_DATASET

    @property
    def versions(self) -> dict[str, str]:
        return {
            "disposable": self.disposable.metadata.version,
            "free_mail": self.free_mail.metadata.version,
            "role": self.roles.metadata.version,
            "provider": self.providers.metadata.version,
            "disposable_overrides": self.disposable_overrides.metadata.version,
        }


def load_passive_datasets(directory: Path) -> PassiveDatasets:
    """Load every dataset in `directory`.

    A missing file is an error, not an empty list: a deployment that meant to
    ship a list and lost it should fail loudly rather than quietly classify
    nothing. An empty list is expressed by a file with an empty array and full
    metadata.
    """
    if not directory.is_dir():
        raise DatasetError(f"dataset directory not found: {directory}")
    return PassiveDatasets(
        disposable=load_domain_dataset(
            read_text(directory / DISPOSABLE_FILE), kind="disposable_domains"
        ),
        free_mail=load_domain_dataset(
            read_text(directory / FREE_MAIL_FILE), kind="free_mail_domains"
        ),
        roles=load_role_dataset(read_text(directory / ROLE_FILE)),
        providers=load_provider_dataset(read_text(directory / PROVIDER_FILE)),
        disposable_overrides=load_override_dataset(read_text(directory / OVERRIDE_FILE)),
    )
