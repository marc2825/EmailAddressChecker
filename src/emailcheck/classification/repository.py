"""Loading a set of passive datasets from a directory, on request.

Nothing is read at import time. A caller names a directory and gets a bundle or
an error; a program that never classifies never touches the filesystem, and a
malformed file fails the load rather than degrading a later answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
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

#: Where the shipped dataset snapshot lives, **inside the package**.
#:
#: `emailcheck/data/passive/`, reached through `importlib.resources` rather than
#: through a path relative to this file or to the working directory. The three
#: things that must not decide where a dataset comes from are the current
#: directory, the existence of a repository checkout, and how far up the tree
#: `..` happens to go — an independent review found the earlier
#: `Path(__file__).parents[3]` form working in a checkout and failing in an
#: installed package, where `data/` sat outside the wheel entirely.
#:
#: One anchor, one lookup, one set of semantics: a developer running from the
#: repository and a service running from a wheel read the same files.
DATASET_ANCHOR: Final = "emailcheck"
DATASET_RESOURCE: Final = ("data", "passive")


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

    @property
    def entry_counts(self) -> dict[str, int]:
        """How many entries each dataset actually holds, under the same keys.

        A version string cannot answer "is this dataset populated": the three
        that ship empty carry a real version (`empty-2026-08-07`) precisely so a
        deliberate emptiness is distinguishable from a failed load. Whether a
        dataset *has data* is a property of the data, and this is where a
        reporting layer reads it rather than inferring it from a name.
        """
        return {
            "disposable": len(self.disposable.domains),
            "free_mail": len(self.free_mail.domains),
            "role": len(self.roles.local_parts),
            "provider": len(self.providers.patterns),
            "disposable_overrides": (
                len(self.disposable_overrides.not_disposable)
                + len(self.disposable_overrides.disposable)
            ),
        }


def shipped_dataset_resource() -> Traversable:
    """The packaged dataset directory, as a resource rather than as a path.

    A `Traversable` and not a `Path` on purpose: an installed package may be a
    directory or a zip import, and only the resource API answers both.
    `load_shipped_datasets` materialises it for the loader.
    """
    resource = resources.files(DATASET_ANCHOR)
    for part in DATASET_RESOURCE:
        resource = resource / part
    return resource


def load_shipped_datasets() -> PassiveDatasets:
    """The snapshot packaged with this distribution.

    **The single production path to the shipped data.** The CLI, the local
    deployment, and the tests all call this, so there is no second loader with a
    checkout's semantics to drift from a wheel's.

    **A missing resource is an error**, on exactly the reasoning
    `load_passive_datasets` already applies to a missing file: a deployment that
    meant to ship a snapshot and lost it must fail loudly rather than quietly
    classify nothing. There is deliberately **no fallback to an empty
    `PassiveDatasets`** — three of these datasets are legitimately empty, so a
    silent fallback is indistinguishable from the intended state, and it would
    reinstate the defect an independent review found: the role list disappearing
    while the version report went on describing it.
    """
    with resources.as_file(shipped_dataset_resource()) as directory:
        return load_passive_datasets(Path(directory))


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
