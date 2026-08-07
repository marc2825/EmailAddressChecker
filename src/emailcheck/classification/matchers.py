"""The three passive matchers, all pure functions over datasets.

Each one answers a narrow question and returns the dataset version that answered
it. None of them looks at the others' results, because a role account on a
free-mail domain is two independent facts and collapsing them loses both.
"""

from __future__ import annotations

from emailcheck.classification.datasets import (
    DomainDataset,
    LocalPartDataset,
    OverrideDataset,
    ProviderPatternDataset,
)
from emailcheck.domain.address import LocalPart
from emailcheck.domain.dns import HostName
from emailcheck.domain.passive import (
    DomainListMatch,
    ProviderFamily,
    ProviderInference,
    ProviderInferenceReason,
    RoleMatch,
)

#: Separates a local part from its tag. Everything from the first one on is a
#: routing hint the receiving server strips, so it is dropped for comparison.
TAG_SEPARATOR = "+"


def role_comparison_form(local_part: LocalPart) -> str:
    """Return the text a role lookup compares, without touching the value.

    Phase 1 promises the local part is never rewritten, so this derives a
    throwaway comparison form instead: lower-cased, and with a `+tag` removed
    because `support+billing` is the `support` mailbox.

    Dots are *not* removed. `info.desk` is not `infodesk`, and only the
    receiving server knows whether it is the same mailbox.
    """
    text = local_part.value
    tag_index = text.find(TAG_SEPARATOR)
    if tag_index >= 0:
        text = text[:tag_index]
    return text.lower()


def match_role(local_part: LocalPart, dataset: LocalPartDataset) -> RoleMatch | None:
    """Return the role entry this local part is, or None.

    The comparison is exact. A substring rule would classify `mysupport` and
    every personal mailbox containing a role word, and `docs/data-sources.md`
    warns against exactly that. A compound such as `support-team` is a role only
    if the dataset lists it.
    """
    comparison = role_comparison_form(local_part)
    if not comparison:
        return None
    name = dataset.canonical(comparison)
    if name is None:
        return None
    return RoleMatch(name=name, dataset_version=dataset.metadata.version)


def match_domain_list(
    domain: HostName,
    dataset: DomainDataset,
    overrides: OverrideDataset | None = None,
) -> DomainListMatch:
    """Decide whether a domain is on one list, honoring local overrides.

    Precedence is fixed: a local override always wins over the dataset. That is
    how a false positive in a vendored list is corrected without editing the
    vendored file or shipping a code change.

    An override changes list membership and nothing else: what comes back is a
    `DomainListMatch`, which has no status and no verdict to change.
    """
    ascii_domain = domain.value
    version = dataset.metadata.version
    if overrides is not None:
        decision = overrides.override_for(ascii_domain)
        if decision is not None:
            matched, reason = decision
            return DomainListMatch(
                matched=matched,
                dataset_version=version,
                overridden=True,
                override_reason=reason,
            )
    return DomainListMatch(matched=dataset.contains(ascii_domain), dataset_version=version)


def infer_provider_family(
    hosts: tuple[HostName, ...], dataset: ProviderPatternDataset
) -> ProviderInference:
    """Infer who hosts a domain's mail from its MX host names.

    Matching is set-based, so the order MX records arrive in cannot change the
    answer. Two different families among the hosts resolve to `unknown`: an
    ambiguous answer is worth less than an honest absence of one.
    """
    version = dataset.metadata.version
    if not dataset.patterns:
        return ProviderInference(
            family=ProviderFamily.UNKNOWN,
            reason=ProviderInferenceReason.NO_DATASET,
            dataset_version=version,
        )
    if not hosts:
        return ProviderInference(
            family=ProviderFamily.UNKNOWN,
            reason=ProviderInferenceReason.NO_MX_HOSTS,
            dataset_version=version,
        )

    matches: dict[ProviderFamily, str] = {}
    for host in hosts:
        for pattern in dataset.patterns:
            if pattern.matches(host.value):
                # The longest matching suffix wins for one family, so a more
                # specific rule reports itself rather than a broader sibling.
                current = matches.get(pattern.family)
                if current is None or len(pattern.suffix) > len(current):
                    matches[pattern.family] = pattern.suffix

    if not matches:
        return ProviderInference(
            family=ProviderFamily.OTHER,
            reason=ProviderInferenceReason.NO_MATCH,
            dataset_version=version,
        )
    if len(matches) > 1:
        return ProviderInference(
            family=ProviderFamily.UNKNOWN,
            reason=ProviderInferenceReason.AMBIGUOUS,
            dataset_version=version,
        )
    family, suffix = next(iter(matches.items()))
    return ProviderInference(
        family=family,
        reason=ProviderInferenceReason.MATCHED,
        dataset_version=version,
        matched_suffix=suffix,
    )
