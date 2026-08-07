"""What can be said about an address without contacting anyone.

Every value here is risk metadata or provider metadata. None of it is evidence
that a mailbox exists or does not exist, and none of it may set a deliverability
status. ADR 0002 fixes that separation and ADR 0007 explains why each signal is
kept apart from the others rather than summed into a score.

A disposable address may be perfectly deliverable. A role address may be
invalid. A free-mail domain is neither. The four signals are independent, so
they are stored independently, each with the dataset version that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from emailcheck.domain.address import local_part_issue
from emailcheck.domain.dns import HostName
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import RiskFlag

#: A role identifier is a short published word such as `support`. The bound is
#: the local-part limit, not because a long role is meaningful, but so that no
#: submitted text can reach evidence by being stored here.
ROLE_NAME_MAX_LENGTH: Final = 64


class PassiveContractError(ValueError):
    """A passive value was built from data that violates its invariants.

    This is a programmer error. Remote or submitted data that cannot be used is
    reported as an absent match, never stored as-is.
    """


@dataclass(frozen=True, slots=True)
class RoleName:
    """A canonical role identifier taken from the role dataset.

    This exists so the submitted local part cannot be stored by accident. It is
    the comparison form of a dataset entry: lower-case ASCII, no `+tag`, no
    `@`, and no control character, which is exactly the shape every entry the
    loader accepted has. `Support+Billing.SECRET` cannot be one of these, so it
    cannot reach `details`, `repr()`, or evidence through a role match.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise PassiveContractError("a role name cannot be empty")
        if len(self.value) > ROLE_NAME_MAX_LENGTH:
            raise PassiveContractError("a role name is longer than the configured limit")
        if self.value != self.value.lower():
            raise PassiveContractError("a role name is stored in its lower-case comparison form")
        if "+" in self.value:
            raise PassiveContractError("a role name carries no tag; the tag is dropped before it")
        issue = local_part_issue(self.value)
        if issue is not None:
            raise PassiveContractError(f"unusable role name: {issue.value}")


class ProviderFamily(StrEnum):
    """Who appears to host a domain's mail.

    Metadata only. A later Phase may use it to pick a reply parser; it may never
    decide a status. `UNKNOWN` means the question could not be answered, and
    `OTHER` means it was answered and the host matched nothing published.
    """

    GOOGLE = "google"
    MICROSOFT = "microsoft"
    YAHOO = "yahoo"
    PROTON = "proton"
    ZOHO = "zoho"
    FASTMAIL = "fastmail"
    OTHER = "other"
    UNKNOWN = "unknown"


class ProviderInferenceReason(StrEnum):
    """Why the provider family came out the way it did."""

    MATCHED = "matched"
    NO_MATCH = "no_match"
    NO_MX_HOSTS = "no_mx_hosts"
    AMBIGUOUS = "ambiguous"
    NO_DATASET = "no_dataset"


@dataclass(frozen=True, slots=True)
class RoleMatch:
    """A local part that matched the role dataset.

    `name` is the dataset entry that matched, drawn from a small published
    vocabulary. Its type is what enforces that: only a canonical `RoleName` can
    be stored, so for a tagged address such as `support+billing` only `support`
    is recorded, and nothing here can ever carry a complete address.
    """

    name: RoleName
    dataset_version: str


@dataclass(frozen=True, slots=True)
class DomainListMatch:
    """Whether a domain is on one list, and whether an override decided it."""

    matched: bool
    dataset_version: str
    overridden: bool = False
    override_reason: str | None = None

    def __post_init__(self) -> None:
        if self.override_reason is not None and not self.overridden:
            raise ValueError("an override reason requires an override")


@dataclass(frozen=True, slots=True)
class ProviderInference:
    """The provider family and how it was reached."""

    family: ProviderFamily
    reason: ProviderInferenceReason
    dataset_version: str
    matched_suffix: str | None = None

    def __post_init__(self) -> None:
        if self.family in {ProviderFamily.UNKNOWN, ProviderFamily.OTHER}:
            if self.matched_suffix is not None:
                raise ValueError("an unresolved provider cannot name a matched suffix")
        elif self.reason is not ProviderInferenceReason.MATCHED:
            raise ValueError("a named provider must have been matched")


@dataclass(frozen=True, slots=True)
class PassiveClassification:
    """Everything the passive layer observed about one address.

    Each signal keeps its own dataset version, so a result can be explained and
    reproduced against the snapshot that produced it.

    `domain` is a validated `HostName`, not text. A complete address, a domain
    carrying CR, LF, or NUL, and a malformed host name are all unrepresentable,
    so whatever reaches `details` is a host name and nothing else.
    """

    domain: HostName
    role: RoleMatch | None = None
    disposable: DomainListMatch | None = None
    free_mail: DomainListMatch | None = None
    provider: ProviderInference | None = None
    route_anomaly: bool = False

    @property
    def is_role_account(self) -> bool:
        return self.role is not None

    @property
    def is_disposable(self) -> bool:
        return self.disposable is not None and self.disposable.matched

    @property
    def is_free_mail(self) -> bool:
        return self.free_mail is not None and self.free_mail.matched

    @property
    def provider_family(self) -> ProviderFamily:
        return self.provider.family if self.provider else ProviderFamily.UNKNOWN

    @property
    def risk_flags(self) -> frozenset[RiskFlag]:
        """The flags this classification raises.

        Provider family is deliberately absent: it is metadata, not risk, and
        `provider_opaque` describes observed SMTP behavior that this Phase
        cannot see.
        """
        flags: set[RiskFlag] = set()
        if self.is_disposable:
            flags.add(RiskFlag.DISPOSABLE)
        if self.is_role_account:
            flags.add(RiskFlag.ROLE_ACCOUNT)
        if self.is_free_mail:
            flags.add(RiskFlag.FREE_MAIL)
        if self.route_anomaly:
            flags.add(RiskFlag.DOMAIN_CONFIGURATION_ANOMALY)
        return frozenset(flags)

    @property
    def reason_codes(self) -> tuple[ReasonCode, ...]:
        """Risk-only reason codes, in a stable order.

        None of these may produce a hard-invalid or an optimistic status. They
        record what a list said, nothing more.
        """
        codes: list[ReasonCode] = []
        if self.is_disposable:
            codes.append(ReasonCode.DISPOSABLE_DOMAIN)
        if self.is_role_account:
            codes.append(ReasonCode.ROLE_ACCOUNT)
        if self.is_free_mail:
            codes.append(ReasonCode.FREE_MAIL)
        return tuple(codes)

    @property
    def dataset_versions(self) -> dict[str, str]:
        """The snapshot behind each answer, for reproducibility."""
        versions: dict[str, str] = {}
        if self.role is not None:
            versions["role"] = self.role.dataset_version
        if self.disposable is not None:
            versions["disposable"] = self.disposable.dataset_version
        if self.free_mail is not None:
            versions["free_mail"] = self.free_mail.dataset_version
        if self.provider is not None:
            versions["provider"] = self.provider.dataset_version
        return versions

    @property
    def details(self) -> dict[str, str | int | bool | None]:
        """A safe structured summary for evidence.

        It names the domain, the matched role category, and the provider family.
        It never carries the submitted local part or a complete address.
        """
        return {
            "domain": self.domain.value,
            "disposable": self.is_disposable,
            "role_account": self.is_role_account,
            "role_name": self.role.name.value if self.role else None,
            "free_mail": self.is_free_mail,
            "provider_family": self.provider_family.value,
            "risk_flag_count": len(self.risk_flags),
        }


#: Risk flags that this layer may raise. Anything outside this set comes from
#: another layer, so a passive result can never widen the risk vocabulary.
PASSIVE_RISK_FLAGS: frozenset[RiskFlag] = frozenset(
    {
        RiskFlag.DISPOSABLE,
        RiskFlag.ROLE_ACCOUNT,
        RiskFlag.FREE_MAIL,
        RiskFlag.DOMAIN_CONFIGURATION_ANOMALY,
    }
)

#: Reason codes this layer may emit. All three are risk-only in
#: `docs/status-model.md`; none is hard-invalid evidence.
PASSIVE_REASON_CODES: frozenset[ReasonCode] = frozenset(
    {
        ReasonCode.DISPOSABLE_DOMAIN,
        ReasonCode.ROLE_ACCOUNT,
        ReasonCode.FREE_MAIL,
    }
)


@dataclass(frozen=True, slots=True)
class ProviderPattern:
    """One rule mapping an MX host suffix to a provider family."""

    family: ProviderFamily
    suffix: str
    evidence: str = field(default="")

    def __post_init__(self) -> None:
        if self.family in {ProviderFamily.UNKNOWN, ProviderFamily.OTHER}:
            raise ValueError("a pattern cannot map to an unresolved family")
        if not self.suffix:
            raise ValueError("a pattern needs a suffix")

    def matches(self, host: str) -> bool:
        """Match only on a label boundary.

        `google.com.evil.example` and `notgoogle.com` must not match
        `google.com`, so the host either equals the suffix or ends with a dot
        followed by it.
        """
        return host == self.suffix or host.endswith(f".{self.suffix}")
