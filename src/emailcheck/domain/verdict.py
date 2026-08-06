from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from emailcheck.domain.reasons import ReasonCode


class Status(StrEnum):
    LIKELY_DELIVERABLE = "likely_deliverable"
    INVALID = "invalid"
    TEMPORARY_UNKNOWN = "temporary_unknown"
    UNKNOWN = "unknown"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskFlag(StrEnum):
    DISPOSABLE = "disposable"
    ROLE_ACCOUNT = "role_account"
    FREE_MAIL = "free_mail"
    ACCEPT_ALL_SUSPECTED = "accept_all_suspected"
    PROVIDER_OPAQUE = "provider_opaque"
    INTERNATIONALIZED_LOCAL_PART = "internationalized_local_part"
    DOMAIN_CONFIGURATION_ANOMALY = "domain_configuration_anomaly"


@dataclass(frozen=True, slots=True)
class Confidence:
    level: ConfidenceLevel
    calibrated: bool = False
    score: float | None = None


@dataclass(frozen=True, slots=True)
class Verdict:
    status: Status
    confidence: Confidence
    primary_reason: ReasonCode
    reason_codes: Sequence[ReasonCode]
    risk_flags: frozenset[RiskFlag] = field(default_factory=frozenset)
    checks: Mapping[str, object] = field(default_factory=dict)
    ruleset: str = "unimplemented"
    no_message_data_sent: bool = True
