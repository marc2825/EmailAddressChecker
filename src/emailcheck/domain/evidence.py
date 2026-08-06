from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from emailcheck.domain.reasons import ReasonCode


class EvidenceLayer(StrEnum):
    INPUT = "input"
    SYNTAX = "syntax"
    DNS = "dns"
    PASSIVE_CLASSIFICATION = "passive_classification"
    SMTP = "smtp"
    ACCEPT_ALL = "accept_all"
    INTERNAL = "internal"


class EvidenceStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


@dataclass(frozen=True, slots=True)
class Evidence:
    layer: EvidenceLayer
    reason: ReasonCode
    strength: EvidenceStrength
    observed_at: datetime
    temporary: bool = False
    source_version: str | None = None
    details: Mapping[str, str | int | bool | None] = field(default_factory=dict)
