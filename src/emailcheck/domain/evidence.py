"""One layer's observation, and never a verdict.

`Evidence` is the value every producer emits and Phase 5 aggregates. It carries
its own invariants because an annotation is not a runtime check: mypy runs on
`src` only, `Any` launders a wrong value, and this type is constructed from
parameters a caller supplies rather than from values that have already validated
themselves.

`observed_at` is the field that matters most. `CONTRIBUTING.md` requires UTC
internally and timestamps serialized with an explicit offset, and a naive
datetime is not merely untidy: comparing one against an aware one raises
`TypeError`, so a single naive timestamp makes ordering a mixed set of evidence
fail at run time rather than at construction. Three of the four producers take a
`Clock`, which always answers aware UTC; the SMTP mapper takes a timestamp as a
parameter, so this is where that guarantee has to be enforced.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.risk import RiskFlag


class EvidenceLayer(StrEnum):
    INPUT = "input"
    SYNTAX = "syntax"
    DNS = "dns"
    PASSIVE_CLASSIFICATION = "passive_classification"
    SMTP = "smtp"
    ACCEPT_ALL = "accept_all"
    INTERNAL = "internal"


class EvidenceStrength(StrEnum):
    """How much weight one observation may carry.

    **`STRONG` means strong evidence, never final truth.** Phase 5 decides a
    status from the precedence in `docs/status-model.md` section 4, and no
    aggregation may read this field alone: `invalid` needs target-specific,
    non-temporary evidence with the right reason semantics, and a reason in
    `NON_TARGET_SMTP_REASONS` never supports it whatever its strength.
    """

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
    #: Risk flags this observation raises **in addition to** whatever its reason
    #: code implies. Typed, published vocabulary, and read by exactly one place.
    #:
    #: **It exists because a risk flag and a status tier are different
    #: questions, and one reason code could only answer both the same way.**
    #: `application/mail_route.py` can see an MX configuration anomaly on a route
    #: that is otherwise perfectly usable — `NULL_MX_WITH_OTHER_RECORDS` is the
    #: measured case — and `docs/requirements.md` section 4 makes
    #: `domain_configuration_anomaly` a risk flag, orthogonal to deliverability.
    #: Publishing that as `ReasonCode.MX_CONFIGURATION_ANOMALY` would have raised
    #: the flag *and* dropped the verdict to `unknown`, because that reason sits
    #: in the aggregator's tier 4 — correctly, for the route outcome that has
    #: nowhere to connect. The final system audit found the flag missing
    #: entirely; adding it through the reason would have traded a lost flag for a
    #: wrong status.
    #:
    #: So a producer states the flag directly. Nothing here decides a status: the
    #: aggregator reads this **after** the tier is chosen, and no branch that
    #: picks a tier consults it.
    risk_flags: frozenset[RiskFlag] = frozenset()
    details: Mapping[str, str | int | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.layer, EvidenceLayer):
            raise ValueError("evidence must name a published layer")
        if not isinstance(self.reason, ReasonCode):
            raise ValueError("evidence must carry a published reason code")
        if not isinstance(self.strength, EvidenceStrength):
            raise ValueError("evidence must carry a published strength")
        if not isinstance(self.observed_at, datetime):
            raise ValueError("evidence must be observed at a datetime")
        if self.observed_at.utcoffset() is None:
            # A naive timestamp cannot be compared with an aware one, so one of
            # them anywhere in a set makes ordering raise rather than answer.
            raise ValueError("evidence must be observed at a timezone-aware datetime")
        if not isinstance(self.temporary, bool):
            raise ValueError("evidence permanence must be a boolean")
        if self.source_version is not None and not isinstance(self.source_version, str):
            raise ValueError("a source version must be a string")
        if not isinstance(self.risk_flags, frozenset):
            raise ValueError("evidence risk flags must be a frozenset")
        for flag in self.risk_flags:
            if not isinstance(flag, RiskFlag):
                raise ValueError("evidence must carry published risk flags")
        for key, value in self.details.items():
            if not isinstance(key, str):
                raise ValueError("every evidence detail key must be a string")
            if value is not None and not isinstance(value, str | int | bool):
                # `docs/status-model.md` section 7.5 bounds what a detail may be,
                # because these values reach a public response. A float, a
                # container, or an object would also break the stable ordering
                # and equality two equal reports are required to produce.
                raise ValueError(f"the evidence detail {key!r} is not a safe scalar")
