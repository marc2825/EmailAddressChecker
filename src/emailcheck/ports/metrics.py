"""Counting what happened, without recording who it happened to.

`docs/threat-model.md` lists what must be measured and states the constraint
first: **metrics must not include local parts**. This port is built so that they
structurally cannot.

**A label is a closed enumeration, not a string.** The dangerous property of a
metrics API is unbounded cardinality: a label taking arbitrary text becomes one
time series per distinct value, which is a memory leak whose trigger is a
request and — when the value comes from user input — a copy of that input in the
monitoring system, where none of this project's redaction applies. So
`MetricName` is an enum, `MetricLabels` is a closed dataclass, and every subject
must be a value one of this project's published enumerations already declares.
There is no method that takes a free string.

That is stricter than the prompt's own wording. "Target-domain and MX rates
subject to cardinality controls" would permit a bounded domain label, but a
bound enforced by a *cap* starts discarding values exactly when an attack makes
them interesting. `docs/requirements.md` section 16 already gives domain-level
analytics a home — the operator event stream, which is redacted and retained
under a policy rather than held forever as a label. ADR 0016 records the choice
and its cost: per-domain rates are queried from events, not scraped.

**A metric never carries a job identifier, a principal, an API key, an
idempotency key, a source address, or a target.** Not as a label and not as a
name, and an inspection test refuses each by name.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from emailcheck.domain.abuse import BudgetLayer
from emailcheck.domain.admin import ControlDecision
from emailcheck.domain.job import JobState
from emailcheck.domain.passive import ProviderFamily
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_protocol import DialogueStage
from emailcheck.domain.verdict import Status


class MetricName(StrEnum):
    """Everything this project counts. `docs/threat-model.md`'s list."""

    #: Jobs, by state.
    JOB_STATE = "job_state"
    #: Verdicts, by status.
    VERDICT_STATUS = "verdict_status"
    #: Verdicts, by primary reason.
    VERDICT_REASON = "verdict_reason"
    #: Verdicts that resolved to `unknown`, by provider family.
    PROVIDER_UNKNOWN = "provider_unknown"
    #: One SMTP stage's duration, in milliseconds.
    SMTP_STAGE_LATENCY = "smtp_stage_latency"
    #: Policy blocks, timeouts, and tarpits, by reason.
    SMTP_OUTCOME = "smtp_outcome"
    #: Cache lookups, hit or miss.
    CACHE_LOOKUP = "cache_lookup"
    #: Budget decisions, by layer and outcome.
    RATE_LIMIT_DECISION = "rate_limit_decision"
    #: Administrative refusals, by which control refused.
    ADMIN_REFUSAL = "admin_refusal"
    #: Retention runs that failed. `docs/operations.md` section 3 alerts on it.
    DELETION_FAILURE = "deletion_failure"
    #: Records a retention run removed.
    DELETION_REMOVED = "deletion_removed"
    #: Whether active probing is enabled.
    KILL_SWITCH_STATE = "kill_switch_state"
    #: Sequence indicators raised, by indicator.
    ABUSE_INDICATOR = "abuse_indicator"


class Outcome(StrEnum):
    """The bounded second label most measurements carry."""

    PERMITTED = "permitted"
    REFUSED = "refused"
    HIT = "hit"
    MISS = "miss"
    ENABLED = "enabled"
    DISABLED = "disabled"
    FAILED = "failed"


def _permitted_subjects() -> frozenset[str]:
    """Every value a metric subject may take.

    Gathered from the published enumerations rather than written out, so a
    status or a job state added later is usable without editing this file — and
    so anything that is *not* one of them never is.
    """
    members: set[str] = set()
    for enumeration in (
        JobState,
        Status,
        ReasonCode,
        BudgetLayer,
        ControlDecision,
        ProviderFamily,
        DialogueStage,
    ):
        members.update(member.value for member in enumeration)
    return frozenset(members)


#: The cardinality bound, expressed as a set of permitted *values* rather than
#: as a cap on their number. A label cannot become high-cardinality by being fed
#: something new — only by somebody adding an enum member on purpose.
PERMITTED_SUBJECTS: Final[frozenset[str]] = _permitted_subjects()

#: Indicator names are published by `domain/indicators.py`, which imports
#: nothing from here. Registered separately to keep that direction.
INDICATOR_SUBJECTS: Final[frozenset[str]] = frozenset(
    {
        "numeric_sequence",
        "dictionary_pattern",
        "domain_concentration",
        "multiple_keys_one_source",
        "exploration_after_positive",
    }
)


@dataclass(frozen=True, slots=True)
class MetricLabels:
    """Every label a metric may carry, and there are no others.

    A closed dataclass rather than a mapping, so a caller cannot attach a
    domain, an address, or an identifier: there is no field that would hold one.
    """

    #: Always the `.value` of a closed enumeration this project publishes.
    subject: str | None = None
    outcome: Outcome | None = None

    def __post_init__(self) -> None:
        if self.outcome is not None and not isinstance(self.outcome, Outcome):
            raise ValueError("a metric outcome must be a published outcome")
        subject = self.subject
        if subject is None:
            return
        if not isinstance(subject, str) or not subject:
            raise ValueError("a metric subject must be non-empty text")
        if subject not in PERMITTED_SUBJECTS and subject not in INDICATOR_SUBJECTS:
            raise ValueError("a metric subject must be a published enumeration value")


class MetricsSink(Protocol):
    def increment(self, name: MetricName, *, labels: MetricLabels | None = None) -> None:
        """Add one to a counter. Must not raise."""
        ...

    def observe(
        self, name: MetricName, value: float, *, labels: MetricLabels | None = None
    ) -> None:
        """Record one measurement. Must not raise."""
        ...
