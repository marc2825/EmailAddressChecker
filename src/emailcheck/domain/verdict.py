"""The final result vocabulary, and the shapes it refuses to take.

`Status`, `ConfidenceLevel`, `RiskFlag`, `Confidence`, and `Verdict` are the
published types every earlier Phase deferred to. Phase 5 is the first code that
produces a `Verdict`, and it adds runtime invariants here for the same reason
`Evidence` carries its own: mypy runs on `src` only, `Any` launders a wrong
value, and this is a value assembled from a caller's parameters.

**Two contradictions are unrepresentable rather than merely unwritten.** A
verdict of `invalid` may not name an accepted recipient as its primary reason,
and one of `likely_deliverable` may not name a rejection. `PERMITTED_PRIMARY_REASONS`
is the table, and it is deliberately permissive for the two unknown statuses:
`docs/status-model.md` section 5 says one reason code may appear under different
statuses depending on the other evidence present, and an aggregator that raised
on an odd evidence set would be worse than one that answered `unknown`.

**Risk is not status.** `risk_flags` is a separate field, and nothing in this
module lets a flag change a status. `docs/requirements.md` section 4: a
disposable address may be likely deliverable, and a role address may be invalid.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from emailcheck.domain.evidence import Evidence
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


#: The only reasons that may be the primary reason of an `invalid` verdict.
#:
#: `docs/status-model.md` section 2 lists them: invalid supported syntax,
#: NXDOMAIN, Null MX, no MX and no implicit route, and an RCPT-stage enhanced
#: code explicitly identifying the recipient as nonexistent. Nothing else is
#: target-specific, non-temporary, hard-invalid evidence, whatever its strength.
HARD_INVALID_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.INVALID_SYNTAX,
        ReasonCode.DOMAIN_NXDOMAIN,
        ReasonCode.NULL_MX,
        ReasonCode.NO_MAIL_ROUTE,
        ReasonCode.RCPT_REJECTED_ADDRESS,
    }
)

#: The only reasons that may be the primary reason of a `likely_deliverable`
#: verdict: the server answered positively about *this* recipient at the RCPT
#: stage. `252` is absent, because "I will not tell you" is not an answer.
POSITIVE_DELIVERY_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.RCPT_ACCEPTED,
        ReasonCode.RCPT_FORWARDED,
    }
)

#: Which reasons may lead each status, as a primary reason.
#:
#: Closed for the two decisive statuses and open for the two unknown ones. That
#: asymmetry is the point: `invalid` and `likely_deliverable` are the answers a
#: caller acts on, so a contradiction there must be unconstructible, while
#: `unknown` and `temporary_unknown` are what any unclassified or contradictory
#: evidence must be free to resolve to.
PERMITTED_PRIMARY_REASONS: Final[Mapping[Status, frozenset[ReasonCode]]] = {
    Status.INVALID: HARD_INVALID_REASONS,
    Status.LIKELY_DELIVERABLE: POSITIVE_DELIVERY_REASONS,
    Status.TEMPORARY_UNKNOWN: frozenset(ReasonCode),
    Status.UNKNOWN: frozenset(ReasonCode),
}


@dataclass(frozen=True, slots=True)
class Confidence:
    """How well supported the status is. Categorical, and not a probability.

    `docs/requirements.md` section 17 and `docs/status-model.md` section 3 are
    explicit: probability scores may be added only after a controlled labelled
    evaluation, and until then `calibrated` is false and `score` is null. A
    level is a category, so `medium` does not mean 0.5 of anything, and nothing
    in this project multiplies, adds, or compares two of them numerically.
    """

    level: ConfidenceLevel
    calibrated: bool = False
    score: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.level, ConfidenceLevel):
            raise ValueError("confidence must name a published level")
        if not isinstance(self.calibrated, bool):
            raise ValueError("confidence calibration must be a boolean")
        if self.score is not None and self.calibrated is False:
            # An uncalibrated score is a number a reader will treat as a
            # probability. There is no calibration study, so there is no score.
            raise ValueError("an uncalibrated confidence carries no score")
        if self.calibrated is True and self.score is None:
            # The mirror of the rule above. `calibrated` asserts that a study
            # exists; without the number it produced, the flag is a claim with
            # nothing behind it, and a reader would take the *level* as the
            # calibrated output.
            raise ValueError("a calibrated confidence must carry the score its study produced")
        if self.score is not None:
            self._check_score()

    def _check_score(self) -> None:
        """The shape of a score, and deliberately not its range.

        `docs/requirements.md` section 17 permits a score only after a
        controlled labelled evaluation, and **no document defines what range it
        would live in**. Guessing `0..1` here would be inventing the calibrated
        semantics the study is supposed to establish, so this checks only what is
        true of a number under every possible reading: it is a real, finite
        number, and it is not a boolean.

        That is the same shape check `TransportTimeouts` makes for the same
        reason — a bound nobody could reach is not a bound, and `True` recorded
        as `1.0` is a value nobody wrote. `plans/phase-05-aggregation.md` carries
        the range as a pre-calibration stop condition.
        """
        if isinstance(self.score, bool) or not isinstance(self.score, int | float):
            raise ValueError("a confidence score must be a real number")
        if self.score != self.score or self.score in (float("inf"), float("-inf")):
            raise ValueError("a confidence score must be finite")


@dataclass(frozen=True, slots=True)
class Verdict:
    """A deterministic aggregation of evidence.

    `primary_reason` is `None` only when there is no evidence at all — there is
    no published reason code meaning "nothing was observed", and inventing one
    would be new API vocabulary for the absence of an observation.
    `reason_codes` holds every distinct reason, primary first, so a caller that
    reads only the primary reason loses ordering and not information.

    `evidence` keeps the input tuple in the order it arrived. Aggregation reads
    it and changes nothing: the decision is order-independent, the retained
    record is not, and keeping the original is what lets an audit re-run the
    rules against exactly what they saw.
    """

    status: Status
    confidence: Confidence
    primary_reason: ReasonCode | None
    reason_codes: Sequence[ReasonCode] = ()
    risk_flags: frozenset[RiskFlag] = field(default_factory=frozenset)
    checks: Mapping[str, object] = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()
    ruleset: str = "unimplemented"
    no_message_data_sent: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.status, Status):
            raise ValueError("a verdict must name a published status")
        if not isinstance(self.confidence, Confidence):
            raise ValueError("a verdict must carry a Confidence")
        if not isinstance(self.reason_codes, tuple):
            # A tuple rather than any sequence: a verdict is immutable, and a
            # caller holding a list could still change what the verdict reports.
            raise ValueError("a verdict's reason codes must be a tuple")
        for reason in self.reason_codes:
            if not isinstance(reason, ReasonCode):
                raise ValueError("every verdict reason must be a published reason code")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("a verdict may not repeat a reason code")
        if not isinstance(self.risk_flags, frozenset):
            raise ValueError("a verdict's risk flags must be a frozenset")
        for flag in self.risk_flags:
            if not isinstance(flag, RiskFlag):
                raise ValueError("every verdict risk flag must be a published risk flag")
        if not isinstance(self.evidence, tuple):
            raise ValueError("a verdict's evidence must be a tuple")
        for item in self.evidence:
            if not isinstance(item, Evidence):
                raise ValueError("a verdict may only retain Evidence")
        if not isinstance(self.no_message_data_sent, bool):
            raise ValueError("no_message_data_sent must be a boolean")
        if not isinstance(self.ruleset, str) or not self.ruleset:
            # `ruleset` records which rules decided, and a cached or stored
            # verdict is matched against it. A non-string, or an empty one, is a
            # provenance record that identifies nothing.
            raise ValueError("a verdict's ruleset must be a non-empty string")
        for key in self.checks:
            # Only the keys. `docs/status-model.md` section 6 shows a layer
            # summary carrying a list of MX hosts, so closing the *values* to
            # scalars here would forbid the shape that document publishes. What
            # a public response may carry is Phase 6's schema to choose
            # explicitly, and `plans/phase-05-aggregation.md` carries that as a
            # stop condition rather than as a guess made here.
            if not isinstance(key, str):
                raise ValueError("every verdict check summary must be keyed by a string")
        self._check_primary_reason()

    def _check_primary_reason(self) -> None:
        """The primary reason must exist, be reported, lead, and suit the status."""
        if self.primary_reason is None:
            if self.reason_codes:
                raise ValueError("a verdict with reasons must name a primary one")
            return
        if not isinstance(self.primary_reason, ReasonCode):
            raise ValueError("a verdict's primary reason must be a published reason code")
        if self.primary_reason not in self.reason_codes:
            # Otherwise the primary reason is a claim no listed evidence made.
            raise ValueError("a verdict's primary reason must appear in its reason codes")
        if self.reason_codes[0] is not self.primary_reason:
            # **The documented ordering, enforced rather than described.** This
            # type's own docstring says `reason_codes` is "primary first", and
            # `docs/status-model.md` section 4.5 says a caller reading only the
            # primary reason loses ordering rather than information — both are
            # false the moment some other reason leads the list.
            #
            # It is here rather than only in the aggregator because the
            # independent review found the two orderings computed separately:
            # ranking `reason_codes` by the enum's declaration order instead of
            # by `REASON_PRIORITY` left `primary_reason` correct, put a different
            # reason first, and broke no test. A value type that refuses the
            # inconsistent shape catches that however the list was assembled,
            # including by a Phase 6 that builds a result some other way.
            raise ValueError("a verdict's reason codes must lead with the primary reason")
        if self.primary_reason not in PERMITTED_PRIMARY_REASONS[self.status]:
            raise ValueError(
                f"{self.primary_reason.value!r} cannot be the primary reason "
                f"of a {self.status.value!r} verdict"
            )
