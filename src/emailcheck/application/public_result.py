"""The public shape of a result, chosen field by field.

Phase 5 stop condition 3: `Evidence.details` is not automatically a public
field. The verdict retains the whole evidence tuple for audit, so
`repr(Verdict)` reaches every detail a producer ever recorded — and "safe to
store" and "safe to return" are different decisions.

So nothing here serializes a `Verdict`. This is an **allowlist**: every field
below was chosen, and anything a later Phase adds to `Verdict` or to `Evidence`
is absent from a response until someone adds it here on purpose. A serializer
written the other way — `asdict(verdict)`, `dict(evidence.details)` — is one
`Evidence` field away from publishing a remote server's prose.

**No status is derived here.** Every value is read from the `Verdict` that
`aggregate_evidence` produced. Phase 5 stop condition 1, and an inspection test
refuses the sets a re-derivation would need.

**No number.** `docs/requirements.md` section 17 permits a probability only
after a calibration study, so `confidence` is the categorical level and nothing
else — no score, no percentage, no rank, and no numeric encoding of a level.
Phase 5 leaves the *range* of a calibrated score undefined, so a response could
not carry one meaningfully even if the study existed; ADR 0013 records that as a
reason to publish nothing rather than to guess.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import ConfidenceLevel, RiskFlag, Status, Verdict

#: Which layers may appear in a public `checks` object, and in this order.
#:
#: `internal` is deliberately absent. `docs/status-model.md` section 4.6 makes
#: `internal_error` the reason a verdict *names* so an operator is not sent to
#: look at the wrong system — but that is an operator concern, and telling a
#: caller which of our components failed is internal structure they cannot act
#: on. It reaches the operator sink instead.
PUBLIC_LAYERS: Final[tuple[EvidenceLayer, ...]] = (
    EvidenceLayer.SYNTAX,
    EvidenceLayer.DNS,
    EvidenceLayer.PASSIVE_CLASSIFICATION,
    EvidenceLayer.SMTP,
)

#: The one key a public layer summary carries.
#:
#: `Verdict.checks` also holds `reason_count` and `evidence_count`, and both are
#: internal shape: how many observations a layer made is a fact about this
#: project's attempt loop, and a caller counting SMTP attempts is reading our
#: fan-out. `docs/status-model.md` section 6 shows an internal representation,
#: and section 6 is not an API schema.
_PUBLIC_CHECK_KEY: Final = "result"


@dataclass(frozen=True, slots=True)
class PublicCheck:
    """One layer's public summary: what it concluded, and nothing else."""

    result: str


@dataclass(frozen=True, slots=True)
class PublicResult:
    """What a caller is told. Built by allowlist from a `Verdict`.

    Every value is a published enum's `.value` — a documented string — rather
    than a Python `repr`. `Status.INVALID` is an implementation detail;
    `"invalid"` is the contract `docs/requirements.md` section 3 publishes.
    """

    status: str
    confidence: str
    primary_reason: str | None
    reasons: tuple[str, ...]
    risk_flags: tuple[str, ...]
    checks: Mapping[str, PublicCheck]
    no_message_data_sent: bool
    ruleset: str

    def __post_init__(self) -> None:
        if self.status not in {member.value for member in Status}:
            raise ValueError("a public result must carry a published status value")
        if self.confidence not in {member.value for member in ConfidenceLevel}:
            raise ValueError("a public result must carry a published confidence level")
        published = {member.value for member in ReasonCode}
        if self.primary_reason is not None and self.primary_reason not in published:
            raise ValueError("a public primary reason must be a published reason code")
        for reason in self.reasons:
            if reason not in published:
                raise ValueError("every public reason must be a published reason code")
        flags = {member.value for member in RiskFlag}
        for flag in self.risk_flags:
            if flag not in flags:
                raise ValueError("every public risk flag must be a published risk flag")
        if not isinstance(self.no_message_data_sent, bool):
            raise ValueError("no_message_data_sent must be a boolean")

    def as_json_object(self) -> dict[str, object]:
        """A JSON-safe mapping. Strings, booleans, lists, and nothing else.

        No float appears anywhere in this object, which is the structural half
        of "no uncalibrated score": there is no field a number could be put in
        without changing this method.
        """
        return {
            "status": self.status,
            "confidence": self.confidence,
            "primary_reason": self.primary_reason,
            "reasons": list(self.reasons),
            "risk_flags": list(self.risk_flags),
            "checks": {
                name: {_PUBLIC_CHECK_KEY: check.result} for name, check in self.checks.items()
            },
            "no_message_data_sent": self.no_message_data_sent,
            "ruleset": self.ruleset,
        }


def public_result(verdict: Verdict) -> PublicResult:
    """Project a `Verdict` onto the public schema. Reads; never decides.

    Every field is copied from the verdict the aggregator produced. There is no
    branch on a `ReasonCode`, no membership test against a published reason set,
    and no reading of `EvidenceStrength` — an inspection test asserts all three,
    because the shortest way to re-derive a status is exactly the shortest code
    someone would write here.
    """
    return PublicResult(
        status=verdict.status.value,
        confidence=verdict.confidence.level.value,
        primary_reason=None if verdict.primary_reason is None else verdict.primary_reason.value,
        reasons=tuple(reason.value for reason in verdict.reason_codes),
        risk_flags=tuple(sorted(flag.value for flag in verdict.risk_flags)),
        checks=_public_checks(verdict),
        no_message_data_sent=verdict.no_message_data_sent,
        ruleset=verdict.ruleset,
    )


def public_result_from_json_object(payload: object) -> PublicResult:
    """Rebuild a result from a published body, refusing anything unpublished.

    Used only by `--remote`, where the body came from another instance rather
    than from this process's aggregator. The validation is `PublicResult`'s own:
    a remote server is not a trusted source of vocabulary, so a status,
    confidence level, reason, or risk flag this build does not publish is
    refused rather than displayed to a user as though this project had said it.

    This parses; it decides nothing. There is no branch here that could turn one
    published value into another.
    """
    if not isinstance(payload, dict):
        raise ValueError("a result must be an object")
    checks: dict[str, PublicCheck] = {}
    raw_checks = payload.get("checks")
    if isinstance(raw_checks, Mapping):
        for name, entry in raw_checks.items():
            if isinstance(entry, Mapping) and isinstance(entry.get(_PUBLIC_CHECK_KEY), str):
                checks[str(name)] = PublicCheck(result=str(entry[_PUBLIC_CHECK_KEY]))
    primary = payload.get("primary_reason")
    return PublicResult(
        status=_text(payload, "status"),
        confidence=_text(payload, "confidence"),
        primary_reason=None if primary is None else str(primary),
        reasons=_text_tuple(payload, "reasons"),
        risk_flags=_text_tuple(payload, "risk_flags"),
        checks=checks,
        no_message_data_sent=_safety_boolean(payload, "no_message_data_sent"),
        ruleset=_text(payload, "ruleset"),
    )


def _text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"a result needs a text {name}")
    return value


def _safety_boolean(payload: Mapping[str, object], name: str) -> bool:
    """A published safety assertion, parsed strictly. Never coerced.

    **This replaced `bool(payload.get(name, True))`, which laundered a remote
    server's silence into this project's strongest promise.** Three ways in, all
    measured by the final system audit:

    - the field **absent** became `True`, so a server that had sent message
      content and simply omitted the field was displayed as one that had not;
    - the string `"false"` became `True`, because every non-empty string is
      truthy — the single most likely shape for a hand-rolled or
      loosely-typed remote encoder to produce;
    - `0`, `[]`, and `{}` became `False`, which is the right answer reached by
      the wrong rule and would have flipped the moment the encoder changed.

    `docs/requirements.md` section 2 makes "no message content was sent" a
    promise to the user rather than a field, and a promise this project repeats
    on another instance's behalf has to have been *made* by that instance. So
    the field is **required** and must be a real JSON boolean. Absence is a
    malformed body, not a safe default: `--remote` is the one path where the
    value is not this build's own invariant, and there is no honest way to infer
    it.

    `isinstance(value, bool)` rather than a truthiness test, and the `bool`
    check comes with the ordering Python requires — `True` and `False` are the
    only two values that pass, and `1` and `0` do not, even though they are
    `int` instances that compare equal.
    """
    if name not in payload:
        raise ValueError(f"a result needs a published {name}")
    value = payload[name]
    if not isinstance(value, bool):
        raise ValueError(f"a result needs a boolean {name}")
    return value


def _text_tuple(payload: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = payload.get(name, ())
    if not isinstance(value, list | tuple):
        raise ValueError(f"a result needs a list of {name}")
    return tuple(str(item) for item in value)


def _public_checks(verdict: Verdict) -> Mapping[str, PublicCheck]:
    """The allowlisted layer summaries, in a fixed order.

    Built from `Verdict.checks` by reading one named key out of each permitted
    layer, so a key added to the internal summary — or a whole new layer — does
    not appear in a response until it is added above.
    """
    summaries: dict[str, PublicCheck] = {}
    for layer in PUBLIC_LAYERS:
        entry = verdict.checks.get(layer.value)
        if not isinstance(entry, Mapping):
            continue
        result = entry.get(_PUBLIC_CHECK_KEY)
        if isinstance(result, str):
            summaries[layer.value] = PublicCheck(result=result)
    return summaries
