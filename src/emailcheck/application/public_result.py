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
from typing import Final

from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.verdict import Verdict
from emailcheck.ports.public_contract import (
    _PUBLIC_CHECK_KEY,
    PublicCheck,
    PublicResult,
    public_result_from_json_object,
)

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


#: Re-exported so every existing import keeps working. The contract itself lives
#: in `ports/public_contract.py`; this module owns the projection onto it.
__all__ = [
    "PUBLIC_LAYERS",
    "PublicCheck",
    "PublicResult",
    "public_result",
    "public_result_from_json_object",
]
