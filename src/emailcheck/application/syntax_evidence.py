"""A Phase 1 rejection, expressed as evidence.

Phase 1 returns `AddressAccepted` or `AddressRejected`, and until now nothing
turned the second into `Evidence`. That made the syntax layer the only one of
the four with no producer, and it left the most decisive tier of the Phase 5
precedence — `invalid_syntax` is the first row of `docs/status-model.md` section
2 — reachable only from evidence a test built by hand.

Writing it here rather than in Phase 6 is the same argument gate 4C made for
writing the 4D mapping table before the 4D code: a mapping authored alongside
the API that consumes it is a mapping shaped by whatever the API made easy, and
the strength of a syntax observation is exactly the kind of decision that gets
made carelessly in passing.

**There is no evidence for an address that parsed.** No published reason code
means "the syntax was fine", and this module does not invent one. That is not an
omission — `docs/status-model.md` section 2 requires positive *delivery-stage*
evidence for `likely_deliverable`, and a reason code meaning "valid syntax"
would be the first thing a later aggregation mistook for it. Valid syntax is
visible in the absence of a syntax reason, which is all it is worth.

Pure apart from the clock, which every non-SMTP producer takes for the same
reason: `Evidence.observed_at` must be aware UTC, and `Clock` is the port that
guarantees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, assert_never

from emailcheck.domain.address import AddressRejected, RejectionKind
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.ports.clock import Clock

#: The version of these rules, recorded on the evidence they produce.
SYNTAX_EVIDENCE_RULESET: Final = "syntax-evidence-2026-08-09"


@dataclass(frozen=True, slots=True)
class SyntaxEvidenceProducer:
    """Turns one Phase 1 rejection into one observation."""

    clock: Clock

    def evidence(self, rejection: AddressRejected) -> tuple[Evidence, ...]:
        """Express a rejection as evidence. Never a status.

        A tuple of exactly one item, matching every other producer's shape, so a
        caller concatenates rather than special-casing this layer.
        """
        if not isinstance(rejection, AddressRejected):
            raise ValueError("syntax evidence is produced from an AddressRejected")
        return (
            Evidence(
                layer=EvidenceLayer.SYNTAX,
                reason=rejection.reason,
                strength=_strength_for(rejection.kind),
                observed_at=self.clock.now(),
                # **Never temporary.** A grammar does not change between two
                # requests, and marking a syntax rejection temporary would put
                # it in the tier that outranks hard invalid and turn a certain
                # answer into a retry.
                temporary=False,
                source_version=SYNTAX_EVIDENCE_RULESET,
                details={
                    "issue": rejection.issue.value,
                    "kind": rejection.kind.value,
                    "about_the_target": True,
                    "no_message_data_sent": True,
                },
            ),
        )


def _strength_for(kind: RejectionKind) -> EvidenceStrength:
    """Strength follows Phase 1's own distinction, and adds nothing to it.

    `RejectionKind` already separates "broke the supported grammar" from "this
    MVP cannot judge this form", and its own docstring says the second must
    resolve to `unknown` and never to a hard verdict. So the strength is read
    off that rather than off the individual issue: there is no per-issue
    judgment to make here, and inventing one would be a second, quieter
    classification of the same fact.

    Exhaustive by mechanism rather than by a default, on the precedent the
    `_CONNECT_REASONS` subscript set: a third `RejectionKind` fails under mypy
    and again at run time instead of silently becoming weak evidence.
    """
    match kind:
        case RejectionKind.INVALID:
            return EvidenceStrength.STRONG
        case RejectionKind.UNSUPPORTED:
            # Weak, and the strength is not what keeps it out of `invalid`: the
            # Phase 5 gate reads the reason, and the three `unsupported_*` codes
            # are in no hard-invalid set. Both hold, and neither is load-bearing
            # alone.
            return EvidenceStrength.WEAK
        case _ as unreachable:  # pragma: no cover - unreachable while the enum is closed
            assert_never(unreachable)
