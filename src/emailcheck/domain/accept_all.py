"""The accept-all experiment's values: what it may ask, and what it may conclude.

`docs/adr/0017-accept-all-control-experiment.md`. Pure domain logic — no socket, no clock, no cache,
no randomness of its own. The experiment service in `application/accept_all.py`
is what runs; this is what it is allowed to say.

**What the experiment measures, and what it does not.** It asks one exchanger
whether it accepts a recipient nobody has ever created. That is a question about
a *domain's configuration*, and the answer is never a fact about the address a
caller asked about:

- the control was **accepted**: the destination may accept every recipient. It
  does *not* follow that the caller's target does not exist;
- the control was **rejected**: nothing is published, because this project has
  no vocabulary for "not accept-all". It does *not* follow that the caller's
  target does exist.

Both halves matter. `docs/requirements.md` section 1 says this project does not
prove mailbox existence, and neither direction of a control probe changes that.
The only thing Phase 9 may emit is `accept_all_suspected` — a risk flag —
because `docs/adr/0017-accept-all-control-experiment.md`'s Result section says "only add" that.

**Suspicion, not certainty.** One accepted control is one observation of one
exchanger at one moment. The prompt says so in those words, `docs/requirements.md`
section 10 adds "do not declare catch-all from one ambiguous response", and
`ReasonCode.ACCEPT_ALL_SUSPECTED` is spelled with `suspected` in it for the same
reason.

**The aggregation was decided in Phase 5 and is not touched here.**
`application/aggregate.py` already places `accept_all_suspected` in tier 4,
which is `unknown` and which blocks a positive verdict — so
`docs/adr/0017-accept-all-control-experiment.md`'s "an accepted target plus suspected accept-all
aggregates to `unknown`" holds already, through the existing evidence
architecture. Phase 9 produces the evidence; it changes no rule about what
evidence means. Nothing in this module names a `Status`.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "CACHEABLE_OUTCOMES",
    "CONTROL_ALPHABET",
    "CONTROL_LOCAL_PART_LENGTH",
    "EXPERIMENT_VERSION",
    "MAX_CACHE_SECONDS",
    "MAX_COLLISION_RETRIES",
    "MIN_CACHE_SECONDS",
    "AcceptAllError",
    "AcceptAllOutcome",
    "AcceptAllSettings",
    "ControlLocalPart",
    "control_local_part",
]

#: The characters a control local part is built from.
#:
#: Lower-case ASCII letters and digits, and nothing else. Every one is a
#: dot-atom character Phase 1 already accepts, so a generated address parses
#: through the ordinary parser rather than through a second grammar. No dot, no
#: `+`, no hyphen: each would make the generated form resemble a tagged or
#: structured address somebody might own, and none adds entropy worth the
#: resemblance.
CONTROL_ALPHABET: Final = string.ascii_lowercase + string.digits

#: How long a control local part is.
#:
#: Twenty characters over a 36-symbol alphabet is about 103 bits. The number is
#: chosen for the property that matters — that the address **is not somebody's
#: mailbox** — rather than for cryptographic strength: at this length the chance
#: of colliding with a real address is negligible against any mailbox namespace,
#: and a receiving operator reading their logs can see at a glance that it was
#: generated rather than guessed.
CONTROL_LOCAL_PART_LENGTH: Final = 20

#: How many times a generator may draw again when the value it produced is one
#: the experiment may not use.
#:
#: **Finite, and small.** `docs/adr/0017-accept-all-control-experiment.md` forbids sequential
#: strings
#: and this project forbids adaptive probing, so a generator that kept drawing
#: until something "worked" would be the beginning of exactly that. A collision
#: at this length is a once-in-the-heat-death event; three draws is generous, and
#: exhausting them is a refusal rather than a fallback.
MAX_COLLISION_RETRIES: Final = 3

#: The experiment's own semantic version, carried in every cache key.
#:
#: A cached answer is seven days old at the end of its life. If what the
#: experiment asks or how it reads the reply changes inside that window, the
#: cached answers were produced by a different experiment, and reusing them
#: would attribute this version's meaning to the previous version's
#: observations. Bumping this invalidates them by construction rather than by
#: anybody remembering to clear a table.
EXPERIMENT_VERSION: Final = "accept-all-2026-08-12"

#: Seven days, the floor `docs/requirements.md` section 13 and
#: `docs/adr/0017-accept-all-control-experiment.md` agree on, and a ceiling so a typo cannot make an
#: answer outlive the deployment that produced it.
MIN_CACHE_SECONDS: Final = 7 * 24 * 60 * 60
MAX_CACHE_SECONDS: Final = 90 * 24 * 60 * 60


class AcceptAllError(ValueError):
    """A control probe this project may not construct or perform."""


class AcceptAllOutcome(StrEnum):
    """What one experiment concluded. Closed, and none of these is a `Status`.

    An **experiment** vocabulary, in the shape Phase 8 established for its
    execution states: what the harness did, never what the mailbox is. Only
    `SUSPECTED` produces evidence; the rest produce none, because this project
    publishes no reason code meaning "not accept-all" and inventing one would be
    inventing a claim nobody reviewed.
    """

    #: The control recipient — an address nobody created — was accepted. The
    #: destination may accept every recipient. Suspicion, not certainty.
    SUSPECTED = "suspected"
    #: The control recipient was rejected for an address-specific reason, so
    #: this exchanger does not appear to accept everything. **Published as
    #: nothing**: it is the absence of suspicion, not evidence about any
    #: mailbox.
    NOT_SUSPECTED = "not_suspected"
    #: The reply was ambiguous — a bare `550`, a `252`, a policy rejection.
    #: `docs/requirements.md` section 10: do not declare catch-all from one
    #: ambiguous response.
    INCONCLUSIVE = "inconclusive"
    #: A `4xx`, a timeout, a TLS failure, or anything else this project reads as
    #: transient. Says nothing about the domain and is never cached.
    TEMPORARY = "temporary"
    #: The experiment did not run: disabled, unauthorized, out of budget,
    #: administratively blocked, or refused by the ordinary controls.
    REFUSED = "refused"


#: The outcomes a seven-day cache may hold.
#:
#: The two **decided** ones. `docs/adr/0017-accept-all-control-experiment.md` asks for a "seven-day
#: or longer domain cache", and a domain cache stores what was learned about the
#: domain's configuration — which both `SUSPECTED` and `NOT_SUSPECTED` are.
#:
#: The other three are deliberately excluded, and that is the more important
#: half: freezing a timeout, an ambiguous reply, or a refusal into a week-long
#: answer would turn one bad minute into seven days of a claim this project
#: never established. ADR 0017 records the alternative — caching only
#: `SUSPECTED`, which `docs/requirements.md` section 13 is the only class it
#: prices — and why the domain-cache reading was taken instead.
CACHEABLE_OUTCOMES: Final[frozenset[AcceptAllOutcome]] = frozenset(
    {AcceptAllOutcome.SUSPECTED, AcceptAllOutcome.NOT_SUSPECTED}
)


@dataclass(frozen=True, slots=True)
class ControlLocalPart:
    """A generated local part, validated as one.

    A type rather than a `str` on the precedent `PeerEndpoint` and `RoleName`
    set: **the value guarantees the shape**, and the generator grants the
    provenance. A `str` parameter would let any caller supply `admin` and have
    it probed as a "control".
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise AcceptAllError("a control local part is text")
        if len(self.value) != CONTROL_LOCAL_PART_LENGTH:
            raise AcceptAllError(
                f"a control local part is exactly {CONTROL_LOCAL_PART_LENGTH} characters"
            )
        if not set(self.value) <= set(CONTROL_ALPHABET):
            # Anything outside the alphabet is either a character Phase 1 would
            # refuse or one that makes the address look structured.
            raise AcceptAllError("a control local part uses the published alphabet only")


def control_local_part(draw: str) -> ControlLocalPart:
    """Build a control local part from a generator's raw draw.

    Separated from the generator so the *shape* rule is testable without
    randomness, and so `application/accept_all.py` owns the `RandomSource` while
    this module owns what a valid value is.
    """
    return ControlLocalPart(draw)


@dataclass(frozen=True, slots=True)
class AcceptAllSettings:
    """The feature flag and its bounds. **Disabled by default.**

    `docs/adr/0017-accept-all-control-experiment.md` requires a "separate feature flag", and
    `docs/requirements.md` section 5 excludes "arbitrary active accept-all
    checks before Phase 9" — so the default is the one that probes nothing, and
    enabling it is an operator's deployment decision.

    **Enabling the feature is not an authorization to probe.** That is a
    separate value, on the precedent Phase 8 set: `BetaAuthorization`
    distinguishes "the harness exists" from "a human said yes", and this Phase
    inherits both the distinction and the human deployment gate in
    `docs/operations.md` section 1. A deployment with `enabled = True` and no
    authorized domain runs no experiment.
    """

    #: The operator's deployment-level switch. Never request-controlled: no API
    #: body key, no query parameter, and no CLI flag reaches it.
    enabled: bool = False
    #: How long a decided outcome stays cached, in seconds.
    #: `docs/requirements.md` section 13 prices accept-all suspicion at seven
    #: days and `docs/adr/0017-accept-all-control-experiment.md` asks for "seven-day or longer", so
    #: seven days is the floor as well as the default.
    cache_seconds: int = 7 * 24 * 60 * 60
    #: How many control probes one experiment may issue. **One**, and it is not
    #: configurable upward: `docs/adr/0017-accept-all-control-experiment.md` says "exactly one
    #: control
    #: recipient probe", and a second would be the enumeration shape
    #: `docs/threat-model.md` lists first.
    control_probes: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise AcceptAllError("the accept-all feature flag is a boolean an operator sets")
        seconds = self.cache_seconds
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise AcceptAllError("cache_seconds must be a whole number, not a boolean")
        if seconds < MIN_CACHE_SECONDS:
            raise AcceptAllError("an accept-all cache is seven days or longer")
        if seconds > MAX_CACHE_SECONDS:
            raise AcceptAllError("an accept-all cache above ninety days is not a cache")
        if self.control_probes != 1:
            # Not a bound that can be widened. One is the requirement.
            raise AcceptAllError("an experiment issues exactly one control probe")
