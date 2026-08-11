"""Signs that somebody is enumerating rather than checking.

`prompts/07-hardening.md` asks for **conservative sequence indicators** and says
what they may do: "suspend or require manual review", and "avoid opaque ML".
This module is the whole of that judgement, and it is pure — a window of recent
observations in, a set of raised indicators out. No clock, no storage, no model,
no threshold learned from anything.

**An indicator is a signal, never a verdict.** Nothing here produces a
`ReasonCode`, a `Status`, or `Evidence`, and nothing here refuses a request on
its own: `application/abuse.py` records what was raised and an operator decides.
`docs/architecture.md` keeps operational telemetry and mailbox semantics apart,
and a caller's behaviour says nothing whatever about whether an address is
deliverable.

**What the observations retain, exactly.** The window holds the recipient
domain, a keyed digest of the whole target, a keyed digest of the local part's
*stem*, and — in the clear — the **trailing run of digits** the stem was split
from. Nothing else of the local part is kept in any form.

The stem is digested because an earlier version stored it as text, and for
`very.secret.localpart+tag7` the stem is very nearly the whole local part. Every
rule here needs only to know whether two attempts *share* a stem, which is
equality, and equality survives hashing while the local part does not.

The ordinal is **not** digested, and saying so plainly matters more than the
tidier claim this docstring used to make. `_numeric_sequence` counts *distinct*
ordinals under one stem, so it needs the values themselves rather than their
equality — hashing them would turn "four different numbers" into "four different
digests", which is the same test, but it would also lose nothing and gain
nothing, so the honest reason is that the rule reads them and the value is what
it reads. What is retained is therefore a short integer: for `user7`, the
number 7. It is a fragment of the local part, it is bounded below, and it is
useless without the stem digest it belongs to — but it is not nothing, and a
docstring claiming "no local part in any form" would be claiming more than the
code does. `docs/adr/0008` names that failure; Phase 7's own privacy corpus
caught the earlier instance of it in this very module.

`docs/requirements.md` section 16 forbids a full address in an ordinary log and
an abuse feature store is ordinary; `prompts/07-hardening.md` says it from the
other side, that indicators must not leak guessed addresses in admin summaries.
Neither is breached by a bare integer.

**Deliberately blunt, and that is the design.** Every threshold is a small
integer an operator can reason about, every rule is one sentence, and a false
positive costs a review rather than a refusal. A cleverer detector that nobody
can explain is one nobody can act on — and one whose mistakes cannot be argued
with, which is worse for the person wrongly flagged than for this project.
"""

from __future__ import annotations

import string
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: How many recent observations an indicator may look at. Small, bounded, and
#: the same for every rule — a per-caller history is a per-caller allocation.
MAX_WINDOW: Final = 64

#: Local parts differing only in a trailing number, this many times.
NUMERIC_SEQUENCE_THRESHOLD: Final = 4

#: Distinct targets at one domain, this many times, from one caller.
DOMAIN_CONCENTRATION_THRESHOLD: Final = 10

#: Distinct API keys from one source address.
MULTIPLE_KEY_THRESHOLD: Final = 3

#: Attempts following an accepted recipient at the same domain.
EXPLORATION_THRESHOLD: Final = 3

#: Attempts matching the configured common-name list.
DICTIONARY_THRESHOLD: Final = 4

_DIGITS: Final = frozenset(string.digits)


class Indicator(StrEnum):
    """The five patterns `prompts/07-hardening.md` names, and no others."""

    NUMERIC_SEQUENCE = "numeric_sequence"
    DICTIONARY_PATTERN = "dictionary_pattern"
    DOMAIN_CONCENTRATION = "domain_concentration"
    MULTIPLE_KEYS_ONE_SOURCE = "multiple_keys_one_source"
    EXPLORATION_AFTER_POSITIVE = "exploration_after_positive"


@dataclass(frozen=True, slots=True)
class AttemptShape:
    """One past attempt, reduced to what a rule may look at.

    Constructed by `application/abuse.py` from an address that has already been
    parsed and normalized. `stem_digest` is a keyed digest of what remains after
    a trailing run of digits is removed, so `user1`, `user2`, and `user3` are
    recognizable as one pattern without the stem being recoverable.

    **The trailing digits themselves are kept in the clear**, in `ordinal`. See
    the module docstring: that is the whole of what survives of a local part
    here, and it is stated rather than glossed.
    """

    #: The recipient domain. A domain is not a mailbox, and
    #: `docs/requirements.md` section 16 permits aggregating by one.
    domain: str
    #: The keyed digest of the whole target, so two attempts can be told apart
    #: without either being recoverable.
    target_digest: str
    #: A keyed digest of the local part's stem, or `""` when there was none.
    stem_digest: str
    #: The trailing digit run as an integer, when there was one — **the one
    #: fragment of the local part kept in the clear**, because
    #: `_numeric_sequence` counts distinct ordinals and reads the values. `user7`
    #: keeps `7`. Bounded by `local_part_shape`, which refuses a run longer than
    #: nine digits rather than converting an unbounded integer from user input.
    ordinal: int | None = None
    #: Whether the local part matched the operator's common-name list.
    dictionary_hit: bool = False
    #: Whether this attempt ended in an accepted recipient.
    accepted: bool = False
    #: Which credential asked, as an opaque handle.
    key_id: str | None = None


def local_part_shape(local_part: str, *, max_stem: int = 32) -> tuple[str, int | None]:
    """Split a local part into its stem and its trailing number.

    `user117` becomes `("user", 117)`; `user` becomes `("user", None)`. The stem
    is truncated, because its purpose is comparison rather than reconstruction.

    A pure function on the local part, called before anything is retained — the
    value returned is what a window may hold, and the argument is not.
    """
    if not isinstance(local_part, str):
        return ("", None)
    index = len(local_part)
    while index > 0 and local_part[index - 1] in _DIGITS:
        index -= 1
    stem = local_part[:index][:max_stem]
    digits = local_part[index:]
    if not digits or len(digits) > 9:
        # An over-long run is not an ordinal anybody is counting through, and
        # converting it would be an unbounded integer from user input.
        return (stem, None)
    return (stem, int(digits))


def evaluate(
    window: Sequence[AttemptShape], *, distinct_keys_from_source: int = 0
) -> frozenset[Indicator]:
    """Which indicators this window raises.

    Deterministic and total: the same window always answers the same set, and no
    input shape raises. The window is the *caller's* recent attempts, ordered
    oldest first, and is never longer than `MAX_WINDOW`.
    """
    recent = tuple(window)[-MAX_WINDOW:]
    raised: set[Indicator] = set()

    if _numeric_sequence(recent):
        raised.add(Indicator.NUMERIC_SEQUENCE)
    if sum(1 for attempt in recent if attempt.dictionary_hit) >= DICTIONARY_THRESHOLD:
        raised.add(Indicator.DICTIONARY_PATTERN)
    if _domain_concentration(recent):
        raised.add(Indicator.DOMAIN_CONCENTRATION)
    if distinct_keys_from_source >= MULTIPLE_KEY_THRESHOLD:
        raised.add(Indicator.MULTIPLE_KEYS_ONE_SOURCE)
    if _exploration_after_positive(recent):
        raised.add(Indicator.EXPLORATION_AFTER_POSITIVE)

    return frozenset(raised)


def _numeric_sequence(window: Sequence[AttemptShape]) -> bool:
    """Several attempts sharing a stem and a domain, differing only by number.

    Not required to be *consecutive* numbers: `a1, a7, a92` is the same
    behaviour as `a1, a2, a3`, and requiring consecutiveness would make the rule
    trivially avoidable by counting in twos.
    """
    counts: dict[tuple[str, str], set[int]] = {}
    for attempt in window:
        if attempt.ordinal is None or not attempt.stem_digest:
            continue
        counts.setdefault((attempt.stem_digest, attempt.domain), set()).add(attempt.ordinal)
    return any(len(ordinals) >= NUMERIC_SEQUENCE_THRESHOLD for ordinals in counts.values())


def _domain_concentration(window: Sequence[AttemptShape]) -> bool:
    """Many *distinct* targets at one domain.

    Distinct rather than total, because repeatedly checking one address is a
    caller with a broken retry loop and repeatedly checking different ones at a
    single domain is the enumeration `docs/threat-model.md` lists first.
    """
    by_domain: dict[str, set[str]] = {}
    for attempt in window:
        by_domain.setdefault(attempt.domain, set()).add(attempt.target_digest)
    return any(len(targets) >= DOMAIN_CONCENTRATION_THRESHOLD for targets in by_domain.values())


def _exploration_after_positive(window: Sequence[AttemptShape]) -> bool:
    """Fresh targets at a domain where something was just accepted.

    "Repeated exploration near positive results" in the prompt: having found one
    live address at a domain, the caller immediately tries more there. Counted
    only *after* the acceptance, so a caller who happens to check several
    addresses and finds a live one last raises nothing.
    """
    for index, attempt in enumerate(window):
        if not attempt.accepted:
            continue
        later = window[index + 1 :]
        explored = {
            candidate.target_digest
            for candidate in later
            if candidate.domain == attempt.domain
            and candidate.target_digest != attempt.target_digest
        }
        if len(explored) >= EXPLORATION_THRESHOLD:
            return True
    return False
