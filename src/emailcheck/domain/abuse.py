"""Layered budgets: what may be counted, against what, and how much.

`docs/threat-model.md` lists nine budget layers. This module holds the
vocabulary and the arithmetic; `application/abuse.py` decides when to consume
and `ports/quota.py` says where the counts live. Pure: no clock, no storage, no
randomness — a window boundary is computed from a timestamp the caller supplies.

**Quota is not pacing and it is not admission.** The three answer different
questions and this project needs all three:

| Control | Phase | Question |
|---|---|---|
| `application/admission.py` | 6 | how many verifications may run *at once* |
| `adapters/system/rate_limit.py` | 4 | how *fast* one destination may be approached |
| this module | 7 | how *many* one caller may ask for in a window |

So the prompt's "global concurrency" layer is admission's and is not
re-implemented here, and its "target domain" layer is a volume budget rather
than a second copy of Phase 4's token bucket. Re-keying that bucket on the
account would have made each account's destination pacing independent, which is
the opposite of protecting a destination.

**A budget key never carries material.** Every value is an opaque digest, a
canonical domain, or a bounded category, and `BudgetKey` refuses an `@` in
either component — the shape check `rate_limit_key`, `Principal`, and
`OperatorEvent` already make, for the same reason: no key may be a mailbox.

**The window is fixed, not sliding.** A sliding window needs the timestamps of
every event in it, which is a per-caller unbounded list with a remote trigger.
A fixed window costs one integer per key and its worst case is well understood:
a caller may spend two windows' allowance across one boundary. That is a
factor of two on a bound, not an unbounded one, and ADR 0016 records it.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: One day, the window `docs/threat-model.md`'s "daily total" is expressed
#: in. Every other layer uses the configured window.
DAY_SECONDS: Final = 24 * 60 * 60

#: A window shorter than this is pacing, which Phase 4 already does better, and
#: a window longer than a day is a budget nobody can reason about.
MIN_WINDOW_SECONDS: Final = 60
MAX_WINDOW_SECONDS: Final = DAY_SECONDS

#: No single budget may be set so high that it is not a bound. Deliberately
#: generous — this is a ceiling on configuration error, not a capacity target.
MAX_BUDGET: Final = 10_000_000

#: The longest a budget key component may be. A digest is 64 characters and a
#: domain is bounded by DNS; anything longer is something else.
MAX_KEY_LENGTH: Final = 255

#: Deliberately narrow, and the same alphabet `Principal` uses plus the colon a
#: composite value needs. Every character outside it is one that could change
#: the meaning of a stored key or a log line.
_PERMITTED: Final = frozenset(string.ascii_letters + string.digits + "-_.:")


class AbuseSettingsError(ValueError):
    """A budget configuration that would not bound anything."""


class BudgetKeyError(ValueError):
    """A budget key that carries something it may not."""


class BudgetLayer(StrEnum):
    """The layers `docs/threat-model.md` names, minus the one that exists.

    "Global concurrency" is `application/admission.py`'s and is deliberately
    absent: a second implementation of a reviewed bound is two bounds that will
    disagree. `application/abuse.py` documents the mapping and a test asserts
    that every layer in the prompt is either here or accounted for there.
    """

    #: One credential. Distinct from the account, because one account may hold
    #: several keys and a leaked key must be containable on its own.
    API_KEY = "api_key"
    #: One authenticated account, across all of its keys.
    ACCOUNT = "account"
    #: One source address, when a trusted transport boundary supplied one.
    SOURCE_IP = "source_ip"
    #: One target address, as a keyed digest. Never the address.
    TARGET = "target"
    #: One recipient domain. Volume, not pacing.
    TARGET_DOMAIN = "target_domain"
    #: One exchanger host.
    TARGET_MX = "target_mx"
    #: One configured sender identity, so a reputation problem is containable.
    SENDER_IDENTITY = "sender_identity"
    #: One recipient domain, for Phase 9's accept-all experiment **only**.
    #:
    #: Separate from `TARGET_DOMAIN` on purpose, and the separation is the
    #: requirement: ADR 0017 and `docs/requirements.md`
    #: section 10 both ask for a *separate* domain budget. An experiment is
    #: additional contact with a domain nobody asked this project to contact —
    #: the caller asked about one mailbox — so it may not be paid for out of the
    #: budget that bounds ordinary verification of that domain, and exhausting
    #: it must not stop ordinary verification either. Sized far smaller: a
    #: domain's accept-all configuration is one fact, cached for seven days.
    ACCEPT_ALL_DOMAIN = "accept_all_domain"
    #: Everything this deployment did, in one day.
    DAILY_TOTAL = "daily_total"


#: The layers whose budget is spent per *day* whatever the configured window.
#: Only one, but named as a set so the rule is data rather than an `if`.
DAILY_LAYERS: Final[frozenset[BudgetLayer]] = frozenset({BudgetLayer.DAILY_TOTAL})


@dataclass(frozen=True, slots=True)
class BudgetKey:
    """One counter's identity: which layer, and which member of it.

    The value is opaque to this module. `application/abuse.py` decides what is
    canonical — a digest for a target, a canonical host for a domain — so this
    type never normalizes and never guesses, the same split
    `security/identifiers.py` uses.
    """

    layer: BudgetLayer
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.layer, BudgetLayer):
            raise BudgetKeyError("a budget key must name a published layer")
        value = self.value
        if not isinstance(value, str) or not value:
            raise BudgetKeyError("a budget key value must be non-empty text")
        if len(value) > MAX_KEY_LENGTH:
            raise BudgetKeyError("a budget key value is too long")
        if not _PERMITTED.issuperset(value):
            # `@` is outside the permitted set, so a key can never be a mailbox
            # even by construction accident.
            raise BudgetKeyError("a budget key value carries an unpermitted character")

    @property
    def storage_key(self) -> str:
        """The stable string a store counts against."""
        return f"{self.layer.value}:{self.value}"


@dataclass(frozen=True, slots=True)
class QuotaSettings:
    """How much each layer allows, and over how long.

    Every value is validated the way every other bound in this project is:
    a whole number, not a boolean, positive, and under a ceiling — because a
    bound nobody would reach is not a bound. A layer may be set to `None`,
    which means *not enforced here*, and that is deliberately explicit rather
    than expressed as a very large number.
    """

    window_seconds: int = 3600
    per_api_key: int | None = 1_000
    per_account: int | None = 5_000
    per_source_ip: int | None = 1_000
    per_target: int | None = 5
    per_target_domain: int | None = 500
    per_target_mx: int | None = 500
    #: Phase 9's separate experiment budget. Deliberately two orders of
    #: magnitude below `per_target_domain`: a seven-day cache means one decided
    #: answer per domain per week is the intended traffic, and a limit that
    #: allowed more would be a limit that permitted the shape it exists to stop.
    per_accept_all_domain: int | None = 5
    per_sender_identity: int | None = 20_000
    daily_total: int | None = 50_000

    def __post_init__(self) -> None:
        window = self.window_seconds
        if isinstance(window, bool) or not isinstance(window, int):
            raise AbuseSettingsError("window_seconds must be a whole number, not a boolean")
        if not MIN_WINDOW_SECONDS <= window <= MAX_WINDOW_SECONDS:
            raise AbuseSettingsError(
                f"window_seconds must be {MIN_WINDOW_SECONDS}..{MAX_WINDOW_SECONDS}"
            )
        for layer in BudgetLayer:
            _check_budget(layer.value, self.limit_for(layer))

    def limit_for(self, layer: BudgetLayer) -> int | None:
        """The budget for one layer, or `None` when it is not enforced."""
        limit: int | None = getattr(self, LIMIT_FIELDS[layer])
        return limit

    def window_for(self, layer: BudgetLayer) -> int:
        """How long this layer's window is.

        The daily total is a day by definition — `docs/threat-model.md` calls
        it that — and every other layer uses the configured window. Reading it
        from a set rather than from an `if` keeps the exception data.
        """
        return DAY_SECONDS if layer in DAILY_LAYERS else self.window_seconds


#: Which field carries which layer's budget. A table rather than a chain of
#: `if`s, so `limit_for` cannot disagree with `__post_init__` about what a layer
#: means, and so a layer added later has one obvious place to be forgotten —
#: which the exhaustiveness check below then refuses.
LIMIT_FIELDS: Final[dict[BudgetLayer, str]] = {
    BudgetLayer.API_KEY: "per_api_key",
    BudgetLayer.ACCOUNT: "per_account",
    BudgetLayer.SOURCE_IP: "per_source_ip",
    BudgetLayer.TARGET: "per_target",
    BudgetLayer.TARGET_DOMAIN: "per_target_domain",
    BudgetLayer.TARGET_MX: "per_target_mx",
    BudgetLayer.ACCEPT_ALL_DOMAIN: "per_accept_all_domain",
    BudgetLayer.SENDER_IDENTITY: "per_sender_identity",
    BudgetLayer.DAILY_TOTAL: "daily_total",
}

if set(LIMIT_FIELDS) != set(BudgetLayer):  # pragma: no cover - a definition error
    raise AbuseSettingsError("every budget layer needs a settings field")


def _check_budget(name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise AbuseSettingsError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise AbuseSettingsError(f"{name} must be positive, or None for unenforced")
    if value > MAX_BUDGET:
        raise AbuseSettingsError(f"{name} above {MAX_BUDGET} is not a bound")


def window_start(epoch_seconds: float, *, window_seconds: int) -> int:
    """The integer start of the window `epoch_seconds` falls in.

    Floor division on a whole number of seconds, so every caller in one window
    computes the same value and a counter is addressable by it. Negative input
    is refused rather than floored: a timestamp before the epoch is a bug in the
    caller's clock, and silently bucketing it would hide that.
    """
    if isinstance(epoch_seconds, bool) or not isinstance(epoch_seconds, int | float):
        raise AbuseSettingsError("a timestamp must be a real number")
    if epoch_seconds != epoch_seconds or epoch_seconds in (float("inf"), float("-inf")):
        raise AbuseSettingsError("a timestamp must be finite")
    if epoch_seconds < 0:
        raise AbuseSettingsError("a timestamp must not precede the epoch")
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int):
        raise AbuseSettingsError("a window must be a whole number of seconds")
    if not MIN_WINDOW_SECONDS <= window_seconds <= MAX_WINDOW_SECONDS:
        raise AbuseSettingsError("a window is outside the permitted range")
    return int(epoch_seconds) // window_seconds * window_seconds
