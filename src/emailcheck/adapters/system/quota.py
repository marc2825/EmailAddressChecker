"""Budget counters in this process's memory, bounded in every direction.

`docs/requirements.md` section 15 gives the service-active profile Redis, and
this Phase installs nothing — so this is the development implementation of
`ports/quota.py`, the same relationship `InMemoryJobExecutor` has to an isolated
worker. It bounds one process; a shared store implements the same port and
nothing above it learns which one it has.

**A live counter is never evicted.** Evicting one resets a budget, which is a
bypass rather than tidiness — the rule the Phase 4 limiter's per-domain table
already follows, and for the same reason. So eviction takes only counters whose
window has ended, and when the table is full of *live* counters the store
refuses rather than making room.

That refusal is the honest failure mode and is worth stating plainly: a caller
who can create unlimited distinct budget keys can fill this table. What stops
that being unbounded is the layering — every request that creates a new target
counter also spends the caller's per-key, per-account, and daily counters, and
those already exist. The table therefore fills at the rate the *narrowest*
budget allows rather than at request rate, and ADR 0016 does the arithmetic.

**No lock is needed and none is taken.** `consume` performs no `await` between
reading the counters and writing them, so the whole check-and-commit is atomic
on one event loop. That is a property of the code rather than a convention, and
a test opens the window a future `await` would create.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from emailcheck.domain.abuse import window_start
from emailcheck.ports.quota import BudgetRequest, QuotaDecision, QuotaStoreUnavailable

#: How many distinct counters this process will hold. Each is a short string
#: and two integers, so this is a table of a few megabytes at the ceiling.
DEFAULT_MAX_COUNTERS: Final = 100_000
MAX_COUNTERS_CEILING: Final = 5_000_000


class QuotaSettingsError(ValueError):
    """A store configuration that would not bound anything."""


@dataclass(slots=True)
class _Counter:
    """How many units are spent in one window, and when that window ends.

    The end is stored rather than recomputed, so the sweep is exact: a counter
    knows its own window length and nothing has to assume the longest one.
    """

    spent: int
    expires_at: int


@dataclass(slots=True)
class InProcessQuotaStore:
    """Fixed-window counters keyed by `(storage_key, window_start)`.

    One instance per process, built by the composition root and shared, for the
    reason the limiter and the admission gate are shared: counters that start at
    zero for every request permit everything.
    """

    max_counters: int = DEFAULT_MAX_COUNTERS
    _counters: dict[tuple[str, int], _Counter] = field(default_factory=dict)
    #: Makes the store fail, so "fails closed" is exercised rather than
    #: asserted. Set by an operator or a test, never read from a request.
    unavailable: bool = False

    def __post_init__(self) -> None:
        value = self.max_counters
        if isinstance(value, bool) or not isinstance(value, int):
            raise QuotaSettingsError("max_counters must be a whole number, not a boolean")
        if value <= 0:
            raise QuotaSettingsError("max_counters must be positive")
        if value > MAX_COUNTERS_CEILING:
            raise QuotaSettingsError(f"max_counters above {MAX_COUNTERS_CEILING} is not a bound")

    @property
    def tracked(self) -> int:
        return len(self._counters)

    async def consume(self, requests: Sequence[BudgetRequest], *, now: float) -> QuotaDecision:
        """Spend one unit against every request, or spend nothing.

        **Three passes, and the order is the whole correctness argument.**

        1. every layer's limit is checked;
        2. every table slot the commit will need is *reserved* — counted as a
           set, before anything is written;
        3. only then does anything increment.

        The second pass is what an independent review found missing. The
        earlier build checked limits, began incrementing, and discovered on the
        third layer that the table was full — raising with the first two already
        spent. A refused request had drained the caller's key, account, and
        daily budgets, which is precisely what `ports/quota.py` promises cannot
        happen. Reserving first means the failure is decided before the first
        write, so there is nothing to roll back.

        Counting the missing slots as a **set** matters too: two layers needing
        new counters need two free slots, and asking `len(table) < max` once per
        insertion answers the wrong question when only one is left.

        Between the first read and the last write there is no `await`, so no
        other task can observe a half-spent state or slip past a limit the first
        pass found reached. That is the whole concurrency argument, and an
        inspection test pins it.
        """
        if self.unavailable:
            raise QuotaStoreUnavailable("the budget counters are not reachable")

        slots = [(request, self._slot(request, now)) for request in requests]

        for request, slot in slots:
            existing = self._counters.get(slot)
            spent = 0 if existing is None else existing.spent
            if spent + 1 > request.limit:
                return QuotaDecision(permitted=False, refused_layer=request.key.layer)

        missing = {slot for _, slot in slots if slot not in self._counters}
        if missing and not self._reserve(len(missing), now):
            # The table is full of counters that are still live. Refusing is the
            # fail-closed answer; the alternative is evicting somebody else's
            # live budget, which resets it. **Nothing has been written yet.**
            raise QuotaStoreUnavailable("the budget table is full")

        for request, slot in slots:
            existing = self._counters.get(slot)
            if existing is not None:
                existing.spent += 1
                continue
            self._counters[slot] = _Counter(spent=1, expires_at=slot[1] + request.window_seconds)

        return QuotaDecision(permitted=True)

    async def purge_expired(self, *, now: float) -> int:
        """Drop every counter whose window has ended."""
        return self._drop_expired(now)

    def _slot(self, request: BudgetRequest, now: float) -> tuple[str, int]:
        return (
            request.key.storage_key,
            window_start(now, window_seconds=request.window_seconds),
        )

    def _reserve(self, needed: int, now: float) -> bool:
        """Whether `needed` new counters fit, without touching a live one.

        Answers about the whole commit rather than about one insertion, which
        is the difference between "there is a free slot" and "there are enough
        free slots". Expired counters are swept once and only then is the
        question re-asked, so a sweep is not repeated per layer.

        A live counter is **never** evicted to make room. Evicting one resets a
        budget, which is a bypass rather than tidiness — the rule the Phase 4
        limiter's per-domain table already follows.
        """
        if len(self._counters) + needed <= self.max_counters:
            return True
        self._drop_expired(now)
        return len(self._counters) + needed <= self.max_counters

    def _drop_expired(self, now: float) -> int:
        dead = [slot for slot, counter in self._counters.items() if counter.expires_at <= now]
        for slot in dead:
            del self._counters[slot]
        return len(dead)
