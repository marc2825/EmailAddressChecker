"""How many verifications may be in flight, and how many may be waiting.

Phase 4 stop condition 5. The Phase 4 limiter's memory bound is
`max_tracked_domains` **plus whatever is in flight**, because a caller registers
interest in a domain before it is admitted globally — so in-flight entries are
bounded by the concurrency of the *calling* code and by nothing inside the
limiter. This is the calling code, and this is that bound.

**Two bounds, because one is not a bound.** Capping concurrent verifications
while letting an unbounded number queue behind them moves the memory growth from
one place to another: ten thousand waiting requests are ten thousand coroutines,
ten thousand sockets held open by whatever is upstream, and ten thousand
`_DomainState` entries if each names a different domain. So the queue is bounded
too, and a request that arrives to a full queue is refused immediately rather
than admitted to an unbounded wait.

**A refusal here is local and operational.** `AdmissionRefused` derives from
neither `TimeoutError` nor `OSError` nor any SMTP type, for the reason
`RateLimitTimeout` does: this project running out of capacity is not a fact
about someone's mailbox, and a handler written for a remote failure must not
catch it. It produces no `Evidence` at all, because nothing was observed.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Final

#: Concurrent verifications, and the ceiling on that. Deliberately small: each
#: admitted verification may open up to `max_attempts` SMTP connections, so the
#: real outbound fan-out is this times the Phase 4 attempt cap.
DEFAULT_MAX_IN_FLIGHT: Final = 8
MAX_IN_FLIGHT_CEILING: Final = 256

#: How many may wait for a slot. A queue longer than this is a queue nobody is
#: served from within any deadline worth having.
DEFAULT_MAX_WAITING: Final = 32
MAX_WAITING_CEILING: Final = 4096

#: Concurrent verifications for one authenticated principal. This is the
#: per-account isolation `docs/requirements.md` section 15 requires, and it is
#: here rather than in the Phase 4 token bucket deliberately: that bucket
#: partitions on the recipient domain, which is a reviewed contract, and
#: re-keying it on `(account, domain, mx)` would change what a reviewed gate
#: measures in order to add something a separate gate does better.
DEFAULT_MAX_PER_PRINCIPAL: Final = 4


class AdmissionError(ValueError):
    """A misconfigured admission gate."""


class AdmissionRefused(Exception):
    """Capacity refused this request. Nothing was observed and nothing was sent.

    Not a `TimeoutError`, not an `OSError`, and not an SMTP type: a handler
    written for a remote condition must not catch this project's own capacity.
    """

    def __init__(self, scope: str) -> None:
        super().__init__(f"admission refused: {scope} is at capacity")
        self.scope = scope


@dataclass(frozen=True, slots=True)
class AdmissionSettings:
    """Every bound, validated the way every other bound in this project is."""

    max_in_flight: int = DEFAULT_MAX_IN_FLIGHT
    max_waiting: int = DEFAULT_MAX_WAITING
    max_per_principal: int = DEFAULT_MAX_PER_PRINCIPAL

    def __post_init__(self) -> None:
        _check("max_in_flight", self.max_in_flight, MAX_IN_FLIGHT_CEILING)
        _check("max_waiting", self.max_waiting, MAX_WAITING_CEILING)
        _check("max_per_principal", self.max_per_principal, MAX_IN_FLIGHT_CEILING)
        if self.max_per_principal > self.max_in_flight:
            # Otherwise the per-principal bound is decorative: one caller could
            # occupy every slot and still be inside its own limit.
            raise AdmissionError("a per-principal bound above the global one bounds nothing")


def _check(name: str, value: int, ceiling: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdmissionError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise AdmissionError(f"{name} must be positive")
    if value > ceiling:
        raise AdmissionError(f"{name} above {ceiling} is not a bound")


@dataclass(slots=True)
class AdmissionControl:
    """The gate every externally initiated verification passes through.

    One instance per process. The composition root builds it once and shares it,
    for the same reason it shares the limiter: a gate constructed per request
    admits everybody.
    """

    settings: AdmissionSettings = field(default_factory=AdmissionSettings)
    _in_flight: int = 0
    _waiting: int = 0
    _per_principal: Counter[str] = field(default_factory=Counter)
    _released: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def in_flight(self) -> int:
        return self._in_flight

    @property
    def waiting(self) -> int:
        return self._waiting

    def held_by(self, account: str) -> int:
        return self._per_principal[account]

    @asynccontextmanager
    async def admit(self, account: str) -> AsyncIterator[None]:
        """Hold one permit for the body, or refuse before any work begins.

        The permit is released in a `finally`, so a cancellation, an exception,
        and an ordinary return all give it back. A permit that is not returned
        removes capacity from the process permanently — the same shape as the
        concurrency slot the Phase 4E review found leaking, and the same fix.
        """
        await self._acquire(account)
        try:
            yield
        finally:
            self._release(account)

    async def _acquire(self, account: str) -> None:
        if self._admissible(account):
            self._take(account)
            return

        if self._waiting >= self.settings.max_waiting:
            # Refused *before* waiting. Admitting to an unbounded queue is the
            # failure this bound exists for.
            raise AdmissionRefused("the request queue")

        self._waiting += 1
        try:
            while not self._admissible(account):
                released = self._released
                await released.wait()
        finally:
            self._waiting -= 1
        self._take(account)

    def _admissible(self, account: str) -> bool:
        return (
            self._in_flight < self.settings.max_in_flight
            and self._per_principal[account] < self.settings.max_per_principal
        )

    def _take(self, account: str) -> None:
        self._in_flight += 1
        self._per_principal[account] += 1

    def _release(self, account: str) -> None:
        self._in_flight -= 1
        remaining = self._per_principal[account] - 1
        if remaining <= 0:
            # Removed rather than left at zero, so the counter cannot grow
            # without a bound as principals come and go.
            del self._per_principal[account]
        else:
            self._per_principal[account] = remaining
        if self._in_flight < 0:
            raise AdmissionError("an admission permit was released more times than it was taken")
        self._signal()

    def _signal(self) -> None:
        """Wake every waiter and hand the next one a fresh event.

        Replacing rather than clearing removes the race the Phase 4 limiter
        documents: a waiter takes a reference, a permit is released, and a
        `clear()` arrives before the `wait()` — leaving that waiter parked on an
        event that has already had its turn.
        """
        previous = self._released
        self._released = asyncio.Event()
        previous.set()
