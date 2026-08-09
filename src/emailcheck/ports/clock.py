"""Time as a port.

Cache expiry and evidence timestamps must be reproducible in a test, so nothing
outside an adapter reads the wall clock.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time as an aware UTC datetime."""
        ...


class MonotonicClock(Protocol):
    """Elapsed time, for deadlines rather than for timestamps.

    Separate from `Clock` because a deadline must not be computed from the wall
    clock. `datetime.now()` moves when the machine's clock is adjusted, and a
    session budget that shrinks because NTP stepped is a failure nobody debugs
    twice. Monotonic time only goes forward.
    """

    def monotonic(self) -> float:
        """Return a monotonically increasing number of seconds."""
        ...


class Sleeper(Protocol):
    """Suspending for a while, as a port rather than as a call to `asyncio`.

    Waiting is the other half of reading a clock, and it has the same problem: a
    component that calls `asyncio.sleep` directly can only be tested by actually
    waiting, which makes a pacing test measure the machine rather than the
    pacing. `MonotonicClock` already made every deadline deterministic; this
    makes the delays between them deterministic too.

    It is deliberately not a general scheduler. One method, one duration, no
    cancellation semantics of its own — a cancellation passes through it exactly
    as it passes through `asyncio.sleep`.
    """

    async def sleep(self, seconds: float) -> None:
        """Suspend for `seconds`, or until cancelled."""
        ...
