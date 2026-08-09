"""The machine's clocks, behind the ports that ask for them."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Wall-clock time, always as an aware UTC datetime."""

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SystemMonotonicClock:
    """Elapsed time from `time.monotonic`, for session deadlines.

    Its zero point is arbitrary and its values are only meaningful as
    differences, which is exactly what a deadline needs and exactly why it must
    not be used as a timestamp.
    """

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class SystemSleeper:
    """Real suspension, for the pacing a production limiter has to do.

    The one line of it is the point: everything that decides *how long* lives in
    `domain/rate_limit.py` against a `MonotonicClock`, so the only thing a test
    has to replace is this.
    """

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
