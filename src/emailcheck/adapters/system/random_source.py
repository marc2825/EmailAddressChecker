"""The production `RandomSource`: `secrets`, and nothing weaker.

ADR 0014 makes a job identifier unguessable, and this is where that is actually
true. `random` is not used anywhere in this module — a Mersenne Twister's state
is recoverable from its output, which for a job identifier means one caller can
predict another's.

Jitter uses the same generator. It does not need to be unpredictable, but
keeping one source means there is no second import to review and no chance of
the two being swapped.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SystemRandomSource:
    """`secrets`, as a port implementation."""

    def token(self, byte_count: int) -> str:
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 16:
            # Below 128 bits an identifier stops being unguessable, and this is
            # the wrong place to discover that a caller passed a small number.
            raise ValueError("a token needs at least 16 bytes of entropy")
        return secrets.token_urlsafe(byte_count)

    def jitter(self, span_seconds: float) -> float:
        if isinstance(span_seconds, bool) or not isinstance(span_seconds, int | float):
            raise ValueError("a jitter span must be a real number")
        if span_seconds < 0:
            raise ValueError("a jitter span must not be negative")
        if span_seconds == 0:
            return 0.0
        # Integer arithmetic over a millisecond grid: `secrets` offers no float
        # primitive, and a grid is precise enough for spreading work by minutes.
        grid = max(1, int(span_seconds * 1000))
        return secrets.randbelow(grid) / 1000.0
