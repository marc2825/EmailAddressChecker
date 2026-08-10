"""Unpredictability as a port.

`docs/architecture.md` section 2 lists `RandomSource` beside `Clock` and
`Sleeper`, for the same reason: a component that calls `secrets` directly can
only be tested against real entropy, so a test cannot fix an identifier and a
review cannot see where unpredictability actually comes from.

Two methods, because the two uses have different requirements. A job identifier
must be **unguessable** — ADR 0014 — and a retry's jitter only has to be
*spread*, so that a thousand jobs deferred by the same rule do not return at the
same instant.
"""

from __future__ import annotations

from typing import Protocol


class RandomSource(Protocol):
    def token(self, byte_count: int) -> str:
        """A URL-safe token with at least `byte_count` bytes of entropy.

        Implementations must use a cryptographically secure generator. This is
        what a job identifier is made of, and a predictable one lets a caller
        enumerate other accounts' jobs — an ownership check is the second
        barrier, not the first.
        """
        ...

    def jitter(self, span_seconds: float) -> float:
        """A value in `[0, span_seconds)`, to spread scheduled work."""
        ...
