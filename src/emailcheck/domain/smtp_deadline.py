"""The deadline that dominates every other one.

`docs/smtp-state-machine.md` section 6 requires a total session deadline on top
of the per-operation ones, and says it dominates them. Gate 4B implemented the
per-operation half and recorded the other as gate 4C's stop condition; this is
it.

Both halves are needed and neither replaces the other. A per-read deadline of 30
seconds bounds one read; a dialogue of eight steps bounds nothing useful, because
a peer that answers each step just inside its deadline holds a worker for four
minutes without ever timing out. The total is what makes a tarpit cost a known
amount.

Time comes from a `MonotonicClock` port. Not the wall clock: a deadline computed
from `datetime.now()` moves when the machine's clock is adjusted, and "the
session ends an hour early because NTP stepped" is a failure mode nobody debugs
twice. Monotonic time only goes forward.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

from emailcheck.domain.smtp_contract import SMTPContractError

#: A whole probe may not be given a longer budget than this. `docs/requirements.md`
#: section 9 requires every session bounded, and a bound nobody would reach is
#: not one: an SMTP recipient probe that has not finished in two minutes is not
#: going to.
MAX_SESSION_SECONDS: Final = 120.0

#: The default budget for one probe. Generous enough for a slow banner, a slow
#: EHLO, a TLS handshake, and the recipient stage on a loaded server; short
#: enough that a tarpit costs one worker half a minute.
DEFAULT_SESSION_SECONDS: Final = 30.0


@dataclass(frozen=True, slots=True)
class SessionBudget:
    """How long one whole probe may take, validated the way a timeout is.

    The same rules as `TransportTimeouts`, for the same reasons: `True` is `1`
    in Python and would silently mean a one-second budget, `float("inf")` is not
    a deadline, and a value above the maximum is a configuration mistake rather
    than a policy.
    """

    total_seconds: float = DEFAULT_SESSION_SECONDS

    def __post_init__(self) -> None:
        value = self.total_seconds
        if isinstance(value, bool):
            raise SMTPContractError("a session budget must be a number of seconds, not a boolean")
        if not isinstance(value, int | float):
            raise SMTPContractError("a session budget must be a number of seconds")
        if math.isnan(value) or math.isinf(value):
            raise SMTPContractError("a session budget must be finite")
        if value <= 0:
            raise SMTPContractError("a session budget must be positive")
        if value > MAX_SESSION_SECONDS:
            raise SMTPContractError("a session budget exceeds the maximum allowed session length")


@dataclass(frozen=True, slots=True)
class SessionDeadline:
    """A budget with a start time, so "how long is left" has an answer.

    Immutable and cheap to pass around. `remaining` is recomputed from the clock
    every time rather than decremented, so a stage that took longer than it
    reported cannot leave the budget looking healthy.
    """

    budget: SessionBudget
    started_at: float

    def remaining(self, now: float) -> float:
        """Seconds left, never negative."""
        elapsed = now - self.started_at
        return max(0.0, self.budget.total_seconds - elapsed)

    def is_expired(self, now: float) -> bool:
        return self.remaining(now) <= 0.0

    def elapsed_milliseconds(self, now: float) -> int:
        """How long the session has taken so far, for the observation."""
        return max(0, int((now - self.started_at) * 1000))


def start_deadline(budget: SessionBudget, now: float) -> SessionDeadline:
    """Begin the clock for one probe."""
    return SessionDeadline(budget=budget, started_at=now)
