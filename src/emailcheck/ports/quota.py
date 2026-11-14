"""Where budget counters live, and what happens when they cannot be reached.

`docs/threat-model.md` requires that a **rate storage failure fails closed
for active checks**, so this port publishes a failure type rather than letting a
store's own exception escape. An implementation raises `QuotaStoreUnavailable`;
`application/abuse.py` turns that into a refusal for an active check and leaves
a passive check alone, which is `docs/architecture.md` section 5's rule that the
API keeps serving passive checks when a dependency is down.

**Spending is all-or-nothing.** A request that is refused by the eighth layer
must not have spent the first seven, or a caller near one limit would be
drained by requests that never ran. So the whole set is presented at once and
the implementation commits only when every layer permits — which is also why
the limit travels with the key rather than staying in the application: an
implementation cannot decide atomically about a rule it was not told.

**The store counts; it does not judge.** It knows nothing about addresses,
principals, or verdicts, and every key it sees is already an opaque digest or a
canonical host.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from emailcheck.domain.abuse import BudgetKey, BudgetLayer


class QuotaStoreUnavailable(Exception):
    """The budget counters could not be reached.

    Deliberately not an `OSError` and not a `TimeoutError`: a handler written
    for a remote mail server must not catch this project's own storage, the
    treatment `RateLimitTimeout` and `AdmissionRefused` already get.
    """


@dataclass(frozen=True, slots=True)
class BudgetRequest:
    """One layer's counter, its allowance, and the window it resets on."""

    key: BudgetKey
    limit: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class QuotaDecision:
    """Whether the whole set was spent, and which layer refused if not."""

    permitted: bool
    #: The first layer that would have been exceeded. `None` when permitted.
    refused_layer: BudgetLayer | None = None

    def __post_init__(self) -> None:
        if self.permitted and self.refused_layer is not None:
            raise ValueError("a permitted decision names no refusing layer")
        if not self.permitted and self.refused_layer is None:
            raise ValueError("a refusal must name the layer that refused")


class QuotaStore(Protocol):
    async def consume(self, requests: Sequence[BudgetRequest], *, now: float) -> QuotaDecision:
        """Spend one unit against every request, or spend nothing at all.

        `now` is epoch seconds, supplied by the caller's `Clock`, so a window
        boundary is testable without waiting for one.

        Raises `QuotaStoreUnavailable` when the counters cannot be reached.
        """
        ...

    async def purge_expired(self, *, now: float) -> int:
        """Drop counters whose window has ended. Returns how many went."""
        ...
