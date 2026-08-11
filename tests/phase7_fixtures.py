"""Fakes for the Phase 7 abuse, privacy, and observability tests.

Every one is deterministic and opens no socket. The two that matter most are
counters rather than stubs — `RecordingOperator` and `InMemoryMetrics` are the
surfaces `prompts/07-hardening.md`'s privacy requirement is *measured* on, so
they keep what they were given rather than discarding it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from emailcheck.domain.abuse import QuotaSettings
from emailcheck.domain.address import (
    AddressAccepted,
    NormalizedAddress,
    RawAddressInput,
    parse_address,
)
from emailcheck.domain.principal import Principal
from emailcheck.domain.source import SourceIdentity
from emailcheck.ports.metrics import MetricLabels, MetricName
from emailcheck.ports.observability import OperatorEvent
from emailcheck.ports.quota import BudgetRequest, QuotaDecision, QuotaStoreUnavailable

CORRELATION_KEY = b"correlation-secret-of-thirty-two"
ACCOUNT = "acct-1"
KEY_ID = "a" * 32
OTHER_KEY_ID = "b" * 32

PRINCIPAL = Principal(account_id=ACCOUNT, key_id=KEY_ID)
SAME_ACCOUNT_OTHER_KEY = Principal(account_id=ACCOUNT, key_id=OTHER_KEY_ID)
OTHER_PRINCIPAL = Principal(account_id="acct-2", key_id="c" * 32)

SOURCE = SourceIdentity("198.51.100.7")
OTHER_SOURCE = SourceIdentity("198.51.100.8")

#: Every scenario carries its own outer bound, so a gate that waits when it
#: should refuse fails rather than hanging the suite.
OUTER_BOUND = 5.0


def target(address: str = "user@example.test") -> NormalizedAddress:
    """A parsed address, through the real Phase 1 parser."""
    parsed = parse_address(RawAddressInput(address))
    assert isinstance(parsed, AddressAccepted), address
    return parsed.address


@dataclass(slots=True)
class SteppableClock:
    """A `Clock` a test moves deliberately.

    Window boundaries are the whole point of a fixed-window budget, so they are
    crossed by advancing this rather than by waiting for one.
    """

    current: datetime = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current = self.current + timedelta(seconds=seconds)


@dataclass(slots=True)
class RecordingOperator:
    """Keeps every operator event, so a privacy scan has something to read."""

    events: list[OperatorEvent] = field(default_factory=list)

    def record(self, event: OperatorEvent) -> None:
        self.events.append(event)

    @property
    def details(self) -> tuple[str, ...]:
        return tuple(event.detail or "" for event in self.events)

    def rendered(self) -> str:
        return " ".join(repr(event) for event in self.events)


@dataclass(slots=True)
class BrokenOperator:
    """An operator sink that fails. Telemetry must never change a verdict."""

    calls: int = 0

    def record(self, event: OperatorEvent) -> None:
        self.calls += 1
        raise RuntimeError("the operator sink is unavailable")


@dataclass(slots=True)
class BrokenMetrics:
    """A metrics sink that fails, for the same reason."""

    calls: int = 0

    def increment(self, name: MetricName, *, labels: MetricLabels | None = None) -> None:
        self.calls += 1
        raise RuntimeError("the metrics sink is unavailable")

    def observe(
        self, name: MetricName, value: float, *, labels: MetricLabels | None = None
    ) -> None:
        self.calls += 1
        raise RuntimeError("the metrics sink is unavailable")


@dataclass(slots=True)
class CountingQuotaStore:
    """A quota store that records what it was asked, and can be made to fail.

    Wraps nothing: the real `InProcessQuotaStore` is used where the *arithmetic*
    matters, and this is used where the question is which requests the guard
    built and in what order.
    """

    decisions: list[QuotaDecision] = field(default_factory=list)
    seen: list[tuple[BudgetRequest, ...]] = field(default_factory=list)
    unavailable: bool = False
    #: When set, `consume` refuses naming this layer without spending anything.
    refuse_layer: object = None
    purges: int = 0

    async def consume(self, requests: Sequence[BudgetRequest], *, now: float) -> QuotaDecision:
        if self.unavailable:
            raise QuotaStoreUnavailable("unavailable")
        self.seen.append(tuple(requests))
        if self.refuse_layer is not None:
            for request in requests:
                if request.key.layer is self.refuse_layer:
                    decision = QuotaDecision(permitted=False, refused_layer=request.key.layer)
                    self.decisions.append(decision)
                    return decision
        decision = QuotaDecision(permitted=True)
        self.decisions.append(decision)
        return decision

    async def purge_expired(self, *, now: float) -> int:
        self.purges += 1
        return 0

    @property
    def layers_seen(self) -> tuple[tuple[str, ...], ...]:
        return tuple(tuple(request.key.layer.value for request in batch) for batch in self.seen)


def quota_settings(**overrides: object) -> QuotaSettings:
    """Settings whose limits are small enough to reach inside a test."""
    base: dict[str, object] = {
        "window_seconds": 60,
        "per_api_key": 3,
        "per_account": 4,
        "per_source_ip": 5,
        "per_target": 2,
        "per_target_domain": 6,
        "per_target_mx": 6,
        "per_sender_identity": 7,
        "daily_total": 8,
    }
    base.update(overrides)
    return QuotaSettings(**base)  # type: ignore[arg-type]
