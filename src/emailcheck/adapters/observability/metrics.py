"""Metrics held in this process, and metrics thrown away.

Two implementations of `ports/metrics.py`, because a deployment needs one and a
test needs the other to be measurable.

`InMemoryMetrics` keeps counters and observation summaries in a dictionary. It
is the development sink and the one tests assert on — `docs/threat-model.md`
requires that full addresses are absent from captured metrics, and that is a
scan over something real rather than a claim.

`NullMetrics` records nothing, and exists so that every component can take a
sink unconditionally instead of writing `if self.metrics is not None` at each
call site. An optional collaborator is one that is sometimes absent and
therefore sometimes untested.

**Neither raises.** `ports/metrics.py` says so and it matters: a monitoring
failure that propagated would turn an observability problem into a verification
failure, which is the inversion `docs/architecture.md` section 5 exists to
prevent. Anything unexpected is dropped, because the alternative is worse.

**Bounded, because the label set is.** The number of series is the number of
`(name, subject, outcome)` triples the enumerations permit — a fixed number
known at import, not a function of traffic. There is no eviction here because
there is nothing to evict.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from emailcheck.ports.metrics import MetricLabels, MetricName


@dataclass(frozen=True, slots=True)
class Observation:
    """A summary of one measured series. Never the individual values.

    Keeping every sample would make memory a function of traffic; a count, a
    total, and the extremes answer what `docs/threat-model.md` asks of
    latency without that.
    """

    count: int = 0
    total: float = 0.0
    minimum: float | None = None
    maximum: float | None = None

    def merged(self, value: float) -> Observation:
        return Observation(
            count=self.count + 1,
            total=self.total + value,
            minimum=value if self.minimum is None else min(self.minimum, value),
            maximum=value if self.maximum is None else max(self.maximum, value),
        )


#: One series' identity: the metric and its two bounded labels.
SeriesKey = tuple[str, str | None, str | None]


@dataclass(slots=True)
class InMemoryMetrics:
    """Counters and summaries for one process."""

    counters: dict[SeriesKey, int] = field(default_factory=dict)
    observations: dict[SeriesKey, Observation] = field(default_factory=dict)

    def increment(self, name: MetricName, *, labels: MetricLabels | None = None) -> None:
        try:
            key = _key(name, labels)
        except Exception:
            return
        self.counters[key] = self.counters.get(key, 0) + 1

    def observe(
        self, name: MetricName, value: float, *, labels: MetricLabels | None = None
    ) -> None:
        try:
            key = _key(name, labels)
            if isinstance(value, bool) or not isinstance(value, int | float):
                return
            numeric = float(value)
            if numeric != numeric:  # NaN would poison every later summary.
                return
        except Exception:
            return
        self.observations[key] = self.observations.get(key, Observation()).merged(numeric)

    def counter(self, name: MetricName, *, labels: MetricLabels | None = None) -> int:
        """What one counter holds. For tests and for an admin summary."""
        return self.counters.get(_key(name, labels), 0)

    def rendered_keys(self) -> tuple[str, ...]:
        """Every series identity, as text.

        The surface a privacy scan reads: if an address ever reached a label,
        this is where it would be visible.
        """
        keys = set(self.counters) | set(self.observations)
        return tuple(sorted("|".join(part or "" for part in key) for key in keys))


@dataclass(frozen=True, slots=True)
class NullMetrics:
    """Records nothing, so no component needs an optional sink."""

    def increment(self, name: MetricName, *, labels: MetricLabels | None = None) -> None:
        return None

    def observe(
        self, name: MetricName, value: float, *, labels: MetricLabels | None = None
    ) -> None:
        return None


def _key(name: MetricName, labels: MetricLabels | None) -> SeriesKey:
    if not isinstance(name, MetricName):
        raise ValueError("a metric must name a published measurement")
    if labels is None:
        return (name.value, None, None)
    outcome = None if labels.outcome is None else labels.outcome.value
    return (name.value, labels.subject, outcome)
