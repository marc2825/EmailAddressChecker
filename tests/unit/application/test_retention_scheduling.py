"""Retention that actually runs, drains, isolates failures, and stops.

`RetentionService` existed since Phase 7 and `composition.py` called it from
nowhere, so every window in `docs/privacy.md` was enforced by an operator
remembering. The final system audit found that, plus three ways the sweep itself
was wrong once something did call it: already-cleared batches were selected for
ever and starved later ones, the cleared count counted selections rather than
changes, and one unreachable store skipped every store after it.

The tests here are about the *sweep and the schedule*.
`tests/unit/application/test_retention.py` keeps the Phase 7 policy tests, and
`tests/unit/test_composition.py` pins which profiles get a scheduler at all.

Nothing here opens a socket, and nothing waits: the interval is measured with a
controlled `Sleeper` rather than by sleeping.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.storage.sqlite_batch_store import SQLiteBatchStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl
from emailcheck.application.retention import (
    MIN_RETENTION_INTERVAL_SECONDS,
    RetentionError,
    RetentionScheduler,
    RetentionService,
    RetentionSettings,
)
from emailcheck.domain.batch import BatchLimits, BatchRowState, BatchSettings
from emailcheck.ports.batch_store import StoredBatch, StoredBatchRow

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 5.0
NOW: Final = datetime.fromisoformat("2026-08-17T12:00:00+00:00")
ADDRESS: Final = "someone@example.test"


@dataclass(slots=True)
class SteppableSleeper:
    """Sleeps until a test releases it, and records what it was asked for.

    Two properties the scheduler tests need and a returns-immediately fake
    cannot give: an interval that is *measured* rather than waited, and a task
    that is genuinely parked so shutdown has something to cancel.
    """

    requested: list[float] = field(default_factory=list)
    gate: asyncio.Event = field(default_factory=asyncio.Event)
    entered: asyncio.Event = field(default_factory=asyncio.Event)

    async def sleep(self, seconds: float) -> None:
        self.requested.append(seconds)
        self.entered.set()
        await self.gate.wait()
        self.gate.clear()

    async def release_one(self) -> None:
        """Let exactly one sleep return, then wait for the next to be entered."""
        self.entered.clear()
        self.gate.set()
        async with asyncio.timeout(OUTER_BOUND):
            await self.entered.wait()


@dataclass(slots=True)
class ScriptedStore:
    """A verdict store that removes what it is told, or fails."""

    removals: list[int] = field(default_factory=list)
    fail: bool = False
    calls: int = 0

    async def purge_expired(self, *, now: datetime, limit: int) -> int:
        self.calls += 1
        if self.fail:
            raise RuntimeError("the store is unavailable at /var/db/verdicts.sqlite")
        return self.removals.pop(0) if self.removals else 0


@dataclass(slots=True)
class ScriptedBatches:
    """A batch store whose two operations fail and count independently."""

    forgotten: list[int] = field(default_factory=list)
    purged: list[int] = field(default_factory=list)
    fail_forget: bool = False
    fail_purge: bool = False
    forget_calls: int = 0
    purge_calls: int = 0

    async def forget_inputs(self, *, before: datetime, limit: int) -> int:
        self.forget_calls += 1
        if self.fail_forget:
            raise RuntimeError("the batch database is unavailable at /var/db/batches.sqlite")
        return self.forgotten.pop(0) if self.forgotten else 0

    async def purge_expired(self, *, now: datetime, limit: int) -> int:
        self.purge_calls += 1
        if self.fail_purge:
            raise RuntimeError("the batch database is unavailable")
        return self.purged.pop(0) if self.purged else 0


def build(**overrides: object) -> tuple[RetentionService, RecordingOperator]:
    metrics = InMemoryMetrics()
    clock = SteppableClock()
    operator = RecordingOperator()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    service = RetentionService(
        clock=clock,
        admin=admin,
        settings=RetentionSettings(batch_limit=2),
        **overrides,  # type: ignore[arg-type]
    )
    return service, operator


# --- the periodic runner -----------------------------------------------------


@asyncio_test
async def test_the_scheduler_sweeps_on_the_configured_interval() -> None:
    """The gap the final system audit named: nothing ever called `run`.

    The interval is asserted as the number handed to the `Sleeper`, so this
    measures twenty-five minutes without waiting them — the same technique the
    Phase 4 pacing tests use.
    """
    store = ScriptedStore(removals=[1, 1])
    service, operator = build(store=store)
    sleeper = SteppableSleeper()
    scheduler = RetentionScheduler(
        service=service,
        sleeper=sleeper,
        operator=operator,
        settings=RetentionSettings(batch_limit=2, interval_seconds=25 * 60),
    )

    scheduler.start()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await sleeper.entered.wait()
            assert store.calls == 0, "a sweep ran before the first interval elapsed"
            await sleeper.release_one()
            assert store.calls == 1
            await sleeper.release_one()
            assert store.calls == 2
    finally:
        await scheduler.aclose()

    assert sleeper.requested[:2] == [25 * 60.0, 25 * 60.0]


@asyncio_test
async def test_the_scheduler_stops_cleanly_and_sweeps_nothing_afterwards() -> None:
    """A sweep left running after shutdown holds a connection and can delete a
    row a test has already asserted about."""
    store = ScriptedStore()
    service, operator = build(store=store)
    sleeper = SteppableSleeper()
    scheduler = RetentionScheduler(service=service, sleeper=sleeper, operator=operator)

    scheduler.start()
    async with asyncio.timeout(OUTER_BOUND):
        await sleeper.entered.wait()
    task = scheduler._task
    assert task is not None

    await scheduler.aclose()

    assert task.done(), "the retention task outlived the stack"
    swept = store.calls
    sleeper.gate.set()
    await asyncio.sleep(0)
    assert store.calls == swept, "a sweep ran after shutdown"
    # Idempotent, and a stopped scheduler does not restart itself.
    await scheduler.aclose()
    scheduler.start()
    assert scheduler._task is None


@asyncio_test
async def test_one_failed_sweep_does_not_end_the_schedule() -> None:
    """Fail-stop here would make one unreachable store a permanent silent halt
    of the thing that enforces the operator's retention policy."""
    store = ScriptedStore(fail=True)
    service, operator = build(store=store)
    sleeper = SteppableSleeper()
    scheduler = RetentionScheduler(service=service, sleeper=sleeper, operator=operator)

    scheduler.start()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await sleeper.entered.wait()
            await sleeper.release_one()
            assert store.calls == 1
            store.fail = False
            store.removals = [1]
            await sleeper.release_one()
    finally:
        await scheduler.aclose()

    assert store.calls == 2, "the schedule died after one failed sweep"
    assert any("retention" in event.detail for event in operator.events if event.detail)


@dataclass(slots=True)
class BrokenSweep:
    """A `RetentionService` whose `run` raises rather than reports.

    `run` is written not to raise, so a store failure alone cannot reach
    `RetentionScheduler._sweep`'s handler — the mutation that removes it stays
    inert against a merely-failing store. What can reach it is a collaborator
    *outside* the per-store handlers: the audit ring, the metrics sink, a bug
    here. This stands in for that, which is the only way the runner's own
    survival is measured rather than assumed.
    """

    calls: int = 0

    async def run(self) -> object:
        self.calls += 1
        raise RuntimeError("the audit sink is unavailable at /var/log/emailcheck")


@asyncio_test
async def test_the_runner_survives_a_sweep_that_raises_rather_than_reports() -> None:
    """Run n raising must not stop run n+1."""
    broken = BrokenSweep()
    _, operator = build()
    sleeper = SteppableSleeper()
    scheduler = RetentionScheduler(
        service=broken,  # type: ignore[arg-type]
        sleeper=sleeper,
        operator=operator,
    )

    scheduler.start()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await sleeper.entered.wait()
            await sleeper.release_one()
            await sleeper.release_one()
    finally:
        await scheduler.aclose()

    assert broken.calls == 2, "the schedule died on a sweep that raised"
    details = [event.detail for event in operator.events if event.detail]
    assert "retention sweep" in details
    assert not any("/var/log" in detail for detail in details)


@asyncio_test
async def test_a_backlog_is_drained_across_bounded_passes_rather_than_one_per_tick() -> None:
    """`more_remaining` exists so a scheduler need not wait a whole interval,
    and the pass bound is what stops that becoming a tight loop."""
    store = ScriptedStore(removals=[2, 2, 2, 2, 2, 2])
    service, operator = build(store=store)
    sleeper = SteppableSleeper()
    scheduler = RetentionScheduler(
        service=service,
        sleeper=sleeper,
        operator=operator,
        settings=RetentionSettings(batch_limit=2),
    )

    scheduler.start()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await sleeper.entered.wait()
            await sleeper.release_one()
    finally:
        await scheduler.aclose()

    assert store.calls == 4, "the drain is not bounded at four passes per interval"


def test_the_interval_is_a_validated_operator_bound() -> None:
    """Not caller-controlled, positive, and never sub-minute polling."""
    assert RetentionSettings().interval_seconds == 15 * 60
    with pytest.raises(RetentionError, match="polling"):
        RetentionSettings(interval_seconds=MIN_RETENTION_INTERVAL_SECONDS - 1)
    for bad in (0, -1, True, 25 * 60 * 60):
        with pytest.raises(RetentionError):
            RetentionSettings(interval_seconds=bad)  # type: ignore[arg-type]


# --- per-store failure isolation ---------------------------------------------


@asyncio_test
async def test_one_failing_store_does_not_suppress_the_others() -> None:
    """The audit's observation: one `try` around every store meant the first
    exception skipped all the rest, and the report said only "failed"."""
    store = ScriptedStore(fail=True)
    batches = ScriptedBatches(forgotten=[1], purged=[1])
    quota = CountingQuotaStore()
    service, _ = build(store=store, batches=batches, quota=quota)

    report = await service.run()

    assert report.failed is True
    assert report.failed_stores == ("verdicts",)
    # Every later store still ran, and counted.
    assert batches.forget_calls == 1 and batches.purge_calls == 1
    assert report.batch_inputs_cleared == 1
    assert report.batches_removed == 1
    assert report.verdicts_removed == 0


@asyncio_test
async def test_a_failing_batch_store_leaves_the_verdict_and_quota_cleanup_alone() -> None:
    """The same property from the other direction, so the isolation is not one
    lucky ordering."""
    store = ScriptedStore(removals=[5])
    batches = ScriptedBatches(fail_forget=True, purged=[1])
    quota = CountingQuotaStore()
    service, _ = build(store=store, batches=batches, quota=quota)

    report = await service.run()

    assert report.failed_stores == ("batch_inputs",)
    assert report.verdicts_removed == 5
    assert report.batches_removed == 1, "a failed forget suppressed the batch purge"
    assert batches.purge_calls == 1


@asyncio_test
async def test_a_failure_report_names_categories_and_never_an_exception_message() -> None:
    """The store messages above carry a filesystem path on purpose."""
    store = ScriptedStore(fail=True)
    batches = ScriptedBatches(fail_forget=True)
    service, _ = build(store=store, batches=batches)

    report = await service.run()

    assert set(report.failed_stores) == {"verdicts", "batch_inputs"}
    rendered = repr(report)
    assert "/var/db" not in rendered
    assert "unavailable" not in rendered


# --- backlog reporting -------------------------------------------------------


@asyncio_test
async def test_a_batch_input_backlog_is_reported_as_more_remaining() -> None:
    """The audit's observation: `more_remaining` ignored `batch_inputs_cleared`,
    so a backlog of stale addresses reported "nothing more to do" — retention
    overrun published as completion."""
    batches = ScriptedBatches(forgotten=[2, 1])
    service, _ = build(batches=batches)

    first = await service.run()
    assert first.batch_inputs_cleared == 2
    assert first.more_remaining is True, "a full batch of cleared inputs is a backlog"

    second = await service.run()
    assert second.batch_inputs_cleared == 1
    assert second.more_remaining is False


@asyncio_test
async def test_a_failed_run_never_claims_the_backlog_is_drained() -> None:
    """A category that failed says nothing about what it still holds."""
    service, _ = build(store=ScriptedStore(fail=True))

    report = await service.run()

    assert report.failed is True
    assert report.more_remaining is True


# --- the real SQLite batch store ---------------------------------------------


def stored_batch(batch_id: str, created_at: datetime) -> StoredBatch:
    return StoredBatch(
        batch_id=batch_id,
        account="acct-1",
        created_at=created_at,
        expires_at=created_at + timedelta(days=30),
        input_rows=1,
        skipped_rows=0,
        rows=(StoredBatchRow(number=1, state=BatchRowState.QUEUED, submitted=ADDRESS),),
    )


async def seed(store: SQLiteBatchStore, batch_id: str, created_at: datetime) -> None:
    await store.save_batch(stored_batch(batch_id, created_at))


async def load(store: SQLiteBatchStore, batch_id: str) -> StoredBatch | None:
    """Read a batch back as its owner, well inside its result window."""
    return await store.load_batch(batch_id, account="acct-1", now=NOW)


@asyncio_test
async def test_an_already_cleared_batch_is_not_selected_again(tmp_path: Path) -> None:
    """`submitted IS NOT NULL` in the predicate, measured rather than read.

    Two sweeps over one stale batch: the first clears it, the second finds
    nothing to do. Without the predicate the second sweep selects the same
    already-`NULL` batch and reports work it did not do.
    """
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    await seed(store, "batch-one", NOW - timedelta(days=2))

    first = await store.forget_inputs(before=NOW, limit=10)
    second = await store.forget_inputs(before=NOW, limit=10)

    assert first == 1
    assert second == 0, "an already-cleared batch was cleared again"


@asyncio_test
async def test_a_bounded_sweep_reaches_the_second_stale_batch(tmp_path: Path) -> None:
    """The starvation regression, with the exact shape the audit described.

    Two stale batches and `limit=1`. The first sweep clears the older one; the
    second must reach the *other* one rather than re-selecting the first for
    ever. Before the fix the first batch occupied the whole budget on every run
    and the second address was retained indefinitely.
    """
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    await seed(store, "batch-older", NOW - timedelta(days=3))
    await seed(store, "batch-newer", NOW - timedelta(days=2))

    first = await store.forget_inputs(before=NOW, limit=1)
    second = await store.forget_inputs(before=NOW, limit=1)
    third = await store.forget_inputs(before=NOW, limit=1)

    assert (first, second, third) == (1, 1, 0), "a bounded sweep starved the second batch"
    for batch_id in ("batch-older", "batch-newer"):
        loaded = await load(store, batch_id)
        assert loaded is not None
        assert all(row.submitted is None for row in loaded.rows), batch_id


@asyncio_test
async def test_the_bounded_selection_takes_the_oldest_batch_first(tmp_path: Path) -> None:
    """Deterministic ordering, pinned. An unordered bounded sweep returns a
    different subset each run, which is progress nobody can reason about."""
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    # **Inserted newest-first on purpose.** SQLite's natural order is insertion
    # order, so a test that seeds oldest-first passes with or without an
    # `ORDER BY` and pins nothing — the ordering mutation stayed inert against
    # exactly that shape until this line was reversed.
    await seed(store, "aaa-newest", NOW - timedelta(days=1))
    await seed(store, "zzz-oldest", NOW - timedelta(days=5))

    assert await store.forget_inputs(before=NOW, limit=1) == 1

    oldest = await load(store, "zzz-oldest")
    newest = await load(store, "aaa-newest")
    assert oldest is not None and newest is not None
    assert all(row.submitted is None for row in oldest.rows), "the oldest was not cleared first"
    assert any(row.submitted is not None for row in newest.rows)


@asyncio_test
async def test_a_fresh_batch_is_never_cleared_and_never_counted(tmp_path: Path) -> None:
    """The cutoff still decides. A batch inside its input window keeps its
    plaintext, and contributes nothing to the count either way."""
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    await seed(store, "batch-fresh", NOW)

    cleared = await store.forget_inputs(before=NOW - timedelta(hours=1), limit=10)

    assert cleared == 0
    loaded = await load(store, "batch-fresh")
    assert loaded is not None
    assert loaded.rows[0].submitted == ADDRESS


@asyncio_test
async def test_the_batch_accounting_survives_its_cleared_plaintext(tmp_path: Path) -> None:
    """Phase 10's semantics, unchanged: clearing an input is an `UPDATE`, and
    the batch's own accounting lives under its separate expiry."""
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    await seed(store, "batch-one", NOW - timedelta(days=2))

    await store.forget_inputs(before=NOW, limit=10)

    loaded = await load(store, "batch-one")
    assert loaded is not None
    assert loaded.input_rows == 1
    assert loaded.rows[0].number == 1
    assert loaded.rows[0].state is BatchRowState.QUEUED
    assert loaded.rows[0].submitted is None


@asyncio_test
async def test_the_service_clears_plaintext_on_the_batch_input_window(tmp_path: Path) -> None:
    """End to end through `RetentionService`, so the cutoff subtracted is the
    batch settings' own rather than a second copy of the number."""
    store = SQLiteBatchStore(path=tmp_path / "batches.db")
    store.initialize()
    await seed(store, "batch-one", NOW - timedelta(hours=2))
    service, _ = build(
        batches=store,
        batch_settings=BatchSettings(
            enabled=True, limits=BatchLimits(), input_retention_seconds=3600
        ),
    )
    service.clock.current = NOW  # type: ignore[attr-defined]

    report = await service.run()

    assert report.batch_inputs_cleared == 1
    loaded = await load(store, "batch-one")
    assert loaded is not None
    assert loaded.rows[0].submitted is None
