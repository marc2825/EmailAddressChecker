"""The in-memory executor: every dimension bounded, and cancellation real.

`docs/architecture.md` asks for a memory executor for tests. An executor is
where unboundedness hides, so these tests are mostly about refusals — and about
the one behaviour a job system either has or does not: cancelling a *running*
job must reach the coroutine, not merely mark a flag.

No test here sleeps. Waiting is the `Sleeper` port, so "twenty minutes later" is
a measurement.
"""

from __future__ import annotations

import asyncio

import pytest
from tests.phase6_fixtures import AdvancingSleeper, FakeMonotonicClock, HoldingSleeper

from emailcheck.adapters.execution.memory_executor import (
    ExecutorError,
    ExecutorNotRunning,
    ExecutorSettings,
    InMemoryJobExecutor,
)
from emailcheck.domain.job import JobId
from emailcheck.ports.job_executor import ExecutorFull

pytestmark = pytest.mark.asyncio

OUTER_BOUND = 5.0


def job(index: int) -> JobId:
    return JobId(f"job-{index:04d}".ljust(24, "x"))


def build(**kwargs: int) -> tuple[InMemoryJobExecutor, FakeMonotonicClock, AdvancingSleeper]:
    clock = FakeMonotonicClock()
    sleeper = AdvancingSleeper(clock=clock)
    executor = InMemoryJobExecutor(
        clock=clock, sleeper=sleeper, settings=ExecutorSettings(**kwargs)
    )
    return executor, clock, sleeper


# --- configuration ----------------------------------------------------------


@pytest.mark.parametrize(
    "settings",
    [
        {"max_workers": 0},
        {"max_workers": -1},
        {"max_workers": True},
        {"max_workers": 10_000},
        {"max_queued": 0},
        {"max_queued": 1_000_000},
        {"max_delayed": 0},
        {"max_delayed": 1_000_000},
    ],
)
async def test_a_bound_that_is_not_a_bound_is_refused(settings: dict[str, int]) -> None:
    with pytest.raises(ExecutorError):
        ExecutorSettings(**settings)


async def test_an_executor_that_was_never_started_accepts_nothing() -> None:
    """A submission that quietly vanished would be a job nobody ever runs."""
    executor, _, _ = build()
    with pytest.raises(ExecutorNotRunning):
        await executor.submit(job(1), _never)


async def test_it_is_not_an_isolated_worker_and_says_so() -> None:
    """`docs/requirements.md` section 15 requires an isolated worker for the
    service-active profile. This one shares the API process and dies with it."""
    executor, _, _ = build()
    assert executor.is_isolated is False


# --- bounds -----------------------------------------------------------------


async def test_no_more_than_max_workers_run_at_once() -> None:
    """Measured by counting who is inside, not by trusting the pool."""
    executor, _, _ = build(max_workers=2, max_queued=16)
    executor.start()
    inside = 0
    peak = 0
    release = asyncio.Event()

    async def work() -> None:
        nonlocal inside, peak
        inside += 1
        peak = max(peak, inside)
        await release.wait()
        inside -= 1

    try:
        async with asyncio.timeout(OUTER_BOUND):
            for index in range(6):
                await executor.submit(job(index), work)
            for _ in range(8):
                await asyncio.sleep(0)
            assert inside == 2
            release.set()
            # A fixed number of turns rather than a condition loop: the queue
            # draining is what is being observed, so waiting on it would be
            # waiting on the thing under test.
            for _ in range(24):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert peak == 2


async def test_a_full_queue_refuses_rather_than_growing() -> None:
    """A bounded pool behind an unbounded queue moves the growth rather than
    stopping it."""
    executor, _, _ = build(max_workers=1, max_queued=2)
    executor.start()
    release = asyncio.Event()

    async def work() -> None:
        await release.wait()

    try:
        async with asyncio.timeout(OUTER_BOUND):
            for index in range(3):
                await executor.submit(job(index), work)
                await asyncio.sleep(0)
            with pytest.raises(ExecutorFull):
                for index in range(3, 40):
                    await executor.submit(job(index), work)
            release.set()
    finally:
        await executor.aclose()


async def test_a_full_delay_set_refuses_rather_than_growing() -> None:
    executor, _, _ = build(max_workers=1, max_queued=4, max_delayed=2)
    executor.start()
    try:
        await executor.schedule(job(1), _never, delay_seconds=600)
        await executor.schedule(job(2), _never, delay_seconds=600)
        with pytest.raises(ExecutorFull):
            await executor.schedule(job(3), _never, delay_seconds=600)
        assert executor.delayed == 2
    finally:
        await executor.aclose()


# --- delays hold no worker --------------------------------------------------


async def test_a_delayed_job_runs_after_the_delay_and_holds_no_worker() -> None:
    """`docs/requirements.md` section 14 measures a retry delay in minutes.

    A handful of retrying jobs holding workers for twenty minutes each is a pool
    that stops serving, so the delay set is owned by a scheduler and the workers
    stay free. The twenty minutes is a fake clock's, not CI's.
    """
    executor, clock, sleeper = build(max_workers=1, max_queued=4, max_delayed=4)
    executor.start()
    ran: list[str] = []

    async def work() -> None:
        ran.append("delayed")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.schedule(job(1), work, delay_seconds=1200)
            for _ in range(12):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    # The wait went through the `Sleeper` port, for exactly the delay asked
    # for, and the whole twenty minutes cost this test nothing.
    assert sleeper.slept == [1200]
    assert clock.current == 1200
    assert ran == ["delayed"]


async def test_a_delayed_job_occupies_no_worker_while_it_waits() -> None:
    """The reason the delay set exists rather than a `sleep` inside a worker.

    `AdvancingSleeper` cannot show this — its wait is over before the test can
    look — so the scheduler is parked on a sleeper that never returns, and the
    single worker is shown serving somebody else meanwhile.
    """
    clock = FakeMonotonicClock()
    sleeper = HoldingSleeper()
    executor = InMemoryJobExecutor(
        clock=clock, sleeper=sleeper, settings=ExecutorSettings(max_workers=1, max_queued=4)
    )
    executor.start()
    ran: list[str] = []

    async def delayed() -> None:  # pragma: no cover - parked for the whole test
        ran.append("delayed")

    async def immediate() -> None:
        ran.append("immediate")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.schedule(job(1), delayed, delay_seconds=1200)
            await executor.submit(job(2), immediate)
            for _ in range(10):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert sleeper.requested == [1200]
    assert executor.delayed == 0  # cleared by `aclose`
    assert ran == ["immediate"]


async def test_a_zero_delay_is_an_ordinary_submission() -> None:
    executor, _, sleeper = build(max_workers=1, max_queued=4)
    executor.start()
    ran: list[str] = []

    async def work() -> None:
        ran.append("now")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.schedule(job(1), work, delay_seconds=0)
            for _ in range(6):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert ran == ["now"]
    assert sleeper.slept == []


# --- cancellation -----------------------------------------------------------


async def test_cancelling_a_running_job_reaches_the_coroutine() -> None:
    """The property a job system either has or does not.

    A flag that only stops the *next* step leaves the SMTP dialogue running, the
    admission permit held, and the socket open. This asserts the cancellation
    arrives inside the awaited body.
    """
    executor, _, _ = build(max_workers=1, max_queued=4)
    executor.start()
    started = asyncio.Event()
    cancelled = asyncio.Event()
    completed = False

    async def work() -> None:
        nonlocal completed
        started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        completed = True

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.submit(job(1), work)
            await started.wait()
            assert await executor.cancel(job(1)) is True
            await cancelled.wait()
            for _ in range(4):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert completed is False


async def test_the_pool_keeps_serving_after_a_job_is_cancelled() -> None:
    """A cancellation aimed at one job must not kill the worker that ran it."""
    executor, _, _ = build(max_workers=1, max_queued=8)
    executor.start()
    started = asyncio.Event()
    ran: list[str] = []

    async def blocking() -> None:
        started.set()
        await asyncio.sleep(3600)

    async def later() -> None:
        ran.append("later")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.submit(job(1), blocking)
            await started.wait()
            await executor.submit(job(2), later)
            await executor.cancel(job(1))
            for _ in range(10):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert ran == ["later"]


async def test_cancelling_a_queued_job_stops_it_from_ever_running() -> None:
    executor, _, _ = build(max_workers=1, max_queued=8)
    executor.start()
    release = asyncio.Event()
    ran: list[str] = []

    async def blocking() -> None:
        await release.wait()

    async def second() -> None:
        ran.append("second")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.submit(job(1), blocking)
            await asyncio.sleep(0)
            await executor.submit(job(2), second)
            assert await executor.cancel(job(2)) is True
            release.set()
            for _ in range(10):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert ran == []


async def test_cancelling_a_delayed_job_removes_it_from_the_delay_set() -> None:
    executor, _, _ = build(max_workers=1, max_queued=4, max_delayed=4)
    executor.start()
    try:
        await executor.schedule(job(1), _never, delay_seconds=600)
        assert executor.delayed == 1
        assert await executor.cancel(job(1)) is True
        assert executor.delayed == 0
    finally:
        await executor.aclose()


async def test_cancelling_something_unknown_reports_that_nothing_was_stopped() -> None:
    executor, _, _ = build()
    executor.start()
    try:
        assert await executor.cancel(job(99)) is False
    finally:
        await executor.aclose()


# --- failure containment and shutdown ---------------------------------------


async def test_a_job_that_raises_does_not_stop_the_pool() -> None:
    """A pool that dies on one bad job stops every other one."""
    executor, _, _ = build(max_workers=1, max_queued=8)
    executor.start()
    ran: list[str] = []

    async def explodes() -> None:
        raise RuntimeError("a job's own failure handling broke")

    async def afterwards() -> None:
        ran.append("afterwards")

    try:
        async with asyncio.timeout(OUTER_BOUND):
            await executor.submit(job(1), explodes)
            await executor.submit(job(2), afterwards)
            for _ in range(10):
                await asyncio.sleep(0)
    finally:
        await executor.aclose()

    assert ran == ["afterwards"]


async def test_closing_stops_every_task_including_the_running_one() -> None:
    """Explicit rather than best effort: a worker left running holds an
    admission permit and possibly an open socket."""
    executor, _, _ = build(max_workers=2, max_queued=4)
    executor.start()
    started = asyncio.Event()

    async def blocking() -> None:
        started.set()
        await asyncio.sleep(3600)

    async with asyncio.timeout(OUTER_BOUND):
        await executor.submit(job(1), blocking)
        await started.wait()
        await executor.aclose()

    assert executor.delayed == 0
    assert all(task.done() for task in _tasks_of(executor))


async def test_starting_twice_creates_no_second_pool() -> None:
    executor, _, _ = build(max_workers=2)
    executor.start()
    first = list(_tasks_of(executor))
    executor.start()
    try:
        assert list(_tasks_of(executor)) == first
    finally:
        await executor.aclose()


async def _never() -> None:  # pragma: no cover - scheduled but never reached
    await asyncio.sleep(3600)


def _tasks_of(executor: InMemoryJobExecutor) -> list[asyncio.Task[None]]:
    tasks = list(executor._workers)
    if executor._scheduler is not None:
        tasks.append(executor._scheduler)
    return tasks
