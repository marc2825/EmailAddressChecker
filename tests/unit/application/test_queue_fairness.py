"""One principal may not have the whole admission queue. Phase 6's F11.

Phase 6 bounded the queue globally, so a caller that could issue requests faster
than they were served occupied every waiting slot and every other account was
refused **while holding no capacity at all**. The review deferred it here.

**Nothing in this file sleeps.** Occupancy is arranged by parking callers inside
the gate and measured by counting who is in it, and every scenario carries its
own outer bound so a gate that waits when it should refuse fails rather than
hanging the suite.
"""

from __future__ import annotations

import asyncio

import pytest
from tests.phase7_fixtures import OUTER_BOUND

from emailcheck.application.admission import (
    AdmissionControl,
    AdmissionError,
    AdmissionRefused,
    AdmissionSettings,
)

#: Marked per test rather than for the module: the settings tests below are
#: synchronous, and a module-level mark on them is a warning per run.
asyncio_test = pytest.mark.asyncio

NOISY = "acct-noisy"
QUIET = "acct-quiet"


def gate(**overrides: int | None) -> AdmissionControl:
    settings: dict[str, int | None] = {
        "max_in_flight": 2,
        "max_waiting": 8,
        "max_per_principal": 2,
        "max_queued_per_principal": 3,
    }
    settings.update(overrides)
    return AdmissionControl(settings=AdmissionSettings(**settings))  # type: ignore[arg-type]


class Parked:
    """Callers held inside or in front of the gate, released at the end."""

    def __init__(self) -> None:
        self.tasks: list[asyncio.Task[None]] = []

    def add(self, control: AdmissionControl, account: str) -> asyncio.Task[None]:
        async def hold() -> None:
            async with control.admit(account):
                await asyncio.Event().wait()

        task = asyncio.ensure_future(hold())
        self.tasks.append(task)
        return task

    async def settle(self) -> None:
        """Let every pending task reach its next suspension point."""
        for _ in range(4):
            await asyncio.sleep(0)

    async def release(self) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


# --- the property ------------------------------------------------------------


@asyncio_test
async def test_one_principal_cannot_take_more_than_its_share_of_the_queue() -> None:
    control = gate()
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()
            assert control.in_flight == 2

            outcomes = [parked.add(control, NOISY) for _ in range(6)]
            await parked.settle()

            queued = sum(1 for task in outcomes if not task.done())
            rejected = sum(
                1
                for task in outcomes
                if task.done() and isinstance(task.exception(), AdmissionRefused)
            )
            assert queued == 3, "the noisy caller held more than its share"
            assert rejected == 3
            assert control.queued_by(NOISY) == 3
    finally:
        await parked.release()


@asyncio_test
async def test_a_quiet_principal_is_still_admitted_while_capacity_remains() -> None:
    """The whole point. A build without the share leaves this caller refused."""
    control = gate()
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()
            for _ in range(6):
                parked.add(control, NOISY)
            await parked.settle()

            quiet = parked.add(control, QUIET)
            await parked.settle()

            assert not quiet.done(), "the quiet caller was refused by the noisy one's queueing"
            assert control.queued_by(QUIET) == 1
            assert control.waiting < control.settings.max_waiting
    finally:
        await parked.release()


@asyncio_test
async def test_a_queue_slot_is_released_when_a_waiter_is_cancelled() -> None:
    """A share that is not given back is capacity removed permanently — the
    shape the Phase 4E review found in a concurrency slot, and the same fix."""
    control = gate()
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()
            waiter = parked.add(control, NOISY)
            await parked.settle()
            assert control.queued_by(NOISY) == 1

            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
            await parked.settle()
            assert control.queued_by(NOISY) == 0
    finally:
        await parked.release()


@asyncio_test
async def test_the_share_is_forgotten_at_zero_rather_than_kept() -> None:
    """A counter keyed by account that is never deleted grows with the number of
    accounts that have ever queued — a memory leak with a remote trigger."""
    control = gate()
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()
            waiter = parked.add(control, QUIET)
            await parked.settle()
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
            await parked.settle()
            assert QUIET not in control._queued_per_principal
    finally:
        await parked.release()


@asyncio_test
async def test_the_global_queue_bound_still_applies() -> None:
    """The share is *inside* the queue bound, not instead of it: enough distinct
    accounts must still fill the queue and be refused."""
    control = gate(max_waiting=4, max_queued_per_principal=3)
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()
            for index in range(4):
                parked.add(control, f"acct-{index}")
            await parked.settle()
            assert control.waiting == 4

            late = parked.add(control, "acct-late")
            await parked.settle()
            assert late.done() and isinstance(late.exception(), AdmissionRefused)
    finally:
        await parked.release()


# --- the setting -------------------------------------------------------------


def test_an_unset_share_is_derived_from_the_queue_and_is_always_a_real_bound() -> None:
    """A fixed default larger than a short queue would bound nothing, and
    refusing configurations that already chose a queue length was the only other
    honest option."""
    for waiting in (1, 2, 7, 8, 9, 32, 4096):
        settings = AdmissionSettings(max_waiting=waiting)
        assert 1 <= settings.queue_share <= waiting


def test_an_explicit_share_above_the_queue_is_refused() -> None:
    with pytest.raises(AdmissionError):
        AdmissionSettings(max_waiting=4, max_queued_per_principal=5)


@pytest.mark.parametrize("value", [0, -1, True, 4097], ids=["zero", "negative", "boolean", "huge"])
def test_an_unusable_share_is_refused(value: object) -> None:
    with pytest.raises(AdmissionError):
        AdmissionSettings(max_waiting=4096, max_queued_per_principal=value)  # type: ignore[arg-type]


@asyncio_test
async def test_the_derived_share_protects_a_quiet_principal_too() -> None:
    """The same property, with `max_queued_per_principal` **unset**.

    Every other test here sets the share explicitly, so all of them passed when
    a mutation made the derived default equal to the whole queue — the
    configuration a deployment that tunes nothing actually runs. A mutation
    matrix found it.
    """
    control = AdmissionControl(
        settings=AdmissionSettings(max_in_flight=2, max_waiting=32, max_per_principal=2)
    )
    assert control.settings.max_queued_per_principal is None
    parked = Parked()
    try:
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(2):
                parked.add(control, NOISY)
            await parked.settle()

            outcomes = [parked.add(control, NOISY) for _ in range(32)]
            await parked.settle()

            queued = sum(1 for task in outcomes if not task.done())
            assert queued < 32, "one principal filled the whole derived queue"
            assert control.waiting < control.settings.max_waiting

            quiet = parked.add(control, QUIET)
            await parked.settle()
            assert not quiet.done(), "the quiet caller was crowded out"
    finally:
        await parked.release()
