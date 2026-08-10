"""Running jobs in this process, with every dimension bounded.

`prompts/06-api-cli.md` asks for a "memory executor for tests". This is that,
and ADR 0014 records what it may and may not be used for: it is **not** the
service-active isolated worker, and `composition.py` refuses that combination
rather than letting a development fake become the production default by
omission. `is_isolated` answers `False` and says so.

Everything here is finite, because an executor is where unboundedness hides:

| Dimension | Bound |
|---|---|
| Concurrent jobs | `max_workers` tasks, created once at `start()` |
| Queued jobs | a bounded `asyncio.Queue`; a full queue **refuses** |
| Delayed jobs | `max_delayed`; a full delay set refuses |
| Tasks | `max_workers` workers plus one scheduler, and no other |

**No `create_task` on the job path.** A worker runs a job on its own task, so
"cancel this job" is `Task.cancel()` on a task that already exists rather than a
new task per job. The worker absorbs a cancellation that targeted its current
job and goes back to the queue; a cancellation that did not — a shutdown —
propagates, which is what stops the loop.

**A delayed job holds no worker.** `docs/requirements.md` section 14 measures a
retry delay in minutes, so a handful of retrying jobs would otherwise occupy the
entire pool. One scheduler task owns the delay set, and waiting is the `Sleeper`
port, so a test measures twenty minutes without waiting twenty minutes.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from emailcheck.domain.job import JobId
from emailcheck.ports.clock import MonotonicClock, Sleeper
from emailcheck.ports.job_executor import ExecutorFull

#: Concurrent jobs, and the ceiling on that. Each running job may itself open up
#: to the Phase 4 attempt cap in SMTP connections, so the real outbound fan-out
#: is this times that cap — the same arithmetic `application/admission.py` does.
DEFAULT_MAX_WORKERS: Final = 4
MAX_WORKERS_CEILING: Final = 64

#: How many may wait for a worker. A queue longer than this is a queue nobody is
#: served from inside any deadline worth having.
DEFAULT_MAX_QUEUED: Final = 64
MAX_QUEUED_CEILING: Final = 4096

#: How many may be waiting out a retry delay at once.
DEFAULT_MAX_DELAYED: Final = 64
MAX_DELAYED_CEILING: Final = 4096

_Work = Callable[[], Awaitable[None]]


class ExecutorError(ValueError):
    """A misconfigured executor."""


class ExecutorNotRunning(RuntimeError):
    """Work was submitted to an executor that was never started, or is closed."""


@dataclass(frozen=True, slots=True)
class ExecutorSettings:
    """Every bound, validated the way every other bound in this project is."""

    max_workers: int = DEFAULT_MAX_WORKERS
    max_queued: int = DEFAULT_MAX_QUEUED
    max_delayed: int = DEFAULT_MAX_DELAYED

    def __post_init__(self) -> None:
        _check("max_workers", self.max_workers, MAX_WORKERS_CEILING)
        _check("max_queued", self.max_queued, MAX_QUEUED_CEILING)
        _check("max_delayed", self.max_delayed, MAX_DELAYED_CEILING)


def _check(name: str, value: int, ceiling: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutorError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise ExecutorError(f"{name} must be positive")
    if value > ceiling:
        raise ExecutorError(f"{name} above {ceiling} is not a bound")


@dataclass(slots=True)
class _Entry:
    job_id: JobId
    work: _Work


@dataclass(slots=True)
class InMemoryJobExecutor:
    """A bounded worker pool with a delay set. One per process."""

    clock: MonotonicClock
    sleeper: Sleeper
    settings: ExecutorSettings = field(default_factory=ExecutorSettings)

    _queue: asyncio.Queue[_Entry] | None = None
    _workers: list[asyncio.Task[None]] = field(default_factory=list)
    _scheduler: asyncio.Task[None] | None = None
    _delayed: dict[str, tuple[float, _Work]] = field(default_factory=dict)
    _accepted: set[str] = field(default_factory=set)
    _running: dict[str, asyncio.Task[None]] = field(default_factory=dict)
    _cancelling: set[str] = field(default_factory=set)
    _abandoned: set[str] = field(default_factory=set)
    _woken: asyncio.Event = field(default_factory=asyncio.Event)
    _closed: bool = False

    @property
    def is_isolated(self) -> bool:
        """`False`, and it must stay false.

        `docs/requirements.md` section 15 requires an isolated worker for the
        service-active profile. This runs inside the API process, shares its
        memory, and dies with it. Answering `True` would be the fake claiming to
        be the thing it exists to stand in for.
        """
        return False

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Create the fixed set of tasks. Idempotent."""
        if self._workers or self._closed:
            return
        self._queue = asyncio.Queue(maxsize=self.settings.max_queued)
        self._workers = [
            asyncio.create_task(self._worker(), name=f"emailcheck-job-worker-{index}")
            for index in range(self.settings.max_workers)
        ]
        self._scheduler = asyncio.create_task(
            self._schedule_loop(), name="emailcheck-job-scheduler"
        )

    async def aclose(self) -> None:
        """Stop every task, including whatever is running right now.

        Explicit rather than best effort: a worker left running holds an
        admission permit and possibly an open socket, and "the process is
        exiting anyway" is not true of a test.
        """
        self._closed = True
        tasks = [*self._workers]
        if self._scheduler is not None:
            tasks.append(self._scheduler)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._workers = []
        self._scheduler = None
        self._delayed.clear()
        self._accepted.clear()
        self._running.clear()

    # --- the port -----------------------------------------------------------

    async def submit(self, job_id: JobId, work: _Work) -> None:
        self._require_running()
        self._accept(job_id)
        self._enqueue(_Entry(job_id=job_id, work=work))

    async def schedule(self, job_id: JobId, work: _Work, *, delay_seconds: float) -> None:
        self._require_running()
        if delay_seconds <= 0:
            await self.submit(job_id, work)
            return
        if len(self._delayed) >= self.settings.max_delayed:
            raise ExecutorFull("the delayed set is at capacity")
        self._accept(job_id)
        self._delayed[job_id.value] = (self.clock.monotonic() + delay_seconds, work)
        self._wake()

    async def cancel(self, job_id: JobId) -> bool:
        """Stop `job_id` wherever it is. Returns whether anything was stopped."""
        key = job_id.value
        if key in self._delayed:
            del self._delayed[key]
            self._accepted.discard(key)
            return True
        task = self._running.get(key)
        if task is not None:
            # Recorded *before* cancelling, so the worker can tell a job
            # cancellation from a shutdown when the exception arrives.
            self._cancelling.add(key)
            task.cancel()
            return True
        if key in self._accepted:
            # Queued and not yet started. An `asyncio.Queue` has no removal, so
            # the entry is marked and skipped when a worker reaches it.
            self._abandoned.add(key)
            return True
        return False

    # --- internals ----------------------------------------------------------

    @property
    def queued(self) -> int:
        return 0 if self._queue is None else self._queue.qsize()

    @property
    def delayed(self) -> int:
        return len(self._delayed)

    def _require_running(self) -> None:
        if self._closed or self._queue is None:
            raise ExecutorNotRunning("this executor is not running")

    def _accept(self, job_id: JobId) -> None:
        if len(self._accepted) >= self.settings.max_queued + self.settings.max_delayed:
            raise ExecutorFull("the executor is at capacity")
        self._accepted.add(job_id.value)

    def _enqueue(self, entry: _Entry) -> None:
        assert self._queue is not None
        try:
            self._queue.put_nowait(entry)
        except asyncio.QueueFull:
            self._accepted.discard(entry.job_id.value)
            raise ExecutorFull("the job queue is at capacity") from None

    def _wake(self) -> None:
        """Wake the scheduler and hand the next wait a fresh event.

        Replacing rather than clearing removes the race
        `application/admission.py` documents: a waiter takes a reference, work
        arrives, and a `clear()` lands before the `wait()`.
        """
        previous = self._woken
        self._woken = asyncio.Event()
        previous.set()

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            entry = await self._queue.get()
            try:
                await self._run(entry)
            finally:
                self._queue.task_done()

    async def _run(self, entry: _Entry) -> None:
        key = entry.job_id.value
        if key in self._abandoned:
            self._abandoned.discard(key)
            self._accepted.discard(key)
            return
        task = asyncio.current_task()
        self._running[key] = task  # type: ignore[assignment]
        try:
            await entry.work()
        except asyncio.CancelledError:
            if key in self._cancelling:
                # This cancellation targeted the job, not this worker. Absorbed
                # so the worker returns to the queue; `uncancel` clears the
                # request so the next `await` is not cancelled again.
                self._cancelling.discard(key)
                if task is not None:
                    task.uncancel()
                return
            raise
        except Exception:
            # A job's own failure handling records `failed`. Reaching here means
            # that handling itself broke; the worker survives, because a pool
            # that dies on one bad job stops every other one.
            return
        finally:
            self._running.pop(key, None)
            self._accepted.discard(key)

    async def _schedule_loop(self) -> None:
        """Move delayed jobs onto the queue when their delay expires."""
        while True:
            if not self._delayed:
                await self._woken.wait()
                continue
            due = min(moment for moment, _ in self._delayed.values())
            remaining = due - self.clock.monotonic()
            if remaining > 0:
                await self.sleeper.sleep(remaining)
                continue
            now = self.clock.monotonic()
            for key, (moment, work) in list(self._delayed.items()):
                if moment > now:
                    continue
                del self._delayed[key]
                with contextlib.suppress(ExecutorFull):
                    # A full queue leaves the job accepted but unrun. The
                    # submitting service owns the job's state; nothing here
                    # invents one.
                    self._enqueue(_Entry(job_id=JobId(key), work=work))
