"""Deleting what this project no longer needs, on a schedule and on demand.

`docs/privacy.md` section 7 requires scheduled expiry, account-requested
deletion, and deletion-failure alerting, and requires all three to be *tested*.
`docs/threat-model.md` lists deletion failures among the metrics and
"trigger deletion" among the admin controls.

**Three retentions, and they are not one retention.** Conflating them is the
mistake this module exists to avoid, so they are named separately and none reads
another's setting:

| What | Lifetime | Decided by |
|---|---|---|
| A cached verdict | its own `expires_at` | ADR 0015, from `docs/requirements.md` §13 |
| A finished job record | `job_retention_seconds` | here, `docs/privacy.md` §3's 24 hours |
| An audit event | the ring's capacity | `application/admin.py` |

`docs/requirements.md` section 13's TTLs price *evidence classes*. Using one of
them as a job or log retention would be applying a deliberability-freshness rule
to a privacy question, which is how a caching decision quietly becomes a
retention policy.

**A live job is never deleted.** Only terminal states are eligible, the same
rule the Phase 6 registry's eviction follows: a `pending` or `running` job
removed by a sweep is work that silently stops existing while something is still
waiting for it.

**Purging is bounded.** `docs/threat-model.md` puts this on a schedule, and a
sweep that deletes every expired row in one statement holds a write lock for as
long as the backlog is — so a run removes at most `batch_limit` rows and says
whether more remain. `docs/operations.md` section 3 alerts on the job failing,
and a run that is merely *incomplete* is not a failure.

**A failure is reported, never swallowed and never fatal.** A store that cannot
be reached must not stop a verification — `docs/architecture.md` section 5 — so
a failed run increments the deletion-failure counter, records an audit event,
and returns.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final, Protocol

from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import JobService
from emailcheck.domain.batch import BatchSettings
from emailcheck.ports.batch_store import BatchStore
from emailcheck.ports.clock import Clock, Sleeper
from emailcheck.ports.job_store import JobStore
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink
from emailcheck.ports.quota import QuotaStore

#: `docs/privacy.md` section 3: plaintext request data lives 24 hours. A
#: finished job record is the only thing in this process that outlives a
#: request, so this is its lifetime too.
DEFAULT_JOB_RETENTION_SECONDS: Final = 24 * 60 * 60

#: How many rows one sweep may delete. Bounded so a backlog is worked through
#: over several runs rather than in one long-held lock.
DEFAULT_BATCH_LIMIT: Final = 1_000

#: How often the scheduler sweeps, and the bounds on that.
#:
#: `docs/privacy.md` fixes retention *windows* and no cadence, so this is the
#: smallest operator-owned number that makes the windows real. Fifteen minutes
#: keeps the effective deletion time within a bounded margin of the configured
#: cutoff without turning cleanup into a polling load; the minimum exists
#: because a sub-minute sweep is a database write amplifier rather than a
#: retention policy, and the maximum because an interval longer than a day would
#: silently extend `docs/privacy.md` section 3's window by more than the window.
DEFAULT_RETENTION_INTERVAL_SECONDS: Final = 15 * 60
MIN_RETENTION_INTERVAL_SECONDS: Final = 60
MAX_RETENTION_INTERVAL_SECONDS: Final = 24 * 60 * 60

#: How many bounded sweeps one interval may chain while a backlog remains.
_MAX_PASSES_PER_TICK: Final = 4


class RetentionError(ValueError):
    """A retention configuration that would not bound anything."""


class ExpiringStore(Protocol):
    """The part of a verdict store a retention sweep needs."""

    async def purge_expired(self, *, now: datetime, limit: int) -> int: ...


@dataclass(frozen=True, slots=True)
class RetentionSettings:
    """Every lifetime, validated like every other bound in this project."""

    job_retention_seconds: int = DEFAULT_JOB_RETENTION_SECONDS
    batch_limit: int = DEFAULT_BATCH_LIMIT
    #: How often `RetentionScheduler` sweeps. Operator configuration: there is
    #: no request field, no CLI flag, and no admin call that changes it, because
    #: a caller who could lengthen the interval could lengthen every retention
    #: window in `docs/privacy.md` section 3 without changing one of them.
    interval_seconds: int = DEFAULT_RETENTION_INTERVAL_SECONDS

    def __post_init__(self) -> None:
        for name, value, ceiling in (
            ("job_retention_seconds", self.job_retention_seconds, 30 * 24 * 60 * 60),
            ("batch_limit", self.batch_limit, 1_000_000),
            ("interval_seconds", self.interval_seconds, MAX_RETENTION_INTERVAL_SECONDS),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise RetentionError(f"{name} must be a whole number, not a boolean")
            if value <= 0:
                raise RetentionError(f"{name} must be positive")
            if value > ceiling:
                raise RetentionError(f"{name} above {ceiling} is not a bound")
        if self.interval_seconds < MIN_RETENTION_INTERVAL_SECONDS:
            raise RetentionError(
                f"interval_seconds below {MIN_RETENTION_INTERVAL_SECONDS}s"
                " is polling rather than retention"
            )


@dataclass(frozen=True, slots=True)
class DeletionReport:
    """What one sweep removed, and whether it finished."""

    verdicts_removed: int = 0
    jobs_removed: int = 0
    quota_counters_removed: int = 0
    #: Expired batches removed, and batches whose retained submitted addresses
    #: were cleared. **Two counts because they are two policies**: a batch's
    #: accounting and its downloadable result live under
    #: `BatchSettings.result_retention_seconds`, and the plaintext a resume
    #: needs lives under the much shorter `input_retention_seconds`. Collapsing
    #: them would let one window silently extend the other.
    batches_removed: int = 0
    batch_inputs_cleared: int = 0
    failed: bool = False
    #: Which cleanup categories failed, in this project's own vocabulary.
    #:
    #: A bare `failed` flag told an operator that *something* was wrong and
    #: nothing about what, which for a sweep over five independent stores is the
    #: difference between "restore the batch database" and "restore everything".
    #: Category names only — never an exception message, a path, or a query.
    failed_stores: tuple[str, ...] = ()
    #: `True` when the batch limit was reached, so a scheduler knows to run
    #: again rather than waiting for the next interval.
    more_remaining: bool = False

    @property
    def total_removed(self) -> int:
        return (
            self.verdicts_removed
            + self.jobs_removed
            + self.quota_counters_removed
            + self.batches_removed
            + self.batch_inputs_cleared
        )


@dataclass(frozen=True, slots=True)
class RetentionService:
    """One sweep, callable on a schedule or by an operator.

    Every collaborator is optional because every deployment profile has a
    different set of them: a local-passive stack has no jobs and may have no
    store, and a sweep over nothing is a valid sweep that removes nothing.
    """

    clock: Clock
    admin: AdminControl
    settings: RetentionSettings = RetentionSettings()
    store: ExpiringStore | None = None
    jobs: JobService | None = None
    #: The persistent half of the job registry, when a deployment has one.
    #:
    #: Swept with the **same window** `JobService.purge_finished` applies in
    #: memory, and by the same sweep. Persistence exists so a restart cannot
    #: duplicate a verification; it is not a reason to keep a job longer than
    #: `docs/privacy.md` section 3 allows, and a second retention policy for the
    #: same records is how one of them becomes wrong.
    job_store: JobStore | None = None
    #: Batch state, its retained submitted addresses, and its expiring results.
    #:
    #: Here rather than behind a timer of its own: `docs/privacy.md` section 3's
    #: deletion is one policy with one operator-visible failure signal, and a
    #: batch-only background loop would be a second retention mechanism to keep
    #: in step with this one.
    batches: BatchStore | None = None
    #: The batch deployment's own settings, because **the plaintext window is
    #: theirs and not this service's**. `RetentionSettings.job_retention_seconds`
    #: prices a job; `BatchSettings.input_retention_seconds` prices a submitted
    #: address, is capped at `MAX_INPUT_RETENTION`, and is what the sweep below
    #: actually subtracts. A second copy of that number here is how the
    #: configured value and the enforced value drift apart.
    batch_settings: BatchSettings = field(default_factory=BatchSettings)
    quota: QuotaStore | None = None

    async def run(self) -> DeletionReport:
        """Delete what has expired. Never raises.

        `docs/privacy.md` section 7 wants deletion-failure alerting, which needs
        the failure to be *reported* rather than propagated: a sweep that raised
        into a scheduler would stop the schedule, which is the opposite of what
        an operator wants from the thing that enforces their retention policy.
        """
        now = self.clock.now()
        limit = self.settings.batch_limit
        cutoff = now - timedelta(seconds=self.settings.job_retention_seconds)
        input_cutoff = now - timedelta(seconds=self.batch_settings.input_retention_seconds)
        failures: list[str] = []

        # **One `try` per store, and that is the fix rather than a style choice.**
        # A single block around all of them meant the first exception skipped
        # every later cleanup: one unreachable verdict store and the job store,
        # the batch plaintext, and the quota counters were all left untouched
        # while the report said "failed" and nothing said which. The final system
        # audit measured it. `docs/architecture.md` section 5's isolation rule is
        # about exactly this — one store being unavailable must not take the
        # others with it — and a retention sweep is where the rule is easiest to
        # lose because the stores are only listed together here.
        verdicts = await self._attempt(
            failures, "verdicts", lambda: self._purge_verdicts(now, limit)
        )
        jobs = await self._attempt(failures, "jobs", lambda: self._purge_jobs(cutoff, limit))
        inputs_cleared = await self._attempt(
            failures, "batch_inputs", lambda: self._forget_inputs(input_cutoff, limit)
        )
        batches = await self._attempt(failures, "batches", lambda: self._purge_batches(now, limit))
        counters = await self._attempt(failures, "quota", lambda: self._purge_quota(now))

        report = DeletionReport(
            verdicts_removed=verdicts,
            jobs_removed=jobs,
            quota_counters_removed=counters,
            batches_removed=batches,
            batch_inputs_cleared=inputs_cleared,
            failed=bool(failures),
            failed_stores=tuple(failures),
            # **Every bounded category, including the batch plaintext.** The
            # earlier expression omitted `inputs_cleared`, so a backlog of stale
            # addresses larger than one run's limit reported "nothing more to
            # do" — and a scheduler that believes it waits a whole interval
            # before clearing the rest, which is retention overrun reported as
            # completion. A category that failed says nothing about its backlog,
            # so it is not counted as drained either.
            more_remaining=any(
                count >= limit for count in (verdicts, jobs, inputs_cleared, batches)
            )
            or bool(failures),
        )
        self.admin.record_deletion(removed=report.total_removed, failed=report.failed)
        return report

    async def _attempt(
        self, failures: list[str], name: str, operation: Callable[[], Awaitable[int]]
    ) -> int:
        """Run one store's cleanup. A failure is recorded and does not propagate.

        The category name is this project's own vocabulary, never the
        exception's text: a store's message can carry a path, a query, or a
        value, and `docs/requirements.md` section 11's rule about exception text
        is not weaker because the reader is an administrator.
        """
        try:
            return await operation()
        except Exception:
            failures.append(name)
            return 0

    async def _purge_verdicts(self, now: datetime, limit: int) -> int:
        if self.store is None:
            return 0
        return await self.store.purge_expired(now=now, limit=limit)

    async def _purge_jobs(self, cutoff: datetime, limit: int) -> int:
        """The registry and its persistent half, on one window.

        Counted into one number rather than reported separately: one job removed
        from memory and from disk is one job removed, and two counters for it
        would make the operator's number the sum of a job with itself.
        """
        removed = 0
        if self.jobs is not None:
            removed = self.jobs.purge_finished(before=cutoff, limit=limit)
        if self.job_store is not None:
            persisted = await self.job_store.purge_terminal(before=cutoff, limit=limit)
            removed = max(removed, persisted)
        return removed

    async def _forget_inputs(self, cutoff: datetime, limit: int) -> int:
        """Clear retained submitted addresses. **Its own cutoff and its own try.**

        Separate from `_purge_batches` because they are two policies: the
        plaintext a resume needs lives under `input_retention_seconds`, and the
        batch's accounting and downloadable result live under the much longer
        `result_retention_seconds`. Running them together under one exception
        handler also meant a failure in either silently skipped the other.
        """
        if self.batches is None:
            return 0
        return await self.batches.forget_inputs(before=cutoff, limit=limit)

    async def _purge_batches(self, now: datetime, limit: int) -> int:
        if self.batches is None:
            return 0
        return await self.batches.purge_expired(now=now, limit=limit)

    async def _purge_quota(self, now: datetime) -> int:
        if self.quota is None:
            return 0
        return await self.quota.purge_expired(now=now.timestamp())


@dataclass(slots=True)
class RetentionScheduler:
    """The thing that actually runs the sweep. One task, bounded, stoppable.

    **`RetentionService` existed and nothing called it.** `docs/privacy.md`
    section 7 requires *scheduled* expiry, `docs/threat-model.md` puts
    deletion on a schedule, and `composition.py` constructed the service and
    then started only the executor — so every retention window in the
    documentation was enforced by whoever remembered to call `run()`, which in
    production was nobody. The final system audit found it. This is the
    scheduler, and it is deliberately the *only* one: the central service stays
    the single cleanup seam, and this adds no second policy, no second cutoff,
    and no second failure signal.

    Shaped like `InMemoryJobExecutor`, which is the repository's existing answer
    to "a component that owns a background task": one task created at `start()`,
    the `Sleeper` port rather than `asyncio.sleep` so a test measures an interval
    without waiting one, and an explicit `aclose()` that cancels and awaits.

    **A failed sweep does not end the schedule.** `run()` already reports rather
    than raises, and this catches anything left — a metrics sink, an audit ring —
    so run *n* failing cannot stop run *n+1*. The opposite would make one
    unreachable store a permanent silent halt of the thing that enforces the
    operator's retention policy, which is the failure nobody notices until an
    audit asks how old the oldest plaintext is.
    """

    service: RetentionService
    sleeper: Sleeper
    operator: OperatorSink
    settings: RetentionSettings = RetentionSettings()
    _task: asyncio.Task[None] | None = None
    _closed: bool = False

    def start(self) -> None:
        """Create the task. Idempotent, on the executor's precedent."""
        if self._task is not None or self._closed:
            return
        self._task = asyncio.create_task(self._loop(), name="emailcheck-retention")

    async def aclose(self) -> None:
        """Cancel the task and wait for it. Explicit rather than best effort.

        A sweep left running after the stack closes holds a database connection
        and can delete rows a test has already asserted about; "the process is
        exiting anyway" is not true of a test, which is the argument
        `InMemoryJobExecutor.aclose` already makes.
        """
        self._closed = True
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _loop(self) -> None:
        """Sleep, sweep, repeat.

        **Sleep first.** Starting a service is the moment it is least likely to
        have expired records and most likely to be doing something else, and a
        sweep on the way up would run before an operator could throw a switch.

        A backlog is drained across a bounded number of passes rather than one
        per interval: `DeletionReport.more_remaining` exists so a scheduler need
        not wait a whole interval to continue, and `_MAX_PASSES_PER_TICK` is what
        stops that becoming the tight loop the bound exists to prevent. Anything
        still remaining waits for the next interval, which is a slower drain and
        never a stalled one.
        """
        while True:
            await self.sleeper.sleep(float(self.settings.interval_seconds))
            for _ in range(_MAX_PASSES_PER_TICK):
                report = await self._sweep()
                if report is None or not report.more_remaining or report.failed:
                    break

    async def _sweep(self) -> DeletionReport | None:
        """One run. Returns `None` when the run itself broke.

        `asyncio.CancelledError` is not caught: a shutdown must stop this loop,
        and swallowing the cancellation would make `aclose` hang on the task it
        just cancelled.
        """
        try:
            report = await self.service.run()
        except Exception:
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail="retention sweep")
            )
            return None
        if report.failed:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR,
                    detail=f"retention: {', '.join(report.failed_stores)}",
                )
            )
        return report
