"""Deleting what this project no longer needs, on a schedule and on demand.

`docs/privacy.md` section 7 requires scheduled expiry, account-requested
deletion, and deletion-failure alerting, and requires all three to be *tested*.
`prompts/07-hardening.md` lists deletion failures among the metrics and
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

**Purging is bounded.** `prompts/07-hardening.md` puts this on a schedule, and a
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

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final, Protocol

from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import JobService
from emailcheck.domain.batch import BatchSettings
from emailcheck.ports.batch_store import BatchStore
from emailcheck.ports.clock import Clock
from emailcheck.ports.job_store import JobStore
from emailcheck.ports.quota import QuotaStore

#: `docs/privacy.md` section 3: plaintext request data lives 24 hours. A
#: finished job record is the only thing in this process that outlives a
#: request, so this is its lifetime too.
DEFAULT_JOB_RETENTION_SECONDS: Final = 24 * 60 * 60

#: How many rows one sweep may delete. Bounded so a backlog is worked through
#: over several runs rather than in one long-held lock.
DEFAULT_BATCH_LIMIT: Final = 1_000


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

    def __post_init__(self) -> None:
        for name, value, ceiling in (
            ("job_retention_seconds", self.job_retention_seconds, 30 * 24 * 60 * 60),
            ("batch_limit", self.batch_limit, 1_000_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise RetentionError(f"{name} must be a whole number, not a boolean")
            if value <= 0:
                raise RetentionError(f"{name} must be positive")
            if value > ceiling:
                raise RetentionError(f"{name} above {ceiling} is not a bound")


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
        verdicts = 0
        jobs = 0
        counters = 0
        batches = 0
        inputs_cleared = 0
        failed = False

        try:
            if self.store is not None:
                verdicts = await self.store.purge_expired(now=now, limit=limit)
            cutoff = now - timedelta(seconds=self.settings.job_retention_seconds)
            if self.jobs is not None:
                jobs = self.jobs.purge_finished(before=cutoff, limit=limit)
            if self.job_store is not None:
                # Counted into the same total rather than reported separately:
                # one job removed from memory and from disk is one job removed,
                # and two counters for it would make the operator's number the
                # sum of a job with itself.
                persisted = await self.job_store.purge_terminal(before=cutoff, limit=limit)
                jobs = max(jobs, persisted)
            if self.batches is not None:
                # **Two operations, two cutoffs.** Clearing the plaintext a
                # resume needs is not the same act as removing a finished
                # batch's accounting and its downloadable result, and running
                # only one of them would leave either an address nobody may
                # keep or a store that only grows.
                inputs_cleared = await self.batches.forget_inputs(
                    before=now - timedelta(seconds=self.batch_settings.input_retention_seconds),
                    limit=limit,
                )
                batches = await self.batches.purge_expired(now=now, limit=limit)
            if self.quota is not None:
                counters = await self.quota.purge_expired(now=now.timestamp())
        except Exception:
            # The exception is not named anywhere an operator reads. A store's
            # own message can carry a path, a query, or a value, and
            # `docs/requirements.md` section 11's rule about exception text is
            # not weaker just because the reader is an administrator.
            failed = True

        report = DeletionReport(
            verdicts_removed=verdicts,
            jobs_removed=jobs,
            quota_counters_removed=counters,
            batches_removed=batches,
            batch_inputs_cleared=inputs_cleared,
            failed=failed,
            more_remaining=not failed and (verdicts >= limit or jobs >= limit or batches >= limit),
        )
        self.admin.record_deletion(removed=report.total_removed, failed=failed)
        return report
