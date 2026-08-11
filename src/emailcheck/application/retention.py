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

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import JobService
from emailcheck.ports.clock import Clock
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
    failed: bool = False
    #: `True` when the batch limit was reached, so a scheduler knows to run
    #: again rather than waiting for the next interval.
    more_remaining: bool = False

    @property
    def total_removed(self) -> int:
        return self.verdicts_removed + self.jobs_removed + self.quota_counters_removed


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
        failed = False

        try:
            if self.store is not None:
                verdicts = await self.store.purge_expired(now=now, limit=limit)
            if self.jobs is not None:
                jobs = self.jobs.purge_finished(
                    before=now - timedelta(seconds=self.settings.job_retention_seconds),
                    limit=limit,
                )
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
            failed=failed,
            more_remaining=not failed and (verdicts >= limit or jobs >= limit),
        )
        self.admin.record_deletion(removed=report.total_removed, failed=failed)
        return report
