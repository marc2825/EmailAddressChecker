"""Scheduled deletion, its bound, and its failure behaviour.

`docs/privacy.md` section 7 requires scheduled expiry and a deletion test;
`docs/operations.md` section 3 alerts on the job failing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pytest
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl, AdminOperation
from emailcheck.application.retention import (
    RetentionError,
    RetentionService,
    RetentionSettings,
)
from emailcheck.ports.metrics import MetricLabels, MetricName, Outcome

asyncio_test = pytest.mark.asyncio


@dataclass(slots=True)
class ScriptedStore:
    """A store that reports what it removed, or fails."""

    removals: list[int] = field(default_factory=list)
    fail: bool = False
    seen_limits: list[int] = field(default_factory=list)

    async def purge_expired(self, *, now: datetime, limit: int) -> int:
        self.seen_limits.append(limit)
        if self.fail:
            raise RuntimeError("the store is unavailable at /var/db/verdicts.sqlite")
        return self.removals.pop(0) if self.removals else 0


def build(
    store: ScriptedStore | None = None, **overrides: object
) -> tuple[RetentionService, AdminControl, InMemoryMetrics]:
    metrics = InMemoryMetrics()
    clock = SteppableClock()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    fields: dict[str, object] = {
        "clock": clock,
        "admin": admin,
        "store": store,
        "quota": guard.quota,
    }
    fields.update(overrides)
    return RetentionService(**fields), admin, metrics  # type: ignore[arg-type]


# --- what a sweep removes ----------------------------------------------------


@asyncio_test
async def test_a_sweep_removes_expired_verdicts_and_reports_the_count() -> None:
    store = ScriptedStore(removals=[7])
    service, _, _ = build(store)
    report = await service.run()
    assert report.verdicts_removed == 7
    assert report.failed is False


@asyncio_test
async def test_a_sweep_is_bounded_and_says_when_more_remain() -> None:
    """An unbounded `DELETE` holds a write lock for as long as the backlog is,
    so a run takes a batch and a scheduler is told to come back."""
    store = ScriptedStore(removals=[10])
    service, _, _ = build(store, settings=RetentionSettings(batch_limit=10))
    report = await service.run()
    assert store.seen_limits == [10]
    assert report.more_remaining is True

    store.removals = [3]
    assert (await service.run()).more_remaining is False


@asyncio_test
async def test_the_quota_counters_are_swept_too() -> None:
    service, _, _ = build(ScriptedStore())
    await service.run()


@asyncio_test
async def test_a_sweep_with_nothing_configured_removes_nothing_and_succeeds() -> None:
    """A local-passive stack has no jobs and may have no store."""
    service = RetentionService(
        clock=SteppableClock(),
        admin=build()[1],
    )
    report = await service.run()
    assert report.total_removed == 0
    assert report.failed is False


# --- failure -----------------------------------------------------------------


@asyncio_test
async def test_a_failed_sweep_is_reported_rather_than_raised() -> None:
    """A sweep that raised into a scheduler would stop the schedule, which is
    the opposite of what an operator wants from the thing enforcing their
    retention policy."""
    service, _, metrics = build(ScriptedStore(fail=True))
    report = await service.run()
    assert report.failed is True
    assert (
        metrics.counter(MetricName.DELETION_FAILURE, labels=MetricLabels(outcome=Outcome.FAILED))
        == 1
    )


@asyncio_test
async def test_a_failure_never_reaches_an_operator_as_the_stores_own_message() -> None:
    """`docs/requirements.md` section 11's rule about exception text is not
    weaker because the reader is an administrator: the store's message names a
    filesystem path."""
    service, admin, _ = build(ScriptedStore(fail=True))
    await service.run()
    rendered = " ".join(str(event.as_json_object()) for event in admin.audit_events())
    assert "/var/db" not in rendered
    assert "unavailable" not in rendered


@asyncio_test
async def test_a_failed_run_is_not_recorded_as_a_successful_removal_of_zero() -> None:
    """A run that removed nothing because there was nothing and a run that
    removed nothing because it broke are different facts."""
    service, _, metrics = build(ScriptedStore(fail=True))
    await service.run()
    assert metrics.counter(MetricName.DELETION_REMOVED) == 0
    assert ("deletion_removed", None, None) not in metrics.observations


@asyncio_test
async def test_every_run_is_audited() -> None:
    service, admin, _ = build(ScriptedStore(removals=[2]))
    await service.run()
    assert [event.operation for event in admin.audit_events()] == [AdminOperation.RUN_DELETION]
    assert admin.audit_events()[0].changed is True


# --- the three retentions stay separate --------------------------------------


def test_the_job_retention_is_not_a_verdict_ttl() -> None:
    """`docs/requirements.md` section 13 prices *evidence classes*. Using one as
    a job retention would apply a freshness rule to a privacy question."""
    from emailcheck.domain.cache_policy import SECTION_13_TTL_SECONDS

    settings = RetentionSettings()
    assert settings.job_retention_seconds == 24 * 60 * 60
    assert settings.job_retention_seconds not in set(SECTION_13_TTL_SECONDS.values())


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("job_retention_seconds", 0),
        ("job_retention_seconds", -1),
        ("job_retention_seconds", True),
        ("job_retention_seconds", 31 * 24 * 60 * 60),
        ("batch_limit", 0),
        ("batch_limit", True),
        ("batch_limit", 2_000_000),
    ],
)
def test_an_unusable_retention_setting_is_refused(field_name: str, value: object) -> None:
    with pytest.raises(RetentionError):
        RetentionSettings(**{field_name: value})  # type: ignore[arg-type]


# --- job records -------------------------------------------------------------


def test_only_terminal_jobs_are_purged() -> None:
    """A `pending` or `running` job removed by a sweep is work that stops
    existing while something is still waiting for it.

    Driven through `purge_finished` itself. An earlier version of this test
    asserted `is_terminal` on two constructed jobs, which is a property of
    `CheckJob` rather than of the sweep — and a mutation removing the terminal
    check from the sweep left it passing.
    """
    from tests.phase6_fixtures import (
        PRINCIPAL,
        FakeClock,
        FakeRandomSource,
        RecordingExecutor,
        build_service,
        resolver_with_route,
    )

    from emailcheck.application.jobs import CheckJob, JobService
    from emailcheck.domain.job import JobId, JobState

    service, _, sink = build_service(resolver=resolver_with_route())
    jobs = JobService(
        verification=service,
        executor=RecordingExecutor(),
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=sink,
        correlation_key=CORRELATION_KEY,
    )
    long_ago = jobs._now() - timedelta(days=7)
    for suffix, state in (("a", JobState.PENDING), ("b", JobState.RUNNING)):
        job = CheckJob(
            id=JobId("job-" + suffix * 22),
            owner=PRINCIPAL.rate_limit_account,
            state=state,
            created_at=long_ago,
            updated_at=long_ago,
        )
        jobs._jobs[job.id.value] = job
    finished = CheckJob(
        id=JobId("job-" + "c" * 22),
        owner=PRINCIPAL.rate_limit_account,
        state=JobState.CANCELLED,
        created_at=long_ago,
        updated_at=long_ago,
    )
    jobs._jobs[finished.id.value] = finished

    removed = jobs.purge_finished(before=jobs._now(), limit=10)

    assert removed == 1
    assert set(jobs._jobs) == {"job-" + "a" * 22, "job-" + "b" * 22}


def test_a_terminal_job_newer_than_the_retention_survives() -> None:
    """The lifetime is the other half of the rule, and it needs its own row."""
    from tests.phase6_fixtures import (
        PRINCIPAL,
        FakeClock,
        FakeRandomSource,
        RecordingExecutor,
        build_service,
        resolver_with_route,
    )

    from emailcheck.application.jobs import CheckJob, JobService
    from emailcheck.domain.job import JobId, JobState

    service, _, sink = build_service(resolver=resolver_with_route())
    jobs = JobService(
        verification=service,
        executor=RecordingExecutor(),
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=sink,
        correlation_key=CORRELATION_KEY,
    )
    now = jobs._now()
    job = CheckJob(
        id=JobId("job-" + "d" * 22),
        owner=PRINCIPAL.rate_limit_account,
        state=JobState.CANCELLED,
        created_at=now,
        updated_at=now,
    )
    jobs._jobs[job.id.value] = job

    assert jobs.purge_finished(before=now - timedelta(hours=1), limit=10) == 0
    assert set(jobs._jobs) == {job.id.value}


def test_a_purge_stops_at_its_batch_limit() -> None:
    from tests.phase6_fixtures import (
        PRINCIPAL,
        FakeClock,
        FakeRandomSource,
        RecordingExecutor,
        build_service,
        resolver_with_route,
    )

    from emailcheck.application.jobs import CheckJob, JobService
    from emailcheck.domain.job import JobId, JobState

    service, _, sink = build_service(resolver=resolver_with_route())
    jobs = JobService(
        verification=service,
        executor=RecordingExecutor(),
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=sink,
        correlation_key=CORRELATION_KEY,
    )
    long_ago = jobs._now() - timedelta(days=7)
    for index in range(10):
        job = CheckJob(
            id=JobId(f"job-{index:022d}"),
            owner=PRINCIPAL.rate_limit_account,
            state=JobState.CANCELLED,
            created_at=long_ago,
            updated_at=long_ago,
        )
        jobs._jobs[job.id.value] = job

    assert jobs.purge_finished(before=jobs._now(), limit=4) == 4
    assert len(jobs._jobs) == 6


def test_a_purge_batch_must_be_positive() -> None:
    from tests.phase6_fixtures import (
        FakeClock,
        FakeRandomSource,
        RecordingExecutor,
        build_service,
        resolver_with_route,
    )

    from emailcheck.application.jobs import JobService
    from emailcheck.domain.job import JobError

    service, _, sink = build_service(resolver=resolver_with_route())
    jobs = JobService(
        verification=service,
        executor=RecordingExecutor(),
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=sink,
        correlation_key=CORRELATION_KEY,
    )
    with pytest.raises(JobError):
        jobs.purge_finished(before=datetime.now(tz=SteppableClock().now().tzinfo), limit=0)


def test_purging_a_job_forgets_its_idempotency_binding() -> None:
    """A binding left behind would point at a job nobody can fetch — the pairing
    `_evict` already keeps, for the same reason."""
    import asyncio

    from tests.phase6_fixtures import (
        PRINCIPAL,
        FakeClock,
        FakeRandomSource,
        InMemoryVerdictStore,
        RecordingExecutor,
        build_service,
        resolver_with_route,
    )

    from emailcheck.application.jobs import JobService
    from emailcheck.domain.job import IdempotencyKey

    async def scenario() -> None:
        service, _, sink = build_service(resolver=resolver_with_route())
        executor = RecordingExecutor()
        jobs = JobService(
            verification=service,
            executor=executor,
            clock=FakeClock(),
            random=FakeRandomSource(),
            operator=sink,
            correlation_key=CORRELATION_KEY,
        )
        outcome = await jobs.submit(
            "user@example.test",
            principal=PRINCIPAL,
            idempotency_key=IdempotencyKey("order-4711-attempt-1"),
        )
        await executor.run_pending()
        assert len(jobs._by_key) == 1

        removed = jobs.purge_finished(before=jobs._now() + timedelta(seconds=1), limit=10)
        assert removed == 1
        assert jobs._by_key == {}
        assert jobs.get(outcome.job.id, principal=PRINCIPAL) is None
        assert InMemoryVerdictStore is not None

    asyncio.run(scenario())
