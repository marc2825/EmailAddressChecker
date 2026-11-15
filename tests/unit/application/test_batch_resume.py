"""Restart, resume, the crash boundary, retention, and what fairness is not.

These tests use the **real** `SQLiteBatchStore` on a temporary file rather than
the in-memory fake. A fake cannot show that a restart works: the whole claim is
that state written by one service is read by another, and a dictionary that both
of them share proves the opposite of what is wanted.

Nothing here opens a socket and nothing sleeps. `sqlite3` runs in a worker
thread through `asyncio.to_thread`, which the suite-wide guard permits because
asyncio's own wakeup socketpair is `AF_UNIX`.
"""

from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import pytest
from tests.batch_fixtures import (
    ACCOUNT,
    CORRELATION_KEY,
    PRINCIPAL,
    MovableClock,
    approved,
    build_jobs,
    csv_for,
)
from tests.dialogue_fixtures import FakeMonotonicClock, FakeSleeper
from tests.phase6_fixtures import FakeRandomSource, RecordingExecutor
from tests.phase7_fixtures import OTHER_PRINCIPAL as OTHER

from emailcheck.adapters.storage.sqlite_batch_store import (
    BatchStoreSchemaError,
    SQLiteBatchStore,
)
from emailcheck.adapters.system.rate_limit import InProcessRateLimiter
from emailcheck.application.batch import BatchService
from emailcheck.application.jobs import JobService
from emailcheck.domain.batch import BatchApproval, BatchId, BatchLimits, BatchRowState
from emailcheck.domain.rate_limit import RateLimitSettings
from emailcheck.ports.batch_store import BatchStoreFull

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0

#: One worker, so an interruption lands at a position a test can name.
SERIAL: Final = BatchLimits(max_in_flight=1, max_in_flight_per_domain=1, max_in_flight_per_mx=1)


class Interrupted(BaseException):
    """What a stopped process looks like from inside the scheduler.

    A `BaseException`, deliberately: `_one` converts every `Exception` into a
    `refused` row, which is exactly right for a quota or a full executor and
    exactly wrong for "the process died". A row that was interrupted must stay
    resumable rather than be recorded as refused.
    """


@dataclass
class InterruptingJobs:
    """A `JobService` stand-in that stops after `after` submissions.

    `before_recording` is the dangerous case: the inner submission **succeeds**
    and the interruption lands before the batch can record the child job.
    """

    inner: JobService
    after: int
    before_recording: bool = False
    seen: int = 0
    ids: list[str] = field(default_factory=list)

    def get(self, *args: object, **kwargs: object) -> object:
        return self.inner.get(*args, **kwargs)  # type: ignore[arg-type]

    async def fetch(self, *args: object, **kwargs: object) -> object:
        return await self.inner.fetch(*args, **kwargs)  # type: ignore[arg-type]

    async def submit(self, raw: str, **kwargs: object):  # type: ignore[no-untyped-def]
        if self.seen >= self.after and not self.before_recording:
            raise Interrupted("the process stopped")
        outcome = await self.inner.submit(raw, **kwargs)  # type: ignore[arg-type]
        self.seen += 1
        self.ids.append(outcome.job.id.value)
        if self.seen > self.after and self.before_recording:
            # Handed over, and then the process stopped. The row stays
            # `claimed`, its handle is already persisted, and a resume must
            # recover this job rather than start another.
            raise Interrupted("the process stopped after the handover")
        return outcome


def open_store(path: Path, **kwargs: object) -> SQLiteBatchStore:
    store = SQLiteBatchStore(path=path, **kwargs)  # type: ignore[arg-type]
    store.initialize()
    return store


def build(
    store: SQLiteBatchStore,
    *,
    clock: MovableClock | None = None,
    jobs: JobService | None = None,
    executor: RecordingExecutor | None = None,
    limits: BatchLimits = SERIAL,
    retention: int = 3600,
) -> tuple[BatchService, RecordingExecutor, JobService]:
    """A service over a given store. Two of these share nothing but the file."""
    if jobs is None:
        jobs, executor, _ = build_jobs()
    assert executor is not None
    return (
        BatchService(
            jobs=jobs,
            store=store,
            clock=clock if clock is not None else MovableClock(),  # type: ignore[arg-type]
            random_source=FakeRandomSource(prefix="batch"),
            settings=approved(limits=limits, result_retention_seconds=retention),
            correlation_key=CORRELATION_KEY,
        ),
        executor,
        jobs,
    )


# --- restart and resume ------------------------------------------------------


@asyncio_test
async def test_a_fresh_service_resumes_what_an_interrupted_one_left(tmp_path: Path) -> None:
    """`docs/adr/0018-controlled-batch-execution.md` Tests: restart/resume.

    Five rows, interrupted after two, then continued by a **different**
    `BatchService` over the same file. The assertions are the four that matter:
    nothing terminal is redone, nothing already submitted is submitted twice,
    the remainder progresses, and every input row is still accounted for.
    """
    store = open_store(tmp_path / "batch.db")
    jobs, executor, _ = build_jobs()
    first, _, _ = build(store, jobs=jobs, executor=executor)
    first.jobs = InterruptingJobs(inner=jobs, after=2)  # type: ignore[assignment]

    with pytest.raises(Interrupted):
        async with asyncio.timeout(OUTER_BOUND):
            await first.submit(
                csv_for(*(f"u{index}@example.test" for index in range(5))), principal=PRINCIPAL
            )

    held = await store.load_batch(
        next(iter(store_ids(store))), account=ACCOUNT, now=first.clock.now()
    )
    assert held is not None
    batch_id = BatchId(held.batch_id)
    states = [row.state for row in held.rows]
    assert states.count(BatchRowState.SUBMITTED) == 2
    assert BatchRowState.QUEUED in states
    submitted_before = list(executor.submitted)
    assert len(submitted_before) == 2

    # A different service, over the same file. It shares no in-process state
    # with the first beyond the job registry the process still holds.
    del first
    second, _, _ = build(store, jobs=jobs, executor=executor)

    async with asyncio.timeout(OUTER_BOUND):
        report = await second.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 5
    assert sum(report.state_summary.values()) == report.input_rows == 5
    # The two already-submitted rows kept their original jobs.
    assert executor.submitted[:2] == submitted_before
    assert len(executor.submitted) == 5, "a row was submitted twice"


@asyncio_test
async def test_a_row_handed_over_before_the_crash_is_recovered_not_repeated(
    tmp_path: Path,
) -> None:
    """The dangerous handoff. `docs/adr/0018-controlled-batch-execution.md`'s restart test,
    sharpened.

    The child job was accepted and the batch never recorded it. This is the
    case a clean checkpoint-only restart test cannot reach, and "unlikely" is
    not an answer to it: the row is persisted as `claimed` **before** the call,
    carrying a deterministic handle, so the resume presents the same handle to
    `JobService.submit` and is answered with the existing job.
    """
    store = open_store(tmp_path / "batch.db")
    jobs, executor, _ = build_jobs()
    first, _, _ = build(store, jobs=jobs, executor=executor)
    interrupting = InterruptingJobs(inner=jobs, after=1, before_recording=True)
    first.jobs = interrupting  # type: ignore[assignment]

    with pytest.raises(Interrupted):
        async with asyncio.timeout(OUTER_BOUND):
            await first.submit(
                csv_for("a@example.test", "b@example.test", "c@example.test"),
                principal=PRINCIPAL,
            )

    batch_id = BatchId(next(iter(store_ids(store))))
    held = await store.load_batch(batch_id.value, account=ACCOUNT, now=first.clock.now())
    assert held is not None
    orphan = [row for row in held.rows if row.state is BatchRowState.CLAIMED]
    assert len(orphan) == 1, "the crash boundary was not recorded"
    assert orphan[0].job_id is None, "this test is not exercising the dangerous case"
    assert orphan[0].idempotency is not None
    handed_over = len(executor.submitted)
    assert handed_over == 2

    second, _, _ = build(store, jobs=jobs, executor=executor)
    async with asyncio.timeout(OUTER_BOUND):
        report = await second.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    # **The orphan did not become a second verification.** Three rows, three
    # jobs — the third is the one the interrupted call had already created.
    assert len(executor.submitted) == 3
    recovered = next(row for row in report.rows if row.number == orphan[0].number)
    assert recovered.job_id == interrupting.ids[1]
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 3


@asyncio_test
async def test_resuming_a_finished_batch_submits_nothing_more(tmp_path: Path) -> None:
    """Terminal rows are terminal. A resume is not a re-run."""
    store = open_store(tmp_path / "batch.db")
    batch, executor, _ = build(store)
    report = await batch.submit(
        csv_for("a@example.test", "a@example.test", "not-an-address"), principal=PRINCIPAL
    )
    before = list(executor.submitted)

    again = await batch.resume(report.batch_id, principal=PRINCIPAL)

    assert again is not None
    assert executor.submitted == before
    assert again.state_summary == report.state_summary


@asyncio_test
async def test_a_cancelled_batch_is_not_resumed_after_a_restart(tmp_path: Path) -> None:
    """`docs/adr/0018-controlled-batch-execution.md` cancellation, across the restart boundary.

    Persisting the flag is what makes this hold: an in-process set would be
    exactly what a restart discards, so the restart would become the way to undo
    a cancellation.
    """
    store = open_store(tmp_path / "batch.db")
    jobs, executor, _ = build_jobs()
    first, _, _ = build(store, jobs=jobs, executor=executor)
    first.jobs = InterruptingJobs(inner=jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await first.submit(
            csv_for(*(f"u{index}@example.test" for index in range(4))), principal=PRINCIPAL
        )
    batch_id = BatchId(next(iter(store_ids(store))))
    assert await first.cancel(batch_id, principal=PRINCIPAL) is True
    before = len(executor.submitted)

    second, _, _ = build(store, jobs=jobs, executor=executor)
    report = await second.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert report.cancelled is True
    assert len(executor.submitted) == before, "a cancelled batch submitted more work"
    assert report.state_summary[BatchRowState.CANCELLED.value] == 3
    assert sum(report.state_summary.values()) == 4


@asyncio_test
async def test_the_persisted_cancelled_flag_stops_a_resume_on_its_own(tmp_path: Path) -> None:
    """Two barriers stop a cancelled batch, and this pins the second alone.

    `cancel` both sets the flag **and** marks every unsubmitted row cancelled,
    so a test that cancels normally is stopped by the rows and would pass with
    the flag check deleted. Here only the flag is set — the rows are left
    resumable — so nothing but the flag can refuse the work.
    """
    store = open_store(tmp_path / "batch.db")
    jobs, executor, _ = build_jobs()
    batch, _, _ = build(store, jobs=jobs, executor=executor)
    batch.jobs = InterruptingJobs(inner=jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await batch.submit(
            csv_for(*(f"u{index}@example.test" for index in range(4))), principal=PRINCIPAL
        )
    batch_id = BatchId(next(iter(store_ids(store))))
    await store.set_cancelled(batch_id.value)
    before = len(executor.submitted)

    second, _, _ = build(store, jobs=jobs, executor=executor)
    held = await store.load_batch(batch_id.value, account=ACCOUNT, now=second.clock.now())
    assert held is not None
    assert any(row.state in {BatchRowState.QUEUED, BatchRowState.CLAIMED} for row in held.rows), (
        "the rows are already terminal, so this test is not exercising the flag"
    )

    report = await second.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert report.cancelled is True
    assert len(executor.submitted) == before, "a cancelled batch submitted more work"


@asyncio_test
async def test_another_account_cannot_delete_a_persisted_batch(tmp_path: Path) -> None:
    """The ownership predicate on the **real** store, not on the fake.

    Deleting through the in-memory fake proves the fake checks ownership. This
    is the statement that actually runs in a deployment, and removing
    `_OWNED` from the adapter passed everything until it existed.
    """
    path = tmp_path / "batch.db"
    store = open_store(path)
    batch, _, _ = build(store)
    report = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)

    assert (
        await store.delete_batch(report.batch_id.value, account=OTHER.rate_limit_account) is False
    )

    assert store_ids(store) == {report.batch_id.value}
    assert await batch.report(report.batch_id, principal=PRINCIPAL) is not None
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is not None


@asyncio_test
async def test_another_account_cannot_resume_a_batch(tmp_path: Path) -> None:
    """Both accounts are **approved**, so the refusal is ownership and nothing else.

    Approving only one would prove the feature gate works, which another test
    already does; this has to prove that an approved account still cannot reach
    a batch it does not own.
    """
    store = open_store(tmp_path / "batch.db")
    jobs, executor, _ = build_jobs()
    batch, _, _ = build(store, jobs=jobs, executor=executor)
    batch.settings = approved(
        limits=SERIAL,
        approval=BatchApproval(accounts=frozenset({ACCOUNT, OTHER.rate_limit_account})),
    )
    batch.jobs = InterruptingJobs(inner=jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await batch.submit(csv_for("a@example.test", "b@example.test"), principal=PRINCIPAL)
    batch_id = BatchId(next(iter(store_ids(store))))
    before = len(executor.submitted)

    batch.jobs = jobs  # type: ignore[assignment]
    assert await batch.resume(batch_id, principal=OTHER) is None

    assert len(executor.submitted) == before


# --- retention ---------------------------------------------------------------


@asyncio_test
async def test_expiring_the_plaintext_makes_an_unfinished_row_refused(tmp_path: Path) -> None:
    """`docs/privacy.md` section 3, and what it costs.

    Once the submitted address is gone the row can never be submitted — so it is
    recorded as refused rather than quietly dropped. The accounting outlives the
    input, which is the whole reason `forget_inputs` is an `UPDATE`.
    """
    store = open_store(tmp_path / "batch.db")
    clock = MovableClock()
    jobs, executor, _ = build_jobs()
    batch, _, _ = build(store, clock=clock, jobs=jobs, executor=executor, retention=172_800)
    batch.jobs = InterruptingJobs(inner=jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await batch.submit(
            csv_for("a@example.test", "b@example.test", "c@example.test"), principal=PRINCIPAL
        )
    batch_id = BatchId(next(iter(store_ids(store))))

    clock.advance(86400)
    assert await store.forget_inputs(before=clock.now(), limit=10) == 1

    held = await store.load_batch(batch_id.value, account=ACCOUNT, now=clock.now())
    assert held is not None
    assert all(row.submitted is None for row in held.rows)

    batch.jobs = jobs  # type: ignore[assignment]
    report = await batch.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert sum(report.state_summary.values()) == 3
    assert report.state_summary[BatchRowState.REFUSED.value] == 2
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 1


@asyncio_test
async def test_an_expired_result_does_not_come_back_after_a_restart(tmp_path: Path) -> None:
    """`docs/adr/0018-controlled-batch-execution.md` Tests: retention expiry, across a reload.

    A cleanup or a restart must not restore a downloadable expired artifact,
    and the property is checked twice: once through a fresh service on the same
    file, and once after the purge has actually removed the rows.
    """
    path = tmp_path / "batch.db"
    store = open_store(path)
    clock = MovableClock()
    batch, _, _ = build(store, clock=clock, retention=60)
    report = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    assert await batch.result(report.batch_id, principal=PRINCIPAL) is not None

    clock.advance(120)

    reopened = open_store(path)
    later, _, _ = build(reopened, clock=clock, retention=60)
    assert await later.result(report.batch_id, principal=PRINCIPAL) is None
    assert await later.report(report.batch_id, principal=PRINCIPAL) is None

    assert await reopened.purge_expired(now=clock.now(), limit=10) == 1
    again = open_store(path)
    third, _, _ = build(again, clock=clock, retention=60)
    assert await third.result(report.batch_id, principal=PRINCIPAL) is None


@asyncio_test
async def test_deleting_removes_the_row_plaintext_from_the_file(tmp_path: Path) -> None:
    """
    `docs/adr/0018-controlled-batch-execution.md` preconditions: cancellation **and deletion**.
    """
    path = tmp_path / "batch.db"
    store = open_store(path)
    jobs, executor, _ = build_jobs()
    batch, _, _ = build(store, jobs=jobs, executor=executor)
    batch.jobs = InterruptingJobs(inner=jobs, after=0)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await batch.submit(csv_for("very.secret.localpart@example.test"), principal=PRINCIPAL)
    batch_id = BatchId(next(iter(store_ids(store))))
    assert b"very.secret.localpart" in path.read_bytes()

    batch.jobs = jobs  # type: ignore[assignment]
    assert await batch.delete(batch_id, principal=PRINCIPAL) is True

    assert await store.load_batch(batch_id.value, account=ACCOUNT, now=batch.clock.now()) is None
    assert store_ids(store) == set()
    assert b"very.secret.localpart" not in path.read_bytes()


@asyncio_test
async def test_deleting_one_batch_leaves_another_intact(tmp_path: Path) -> None:
    store = open_store(tmp_path / "batch.db")
    batch, executor, _ = build(store)
    first = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    batch.random_source = FakeRandomSource(prefix="second")  # type: ignore[assignment]
    second = await batch.submit(csv_for("b@example.test"), principal=PRINCIPAL)
    before = list(executor.submitted)

    # Both batches ran to completion, so both have a downloadable result — which
    # is what lets this assert that deletion takes one and leaves the other.
    assert await batch.result(first.batch_id, principal=PRINCIPAL) is not None

    assert await batch.delete(first.batch_id, principal=PRINCIPAL) is True

    # The artifact goes with the state. Removing the rows and leaving the result
    # readable is the deletion that looks complete and is not: the artifact
    # holds every row of the report.
    assert await batch.result(first.batch_id, principal=PRINCIPAL) is None
    assert await batch.report(second.batch_id, principal=PRINCIPAL) is not None
    assert await batch.result(second.batch_id, principal=PRINCIPAL) is not None
    # No child job of either batch was touched: deletion is batch state only.
    assert executor.submitted == before


# --- the store's own contract ------------------------------------------------


@asyncio_test
async def test_the_store_refuses_at_capacity_rather_than_evicting(tmp_path: Path) -> None:
    """
    `docs/adr/0018-controlled-batch-execution.md` needs a bound; evicting a live batch is not one.
    """
    store = open_store(tmp_path / "batch.db", max_batches=1)
    batch, _, _ = build(store)
    first = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    batch.random_source = FakeRandomSource(prefix="second")  # type: ignore[assignment]

    with pytest.raises(BatchStoreFull):
        await batch.submit(csv_for("b@example.test"), principal=PRINCIPAL)

    assert await batch.report(first.batch_id, principal=PRINCIPAL) is not None


@asyncio_test
async def test_an_expired_batch_makes_room_and_a_live_one_does_not(tmp_path: Path) -> None:
    store = open_store(tmp_path / "batch.db", max_batches=1)
    clock = MovableClock()
    batch, _, _ = build(store, clock=clock, retention=60)
    first = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)

    clock.advance(120)
    batch.random_source = FakeRandomSource(prefix="second")  # type: ignore[assignment]
    second = await batch.submit(csv_for("b@example.test"), principal=PRINCIPAL)

    assert await batch.report(second.batch_id, principal=PRINCIPAL) is not None
    assert await batch.report(first.batch_id, principal=PRINCIPAL) is None


def test_a_store_written_by_another_schema_is_refused(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "batch.db"
    open_store(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("UPDATE batch_schema_version SET version = 99")

    with pytest.raises(BatchStoreSchemaError):
        SQLiteBatchStore(path=path).initialize()


@pytest.mark.parametrize("size", [0, -1, True])
def test_a_store_bound_refuses_a_boolean_and_a_non_positive(size: object) -> None:
    with pytest.raises(ValueError):
        SQLiteBatchStore(path=Path("unused.db"), max_batches=size)  # type: ignore[arg-type]


# --- ownership on the real adapter, not on the fake --------------------------


@asyncio_test
async def test_another_account_cannot_load_an_artifact_from_the_real_store(
    tmp_path: Path,
) -> None:
    """The owner predicate lives in the SQL, and this is what pins it there.

    An independent review removed `account` from `_SELECT_ARTIFACT` and the
    whole suite still passed: the cross-account artifact test used the
    in-memory fake, so it proved the fake checks ownership. The artifact holds
    every row of a report, which makes this the highest-value cross-account
    read in the subsystem.
    """
    store = open_store(tmp_path / "batch.db")
    batch, _, _ = build(store)
    report = await batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    now = batch.clock.now()

    assert await store.load_artifact(report.batch_id.value, account=ACCOUNT, now=now) is not None
    assert (
        await store.load_artifact(report.batch_id.value, account=OTHER.rate_limit_account, now=now)
        is None
    )
    # And through the service, which is the surface a transport would bind to.
    assert await batch.result(report.batch_id, principal=OTHER) is None


# --- rate limiting is not fairness -------------------------------------------


@asyncio_test
async def test_the_limiter_bounds_different_domains_on_a_shared_exchanger() -> None:
    """ADR 0020 adds MX protection; scheduler fairness remains separate."""
    from emailcheck.domain.rate_limit import RateLimitTimeout

    clock = FakeMonotonicClock()
    limiter = InProcessRateLimiter(
        clock=clock,
        sleeper=FakeSleeper(clock=clock),
        settings=RateLimitSettings(global_concurrency=8, domain_concurrency=1),
    )
    shared = "mx.shared.test"
    async with limiter.acquire(account="acct", domain="a.test", mx_host=shared):
        with pytest.raises(RateLimitTimeout):
            async with limiter.acquire(account="acct", domain="b.test", mx_host=shared):
                raise AssertionError("shared MX capacity bypassed")
        assert limiter.active_leases == 1
    assert limiter.active_leases == 0


def store_ids(store: SQLiteBatchStore) -> set[str]:
    import sqlite3

    with closing(sqlite3.connect(store.path)) as connection, connection:
        return {row[0] for row in connection.execute("SELECT batch_id FROM batches")}
