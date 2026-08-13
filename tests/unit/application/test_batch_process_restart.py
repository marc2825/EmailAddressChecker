"""A **whole-process** restart: both services rebuilt, only the files shared.

`tests/unit/application/test_batch_resume.py` rebuilds the `BatchService` and
keeps the `JobService`, which is a scheduler restart. That is not what
`prompts/10-batch.md`'s *restart/resume* asks for, and the difference was not
cosmetic: with the job registry in memory, a resumed batch presenting its
deterministic handle was answered "new" by a fresh process and started a
**second verification** for a row whose verification had already run. A
duplicate `RCPT TO` for one address, arranged by restarting — the pattern
`docs/threat-model.md` lists first.

So every test here discards both services and constructs new ones over the same
SQLite files, exactly as a new process would find them. `build_jobs` takes the
stores as parameters so that what the two processes share is the disk and
nothing else.

Nothing here opens a socket and nothing sleeps.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
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
from tests.phase6_fixtures import (
    FakeRandomSource,
    InMemoryVerdictStore,
    RecordingExecutor,
    ScriptedSMTPVerification,
)
from tests.phase7_fixtures import OTHER_PRINCIPAL as OTHER

from emailcheck.adapters.storage.sqlite_batch_store import SQLiteBatchStore
from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.application.batch import BatchService
from emailcheck.application.jobs import IdempotencyConflict, JobService
from emailcheck.domain.batch import BatchId, BatchLimits, BatchRowState
from emailcheck.domain.job import IdempotencyKey, JobError, JobFailure, JobId, JobState
from emailcheck.ports.job_executor import ExecutorFull

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0
SERIAL: Final = BatchLimits(max_in_flight=1, max_in_flight_per_domain=1, max_in_flight_per_mx=1)


class Interrupted(BaseException):
    """A stopped process, from inside the scheduler.

    A `BaseException`: `_one` turns every `Exception` into a `refused` row,
    which is right for a quota and wrong for "the machine went away".
    """


@dataclass
class InterruptingJobs:
    """Stops after `after` submissions, optionally *after* the handover."""

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
            raise Interrupted("the process stopped after the handover")
        return outcome


@dataclass(slots=True)
class Machine:
    """One process's worth of state, over files that outlive it.

    `restart()` throws away every in-memory object and builds fresh ones from
    the same two paths — which is the whole point: a test that reused the
    registry would be measuring nothing.
    """

    root: Path
    clock: MovableClock = field(default_factory=MovableClock)
    verdicts: InMemoryVerdictStore = field(default_factory=InMemoryVerdictStore)
    executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    jobs: JobService = field(init=False)
    batch: BatchService = field(init=False)
    retention_seconds: int = 3600
    limits: BatchLimits = SERIAL
    #: The scripted recipient answer. A temporary one is what makes
    #: `retry_scheduled` reachable through the ordinary pipeline.
    reply_lines: tuple[str, ...] = ("250 2.1.5 ok",)

    def __post_init__(self) -> None:
        self.restart()

    @property
    def batch_store(self) -> SQLiteBatchStore:
        store = SQLiteBatchStore(path=self.root / "batch.db")
        store.initialize()
        return store

    @property
    def job_store(self) -> SQLiteJobStore:
        store = SQLiteJobStore(path=self.root / "jobs.db")
        store.initialize()
        return store

    def restart(self) -> None:
        """Simulate a hard death: nothing in memory survives but the disk.

        The **verdict cache and the executor are carried across**, and both are
        deliberate. The cache is a store in a real deployment and carrying it
        keeps the test honest about what a restart loses; the executor stands in
        for a worker whose queue this test is not about, and it is what lets
        "was a second verification enqueued" be counted across the boundary.
        """
        self.jobs = build_jobs(
            smtp=ScriptedSMTPVerification(reply_lines=self.reply_lines),
            job_store=self.job_store,
            verdicts=self.verdicts,
            executor=self.executor,
            random_prefix=f"job{len(self.executor.submitted)}",
        )[0]
        self.batch = BatchService(
            jobs=self.jobs,
            store=self.batch_store,
            clock=self.clock,  # type: ignore[arg-type]
            random_source=FakeRandomSource(prefix="batch"),
            settings=approved(limits=self.limits, result_retention_seconds=self.retention_seconds),
            correlation_key=CORRELATION_KEY,
        )

    def batch_ids(self) -> set[str]:
        import sqlite3

        with sqlite3.connect(self.root / "batch.db") as connection:
            return {row[0] for row in connection.execute("SELECT batch_id FROM batches")}


# --- the property the whole seam exists for ---------------------------------


@asyncio_test
async def test_a_new_process_recovers_the_same_job_for_the_same_handle(tmp_path: Path) -> None:
    """§7's exact property, on two `JobService` instances sharing only a file.

    Without the store this fails by returning a *new* `JobId`, which for a batch
    means a second verification for a row that already had one.
    """
    machine = Machine(root=tmp_path)
    key = IdempotencyKey("handle-" + "a" * 20)

    first = await machine.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)
    assert first.enqueued is True
    enqueued_before = len(machine.executor.submitted)

    machine.restart()
    again = await machine.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)

    assert again.job.id.value == first.job.id.value, "a restart minted a second job"
    assert again.enqueued is False
    assert again.existing is True
    assert len(machine.executor.submitted) == enqueued_before, "a restart enqueued the work twice"


@asyncio_test
async def test_the_same_handle_with_a_different_address_still_conflicts(tmp_path: Path) -> None:
    """Phase 6's contract survives the restart rather than being relaxed by it.

    Answering with the first address's job would be a confident verdict about a
    mailbox nobody asked about — ADR 0014's reason, and a stored digest is what
    lets a fresh process still notice.
    """
    machine = Machine(root=tmp_path)
    key = IdempotencyKey("handle-" + "b" * 20)
    await machine.jobs.submit("first@example.test", principal=PRINCIPAL, idempotency_key=key)

    machine.restart()

    with pytest.raises(IdempotencyConflict):
        await machine.jobs.submit("second@example.test", principal=PRINCIPAL, idempotency_key=key)


@asyncio_test
async def test_another_account_cannot_read_a_persisted_job(tmp_path: Path) -> None:
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit("user@example.test", principal=PRINCIPAL)

    machine.restart()

    assert await machine.jobs.fetch(outcome.job.id, principal=OTHER) is None
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)
    assert recovered is not None
    assert recovered.owner == ACCOUNT


# --- the batch across a whole-process restart -------------------------------


@asyncio_test
async def test_a_batch_resumes_across_a_whole_process_restart(tmp_path: Path) -> None:
    """`prompts/10-batch.md` Tests: restart/resume, with **both** services new.

    Five rows, interrupted after two, then continued by a process that shares
    only the two database files. Every assertion §4 asks for.
    """
    machine = Machine(root=tmp_path)
    machine.batch.jobs = InterruptingJobs(inner=machine.jobs, after=2)  # type: ignore[assignment]

    with pytest.raises(Interrupted):
        async with asyncio.timeout(OUTER_BOUND):
            await machine.batch.submit(
                csv_for(*(f"u{index}@example.test" for index in range(5))), principal=PRINCIPAL
            )

    batch_id = BatchId(next(iter(machine.batch_ids())))
    submitted_before = list(machine.executor.submitted)
    assert len(submitted_before) == 2

    machine.restart()
    async with asyncio.timeout(OUTER_BOUND):
        report = await machine.batch.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    # Already-submitted rows kept their original jobs, and no job was made twice.
    assert machine.executor.submitted[:2] == submitted_before
    assert len(machine.executor.submitted) == 5, "a row was verified twice"
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 5
    assert sum(report.state_summary.values()) == report.input_rows == 5
    # The child jobs are not silently lost: the report can still name them.
    assert all(row.job_id is not None for row in report.rows)
    assert all(row.job_state is not None for row in report.rows)


@asyncio_test
async def test_the_dangerous_handoff_survives_a_whole_process_restart(tmp_path: Path) -> None:
    """§8. The job was accepted; the batch never recorded it; everything died.

    Both records that make the recovery possible were committed **before** the
    crash — the job with its idempotency digest, and the row as `claimed` with
    its handle — and neither is in memory. A fresh process re-presents the
    handle and is answered with the existing job.
    """
    machine = Machine(root=tmp_path)
    interrupting = InterruptingJobs(inner=machine.jobs, after=1, before_recording=True)
    machine.batch.jobs = interrupting  # type: ignore[assignment]

    with pytest.raises(Interrupted):
        async with asyncio.timeout(OUTER_BOUND):
            await machine.batch.submit(
                csv_for("a@example.test", "b@example.test", "c@example.test"),
                principal=PRINCIPAL,
            )

    batch_id = BatchId(next(iter(machine.batch_ids())))
    held = await machine.batch_store.load_batch(
        batch_id.value, account=ACCOUNT, now=machine.clock.now()
    )
    assert held is not None
    orphan = [row for row in held.rows if row.state is BatchRowState.CLAIMED]
    assert len(orphan) == 1, "the crash boundary was not recorded"
    assert orphan[0].job_id is None, "this test is not exercising the dangerous case"
    handed_over = list(machine.executor.submitted)
    assert len(handed_over) == 2

    machine.restart()
    async with asyncio.timeout(OUTER_BOUND):
        report = await machine.batch.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert len(machine.executor.submitted) == 3, "the orphan became a second verification"
    recovered = next(row for row in report.rows if row.number == orphan[0].number)
    assert recovered.job_id == interrupting.ids[1]
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 3


@asyncio_test
async def test_the_opposite_boundary_submits_the_row_exactly_once(tmp_path: Path) -> None:
    """§9. `claimed` was written and the job service never accepted anything.

    The row must be submitted, once. This is the boundary where doing nothing
    would be the failure: the handle names no job, so a resume that refused to
    submit would leave a row that can never finish.
    """
    machine = Machine(root=tmp_path)
    machine.batch.jobs = InterruptingJobs(inner=machine.jobs, after=0)  # type: ignore[assignment]

    with pytest.raises(Interrupted):
        await machine.batch.submit(csv_for("a@example.test", "b@example.test"), principal=PRINCIPAL)

    batch_id = BatchId(next(iter(machine.batch_ids())))
    assert machine.executor.submitted == []

    machine.restart()
    report = await machine.batch.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert len(machine.executor.submitted) == 2
    assert report.state_summary[BatchRowState.SUBMITTED.value] == 2

    # And resuming again submits nothing more: the rows are recorded now.
    machine.restart()
    again = await machine.batch.resume(batch_id, principal=PRINCIPAL)
    assert again is not None
    assert len(machine.executor.submitted) == 2


# --- results, retries, and cancellation across the boundary ------------------


@asyncio_test
async def test_a_terminal_child_result_is_recoverable_by_a_new_process(tmp_path: Path) -> None:
    """§10. Recovering a `JobId` is not enough if the answer never comes back.

    The verification completes in the first process; the second one reads its
    verdict out of the job store and finalizes the batch result from it.
    """
    machine = Machine(root=tmp_path)
    report = await machine.batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    assert report.complete is False
    await machine.executor.run_pending()

    machine.restart()
    final = await machine.batch.report(report.batch_id, principal=PRINCIPAL)

    assert final is not None
    assert final.complete is True
    assert final.rows[0].job_state == JobState.COMPLETED.value
    assert final.rows[0].status is not None
    assert final.rows[0].primary_reason is not None
    artifact = await machine.batch.result(report.batch_id, principal=PRINCIPAL)
    assert artifact is not None and artifact.complete is True
    assert final.rows[0].status in artifact.content


@asyncio_test
async def test_a_restart_does_not_reset_a_childs_retry_budget(tmp_path: Path) -> None:
    """§11. One retry is a budget, and a budget a restart refills is none.

    Driven through the ordinary pipeline: a `450` is `docs/requirements.md`
    section 14's explicit temporary condition, so the job moves to
    `retry_scheduled` with its one retry spent. `CheckJob` refuses a second
    retry structurally — but only if the count survives, which is what this
    asserts about the store rather than about the type.
    """
    machine = Machine(root=tmp_path, reply_lines=("450 4.7.1 try later",))
    outcome = await machine.jobs.submit("user@example.test", principal=PRINCIPAL)
    await machine.executor.run_pending()
    scheduled = machine.jobs.get(outcome.job.id, principal=PRINCIPAL)
    assert scheduled is not None
    assert scheduled.state is JobState.RETRY_SCHEDULED
    assert scheduled.retries_used == 1

    machine.restart()
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)

    assert recovered is not None
    assert recovered.state is JobState.RETRY_SCHEDULED, "the retry was forgotten"
    assert recovered.retries_used == 1
    assert recovered.may_retry is False, "a restart refilled the retry budget"
    # And the batch reading such a row publishes no status for it: a scheduled
    # retry is not an answer.
    assert recovered.result is None


@asyncio_test
async def test_a_cancelled_child_stays_cancelled_across_a_restart(tmp_path: Path) -> None:
    """§12. The batch does not resubmit it, and the state is not re-decided."""
    machine = Machine(root=tmp_path)
    report = await machine.batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    child = JobId(report.rows[0].job_id or "")
    await machine.jobs.cancel(child, principal=PRINCIPAL)
    before = list(machine.executor.submitted)

    machine.restart()
    recovered = await machine.jobs.fetch(child, principal=PRINCIPAL)
    resumed = await machine.batch.resume(report.batch_id, principal=PRINCIPAL)

    assert recovered is not None
    assert recovered.state is JobState.CANCELLED
    assert machine.executor.submitted == before, "a cancelled child was resubmitted"
    assert resumed is not None
    assert resumed.rows[0].job_state == JobState.CANCELLED.value
    assert resumed.rows[0].status is None


@asyncio_test
async def test_a_cancelled_batch_submits_nothing_after_a_whole_process_restart(
    tmp_path: Path,
) -> None:
    machine = Machine(root=tmp_path)
    machine.batch.jobs = InterruptingJobs(inner=machine.jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await machine.batch.submit(
            csv_for(*(f"u{index}@example.test" for index in range(4))), principal=PRINCIPAL
        )
    batch_id = BatchId(next(iter(machine.batch_ids())))
    assert await machine.batch.cancel(batch_id, principal=PRINCIPAL) is True
    before = list(machine.executor.submitted)

    machine.restart()
    report = await machine.batch.resume(batch_id, principal=PRINCIPAL)

    assert report is not None
    assert report.cancelled is True
    assert machine.executor.submitted == before
    assert sum(report.state_summary.values()) == 4


@asyncio_test
async def test_a_job_the_executor_refused_leaves_nothing_persisted(tmp_path: Path) -> None:
    """The rollback reaches the store, not only the registry.

    `submit` writes the claim before handing the work over, so a refusal has to
    unwind both. A record left behind would answer a later presentation of the
    same handle with a job that was never enqueued and can never run — the
    persistent form of the `pending`-job leak an independent review found in
    Phase 6's registry.
    """
    machine = Machine(root=tmp_path)
    machine.executor.full = True
    key = IdempotencyKey("handle-" + "c" * 20)

    with pytest.raises(ExecutorFull):
        await machine.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)

    machine.restart()
    machine.executor.full = False
    recovered = await machine.jobs.submit(
        "user@example.test", principal=PRINCIPAL, idempotency_key=key
    )

    assert recovered.enqueued is True, "a refused job was recovered from the store"
    assert recovered.existing is False
    assert len(machine.executor.submitted) == 1


def test_a_stored_job_may_not_carry_a_status_before_it_completes() -> None:
    """The `CheckJob` pairing, re-checked where a row becomes a value again.

    A stored job is assembled from a database row rather than from a value that
    already validated itself, so this is the one place a `running` job could
    acquire a published deliverability status — which is the re-derivation
    Phase 5 stop condition 1 forbids, arriving through a restart.
    """
    from emailcheck.ports.job_store import StoredJob

    moment = MovableClock().now()
    common = {
        "job_id": "j" * 32,
        "owner": ACCOUNT,
        "created_at": moment,
        "updated_at": moment,
    }

    with pytest.raises(JobError):
        StoredJob(state=JobState.RUNNING, status="likely_deliverable", **common)  # type: ignore[arg-type]
    with pytest.raises(JobError):
        StoredJob(state=JobState.COMPLETED, **common)  # type: ignore[arg-type]
    with pytest.raises(JobError):
        StoredJob(state=JobState.RUNNING, failure=JobFailure.SERVICE_ERROR, **common)  # type: ignore[arg-type]
    with pytest.raises(JobError):
        StoredJob(state=JobState.FAILED, **common)  # type: ignore[arg-type]
    # An owner is an account, never a mailbox — the shape check every budget
    # key and every stored record in this project makes.
    with pytest.raises(JobError):
        StoredJob(
            job_id="j" * 32,
            owner="someone@example.test",
            state=JobState.PENDING,
            created_at=moment,
            updated_at=moment,
        )

    # And the shapes that are legal stay legal.
    assert StoredJob(state=JobState.RUNNING, **common).status is None  # type: ignore[arg-type]


# --- ownership on the real job store, and the three barriers -----------------


@asyncio_test
async def test_another_owner_cannot_find_a_persisted_idempotency_binding(
    tmp_path: Path,
) -> None:
    """The `WHERE owner = ?` predicate, pinned on the adapter itself.

    Removing it passed the whole suite in an independent review, because no
    test called `find_by_idempotency` on the real store at all — only the
    digest's own domain separation was doing any work.
    """
    machine = Machine(root=tmp_path)
    key = IdempotencyKey("handle-" + "d" * 20)
    outcome = await machine.jobs.submit(
        "user@example.test", principal=PRINCIPAL, idempotency_key=key
    )
    digest = machine.jobs._idempotency_digest(ACCOUNT, key)
    store = machine.job_store

    found = await store.find_by_idempotency(ACCOUNT, digest)
    assert found is not None and found.job_id == outcome.job.id.value

    # The *same digest* under another owner must not answer. Passing A's digest
    # with B's account is the query a removed predicate would satisfy — and it
    # cannot be reached by ordinary construction, which is exactly why the
    # predicate needs a test that constructs it deliberately.
    assert await store.find_by_idempotency(OTHER.rate_limit_account, digest) is None


def test_the_idempotency_digest_separates_owners_on_the_same_key() -> None:
    """Barrier one, tested where it cannot be confused with barrier two.

    Two accounts choosing the same handle must not produce the same binding.
    This is asserted on the digest alone so that the adapter test above is not
    passing merely because the digest happened to differ.
    """
    from tests.batch_fixtures import build_jobs as make

    jobs = make()[0]
    key = IdempotencyKey("shared-" + "e" * 20)

    mine = jobs._idempotency_digest(ACCOUNT, key)
    theirs = jobs._idempotency_digest(OTHER.rate_limit_account, key)
    other_key = jobs._idempotency_digest(ACCOUNT, IdempotencyKey("другой-" + "f" * 20))

    assert mine != theirs
    assert mine != other_key
    assert "@" not in mine
    # Deterministic for the same pair, or a restart would recover nothing.
    assert jobs._idempotency_digest(ACCOUNT, key) == mine


@asyncio_test
async def test_a_store_answering_with_another_owners_job_is_refused(tmp_path: Path) -> None:
    """Barrier three: the application checks the owner it asked for.

    The digest carries the owner and the SQL names it, so reaching this needs a
    store that answered a question it was not asked — a bug, a shared file, or
    a compromised adapter. Failing closed costs one duplicate submission;
    trusting it hands one account another account's job.

    The caller learns nothing: `None` is what an unknown binding returns too.
    The operator gets the event, because they are who can act on it.
    """

    @dataclass
    class TreacherousStore:
        inner: SQLiteJobStore
        planted: object = None

        async def save(self, record: object) -> None:
            await self.inner.save(record)  # type: ignore[arg-type]

        async def load(self, job_id: str) -> object | None:
            return await self.inner.load(job_id)

        async def find_by_idempotency(self, owner: str, digest: str) -> object | None:
            return self.planted

        async def delete(self, job_id: str) -> None:
            await self.inner.delete(job_id)

        async def purge_terminal(self, *, before: object, limit: int) -> int:
            return await self.inner.purge_terminal(before=before, limit=limit)  # type: ignore[arg-type]

    machine = Machine(root=tmp_path)
    key = IdempotencyKey("handle-" + "g" * 20)
    theirs = await machine.jobs.submit("user@example.test", principal=OTHER, idempotency_key=key)
    planted = await machine.job_store.load(theirs.job.id.value)
    assert planted is not None

    treacherous = TreacherousStore(inner=machine.job_store, planted=planted)
    machine.restart()
    machine.jobs.store = treacherous  # type: ignore[assignment]

    mine = await machine.jobs.submit("user@example.test", principal=PRINCIPAL, idempotency_key=key)

    assert mine.job.id.value != theirs.job.id.value, "another account's job was handed over"
    assert mine.job.owner == ACCOUNT
    assert mine.existing is False


# --- retention and privacy ---------------------------------------------------


@asyncio_test
async def test_a_persisted_job_holds_no_address_anywhere(tmp_path: Path) -> None:
    """The store is new persistent state, so this is its privacy audit.

    Read off the **file**, not the object: the question is what a disk holds
    after the process is gone.
    """
    machine = Machine(root=tmp_path)
    await machine.jobs.submit(
        "very.secret.localpart+tag@example.test",
        principal=PRINCIPAL,
        idempotency_key=IdempotencyKey("also.secret@example.test"),
    )

    raw = (tmp_path / "jobs.db").read_bytes()

    assert b"very.secret.localpart" not in raw
    assert b"also.secret" not in raw
    assert CORRELATION_KEY not in raw


@asyncio_test
async def test_a_persisted_job_expires_on_the_same_window_as_the_registry(
    tmp_path: Path,
) -> None:
    """§13. Persistence is not a reason to keep a job longer than the policy.

    The sweep uses one cutoff for both, so a terminal job cannot outlive
    `docs/privacy.md` section 3 by being on disk.
    """
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit("user@example.test", principal=PRINCIPAL)
    await machine.executor.run_pending()
    store = machine.job_store
    assert await store.load(outcome.job.id.value) is not None

    removed = await store.purge_terminal(
        before=machine.clock.now() + timedelta(seconds=1), limit=10
    )

    assert removed == 1
    assert await store.load(outcome.job.id.value) is None


@asyncio_test
async def test_a_live_job_is_never_purged(tmp_path: Path) -> None:
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit("user@example.test", principal=PRINCIPAL)

    removed = await machine.job_store.purge_terminal(
        before=machine.clock.now() + timedelta(days=365), limit=10
    )

    assert removed == 0
    assert await machine.job_store.load(outcome.job.id.value) is not None


@asyncio_test
async def test_the_central_sweep_clears_batch_plaintext_after_a_restart(tmp_path: Path) -> None:
    """B1 end to end: real stores, a real sweep, across a process boundary.

    The window belongs to `BatchSettings.input_retention_seconds`; the sweep is
    `RetentionService`'s; and neither is in memory, so the plaintext of a batch
    submitted by a process that no longer exists is still cleared.

    What survives the clearing is asserted too, because the two policies are
    different: the batch's accounting, its identifier, and its child `JobId`s
    live under `result_retention_seconds` and must **not** go early.
    """
    from tests.phase7_fixtures import CORRELATION_KEY as KEY
    from tests.phase7_fixtures import CountingQuotaStore, RecordingOperator
    from tests.phase7_fixtures import SteppableClock as _Steppable

    from emailcheck.adapters.observability.metrics import InMemoryMetrics
    from emailcheck.application.abuse import AbuseGuard
    from emailcheck.application.admin import AdminControl
    from emailcheck.application.retention import RetentionService
    from emailcheck.domain.batch import BatchSettings

    machine = Machine(root=tmp_path)
    machine.retention_seconds = 24 * 60 * 60
    machine.restart()
    machine.batch.jobs = InterruptingJobs(inner=machine.jobs, after=1)  # type: ignore[assignment]
    with pytest.raises(Interrupted):
        await machine.batch.submit(
            csv_for("kept@example.test", "very.secret.localpart@example.test"),
            principal=PRINCIPAL,
        )
    batch_id = BatchId(next(iter(machine.batch_ids())))
    path = tmp_path / "batch.db"
    assert b"very.secret.localpart" in path.read_bytes(), "nothing to clear"

    machine.restart()
    machine.clock.advance(3600)
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=_Steppable(),
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=KEY,
    )
    sweep = RetentionService(
        clock=machine.clock,  # type: ignore[arg-type]
        admin=AdminControl(guard=guard, clock=_Steppable(), metrics=metrics, correlation_key=KEY),
        batches=machine.batch_store,
        batch_settings=BatchSettings(input_retention_seconds=1800),
    )

    report = await sweep.run()

    assert report.failed is False
    assert report.batch_inputs_cleared == 1
    assert b"very.secret.localpart" not in path.read_bytes(), "plaintext survived the sweep"

    # **The accounting did not go with it.** The batch is still readable, still
    # names its child job, and its rows still balance.
    held = await machine.batch_store.load_batch(
        batch_id.value, account=ACCOUNT, now=machine.clock.now()
    )
    assert held is not None
    assert held.input_rows == 2
    assert any(row.job_id is not None for row in held.rows)
    assert all(row.submitted is None for row in held.rows)

    # And resuming now refuses the row nothing can submit, explicitly.
    resumed = await machine.batch.resume(batch_id, principal=PRINCIPAL)
    assert resumed is not None
    assert sum(resumed.state_summary.values()) == 2
    assert resumed.state_summary[BatchRowState.REFUSED.value] == 1
    assert resumed.state_summary[BatchRowState.SUBMITTED.value] == 1
    assert all(row.status is None for row in resumed.rows), "a status was fabricated"


@asyncio_test
async def test_the_central_sweep_purges_an_expired_batch_and_its_artifact(
    tmp_path: Path,
) -> None:
    """The other half, and on its own clock: `result_retention_seconds`."""
    from tests.phase7_fixtures import CORRELATION_KEY as KEY
    from tests.phase7_fixtures import CountingQuotaStore, RecordingOperator
    from tests.phase7_fixtures import SteppableClock as _Steppable

    from emailcheck.adapters.observability.metrics import InMemoryMetrics
    from emailcheck.application.abuse import AbuseGuard
    from emailcheck.application.admin import AdminControl
    from emailcheck.application.retention import RetentionService
    from emailcheck.domain.batch import BatchSettings

    machine = Machine(root=tmp_path)
    machine.retention_seconds = 60
    machine.restart()
    report = await machine.batch.submit(csv_for("a@example.test"), principal=PRINCIPAL)
    assert await machine.batch.result(report.batch_id, principal=PRINCIPAL) is not None

    machine.clock.advance(120)
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=_Steppable(),
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=KEY,
    )
    sweep = RetentionService(
        clock=machine.clock,  # type: ignore[arg-type]
        admin=AdminControl(guard=guard, clock=_Steppable(), metrics=metrics, correlation_key=KEY),
        batches=machine.batch_store,
        batch_settings=BatchSettings(),
    )

    swept = await sweep.run()

    assert swept.batches_removed == 1
    assert machine.batch_ids() == set()
    machine.restart()
    assert await machine.batch.result(report.batch_id, principal=PRINCIPAL) is None
