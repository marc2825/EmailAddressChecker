"""What survives a stopped process, and what may never be replayed.

The final system audit's third finding: the handoff between the job store and
the executor left states nothing could advance and states memory and disk
disagreed about. Four of them were measured — an initial save failure leaving an
in-memory phantom, an executor refusal leaving a persistent one, a `running`
transition whose persist failed while SMTP went ahead anyway, and a
`retry_scheduled` job whose `schedule()` was refused and which then sat
nonterminal for ever.

**Every restart here discards the executor as well as the service.** The Phase 10
restart tests deliberately carried the executor across, because what they were
measuring was the idempotency binding and the executor stood in for a queue this
project does not have. That is exactly the wrong shape for these tests: an
executor that survives is a queue that survives, and the whole question here is
what happens when nothing does. `Machine.restart()` builds a new `JobService`
**and** a new empty `RecordingExecutor` over the same file.

The recovery policy under test is deliberately conservative and is not
resumption. `ports/job_executor.py`'s only implementation dies with its process,
so a nonterminal row has nowhere to be resumed *to*; `recover_interrupted` ends
it as `failed` / `interrupted`, which is an operational category carrying **no
status**. Turning "we do not know whether the `RCPT TO` went out" into `unknown`
or `temporary_unknown` would be answering a question about a mailbox with a fact
about a machine.

Nothing here opens a socket and nothing sleeps.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from tests.batch_fixtures import PRINCIPAL, build_jobs
from tests.phase6_fixtures import (
    GatedSMTPVerification,
    InMemoryVerdictStore,
    RecordingExecutor,
    ScriptedSMTPVerification,
    resolver_with_temporary_failure,
)
from tests.phase7_fixtures import OTHER_PRINCIPAL as OTHER

from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.application.jobs import IdempotencyConflict, JobService
from emailcheck.domain.job import IdempotencyKey, JobAdmission, JobFailure, JobId, JobState
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.verdict import Status
from emailcheck.ports.job_executor import ExecutorFull
from emailcheck.ports.job_store import StoredJob

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0
ADDRESS: Final = "user@example.test"
KEY: Final = IdempotencyKey("crash-handle-" + "a" * 12)
LATER: Final = datetime(2099, 1, 1, tzinfo=UTC)


class StoreStopped(RuntimeError):
    """The database went away. Distinct from anything the application raises."""


@dataclass
class GatedRefusingExecutor(RecordingExecutor):
    """Expose the durable-claim/admission gap without a timing sleep."""

    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def submit(self, job_id: JobId, work: object) -> None:
        del job_id, work
        self.entered.set()
        await self.release.wait()
        raise ExecutorFull("admission refused")


@dataclass
class FaultyJobStore:
    """A real store with one operation broken on demand.

    Wrapping the real adapter rather than faking it: what is being tested is the
    *protocol* around a write that does not land, and a fake store would let the
    protocol pass against SQL that never ran.
    """

    inner: SQLiteJobStore
    fail_claim: bool = False
    fail_save_from: int = 0
    saves: int = 0

    async def claim_idempotency(self, record: object, *, expected_generation: int) -> object:
        if self.fail_claim:
            raise StoreStopped("the store is unavailable")
        return await self.inner.claim_idempotency(  # type: ignore[arg-type]
            record, expected_generation=expected_generation
        )

    async def save(self, record: object, *, expected_generation: int) -> bool:
        self.saves += 1
        if self.fail_save_from and self.saves >= self.fail_save_from:
            raise StoreStopped("the store is unavailable")
        return await self.inner.save(  # type: ignore[arg-type]
            record, expected_generation=expected_generation
        )

    async def fence(self, *, account: str, generation: int) -> int:
        return await self.inner.fence(account=account, generation=generation)

    async def load(self, job_id: str) -> object | None:
        return await self.inner.load(job_id)

    async def find_by_idempotency(self, owner: str, digest: str) -> object | None:
        return await self.inner.find_by_idempotency(owner, digest)

    async def find_nonterminal(self, *, before: object, limit: int) -> object:
        return await self.inner.find_nonterminal(before=before, limit=limit)  # type: ignore[arg-type]

    async def delete(self, job_id: str) -> None:
        await self.inner.delete(job_id)

    async def purge_terminal(self, *, before: object, limit: int) -> int:
        return await self.inner.purge_terminal(before=before, limit=limit)  # type: ignore[arg-type]


@dataclass(slots=True)
class Machine:
    """One process's worth of state over a file that outlives it."""

    root: Path
    verdicts: InMemoryVerdictStore = field(default_factory=InMemoryVerdictStore)
    executor: RecordingExecutor = field(init=False)
    jobs: JobService = field(init=False)
    smtp: object = None
    servfail: bool = False
    restarts: int = 0

    def __post_init__(self) -> None:
        self.restart()

    @property
    def store(self) -> SQLiteJobStore:
        store = SQLiteJobStore(path=self.root / "jobs.db")
        store.initialize()
        return store

    def restart(self, *, store: object | None = None) -> None:
        """A hard death: **new service, new empty executor**, same file.

        Reusing the executor would be reusing the queue, and a test of "what can
        a fresh process do with this row" that keeps the previous process's work
        answers a different question.
        """
        self.restarts += 1
        self.executor = RecordingExecutor()
        self.jobs = build_jobs(
            smtp=self.smtp,  # type: ignore[arg-type]
            resolver=resolver_with_temporary_failure() if self.servfail else None,
            job_store=store if store is not None else self.store,
            verdicts=self.verdicts,
            executor=self.executor,
            random_prefix=f"p{self.restarts}",
        )[0]

    async def row(self, job_id: JobId) -> StoredJob | None:
        return await self.store.load(job_id.value)


# --- 1. the claim never landed ----------------------------------------------


@asyncio_test
async def test_a_failed_initial_claim_leaves_no_phantom_anywhere(tmp_path: Path) -> None:
    """The audit's observation: the durable write failed and the job survived.

    Before, `_claim` registered in memory and *then* persisted, so a store
    failure left a `pending` job in the registry, an idempotency binding naming
    it, and nothing in the executor — a job that could never run, occupying a
    registry slot that eviction only frees for terminal jobs.

    Now the durable claim is first, so a failure means nothing was created at
    all: no binding, no fetchable job, no admission.
    """
    machine = Machine(root=tmp_path)
    faulty = FaultyJobStore(inner=machine.store, fail_claim=True)
    machine.jobs.store = faulty  # type: ignore[assignment]

    with pytest.raises(StoreStopped):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert machine.executor.submitted == [], "work was handed over without a durable record"
    assert machine.jobs._by_key == {}, "a binding survived a claim that did not land"
    assert machine.jobs._jobs == {}, "a phantom job survived a claim that did not land"


@asyncio_test
async def test_the_same_handle_can_be_submitted_again_after_a_failed_claim(
    tmp_path: Path,
) -> None:
    """A failure is not a poisoned key. The store recovers, the caller retries,
    and the submission proceeds exactly as a first one."""
    machine = Machine(root=tmp_path)
    faulty = FaultyJobStore(inner=machine.store, fail_claim=True)
    machine.jobs.store = faulty  # type: ignore[assignment]
    with pytest.raises(StoreStopped):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    faulty.fail_claim = False
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert outcome.enqueued is True
    assert outcome.existing is False
    assert machine.executor.submitted == [outcome.job.id.value]
    assert await machine.row(outcome.job.id) is not None


# --- 2. the claim landed and the executor refused ----------------------------


@asyncio_test
async def test_an_executor_refusal_preserves_the_identity_as_a_terminal_failure(
    tmp_path: Path,
) -> None:
    """A committed idempotency winner is observable and therefore never deleted."""
    machine = Machine(root=tmp_path)
    machine.executor.full = True

    with pytest.raises(ExecutorFull):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    stored = await machine.store.find_by_idempotency(
        PRINCIPAL.rate_limit_account,
        machine.jobs._idempotency_digest(PRINCIPAL.rate_limit_account, KEY),
    )
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is JobFailure.CAPACITY_UNAVAILABLE
    assert stored.admission is JobAdmission.ADMISSION_FAILED
    assert stored.status is None
    held = machine.jobs.get(JobId(stored.job_id), principal=PRINCIPAL)
    assert held is not None and held.state is JobState.FAILED


@asyncio_test
async def test_a_later_submission_after_a_refusal_is_deterministic(tmp_path: Path) -> None:
    """The refusal keeps one terminal identity and never creates later work."""
    machine = Machine(root=tmp_path)
    machine.executor.full = True
    with pytest.raises(ExecutorFull):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    machine.executor.full = False
    first = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    again = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert first.enqueued is False and first.existing is True
    assert first.job.state is JobState.FAILED
    assert again.job.id == first.job.id and again.enqueued is False
    assert machine.executor.submitted == []


@asyncio_test
async def test_an_observer_refreshes_a_provisional_job_after_the_owner_is_refused(
    tmp_path: Path,
) -> None:
    """The exact RA-01 race: B must not retain A's deleted pending phantom."""
    store_a = SQLiteJobStore(path=tmp_path / "jobs.db")
    store_a.initialize()
    store_b = SQLiteJobStore(path=tmp_path / "jobs.db")
    store_b.initialize()
    verdicts = InMemoryVerdictStore()
    gate = GatedRefusingExecutor()
    observer_executor = RecordingExecutor()
    first = build_jobs(
        job_store=store_a,
        verdicts=verdicts,
        executor=gate,
        random_prefix="owner",
    )[0]
    second = build_jobs(
        job_store=store_b,
        verdicts=verdicts,
        executor=observer_executor,
        random_prefix="observer",
    )[0]

    owner = asyncio.create_task(first.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY))
    async with asyncio.timeout(OUTER_BOUND):
        await gate.entered.wait()
        observed = await second.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
        assert observed.job.state is JobState.PENDING
        assert observed.existing is True and observed.enqueued is False
        provisional = await store_b.load(observed.job.id.value)
        assert provisional is not None
        assert provisional.admission is JobAdmission.HANDOFF_COMMITTED
        gate.release.set()
        with pytest.raises(ExecutorFull):
            await owner

    repeated = await second.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    stored = await store_b.find_by_idempotency(
        PRINCIPAL.rate_limit_account,
        second._idempotency_digest(PRINCIPAL.rate_limit_account, KEY),
    )

    assert stored is not None, "the observable identity winner disappeared"
    assert repeated.job.id == observed.job.id == JobId(stored.job_id)
    assert repeated.job.state is JobState.FAILED
    assert repeated.job.failure is JobFailure.CAPACITY_UNAVAILABLE
    assert stored.admission is JobAdmission.ADMISSION_FAILED
    assert repeated.existing is True and repeated.enqueued is False
    assert observer_executor.submitted == []


@asyncio_test
async def test_an_admission_failure_survives_restart_and_keeps_the_target_binding(
    tmp_path: Path,
) -> None:
    machine = Machine(root=tmp_path)
    machine.executor.full = True
    with pytest.raises(ExecutorFull):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    failed = await machine.store.find_by_idempotency(
        PRINCIPAL.rate_limit_account,
        machine.jobs._idempotency_digest(PRINCIPAL.rate_limit_account, KEY),
    )
    assert failed is not None
    failed_id = JobId(failed.job_id)

    machine.restart()
    same = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    assert same.job.id == failed_id
    assert same.job.state is JobState.FAILED
    assert same.enqueued is False
    assert machine.executor.submitted == []

    with pytest.raises(IdempotencyConflict):
        await machine.jobs.submit(
            "different@example.test", principal=PRINCIPAL, idempotency_key=KEY
        )
    assert machine.executor.submitted == []


@asyncio_test
async def test_a_handoff_marker_failure_happens_before_any_executor_admission(
    tmp_path: Path,
) -> None:
    """There is no post-accept marker: an unwritable token prevents the call."""
    machine = Machine(root=tmp_path)
    faulty = FaultyJobStore(inner=machine.store, fail_save_from=1)
    machine.jobs.store = faulty

    with pytest.raises(StoreStopped):
        await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert machine.executor.submitted == []
    durable = await machine.row(next(iter(machine.jobs._jobs.values())).id)
    assert durable is not None
    assert durable.state is JobState.PENDING
    assert durable.admission is JobAdmission.CLAIMED
    local = next(iter(machine.jobs._jobs.values()))
    assert local.state is JobState.FAILED
    assert local.failure is JobFailure.SERVICE_ERROR

    machine.restart()
    repeated = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    assert repeated.job.id == JobId(durable.job_id)
    assert repeated.enqueued is False
    assert machine.executor.submitted == []

    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)
    assert report.interrupted == 1
    recovered = await machine.jobs.fetch(JobId(durable.job_id), principal=PRINCIPAL)
    assert recovered is not None
    assert recovered.state is JobState.FAILED
    final_row = await machine.row(JobId(durable.job_id))
    assert final_row is not None
    assert final_row.admission is JobAdmission.INTERRUPTED

    with pytest.raises(IdempotencyConflict):
        await machine.jobs.submit(
            "different@example.test", principal=PRINCIPAL, idempotency_key=KEY
        )
    assert machine.executor.submitted == []


# --- 3. the running transition could not be recorded -------------------------


@asyncio_test
async def test_smtp_does_not_proceed_when_the_running_state_cannot_be_persisted(
    tmp_path: Path,
) -> None:
    """The checkpoint is the authorization, so an unwritten checkpoint is a
    refusal.

    `running` carries `MAYBE_TOUCHED`, and it is what a later process reads to
    decide that replay is unsafe. Probing without it would put a recipient on a
    wire with nothing on disk saying so — precisely the state the checkpoint
    exists to make impossible.
    """
    machine = Machine(root=tmp_path, smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",)))
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)
    faulty = FaultyJobStore(inner=machine.store, fail_save_from=1)
    machine.jobs.store = faulty

    await machine.executor.run_pending()

    settled = machine.jobs.get(outcome.job.id, principal=PRINCIPAL)
    assert settled is not None
    assert machine.smtp.calls == [], "SMTP ran under a state the store never accepted"  # type: ignore[union-attr]
    assert settled.state is JobState.FAILED
    assert settled.failure is JobFailure.SERVICE_ERROR
    assert settled.result is None, "an operational failure produced a mailbox result"


# --- 4. the checkpoint is durable before the recipient stage, not after ------


@asyncio_test
async def test_the_recipient_checkpoint_is_on_disk_while_the_probe_is_still_running(
    tmp_path: Path,
) -> None:
    """The ordering that makes the guarantee real.

    A checkpoint written when the verification *returns* is missing for the one
    crash it exists to describe: between `RCPT TO` going out and the reply
    coming back. So the row is inspected mid-flight, with the SMTP step parked
    inside the dialogue, and it already says the recipient may have been
    touched.
    """
    gate = GatedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    machine = Machine(root=tmp_path, smtp=gate)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)

    running = asyncio.create_task(machine.executor.run_pending())
    try:
        async with asyncio.timeout(OUTER_BOUND):
            await gate.entered.wait()
            row = await machine.row(outcome.job.id)
            assert row is not None
            assert row.state is JobState.RUNNING
            assert row.recipient_touch is RecipientTouch.MAYBE_TOUCHED
    finally:
        gate.gate.set()
        async with asyncio.timeout(OUTER_BOUND):
            await running


@asyncio_test
async def test_a_crash_at_the_recipient_stage_is_not_replayed_by_a_new_process(
    tmp_path: Path,
) -> None:
    """Crash points 6 and 7 of the matrix, which are indistinguishable on disk.

    Whether the process died just before writing `RCPT TO` or just after — with
    the reply lost — the durable record says the same thing, and that is the
    design rather than a limitation: both must refuse replay, so both are one
    state. A new process with an empty executor gets no work and mints no second
    verification.
    """
    gate = GatedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    machine = Machine(root=tmp_path, smtp=gate)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    running = asyncio.create_task(machine.executor.run_pending())
    async with asyncio.timeout(OUTER_BOUND):
        await gate.entered.wait()
    running.cancel()  # the process stops here, mid-dialogue
    await asyncio.gather(running, return_exceptions=True)

    machine.restart()
    row = await machine.row(outcome.job.id)
    assert row is not None
    assert row.state is JobState.RUNNING
    assert row.recipient_touch is RecipientTouch.MAYBE_TOUCHED

    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)

    assert machine.executor.submitted == [], "an interrupted operation was re-enqueued"
    assert machine.executor.scheduled == []
    assert report.interrupted == 1
    assert report.unsafe_to_replay == 1, "the checkpoint did not survive the restart"
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)
    assert recovered is not None
    assert recovered.state is JobState.FAILED
    assert recovered.failure is JobFailure.INTERRUPTED
    assert recovered.result is None


# --- 5. a retry that could not be scheduled ----------------------------------


@asyncio_test
async def test_a_retry_that_cannot_be_scheduled_does_not_stay_nonterminal(
    tmp_path: Path,
) -> None:
    """The audit's fourth observation.

    The state was persisted as `retry_scheduled`, `schedule()` raised, the
    worker swallowed it, and the job stayed nonterminal with no durable
    representation of scheduled work anywhere. It is terminalized instead —
    a capacity category, because that is what refused it, and no status.
    """
    machine = Machine(root=tmp_path, servfail=True)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)
    machine.executor.full_on_schedule = True

    await machine.executor.run_pending()

    settled = machine.jobs.get(outcome.job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.FAILED
    assert settled.failure is JobFailure.CAPACITY_UNAVAILABLE
    assert settled.result is None
    row = await machine.row(outcome.job.id)
    assert row is not None and row.state is JobState.FAILED
    assert row.status is None, "an unschedulable retry published a status"


# --- 6. what a fresh process does with each persistent state -----------------


@asyncio_test
async def test_a_completed_result_survives_and_is_never_re_run(tmp_path: Path) -> None:
    machine = Machine(root=tmp_path, smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",)))
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    await machine.executor.run_pending()

    machine.restart()
    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)

    assert report.scanned == 0, "a completed job was offered to the recovery scan"
    assert recovered is not None
    assert recovered.state is JobState.COMPLETED
    assert recovered.result is not None
    assert machine.executor.submitted == []


@asyncio_test
async def test_a_cancelled_job_is_never_resurrected_by_the_recovery_scan(
    tmp_path: Path,
) -> None:
    """Structural rather than a check that could be edited away: the store's
    predicate does not return terminal rows at all, so there is no branch here
    that could decide to re-run one."""
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    await machine.jobs.cancel(outcome.job.id, principal=PRINCIPAL)

    machine.restart()
    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)

    assert report.scanned == 0
    assert report.interrupted == 0
    assert machine.executor.submitted == []
    assert recovered is not None and recovered.state is JobState.CANCELLED


@asyncio_test
async def test_a_pending_job_is_not_re_enqueued_by_a_process_with_no_queue(
    tmp_path: Path,
) -> None:
    """Crash point 2: the claim landed, the executor of a dead process holds the
    work, and there is no durable queue to recover it from.

    A `pending` row is *provably* safe to replay — nothing was touched — and it
    is still not replayed, because inventing a durable queue out of an in-memory
    one is the overclaim this project refuses to make. It becomes an operational
    failure, which an operator can see and act on.
    """
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    machine.restart()
    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)

    assert machine.executor.submitted == []
    assert report.interrupted == 1
    assert report.unsafe_to_replay == 0, "a pending row was recorded as recipient-touched"
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)
    assert recovered is not None and recovered.failure is JobFailure.INTERRUPTED


@asyncio_test
async def test_a_retry_scheduled_job_is_not_resumed_by_a_process_with_no_queue(
    tmp_path: Path,
) -> None:
    machine = Machine(root=tmp_path, servfail=True)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    await machine.executor.run_pending()
    assert machine.jobs.get(outcome.job.id, principal=PRINCIPAL).state is JobState.RETRY_SCHEDULED  # type: ignore[union-attr]

    machine.restart()
    row = await machine.row(outcome.job.id)
    assert row is not None and row.retries_used == 1

    report = await machine.jobs.recover_interrupted(before=LATER, limit=10)

    assert machine.executor.scheduled == []
    assert machine.executor.submitted == []
    assert report.interrupted == 1


@asyncio_test
async def test_a_restart_does_not_refill_the_retry_budget(tmp_path: Path) -> None:
    """The budget is on the record, and a record a restart forgets is no budget.

    Asserted on the row rather than only on the rehydrated job, so a build that
    reconstructed the job with a default count would fail here.
    """
    machine = Machine(root=tmp_path, servfail=True)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    await machine.executor.run_pending()

    machine.restart()
    recovered = await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL)

    assert recovered is not None
    assert recovered.retries_used == 1
    assert recovered.may_retry is False


# --- 7. no interruption becomes a statement about a mailbox ------------------


@asyncio_test
async def test_no_recovery_state_fabricates_a_status(tmp_path: Path) -> None:
    """Every reachable interrupted state, checked against the published
    vocabulary rather than against one expected string."""
    machine = Machine(root=tmp_path, servfail=True)
    pending = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)
    scheduled = await machine.jobs.submit("second@example.test", principal=PRINCIPAL)
    await machine.executor.run_pending()

    machine.restart()
    await machine.jobs.recover_interrupted(before=LATER, limit=10)

    published = {member.value for member in Status}
    for job_id in (pending.job.id, scheduled.job.id):
        recovered = await machine.jobs.fetch(job_id, principal=PRINCIPAL)
        assert recovered is not None
        assert recovered.state is JobState.FAILED
        assert recovered.result is None
        assert recovered.failure is JobFailure.INTERRUPTED
        assert recovered.failure.value not in published


# --- 8. the scan is bounded, cut off, and blind to live work -----------------


@asyncio_test
async def test_the_scan_leaves_a_live_replicas_recent_work_alone(tmp_path: Path) -> None:
    """A store may be shared, so an unbounded scan is one replica declaring
    another's running jobs interrupted. Two guards: a cutoff the caller must
    supply, and rows this process still holds itself."""
    machine = Machine(root=tmp_path)
    mine = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)

    long_ago = datetime.now(UTC) - timedelta(days=365)
    by_cutoff = await machine.jobs.recover_interrupted(before=long_ago, limit=10)
    by_ownership = await machine.jobs.recover_interrupted(before=LATER, limit=10)

    assert by_cutoff.scanned == 0, "the cutoff was ignored"
    assert by_ownership.skipped_live == 1, "this process's own live job was terminalized"
    assert by_ownership.interrupted == 0
    held = machine.jobs.get(mine.job.id, principal=PRINCIPAL)
    assert held is not None and held.state is JobState.PENDING


@asyncio_test
async def test_a_service_with_no_store_recovers_nothing_and_says_so(tmp_path: Path) -> None:
    """A deployment with no persistence has no interrupted work to find, which
    is different from having none."""
    jobs = build_jobs(executor=RecordingExecutor())[0]

    report = await jobs.recover_interrupted(before=LATER, limit=10)

    assert report.scanned == 0
    assert report.interrupted == 0


# --- 9. two replicas and a crash, together ----------------------------------


@asyncio_test
async def test_a_second_replica_cannot_duplicate_a_job_the_first_one_crashed_on(
    tmp_path: Path,
) -> None:
    """F1 and F3 composed, which is the arrangement that would defeat either
    alone.

    Replica A claims the key and dies mid-dialogue. Replica B, alive and sharing
    only the file, presents the same handle. It must reconnect to A's job rather
    than mint a second one — the persistent winner stays authoritative through
    the crash — and it must not start a verification for an operation whose
    recipient may already have been contacted.
    """
    first = Machine(root=tmp_path, smtp=GatedSMTPVerification(reply_lines=("250 2.1.5 ok",)))
    claimed = await first.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    running = asyncio.create_task(first.executor.run_pending())
    async with asyncio.timeout(OUTER_BOUND):
        await first.smtp.entered.wait()  # type: ignore[union-attr]

    second = Machine(root=tmp_path, verdicts=first.verdicts)
    again = await second.jobs.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    running.cancel()
    await asyncio.gather(running, return_exceptions=True)

    assert again.job.id == claimed.job.id, "a crashed replica's key was claimed twice"
    assert again.enqueued is False
    assert second.executor.submitted == [], "a second verification was started"
    assert again.job.recipient_touch is RecipientTouch.MAYBE_TOUCHED


@asyncio_test
async def test_another_account_still_cannot_read_a_recovered_job(tmp_path: Path) -> None:
    """Recovery changes state; it does not change ownership."""
    machine = Machine(root=tmp_path)
    outcome = await machine.jobs.submit(ADDRESS, principal=PRINCIPAL)

    machine.restart()
    await machine.jobs.recover_interrupted(before=LATER, limit=10)

    assert await machine.jobs.fetch(outcome.job.id, principal=OTHER) is None
    assert await machine.jobs.fetch(outcome.job.id, principal=PRINCIPAL) is not None
