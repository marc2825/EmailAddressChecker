"""The two optional subsystems, and the barriers that make them optional safely.

D5  accept-all: every reachable exchanger is authorized, and an answer is filed
    against the mail system it was obtained from rather than against a name.
D10 batch: the store decides who schedules a row, a row names one child for
    ever, and every account-owned batch write is fenced by the same durable
    deletion generation the job and verdict stores use.

Nothing here opens a socket, sleeps on a wall clock, or composes batch: Phase
10's own inspection keeps batch out of every request surface and out of
`composition.py`, and Remediation D does not weaken that. What it removes is the
reason batch could not be composed *safely*.
"""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from tests.batch_fixtures import CORRELATION_KEY, InMemoryBatchStore, build_batch
from tests.phase6_fixtures import RecordingOperatorSink
from tests.phase7_fixtures import PRINCIPAL, CountingQuotaStore, SteppableClock

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.storage.account_fence import AccountAuthorityError
from emailcheck.adapters.storage.sqlite_account_state import SQLiteAccountStateStore
from emailcheck.adapters.storage.sqlite_batch_store import SQLiteBatchStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.account_deletion import AccountDeletionService
from emailcheck.application.admin import AdminControl
from emailcheck.domain.batch import BatchRowState
from emailcheck.ports.batch_store import BatchArtifact, StoredBatch, StoredBatchRow

asyncio_test = pytest.mark.asyncio

NOW: Final = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
ACCOUNT: Final = "acct-a"
SCHEDULABLE: Final = ("queued",)


# --- D10: the store owns scheduling ------------------------------------------


def batch_store(root: Path, name: str = "batches.db") -> SQLiteBatchStore:
    store = SQLiteBatchStore(path=root / name)
    store.initialize()
    return store


def a_batch(rows: int = 2, account: str = ACCOUNT, batch_id: str = "batch-1") -> StoredBatch:
    return StoredBatch(
        batch_id=batch_id,
        account=account,
        created_at=NOW,
        expires_at=NOW.replace(hour=23),
        input_rows=rows,
        skipped_rows=0,
        cancelled=False,
        rows=tuple(
            StoredBatchRow(
                number=number,
                state=BatchRowState.QUEUED,
                target_digest=f"digest-{number}",
                idempotency=f"handle-{number:016d}",
                submitted=f"user{number}@example.test",
            )
            for number in range(1, rows + 1)
        ),
    )


@asyncio_test
async def test_two_replicas_racing_for_one_row_produce_exactly_one_winner(
    tmp_path: Path,
) -> None:
    """D10: the claim is a conditional write, not a read followed by a write.

    Two `BatchStore` objects over one file, as two replicas resuming the same
    batch are. The previous design wrote `claimed` unconditionally, so both
    would have proceeded and one address would have been submitted twice.
    """
    writer = batch_store(tmp_path)
    await writer.save_batch(a_batch())
    replicas = [SQLiteBatchStore(path=tmp_path / "batches.db") for _ in range(6)]

    answers = await asyncio.gather(
        *(
            replica.claim_row(
                batch_id="batch-1", number=1, schedulable=SCHEDULABLE, claimed="claimed"
            )
            for replica in replicas
        )
    )

    assert answers.count(True) == 1, "two replicas were both told to schedule one row"
    assert answers.count(False) == len(replicas) - 1


@asyncio_test
async def test_a_row_already_past_scheduling_cannot_be_claimed_again(tmp_path: Path) -> None:
    """Restart, a repeated resume, a status poll: none may reschedule."""
    store = batch_store(tmp_path)
    record = a_batch()
    await store.save_batch(record)
    await store.update_rows("batch-1", (replace(record.rows[0], state=BatchRowState.SUBMITTED),))

    assert (
        await store.claim_row(
            batch_id="batch-1", number=1, schedulable=SCHEDULABLE, claimed="claimed"
        )
        is False
    )
    assert (
        await store.claim_row(
            batch_id="batch-1", number=2, schedulable=SCHEDULABLE, claimed="claimed"
        )
        is True
    )


@asyncio_test
async def test_a_row_names_one_child_job_for_ever(tmp_path: Path) -> None:
    """D10: the binding is immutable, so no row can point at a second verification."""
    store = batch_store(tmp_path)
    await store.save_batch(a_batch())

    assert await store.bind_child(batch_id="batch-1", number=1, job_id="job-first") is True
    assert await store.bind_child(batch_id="batch-1", number=1, job_id="job-second") is False

    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None
    assert held.rows[0].job_id == "job-first"


@asyncio_test
async def test_rows_are_returned_in_deterministic_input_order(tmp_path: Path) -> None:
    """Ordering is the input ordinal, never SQLite's rowid accident."""
    store = batch_store(tmp_path)
    record = a_batch(rows=5)
    await store.save_batch(record)
    # Write them back in reverse, which is what would expose a rowid dependence.
    await store.update_rows("batch-1", tuple(reversed(record.rows)))

    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None
    assert [row.number for row in held.rows] == [1, 2, 3, 4, 5]


@asyncio_test
async def test_the_service_asks_the_store_before_it_submits(tmp_path: Path) -> None:
    """The scheduler defers to the store's answer rather than deciding itself."""
    from tests.batch_fixtures import csv_for

    batch, _, _ = build_batch()
    store = batch.store
    assert isinstance(store, InMemoryBatchStore)
    await batch.submit(csv_for("user1@example.test", "user2@example.test"), principal=PRINCIPAL)

    held = next(iter(store.batches.values()))
    assert [row.state for row in held.rows] == [BatchRowState.SUBMITTED] * 2

    # And a row another replica already holds is not submitted by this one.
    denied: list[int] = []
    inner = InMemoryBatchStore()

    class RefusingStore:
        """Hands no row over, as a second live replica's store would not."""

        def __getattr__(self, name: str) -> object:
            return getattr(inner, name)

        async def claim_row(
            self,
            *,
            batch_id: str,
            number: int,
            schedulable: tuple[str, ...],
            claimed: str,
            expected_generation: int | None = None,
        ) -> bool:
            denied.append(number)
            return False

    second, _, _ = build_batch(store=RefusingStore())
    report = await second.submit(
        csv_for("user1@example.test", "user2@example.test"), principal=PRINCIPAL
    )
    assert denied == [1, 2], "the scheduler never asked the store"
    stored = next(iter(inner.batches.values()))
    assert [row.state for row in stored.rows] == [BatchRowState.QUEUED] * 2, (
        "a row the store refused to hand over was submitted anyway"
    )
    assert report.state_summary.get("submitted", 0) == 0


@pytest.mark.inspection
def test_a_row_left_claimed_by_a_dead_process_is_not_claimed_again() -> None:
    """The other half of the exclusive claim: recovery must still work.

    A `claimed` row belongs to a process that did not finish. It is **not**
    claimed again — the transition is `queued -> claimed`, so re-taking it would
    match for every caller and exclude nobody — and it is re-driven instead
    through the idempotency handle persisted before the first submission, which
    `JobService` answers with the existing job rather than a second
    verification. A build that marked every resumable row unclaimed would try to
    claim it, fail, and silently drop the row.
    """
    from emailcheck.application.batch import _Pending

    source = Path("src/emailcheck/application/batch.py").read_text()

    assert "unclaimed=row.state is not BatchRowState.CLAIMED," in source
    assert "if row.unclaimed and not await self.store.claim_row(" in source
    assert _Pending(number=1, domain="example.test", target_digest="d", idempotency="h").unclaimed


# --- D10: account fencing ----------------------------------------------------


def deletion_for(root: Path, batches: SQLiteBatchStore | None = None) -> AccountDeletionService:
    clock, metrics, operator = SteppableClock(), InMemoryMetrics(), RecordingOperatorSink()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    state = SQLiteAccountStateStore(path=root / "accounts.db")
    state.initialize()
    return AccountDeletionService(
        admin=admin,
        operator=operator,
        account_state=state,
        cache=None,
        jobs=None,
        job_store=None,
        batches=batches if batches is not None else batch_store(root),
    )


def batch_rows(root: Path) -> int:
    with closing(sqlite3.connect(root / "batches.db")) as connection, connection:
        return int(connection.execute("SELECT count(*) FROM batches").fetchone()[0])


@asyncio_test
async def test_a_stale_batch_worker_cannot_recreate_a_deleted_account(tmp_path: Path) -> None:
    """D10 + Remediation C: the third store joins the fencing model.

    The account is deleted while a batch worker still holds the generation it
    was admitted under. Its write is refused inside the store's own
    transaction, so nothing reappears after the operator was told the deletion
    was complete.
    """
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    assert batch_rows(tmp_path) == 1

    report = await deletion_for(tmp_path, store).delete(ACCOUNT)

    assert report.complete is True
    assert batch_rows(tmp_path) == 0
    stale = SQLiteBatchStore(path=tmp_path / "batches.db")
    assert await stale.save_batch(a_batch(), expected_generation=0) is False
    assert batch_rows(tmp_path) == 0, "a stale batch worker recreated a deleted account"


@asyncio_test
async def test_every_account_owned_batch_write_is_fenced(tmp_path: Path) -> None:
    """Not only `delete_account`: rows, cancellation, and the artifact too."""
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    await store.fence(account=ACCOUNT, generation=1)
    row = replace(a_batch().rows[0], state=BatchRowState.SUBMITTED)
    artifact = BatchArtifact(
        batch_id="batch-1",
        account=ACCOUNT,
        created_at=NOW,
        expires_at=NOW.replace(hour=23),
        media_type="text/csv",
        content="email,status\n",
        complete=True,
    )

    assert await store.save_batch(a_batch(), expected_generation=0) is False
    assert await store.update_rows("batch-1", (row,), expected_generation=0) is False
    assert await store.set_cancelled("batch-1", expected_generation=0) is False
    assert await store.save_artifact(artifact, expected_generation=0) is False

    # And the current generation still works, so the fence is a fence and not a
    # wall: an account that is deleted may be used again.
    assert await store.update_rows("batch-1", (row,), expected_generation=1) is True
    assert await store.save_artifact(artifact, expected_generation=1) is True


@asyncio_test
async def test_the_batch_fence_is_raised_before_any_batch_row_is_deleted(
    tmp_path: Path,
) -> None:
    """Ordering, as behaviour: a store whose fence cannot go up is not emptied."""
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)

    attempted: list[str] = []

    class FenceFails:
        async def fence(self, *, account: str, generation: int) -> int:
            raise RuntimeError("the store is unavailable")

        async def delete_account(self, *, account: str) -> int:
            attempted.append(account)
            return 1

    report = await deletion_for(tmp_path, FenceFails()).delete(ACCOUNT)  # type: ignore[arg-type]

    assert attempted == [], "rows were deleted from a store whose fence never went up"
    assert report.complete is False
    assert "batches" in report.failed_stores
    assert report.batches_removed == 0
    assert batch_rows(tmp_path) == 1


@asyncio_test
async def test_a_batch_fence_never_falls(tmp_path: Path) -> None:
    store = batch_store(tmp_path)
    assert await store.fence(account=ACCOUNT, generation=4) == 4
    assert await store.fence(account=ACCOUNT, generation=2) == 4


@asyncio_test
async def test_one_accounts_deletion_leaves_another_accounts_batches(tmp_path: Path) -> None:
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    await store.save_batch(a_batch(account="acct-b", batch_id="batch-2"), expected_generation=0)

    assert (await deletion_for(tmp_path, store).delete(ACCOUNT)).complete is True

    assert batch_rows(tmp_path) == 1
    assert (
        await store.save_batch(a_batch(account="acct-b", batch_id="batch-3"), expected_generation=0)
        is True
    )


# --- D10: authority binding --------------------------------------------------


def test_a_batch_store_refuses_a_second_account_state_authority(tmp_path: Path) -> None:
    """The same binding the job and verdict stores carry, on the third store."""
    store = batch_store(tmp_path)
    first = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    first.initialize()
    second = SQLiteAccountStateStore(path=tmp_path / "other-accounts.db")
    second.initialize()

    assert store.bind_authority(first.authority_id()) == first.authority_id()
    with pytest.raises(AccountAuthorityError, match="different account-state authority"):
        store.bind_authority(second.authority_id())


def test_a_batch_store_written_before_the_fence_is_refused_by_version(tmp_path: Path) -> None:
    """A version 1 file predates the deletion authority and is not adopted."""
    from emailcheck.adapters.storage.sqlite_batch_store import BatchStoreSchemaError

    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        connection.execute("CREATE TABLE batch_schema_version (version INTEGER NOT NULL)")
        connection.execute("INSERT INTO batch_schema_version (version) VALUES (1)")

    with pytest.raises(BatchStoreSchemaError, match="schema version 1"):
        SQLiteBatchStore(path=tmp_path / "batches.db").initialize()


# --- D10: composition and coupling -------------------------------------------


@pytest.mark.inspection
def test_batch_is_still_reachable_from_no_request_surface() -> None:
    """Remediation D hardens batch; it does not expose it.

    `docs/adr/0018-controlled-batch-execution.md`'s non-goals begin with public uploads, and Phase
    10's
    own inspection keeps the word out of every request surface. Fixing the
    scheduler is not authorization to compose it, so this states the decision
    rather than leaving it to be inferred from an absence.
    """
    from tests.unit.test_batch_isolation import code_without_docstrings

    for surface in (
        "src/emailcheck/apps/api.py",
        "src/emailcheck/apps/schema.py",
        "src/emailcheck/composition.py",
    ):
        assert "batch" not in code_without_docstrings(surface).lower()


@pytest.mark.inspection
def test_neither_optional_subsystem_instantiates_the_other() -> None:
    """D5 and D10 stay independent: enabling one may not enable the other."""
    batch_code = Path("src/emailcheck/application/batch.py").read_text()
    accept_all_code = Path("src/emailcheck/application/accept_all.py").read_text()

    assert "accept_all" not in batch_code.lower()
    assert "AcceptAll" not in batch_code
    assert "batch" not in accept_all_code.lower()


# --- D5: accept-all ----------------------------------------------------------


@pytest.mark.inspection
def test_accept_all_authorizes_every_reachable_exchanger() -> None:
    """D5: a block a fallback could step past is not a block.

    The previous version read `connectable_candidates[0]` and authorized that
    one alone, while the verification below it falls back through the rest.
    """
    source = Path("src/emailcheck/application/accept_all.py").read_text()

    body = source.split("async def _authorize_destination")[1].split("def _read")[0]
    assert "for candidate in route.connectable_candidates:" in body
    assert "exchanger_blocked(candidate.host.value)" in body


def test_the_accept_all_cache_key_carries_the_route_it_was_obtained_from() -> None:
    """D5: an answer describes a mail system, not a name."""
    from emailcheck.ports.accept_all_cache import AcceptAllCacheKey

    fields = set(AcceptAllCacheKey.__dataclass_fields__)

    assert "route_digest" in fields
    for absent in ("local_part", "target", "address", "mailbox"):
        assert absent not in fields


# --- D10-R1/R2: a missing parent is a refusal, and every mutation is fenced ---
#
# The focused review reproduced both. After a completed deletion the parent
# batch is gone, so the account could not be resolved, so the old helper waved
# the write through and `update_rows` inserted an orphan `batch_rows` row for an
# account the operator had been told was erased. `claim_row` and `bind_child`
# carried no generation at all.


def row_counts(root: Path) -> tuple[int, int, int]:
    with closing(sqlite3.connect(root / "batches.db")) as connection, connection:
        return (
            int(connection.execute("SELECT count(*) FROM batches").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM batch_rows").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM batch_artifacts").fetchone()[0]),
        )


def an_artifact(account: str = ACCOUNT) -> BatchArtifact:
    return BatchArtifact(
        batch_id="batch-1",
        account=account,
        created_at=NOW,
        expires_at=NOW.replace(hour=23),
        media_type="text/csv",
        content="email,status\n",
        complete=True,
    )


@asyncio_test
async def test_a_stale_update_cannot_recreate_rows_after_a_completed_deletion(
    tmp_path: Path,
) -> None:
    """D10-R1, exactly as the review reproduced it.

    Before the fix this returned `True` and left one orphan `batch_rows` row —
    carrying the target digest, the child handle and the idempotency digest —
    that no later deletion could find, because `delete_account` works from the
    `batches` table and that was already empty.
    """
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    assert row_counts(tmp_path) == (1, 2, 0)

    report = await deletion_for(tmp_path, store).delete(ACCOUNT)

    assert report.complete is True
    assert row_counts(tmp_path) == (0, 0, 0)
    stale = replace(a_batch().rows[0], state=BatchRowState.SUBMITTED, job_id="job-x")
    assert await store.update_rows("batch-1", (stale,), expected_generation=0) is False
    assert row_counts(tmp_path) == (0, 0, 0), "a stale write recreated an orphan row"


@asyncio_test
async def test_a_mutation_of_a_batch_that_never_existed_is_refused(tmp_path: Path) -> None:
    """The same rule without a deletion anywhere near it.

    A missing parent refuses because it is missing, not because a tombstone
    happens to be present — so the barrier does not depend on deletion state.
    """
    store = batch_store(tmp_path)
    row = a_batch().rows[0]

    assert await store.update_rows("never-existed", (row,), expected_generation=0) is False
    assert await store.update_rows("never-existed", (row,)) is False
    assert (
        await store.claim_row(
            batch_id="never-existed", number=1, schedulable=SCHEDULABLE, claimed="claimed"
        )
        is False
    )
    assert await store.bind_child(batch_id="never-existed", number=1, job_id="job-x") is False
    assert row_counts(tmp_path) == (0, 0, 0)


@asyncio_test
async def test_a_stale_claim_is_refused_while_the_rows_are_still_there(tmp_path: Path) -> None:
    """D10-R2: the fence window, where "the rows are gone" cannot explain it.

    The fence is advanced but nothing has been deleted yet, so the parent and
    the row are both present and the conditional update would match. Only the
    generation check refuses — which is what makes this test load-bearing for
    the fence rather than for the deletion.
    """
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    await store.fence(account=ACCOUNT, generation=1)
    assert row_counts(tmp_path) == (1, 2, 0)

    assert (
        await store.claim_row(
            batch_id="batch-1",
            number=1,
            schedulable=SCHEDULABLE,
            claimed="claimed",
            expected_generation=0,
        )
        is False
    )
    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None
    assert held.rows[0].state is BatchRowState.QUEUED, "a stale claim mutated the row"

    # The current generation still works: a fence is not a wall.
    assert (
        await store.claim_row(
            batch_id="batch-1",
            number=1,
            schedulable=SCHEDULABLE,
            claimed="claimed",
            expected_generation=1,
        )
        is True
    )


@asyncio_test
async def test_a_stale_bind_is_refused_while_the_row_is_still_bindable(tmp_path: Path) -> None:
    """D10-R2 for `bind_child`, in the same window, with both barriers pinned."""
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)
    await store.fence(account=ACCOUNT, generation=1)

    assert (
        await store.bind_child(
            batch_id="batch-1", number=1, job_id="job-stale", expected_generation=0
        )
        is False
    )
    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None and held.rows[0].job_id is None

    # Current generation binds once, and the binding is still immutable.
    assert (
        await store.bind_child(
            batch_id="batch-1", number=1, job_id="job-first", expected_generation=1
        )
        is True
    )
    assert (
        await store.bind_child(
            batch_id="batch-1", number=1, job_id="job-second", expected_generation=1
        )
        is False
    )
    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None and held.rows[0].job_id == "job-first"


@asyncio_test
async def test_creation_still_works_and_a_stale_creation_does_not(tmp_path: Path) -> None:
    """§19: creation is the one write that legitimately has no parent.

    It carries its owner in the record, so it is fenced against that account
    directly rather than through a parent it is about to become.
    """
    store = batch_store(tmp_path)

    assert await store.save_batch(a_batch(), expected_generation=0) is True
    await store.fence(account=ACCOUNT, generation=1)
    assert await store.save_batch(a_batch(batch_id="batch-2"), expected_generation=0) is False
    assert await store.save_batch(a_batch(batch_id="batch-3"), expected_generation=1) is True


@asyncio_test
async def test_no_stale_write_of_any_kind_survives_a_completed_deletion(tmp_path: Path) -> None:
    """§22: the strongest D10 regression, over a manually assembled stack.

    Every account-owned mutation the port publishes, presented by a worker
    still carrying the generation it was admitted under, after the operator has
    been told the deletion is complete. Batch stays uncomposed publicly; this
    is an internal composition a deployment could build.
    """
    from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
    from emailcheck.application.jobs import CheckJob, _stored
    from emailcheck.domain.job import JobAdmission, JobId, JobState

    store = batch_store(tmp_path)
    jobs = SQLiteJobStore(path=tmp_path / "jobs.db")
    jobs.initialize()
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    for bound in (store, jobs):
        bound.bind_authority(state.authority_id())
    await store.save_batch(a_batch(), expected_generation=0)
    await store.save_artifact(an_artifact(), expected_generation=0)

    deletion = deletion_for(tmp_path, store)
    object.__setattr__(deletion, "job_store", jobs)
    report = await deletion.delete(ACCOUNT)

    assert report.complete is True
    assert row_counts(tmp_path) == (0, 0, 0)

    stale_row = replace(a_batch().rows[0], state=BatchRowState.SUBMITTED)
    stale_job = _stored(
        CheckJob(
            id=JobId("late-write" + "x" * 14),
            owner=ACCOUNT,
            state=JobState.PENDING,
            created_at=NOW,
            updated_at=NOW,
        ),
        target_digest=None,
        idempotency=None,
        admission=JobAdmission.CLAIMED,
    )

    assert await store.save_batch(a_batch(), expected_generation=0) is False
    assert await store.update_rows("batch-1", (stale_row,), expected_generation=0) is False
    assert await store.set_cancelled("batch-1", expected_generation=0) is False
    assert await store.save_artifact(an_artifact(), expected_generation=0) is False
    assert (
        await store.claim_row(
            batch_id="batch-1",
            number=1,
            schedulable=SCHEDULABLE,
            claimed="claimed",
            expected_generation=0,
        )
        is False
    )
    assert (
        await store.bind_child(batch_id="batch-1", number=1, job_id="job-x", expected_generation=0)
        is False
    )
    assert await jobs.save(stale_job, expected_generation=0) is False

    # §23: the orphan audit, in SQL rather than through a reader that filters.
    assert row_counts(tmp_path) == (0, 0, 0)
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        orphans = connection.execute(
            "SELECT count(*) FROM batch_rows WHERE batch_id NOT IN (SELECT batch_id FROM batches)"
        ).fetchone()[0]
        stray = connection.execute(
            "SELECT count(*) FROM batch_artifacts "
            "WHERE batch_id NOT IN (SELECT batch_id FROM batches)"
        ).fetchone()[0]
    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        held_jobs = connection.execute(
            "SELECT count(*) FROM jobs WHERE owner = ?", (ACCOUNT,)
        ).fetchone()[0]
    assert (orphans, stray, held_jobs) == (0, 0, 0)


@asyncio_test
async def test_a_resumed_batch_carries_its_admitted_generation_not_a_fresh_one(
    tmp_path: Path,
) -> None:
    """§27/§28/§29: no laundering across a restart.

    The batch persists the generation it was admitted under, so a scheduler
    recovered after a deletion presents that value and is refused — rather than
    reading the current generation and becoming legitimate by restarting.
    """
    store = batch_store(tmp_path)
    await store.save_batch(a_batch(), expected_generation=0)

    held = await store.load_batch("batch-1", account=ACCOUNT, now=NOW)
    assert held is not None and held.generation == 0

    await store.fence(account=ACCOUNT, generation=1)
    reopened = SQLiteBatchStore(path=tmp_path / "batches.db")
    recovered = await reopened.load_batch("batch-1", account=ACCOUNT, now=NOW)

    assert recovered is not None
    assert recovered.generation == 0, "a restart re-read the generation instead of loading it"
    assert (
        await reopened.claim_row(
            batch_id="batch-1",
            number=1,
            schedulable=SCHEDULABLE,
            claimed="claimed",
            expected_generation=recovered.generation,
        )
        is False
    )


@asyncio_test
async def test_a_resumed_scheduler_presents_the_batchs_own_generation(tmp_path: Path) -> None:
    """§26/§27: the call site, not only the store.

    The store refuses a stale generation, but only if the scheduler hands it
    one. A `BatchService` that read the account's *current* generation before
    each write would launder its own stale work into current work — the store
    would see a matching value and accept it. This drives the real service
    across a deletion and requires that nothing it writes lands.
    """
    from tests.batch_fixtures import MovableClock, approved, build_jobs, csv_for
    from tests.phase6_fixtures import FakeRandomSource

    from emailcheck.application.batch import BatchService

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    jobs = build_jobs()[0]
    service = BatchService(
        jobs=jobs,
        store=store,
        clock=MovableClock(),
        random_source=FakeRandomSource(prefix="batch"),
        settings=approved(),
        correlation_key=CORRELATION_KEY,
        account_state=state,
    )

    report = await service.submit(csv_for("user1@example.test"), principal=PRINCIPAL)
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        recorded = connection.execute(
            "SELECT generation FROM batches WHERE batch_id = ?", (report.batch_id.value,)
        ).fetchone()
    assert recorded == (0,), "the batch did not record the generation it was admitted under"

    # Put the row back to schedulable, as an interrupted batch's would be, so
    # the resumed scheduler actually reaches the claim.
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        connection.execute(
            "UPDATE batch_rows SET state = 'queued', job_id = NULL, "
            "submitted = 'user1@example.test'"
        )
        connection.execute("DELETE FROM batch_artifacts")

    # The account is deleted underneath the batch, and the rows survive only
    # because this test deletes nothing — the fence alone must refuse the write.
    await state.advance(PRINCIPAL.rate_limit_account)
    await store.fence(account=PRINCIPAL.rate_limit_account, generation=1)
    before = row_counts(tmp_path)

    resumed = await service.resume(report.batch_id, principal=PRINCIPAL)

    assert resumed is not None
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        states = [
            row[0] for row in connection.execute("SELECT state FROM batch_rows ORDER BY number")
        ]
    assert states == ["queued"], "a stale scheduler mutated a row under a raised fence"
    assert row_counts(tmp_path) == before
    assert row_counts(tmp_path)[2] == 0, "a stale scheduler wrote an artifact"


# --- D10-R3: the service carries the batch's own generation token -------------
#
# The store refuses a stale generation; this is about what the *service* hands
# it. Three mutations survived the previous round because the row's persisted
# state could not distinguish them — a claim admitted under the wrong token was
# still followed by a `_persist` that used the right one, so the row looked
# refused either way. The observation point therefore has to be the argument
# itself, and the generations have to be non-zero so that "0", "current" and
# "the batch's own" are three different numbers.


@dataclass
class RecordingBatchStore:
    """The real SQLite store, with every generation-bearing argument recorded.

    Delegates rather than reimplements, so the transactional behaviour under
    test is the production one; `__getattr__` forwards everything not named
    here.
    """

    inner: SQLiteBatchStore
    claims: list[int | None] = field(default_factory=list)
    binds: list[int | None] = field(default_factory=list)
    updates: list[int | None] = field(default_factory=list)
    creates: list[int | None] = field(default_factory=list)

    def __getattr__(self, name: str) -> object:
        return getattr(self.inner, name)

    async def claim_row(
        self,
        *,
        batch_id: str,
        number: int,
        schedulable: tuple[str, ...],
        claimed: str,
        expected_generation: int | None = None,
    ) -> bool:
        self.claims.append(expected_generation)
        return await self.inner.claim_row(
            batch_id=batch_id,
            number=number,
            schedulable=schedulable,
            claimed=claimed,
            expected_generation=expected_generation,
        )

    async def bind_child(
        self,
        *,
        batch_id: str,
        number: int,
        job_id: str,
        expected_generation: int | None = None,
    ) -> bool:
        self.binds.append(expected_generation)
        return await self.inner.bind_child(
            batch_id=batch_id,
            number=number,
            job_id=job_id,
            expected_generation=expected_generation,
        )

    async def update_rows(
        self,
        batch_id: str,
        rows: tuple[StoredBatchRow, ...],
        *,
        expected_generation: int | None = None,
    ) -> bool:
        self.updates.append(expected_generation)
        return await self.inner.update_rows(batch_id, rows, expected_generation=expected_generation)

    async def save_batch(
        self, record: StoredBatch, *, expected_generation: int | None = None
    ) -> bool:
        self.creates.append(expected_generation)
        return await self.inner.save_batch(record, expected_generation=expected_generation)


def batch_service(store: object, state: SQLiteAccountStateStore) -> object:
    from tests.batch_fixtures import MovableClock, approved, build_jobs
    from tests.phase6_fixtures import FakeRandomSource

    from emailcheck.application.batch import BatchService

    return BatchService(
        jobs=build_jobs()[0],
        store=store,  # type: ignore[arg-type]
        clock=MovableClock(),
        random_source=FakeRandomSource(prefix="batch"),
        settings=approved(),
        correlation_key=CORRELATION_KEY,
        account_state=state,
    )


def persisted_generation(root: Path, batch_id: str) -> int | None:
    with closing(sqlite3.connect(root / "batches.db")) as connection, connection:
        row = connection.execute(
            "SELECT generation FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
    return None if row is None else int(row[0])


def row_states(root: Path) -> list[str]:
    with closing(sqlite3.connect(root / "batches.db")) as connection, connection:
        return [
            str(state)
            for (state,) in connection.execute("SELECT state FROM batch_rows ORDER BY number")
        ]


async def advance_in_step(
    store: SQLiteBatchStore, state: SQLiteAccountStateStore, account: str, times: int = 1
) -> int:
    """Move the authority and the store fence together, as a deletion does.

    `AccountDeletionService` advances the durable generation and then raises
    every store's fence, so the two are always in step. Advancing only the
    authority would build a state production cannot reach.
    """
    generation = 0
    for _ in range(times):
        generation = await state.advance(account)
        await store.fence(account=account, generation=generation)
    return generation


@asyncio_test
async def test_a_batch_records_the_generation_it_was_admitted_under(tmp_path: Path) -> None:
    """§3/§4: a non-zero admission, so `0` is not accidentally right.

    The account is moved to generation 3 *before* the batch exists, so a service
    that recorded a constant, an initial value, or nothing at all is visibly
    wrong rather than coincidentally correct.
    """
    from tests.batch_fixtures import csv_for

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account, 3)
    assert await state.generation(PRINCIPAL.rate_limit_account) == 3

    service = batch_service(store, state)
    report = await service.submit(csv_for("user1@example.test"), principal=PRINCIPAL)

    assert persisted_generation(tmp_path, report.batch_id.value) == 3


@asyncio_test
async def test_a_restart_loads_the_persisted_generation_rather_than_the_current_one(
    tmp_path: Path,
) -> None:
    """§5/§6: the token survives the process, and the authority moves past it."""
    from tests.batch_fixtures import csv_for

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account, 3)
    service = batch_service(store, state)
    report = await service.submit(csv_for("user1@example.test"), principal=PRINCIPAL)
    batch_id = report.batch_id.value
    del service

    await advance_in_step(store, state, PRINCIPAL.rate_limit_account)
    assert await state.generation(PRINCIPAL.rate_limit_account) == 4

    reopened = SQLiteBatchStore(path=tmp_path / "batches.db")
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        expires = connection.execute(
            "SELECT expires_at FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()[0]
    loaded = await reopened.load_batch(
        batch_id,
        account=PRINCIPAL.rate_limit_account,
        now=datetime.fromisoformat(expires) - timedelta(seconds=1),
    )

    assert loaded is not None
    assert loaded.generation == 3, "the loader reconstructed the generation instead of reading it"
    assert await state.generation(PRINCIPAL.rate_limit_account) == 4


@asyncio_test
async def test_a_resumed_service_presents_the_batchs_token_and_not_the_current_one(
    tmp_path: Path,
) -> None:
    """§7-§10, §19: the whole guarantee, observed at the argument.

    A batch admitted at generation 3, a restart, the account advanced to 4, and
    a **fresh** service resuming it — which must obtain the token through the
    persisted store path rather than from anything this test injects. The
    assertion is on the value handed to `claim_row`, because the row's state
    cannot distinguish "claimed under the wrong token" from "refused": a
    mis-admitted claim is still followed by a `_persist` carrying the right one.
    """
    from tests.batch_fixtures import csv_for

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account, 3)
    first = batch_service(store, state)
    report = await first.submit(csv_for("user1@example.test"), principal=PRINCIPAL)
    del first

    # An interrupted batch: the row is schedulable again, and nothing else of
    # the first process survives.
    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        connection.execute(
            "UPDATE batch_rows SET state = 'queued', job_id = NULL, "
            "submitted = 'user1@example.test'"
        )
        connection.execute("DELETE FROM batch_artifacts")
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account)

    recording = RecordingBatchStore(inner=SQLiteBatchStore(path=tmp_path / "batches.db"))
    resumed = batch_service(recording, state)
    jobs = resumed.jobs  # type: ignore[attr-defined]
    outcome = await resumed.resume(report.batch_id, principal=PRINCIPAL)  # type: ignore[attr-defined]

    assert outcome is not None
    assert recording.claims == [3], (
        f"the service presented {recording.claims} rather than the batch's own generation"
    )
    assert 4 not in recording.claims and 0 not in recording.claims
    assert row_states(tmp_path) == ["queued"], "a stale row was mutated"
    assert recording.binds == [], "a child was bound for a stale batch"
    assert jobs._jobs == {}, "a stale resume created a job"
    assert row_counts(tmp_path)[2] == 0, "a stale resume wrote an artifact"


@asyncio_test
async def test_a_batch_admitted_at_the_current_generation_still_runs(tmp_path: Path) -> None:
    """§14: the control. The rule rejects stale work, not resumed work."""
    from tests.batch_fixtures import csv_for

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account, 4)

    recording = RecordingBatchStore(inner=store)
    service = batch_service(recording, state)
    report = await service.submit(csv_for("user1@example.test"), principal=PRINCIPAL)

    assert persisted_generation(tmp_path, report.batch_id.value) == 4
    assert recording.claims == [4]
    assert row_states(tmp_path) == ["submitted"]
    assert recording.binds == [4]


@asyncio_test
async def test_a_restart_at_the_same_generation_resumes_normally(tmp_path: Path) -> None:
    """§15: a restart is not itself staleness."""
    from tests.batch_fixtures import csv_for

    store = batch_store(tmp_path)
    state = SQLiteAccountStateStore(path=tmp_path / "accounts.db")
    state.initialize()
    store.bind_authority(state.authority_id())
    await advance_in_step(store, state, PRINCIPAL.rate_limit_account, 5)
    first = batch_service(store, state)
    report = await first.submit(csv_for("user1@example.test"), principal=PRINCIPAL)
    del first

    with closing(sqlite3.connect(tmp_path / "batches.db")) as connection, connection:
        connection.execute(
            "UPDATE batch_rows SET state = 'queued', job_id = NULL, "
            "submitted = 'user1@example.test'"
        )
    recording = RecordingBatchStore(inner=SQLiteBatchStore(path=tmp_path / "batches.db"))
    resumed = batch_service(recording, state)

    await resumed.resume(report.batch_id, principal=PRINCIPAL)  # type: ignore[attr-defined]

    assert recording.claims == [5]
    assert row_states(tmp_path) == ["submitted"]
