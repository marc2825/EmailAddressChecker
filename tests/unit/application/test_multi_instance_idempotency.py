"""Two `JobService` instances, one database, one idempotency key.

The final system audit's first critical finding. `JobService._claim` decided
idempotency under an `asyncio.Lock`, which is exactly the right barrier for two
coroutines in one process and no barrier at all for two replicas: measured over
one temporary SQLite file, one owner, one key, and one address produced **two**
job identifiers, **two** executor admissions, and **two** persistent bindings —
so two active verifications, so a second `RCPT TO` for one submitted address,
arranged by scaling the service out.

Every test here builds **two independent services** with their own registries,
their own locks, and their own executors, sharing nothing but the file. That is
what makes the assertions about the store rather than about a lock: a build
whose only barrier is process-local fails all of them.

`tests/unit/application/test_jobs.py` keeps the single-process concurrency tests,
which are still worth having — the lock is still what two coroutines in one
process need. This is the layer underneath it.

Nothing here opens a socket and nothing sleeps.
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
from tests.batch_fixtures import ACCOUNT, PRINCIPAL, build_jobs
from tests.phase6_fixtures import BarrierVerdictStore, InMemoryVerdictStore, RecordingExecutor
from tests.phase7_fixtures import OTHER_PRINCIPAL as OTHER

from emailcheck.adapters.storage.sqlite_job_store import (
    SCHEMA_VERSION,
    JobStoreConflictError,
    JobStoreSchemaError,
    SQLiteJobStore,
)
from emailcheck.application.jobs import IdempotencyConflict, JobService
from emailcheck.domain.job import IdempotencyKey, JobAdmission, JobState
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.ports.job_store import ClaimStatus, StoredJob

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0
KEY: Final = IdempotencyKey("shared-handle-" + "a" * 12)
ADDRESS: Final = "user@example.test"
OTHER_ADDRESS: Final = "other@example.test"
NOW: Final = datetime(2026, 8, 13, tzinfo=UTC)


@dataclass(slots=True)
class Replicas:
    """Two services over one file, and the counters that make the claim testable.

    The verdict store is shared because it stands in for a real one, and it is
    the **barrier**: `VerdictCache.find` is the last `await` before the claim, so
    parking both submissions there puts them at the claim boundary together.
    Without it, two gathered submissions run one after the other in practice and
    the race is never attempted — the Phase 6 review measured a lock-removal
    mutation staying inert against exactly that shape.
    """

    root: Path
    verdicts: InMemoryVerdictStore = field(default_factory=lambda: BarrierVerdictStore(parties=2))
    first_executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    second_executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    first: JobService = field(init=False)
    second: JobService = field(init=False)

    def __post_init__(self) -> None:
        self.first = self._service(self.first_executor, "A")
        self.second = self._service(self.second_executor, "B")

    @property
    def store(self) -> SQLiteJobStore:
        store = SQLiteJobStore(path=self.root / "jobs.db")
        store.initialize()
        return store

    def _service(self, executor: RecordingExecutor, prefix: str) -> JobService:
        return build_jobs(
            job_store=self.store,
            verdicts=self.verdicts,
            executor=executor,
            random_prefix=prefix,
        )[0]

    @property
    def admissions(self) -> list[str]:
        """Every executor admission either replica made, in no particular order."""
        return [*self.first_executor.submitted, *self.second_executor.submitted]

    def rows(self) -> list[tuple[str, str, str, str]]:
        with closing(sqlite3.connect(self.root / "jobs.db")) as connection, connection:
            return list(
                connection.execute(
                    "SELECT job_id, owner, idempotency_digest, target_digest FROM jobs"
                )
            )

    def bindings(self) -> list[tuple[str, str, str, str]]:
        return [row for row in self.rows() if row[2] is not None]


# --- the race the audit measured --------------------------------------------


@asyncio_test
async def test_two_services_one_key_and_one_target_create_one_of_everything(
    tmp_path: Path,
) -> None:
    """The unsafe baseline, inverted into the property that must hold.

    Before: two job identifiers, two enqueues, two persistent bindings. Every
    one of those four counts is asserted, because a build that minted two jobs
    and returned the same one would satisfy an identifier comparison alone and
    would still have started a second verification.
    """
    replicas = Replicas(root=tmp_path)

    async with asyncio.timeout(OUTER_BOUND):
        first, second = await asyncio.gather(
            replicas.first.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY),
            replicas.second.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY),
        )

    assert first.job.id.value == second.job.id.value, "two replicas minted two jobs for one key"
    assert len(replicas.admissions) == 1, "one operation was admitted to two executors"
    assert len(replicas.bindings()) == 1, "one key holds two persistent bindings"
    # Exactly one caller created the work; the other reconnected to it.
    assert sorted([first.enqueued, second.enqueued]) == [False, True]
    assert sorted([first.existing, second.existing]) == [False, True]
    assert replicas.bindings()[0][0] == first.job.id.value


@asyncio_test
async def test_two_services_one_key_and_two_targets_conflict_exactly_once(
    tmp_path: Path,
) -> None:
    """One target wins atomically and the other is refused.

    Which one wins is the scheduler's business and this test does not care. What
    it fixes is that there is never a second job, a second admission, or one key
    naming two addresses — the last of which would hand a caller a confident
    verdict about a mailbox nobody asked about.
    """
    replicas = Replicas(root=tmp_path)

    async def submit(service: JobService, address: str) -> tuple[str, str]:
        try:
            await service.submit(address, principal=PRINCIPAL, idempotency_key=KEY)
        except IdempotencyConflict:
            return ("conflict", address)
        return ("accepted", address)

    async with asyncio.timeout(OUTER_BOUND):
        results = await asyncio.gather(
            submit(replicas.first, ADDRESS),
            submit(replicas.second, OTHER_ADDRESS),
        )

    assert sorted(kind for kind, _ in results) == ["accepted", "conflict"]
    assert len(replicas.admissions) == 1
    bindings = replicas.bindings()
    assert len(bindings) == 1, "a losing target left a binding behind"


@asyncio_test
async def test_one_key_is_two_independent_requests_for_two_accounts(tmp_path: Path) -> None:
    """The unique constraint is `(owner, digest)` and not `digest`.

    An idempotency key is caller-chosen text — `order-1` is a plausible choice
    for everybody — so a constraint that made keys global would let one account's
    submission silently answer another's, or refuse it. Two rows, two jobs, two
    admissions, and neither caller sees the other.
    """
    replicas = Replicas(root=tmp_path)

    async with asyncio.timeout(OUTER_BOUND):
        mine, theirs = await asyncio.gather(
            replicas.first.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY),
            replicas.second.submit(ADDRESS, principal=OTHER, idempotency_key=KEY),
        )

    assert mine.job.id.value != theirs.job.id.value
    assert mine.existing is False and theirs.existing is False
    assert len(replicas.admissions) == 2
    assert len(replicas.bindings()) == 2
    assert {row[1] for row in replicas.bindings()} == {ACCOUNT, OTHER.rate_limit_account}


# --- across a restart rather than across a replica ---------------------------


@asyncio_test
async def test_a_second_process_answers_the_same_handle_with_the_same_job(
    tmp_path: Path,
) -> None:
    """Claim, discard every in-memory object, present the handle again.

    The second service has an empty registry, an empty binding map, and its own
    executor. Only the file connects them.
    """
    replicas = Replicas(root=tmp_path, verdicts=InMemoryVerdictStore())

    first = await replicas.first.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)
    assert first.enqueued is True

    again = await replicas.second.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert again.job.id.value == first.job.id.value
    assert again.enqueued is False
    assert again.existing is True
    assert replicas.second_executor.submitted == [], "a restart re-enqueued the work"


@asyncio_test
async def test_a_second_process_still_refuses_the_same_handle_for_another_address(
    tmp_path: Path,
) -> None:
    replicas = Replicas(root=tmp_path, verdicts=InMemoryVerdictStore())
    await replicas.first.submit(ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    with pytest.raises(IdempotencyConflict):
        await replicas.second.submit(OTHER_ADDRESS, principal=PRINCIPAL, idempotency_key=KEY)

    assert replicas.second_executor.submitted == []
    assert len(replicas.bindings()) == 1


# --- the barrier is in the schema, not in the application --------------------


def test_the_idempotency_index_is_unique(tmp_path: Path) -> None:
    """Read out of the file rather than out of the module that wrote it.

    A constraint asserted by the code that creates it proves the code ran, not
    that the database enforces anything. `PRAGMA index_list` is SQLite's own
    answer.
    """
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()

    with closing(sqlite3.connect(tmp_path / "jobs.db")) as connection, connection:
        indexes = {row[1]: row[2] for row in connection.execute("PRAGMA index_list('jobs')")}
        columns = [row[2] for row in connection.execute("PRAGMA index_info('jobs_idempotency')")]

    assert indexes["jobs_idempotency"] == 1, "the idempotency index permits duplicates"
    assert columns == ["owner", "idempotency_digest"]


@asyncio_test
async def test_the_database_refuses_a_duplicate_binding_the_application_never_sends(
    tmp_path: Path,
) -> None:
    """The constraint holds against a writer that bypasses `claim_idempotency`.

    This is the barrier's own test: `save` is the path every state transition
    takes, and under the old `INSERT OR REPLACE` it would have **deleted** the
    row holding this binding — the winner of a claim, removed by a loser's next
    write. It raises instead, translated out of the driver's vocabulary.
    """
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    winner = _record("winner" + "x" * 18)
    assert (
        await store.claim_idempotency(winner, expected_generation=0)
    ).status is ClaimStatus.NEW_CLAIM

    with pytest.raises(JobStoreConflictError):
        await store.save(_record("usurper" + "x" * 17), expected_generation=0)

    survivor = await store.load(winner.job_id)
    assert survivor is not None, "the winner's row was replaced"
    assert survivor.state is JobState.PENDING


@pytest.mark.parametrize(
    ("field_name", "changed"),
    (
        ("owner", "acct-immutable-other"),
        ("idempotency_digest", "different-idempotency-digest"),
        ("target_digest", "different-target-digest"),
        ("created_at", NOW - timedelta(seconds=1)),
    ),
)
@asyncio_test
async def test_an_ordinary_save_cannot_rewrite_each_identity_field(
    tmp_path: Path, field_name: str, changed: object
) -> None:
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    original = _record("immutable" + "x" * 15)
    await store.save(original, expected_generation=0)

    with pytest.raises(JobStoreConflictError):
        await store.save(replace(original, **{field_name: changed}), expected_generation=0)

    assert await store.load(original.job_id) == original


@pytest.mark.parametrize(
    ("before", "after"),
    (
        (None, "new-idempotency-digest"),
        ("idempotency-digest", None),
    ),
)
@asyncio_test
async def test_an_ordinary_save_cannot_add_or_clear_an_idempotency_identity(
    tmp_path: Path, before: str | None, after: str | None
) -> None:
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    original = replace(
        _record("nullable" + "x" * 16),
        idempotency_digest=before,
        target_digest=None if before is None else "target-digest",
    )
    await store.save(original, expected_generation=0)

    with pytest.raises(JobStoreConflictError):
        await store.save(replace(original, idempotency_digest=after), expected_generation=0)

    assert await store.load(original.job_id) == original


@asyncio_test
async def test_an_ordinary_save_still_updates_every_mutable_job_field(tmp_path: Path) -> None:
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    original = _record("mutable" + "x" * 17)
    await store.save(original, expected_generation=0)
    updated = replace(
        original,
        state=JobState.RUNNING,
        admission=JobAdmission.HANDOFF_COMMITTED,
        updated_at=NOW + timedelta(seconds=1),
        retries_used=1,
        recipient_touch=RecipientTouch.MAYBE_TOUCHED,
    )

    await store.save(updated, expected_generation=0)

    assert await store.load(original.job_id) == updated


@asyncio_test
async def test_a_claim_reports_the_three_answers_and_writes_only_on_the_first(
    tmp_path: Path,
) -> None:
    """The port's contract, against the real adapter and one file."""
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()

    won = await store.claim_idempotency(_record("first" + "x" * 19), expected_generation=0)
    same = await store.claim_idempotency(_record("second" + "x" * 18), expected_generation=0)
    other = await store.claim_idempotency(
        _record("third" + "x" * 19, target="other-target"), expected_generation=0
    )
    elsewhere = await store.claim_idempotency(
        _record("fourth" + "x" * 18, owner="acct-9"), expected_generation=0
    )

    assert won.status is ClaimStatus.NEW_CLAIM and won.existing is None
    assert same.status is ClaimStatus.EXISTING_SAME_TARGET
    assert other.status is ClaimStatus.CONFLICT_DIFFERENT_TARGET
    assert elsewhere.status is ClaimStatus.NEW_CLAIM
    for result in (same, other):
        assert result.existing is not None
        assert result.existing.job_id == "first" + "x" * 19

    # Two winners, two rows: the losers wrote nothing at all.
    assert {row.job_id for row in await store.find_nonterminal(before=NOW, limit=10)} == {
        "first" + "x" * 19,
        "fourth" + "x" * 18,
    }


def test_a_file_from_an_older_schema_is_refused_by_version(tmp_path: Path) -> None:
    """Refused at start with a sentence, not at some later write with an index
    error. Version 1 had no uniqueness constraint, so its file may already hold
    the duplicate rows the later schemas prevent."""
    path = tmp_path / "jobs.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            "CREATE TABLE job_schema_version (version INTEGER NOT NULL);"
            "INSERT INTO job_schema_version (version) VALUES (1);"
        )

    with pytest.raises(JobStoreSchemaError) as refusal:
        SQLiteJobStore(path=path).initialize()

    assert str(SCHEMA_VERSION) in str(refusal.value)


def _record(job_id: str, *, owner: str = ACCOUNT, target: str = "target-digest") -> StoredJob:
    return StoredJob(
        job_id=job_id,
        owner=owner,
        state=JobState.PENDING,
        created_at=NOW,
        updated_at=NOW,
        idempotency_digest="idempotency-digest",
        target_digest=target,
    )
