"""Job identity, state, and result on disk, so a restart cannot duplicate work.

The `adapters/storage/sqlite_store.py` conventions, unchanged: one schema, an
explicit version, every statement a module constant so an inspection can see
that what reaches a cursor is a literal, and `sqlite3` behind `asyncio.to_thread`
because a blocking driver should not pretend otherwise.

**The idempotency lookup is an index, not a scan.** A resumed batch presents one
handle per row, so this is the hot path of a restart and a table scan per row
would make recovery cost the whole registry.

**That index is `UNIQUE`, and it is the barrier rather than the optimization.**
Remediation A: the application used to decide idempotency under a process-local
`asyncio.Lock`, which two replicas sharing one database do not share — measured
as one owner, one key, one address producing two jobs, two enqueues, and two
persistent bindings. A constraint in the schema is the only version of that rule
a second process is subject to, so `claim_idempotency` resolves the race against
the index inside one write transaction and the losing caller reads the winner in
the same transaction. Nothing above this file may assume it is alone.

The index is **partial** — `WHERE idempotency_digest IS NOT NULL`. SQLite treats
NULLs as distinct in a unique index, so an unconditional one would behave
identically for keyless submissions; writing the predicate says that on purpose
rather than leaving a reader to remember SQL's NULL rule.

This adapter stores what `ports/job_store.py` permits and nothing more. There is
no column an address, a caller's key, a reply, or an exception could occupy.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from emailcheck.adapters.storage.account_fence import (
    FENCE_SCHEMA,
    bind_authority,
    fenced_generation,
    raise_fence,
)
from emailcheck.domain.job import JobAdmission, JobFailure, JobState
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.ports.job_store import ClaimResult, ClaimStatus, StoredJob

#: Bumped when the shape changes. A file written by another shape is refused at
#: start rather than migrated.
#:
#: Version 5 adds the account fence and the authority binding. A version 4 file
#: predates both: it carries no record of which deletion authority it belongs
#: to, and adopting it under whichever one happens to be configured is the
#: mistake `adapters/storage/account_fence.py` refuses to make. Refused loudly,
#: as every earlier version of this file is.
#:
#: Version 4 is Remediation B: it persists the completed result's
#: `no_message_data_sent`. A version 3 file has no column for it, and the value
#: a reload would have to invent is precisely the assertion the column exists to
#: stop being invented — so such a file is refused by version rather than read
#: with an assumed `True`.
#:
#: Version 3 is the final Remediation A follow-up: it adds the executor-handoff
#: admission fact. Version 2 added `recipient_touch` and — the reason a version
#: 1 file cannot simply be opened — the **unique** idempotency index. A file
#: written by version 1 may already hold two rows for one
#: `(owner, idempotency_digest)`, because version 1 had no constraint that could
#: refuse them. Creating the index over such a file would fail with an integrity
#: error from the driver at some unrelated moment; refusing the file by version
#: fails at start, with a sentence, which is the convention
#: `adapters/storage/sqlite_store.py` set.
SCHEMA_VERSION: Final = 5

_TABLES: Final = """
CREATE TABLE IF NOT EXISTS job_schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS jobs (
    job_id             TEXT PRIMARY KEY,
    owner              TEXT NOT NULL,
    state              TEXT NOT NULL,
    admission          TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    retries_used       INTEGER NOT NULL,
    idempotency_digest TEXT,
    target_digest      TEXT,
    recipient_touch    TEXT NOT NULL,
    failure            TEXT,
    status             TEXT,
    confidence         TEXT,
    primary_reason     TEXT,
    reasons            TEXT NOT NULL,
    risk_flags         TEXT NOT NULL,
    checks             TEXT NOT NULL,
    ruleset            TEXT,
    no_message_data_sent INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency
    ON jobs (owner, idempotency_digest)
 WHERE idempotency_digest IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_terminal ON jobs (state, updated_at);
"""

#: The store's own tables plus the fence and authority tables every
#: account-owned store carries.
_SCHEMA: Final = _TABLES + FENCE_SCHEMA

_VERSION: Final = "SELECT version FROM job_schema_version"
_VERSION_TABLE: Final = (
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'job_schema_version'"
)
_RECORD_VERSION: Final = "INSERT INTO job_schema_version (version) VALUES (?)"

_COLUMNS: Final = """
SELECT job_id, owner, state, admission, created_at, updated_at, retries_used,
       idempotency_digest, target_digest, recipient_touch, failure, status,
       confidence, primary_reason, reasons, risk_flags, checks, ruleset,
       no_message_data_sent
  FROM jobs
"""

#: **Not `INSERT OR REPLACE`.** SQLite's `REPLACE` resolves *every* constraint by
#: deleting the rows that conflict — so once `jobs_idempotency` is unique, one
#: job saving its own state transition would have silently deleted whatever other
#: job held its `(owner, idempotency_digest)` pair, which is the winner of an
#: atomic claim. `ON CONFLICT (job_id) DO UPDATE` names the one conflict that
#: may be an update. The immutable identity columns are absent from the `SET`
#: list, and the `WHERE` guard requires exact equality (`IS` for nullable
#: digests). A mismatch updates zero rows and becomes `JobStoreConflictError`.
_INSERT: Final = """
INSERT INTO jobs (
    job_id, owner, state, admission, created_at, updated_at, retries_used,
    idempotency_digest, target_digest, recipient_touch, failure, status,
    confidence, primary_reason, reasons, risk_flags, checks, ruleset,
    no_message_data_sent
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (job_id) DO UPDATE SET
    state              = excluded.state,
    admission          = excluded.admission,
    updated_at         = excluded.updated_at,
    retries_used       = excluded.retries_used,
    recipient_touch    = excluded.recipient_touch,
    failure            = excluded.failure,
    status             = excluded.status,
    confidence         = excluded.confidence,
    primary_reason     = excluded.primary_reason,
    reasons            = excluded.reasons,
    risk_flags         = excluded.risk_flags,
    checks             = excluded.checks,
    ruleset            = excluded.ruleset,
    no_message_data_sent = excluded.no_message_data_sent
 WHERE jobs.owner = excluded.owner
   AND jobs.created_at = excluded.created_at
   AND jobs.idempotency_digest IS excluded.idempotency_digest
   AND jobs.target_digest IS excluded.target_digest
"""

#: The claim's insert. `DO NOTHING` rather than an update: losing the race must
#: leave the winner's row **exactly** as it is, including its state, its retry
#: count, and its recipient-touch checkpoint.
_CLAIM_INSERT: Final = """
INSERT INTO jobs (
    job_id, owner, state, admission, created_at, updated_at, retries_used,
    idempotency_digest, target_digest, recipient_touch, failure, status,
    confidence, primary_reason, reasons, risk_flags, checks, ruleset,
    no_message_data_sent
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING
"""

#: Taken before the claim's insert, so the whole decide-and-write is one write
#: transaction rather than a read that another connection can overtake.
_BEGIN_IMMEDIATE: Final = "BEGIN IMMEDIATE"

_SELECT_ONE: Final = _COLUMNS + " WHERE job_id = ?"

#: Owner **and** digest in the predicate. The digest is unguessable, and the
#: owner is checked anyway — ADR 0014's rule that an identifier which leaks is
#: survivable only because the second barrier exists.
_SELECT_BY_IDEMPOTENCY: Final = (
    _COLUMNS + " WHERE owner = ? AND idempotency_digest = ? ORDER BY created_at DESC LIMIT 1"
)

#: Nonterminal jobs for the recovery scan, oldest first and bounded. The state
#: list is the complement of `_PURGE_TERMINAL`'s, written out rather than
#: negated, so a state added later appears in neither until somebody chooses.
#: The tiebreak is not decoration: two jobs created in the same millisecond sort
#: arbitrarily without it, and a bounded scan that returns a different subset
#: each run is a recovery pass a test cannot pin.
_SELECT_NONTERMINAL: Final = (
    _COLUMNS + " WHERE state IN ('pending', 'running', 'retry_scheduled')"
    "   AND updated_at <= ?"
    " ORDER BY created_at ASC, job_id ASC LIMIT ?"
)

_DELETE: Final = "DELETE FROM jobs WHERE job_id = ?"

#: Every job this account owns, whatever its state, whatever it holds. The
#: `owner` column is the deletion key and the only one: a job's target is a
#: digest, and two accounts checking one address share it.
_DELETE_ACCOUNT: Final = "DELETE FROM jobs WHERE owner = ?"

#: Bounded, on the `_PURGE` precedent, and **terminal only**: removing a job
#: that is still running is work that stops existing while something waits for
#: it, which is the rule `JobService.purge_finished` already keeps in memory.
_PURGE_TERMINAL: Final = """
DELETE FROM jobs
 WHERE job_id IN (
       SELECT job_id FROM jobs
        WHERE state IN ('completed', 'failed', 'cancelled') AND updated_at <= ?
        LIMIT ?
 )
"""


class JobStoreSchemaError(RuntimeError):
    """The database on disk was written by a different schema version."""


class JobStoreConflictError(RuntimeError):
    """A write would have crossed two job identities, so it was refused.

    Raised in place of the driver's own integrity error, on the
    `AGENTS.md` rule that a library exception must not escape an adapter — and
    because the driver's message names the index rather than the invariant.

    Two ways to reach it, both bugs rather than conditions. A `save` whose
    `(owner, idempotency_digest)` pair belongs to a **different** job would, under
    the old `INSERT OR REPLACE`, have deleted that job: the winner of an atomic
    claim, removed by the loser's next state transition. And a claim that neither
    inserted nor found a holder means the conflict was on `job_id` — a generator
    collision, which 32 bytes of entropy do not produce.

    Never a `sqlite3` type and never a `ValueError`, so a caller cannot catch it
    by accident while meaning something else.
    """


@dataclass(frozen=True, slots=True)
class SQLiteJobStore:
    """One table, parameterized SQL, and an indexed idempotency lookup."""

    path: Path

    def initialize(self) -> None:
        """Create the schema, or refuse a file this build cannot write.

        **The version is read before the schema script runs**, which the earlier
        order did not do. `CREATE ... IF NOT EXISTS` is harmless against a file
        of the same shape and is not harmless against an older one: version 1
        permitted two rows per `(owner, idempotency_digest)`, so creating
        version 2's unique index over such a file raises an integrity error from
        the driver rather than the schema error this class publishes. Reading
        first means an unsupported file is refused by version, with a sentence
        naming both numbers.
        """
        with self._connect() as connection:
            existing = self._stored_version(connection)
            if existing is not None and existing != SCHEMA_VERSION:
                raise JobStoreSchemaError(
                    f"this store is schema version {existing}, "
                    f"and this build writes {SCHEMA_VERSION}"
                )
            connection.executescript(_SCHEMA)
            if existing is None:
                connection.execute(_RECORD_VERSION, (SCHEMA_VERSION,))

    @staticmethod
    def _stored_version(connection: sqlite3.Connection) -> int | None:
        """The version on disk, or `None` for a file this build has never seen."""
        if connection.execute(_VERSION_TABLE).fetchone() is None:
            return None
        row = connection.execute(_VERSION).fetchone()
        return None if row is None else int(row[0])

    def bind_authority(self, authority_id: str) -> str:
        """Tie this file to one deletion authority, or refuse to open under another."""
        with self._connect() as connection:
            return bind_authority(connection, authority_id)

    async def fence(self, *, account: str, generation: int) -> int:
        """Raise this store's fence before its rows are deleted."""
        return await asyncio.to_thread(self._fence, account, generation)

    async def claim_idempotency(
        self, record: StoredJob, *, expected_generation: int
    ) -> ClaimResult:
        return await asyncio.to_thread(self._claim_idempotency, record, expected_generation)

    async def save(self, record: StoredJob, *, expected_generation: int) -> bool:
        return await asyncio.to_thread(self._save, record, expected_generation)

    async def load(self, job_id: str) -> StoredJob | None:
        return await asyncio.to_thread(self._load, job_id)

    async def find_by_idempotency(self, owner: str, idempotency_digest: str) -> StoredJob | None:
        return await asyncio.to_thread(self._find_by_idempotency, owner, idempotency_digest)

    async def find_nonterminal(self, *, before: datetime, limit: int) -> tuple[StoredJob, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("a recovery scan must be a positive whole number")
        return await asyncio.to_thread(self._find_nonterminal, before, limit)

    async def delete(self, job_id: str) -> None:
        await asyncio.to_thread(self._delete, job_id)

    async def delete_account(self, *, owner: str) -> int:
        return await asyncio.to_thread(self._delete_account, owner)

    async def purge_terminal(self, *, before: datetime, limit: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("a purge batch must be a positive whole number")
        return await asyncio.to_thread(self._purge_terminal, before, limit)

    # --- the blocking half, in a worker thread ------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, isolation_level="DEFERRED")
        with closing(connection), connection:
            yield connection

    def _fence(self, account: str, generation: int) -> int:
        with self._connect() as connection:
            connection.execute(_BEGIN_IMMEDIATE)
            return raise_fence(connection, account, generation)

    def _claim_idempotency(self, record: StoredJob, expected_generation: int) -> ClaimResult:
        """Decide and write in one transaction, or read the winner in the same one.

        ```text
        BEGIN IMMEDIATE          the write lock, before anything is read
          INSERT ... DO NOTHING  wins, or does nothing
          rowcount == 1          -> NEW_CLAIM
          rowcount == 0          -> SELECT the holder, compare the target
        COMMIT
        ```

        The partial UNIQUE index is the structural identity barrier, and the
        insert-first shape makes the first database action the write that
        contends on it. Keeping the insert and winner lookup in one transaction
        makes the answer atomic. `BEGIN IMMEDIATE` acquires the write lock before
        even that insert, simplifying contention and snapshot semantics, but it
        is not by itself the uniqueness guarantee; changing only it to a deferred
        `BEGIN` leaves this insert-first algorithm serialized at its first write.

        The comparison is on `target_digest`, so "the same key for a different
        address" is refused by the store and not merely by the caller that
        happens to be in the same process as the first submission.
        """
        if record.idempotency_digest is None or record.target_digest is None:
            raise ValueError("a claim needs both an idempotency digest and a target digest")
        with self._connect() as connection:
            connection.execute(_BEGIN_IMMEDIATE)
            # Inside the claim's own write transaction, before the insert it
            # guards. A claim creates both a job row and an idempotency binding,
            # so an unfenced one recreates two pieces of a deleted account.
            if fenced_generation(connection, record.owner) != expected_generation:
                return ClaimResult(status=ClaimStatus.ACCOUNT_FENCED)
            cursor = connection.execute(_CLAIM_INSERT, _row_for(record))
            if cursor.rowcount == 1:
                return ClaimResult(status=ClaimStatus.NEW_CLAIM)
            held = connection.execute(
                _SELECT_BY_IDEMPOTENCY, (record.owner, record.idempotency_digest)
            ).fetchone()
            if held is None:
                # The insert wrote nothing and no row holds the binding, so the
                # conflict was on `job_id`: this identifier already exists. That
                # is a generator collision or a caller reusing an identifier,
                # and either way this claim did not create the job it proposed.
                raise JobStoreConflictError("this job identifier already exists")
            existing = _record(held)
        status = (
            ClaimStatus.EXISTING_SAME_TARGET
            if existing.target_digest == record.target_digest
            else ClaimStatus.CONFLICT_DIFFERENT_TARGET
        )
        return ClaimResult(status=status, existing=existing)

    def _save(self, record: StoredJob, expected_generation: int) -> bool:
        """The fence and the write, in one transaction. `False` means fenced.

        `BEGIN IMMEDIATE` first, so the fence read happens under this
        connection's write lock and an account deletion raising the fence in
        this same database must either come before it or wait for it. A `False`
        return is a refusal rather than an error: the account's data is being
        erased, and there is nothing for the caller to retry.
        """
        try:
            with self._connect() as connection:
                connection.execute(_BEGIN_IMMEDIATE)
                if fenced_generation(connection, record.owner) != expected_generation:
                    return False
                cursor = connection.execute(_INSERT, _row_for(record))
                if cursor.rowcount != 1:
                    raise JobStoreConflictError(
                        "this job identifier already belongs to another immutable identity"
                    )
        except sqlite3.IntegrityError as exc:
            # The only constraint a state write can violate is the unique
            # idempotency index, and violating it means this record's binding
            # belongs to a different job. Refused, and translated: the driver's
            # message names an index, and a caller needs the invariant.
            raise JobStoreConflictError(
                "this idempotency binding belongs to a different job"
            ) from exc
        return True

    def _load(self, job_id: str) -> StoredJob | None:
        with self._connect() as connection:
            row = connection.execute(_SELECT_ONE, (job_id,)).fetchone()
        return None if row is None else _record(row)

    def _find_by_idempotency(self, owner: str, digest: str) -> StoredJob | None:
        with self._connect() as connection:
            row = connection.execute(_SELECT_BY_IDEMPOTENCY, (owner, digest)).fetchone()
        return None if row is None else _record(row)

    def _find_nonterminal(self, before: datetime, limit: int) -> tuple[StoredJob, ...]:
        with self._connect() as connection:
            rows = connection.execute(_SELECT_NONTERMINAL, (before.isoformat(), limit)).fetchall()
        return tuple(_record(row) for row in rows)

    def _delete(self, job_id: str) -> None:
        with self._connect() as connection:
            connection.execute(_DELETE, (job_id,))

    def _delete_account(self, owner: str) -> int:
        with self._connect() as connection:
            return int(connection.execute(_DELETE_ACCOUNT, (owner,)).rowcount)

    def _purge_terminal(self, before: datetime, limit: int) -> int:
        with self._connect() as connection:
            cursor = connection.execute(_PURGE_TERMINAL, (before.isoformat(), limit))
            return int(cursor.rowcount)


def _row_for(record: StoredJob) -> tuple[Any, ...]:
    """The parameter row, in the one order both writes use.

    One function rather than two literal tuples: the claim and the save write
    the same eighteen columns, and two hand-maintained orderings is how a
    column ends up in the wrong slot the day somebody adds one.
    """
    return (
        record.job_id,
        record.owner,
        record.state.value,
        record.admission.value,
        record.created_at.isoformat(),
        record.updated_at.isoformat(),
        record.retries_used,
        record.idempotency_digest,
        record.target_digest,
        record.recipient_touch.value,
        None if record.failure is None else record.failure.value,
        record.status,
        record.confidence,
        record.primary_reason,
        json.dumps(list(record.reasons)),
        json.dumps(list(record.risk_flags)),
        json.dumps([list(pair) for pair in record.checks]),
        record.ruleset,
        None if record.no_message_data_sent is None else int(record.no_message_data_sent),
    )


def _record(row: tuple[Any, ...]) -> StoredJob:
    return StoredJob(
        job_id=str(row[0]),
        owner=str(row[1]),
        state=JobState(row[2]),
        admission=JobAdmission(row[3]),
        created_at=datetime.fromisoformat(str(row[4])),
        updated_at=datetime.fromisoformat(str(row[5])),
        retries_used=int(row[6]),
        idempotency_digest=None if row[7] is None else str(row[7]),
        target_digest=None if row[8] is None else str(row[8]),
        recipient_touch=RecipientTouch(row[9]),
        failure=None if row[10] is None else JobFailure(row[10]),
        status=None if row[11] is None else str(row[11]),
        confidence=None if row[12] is None else str(row[12]),
        primary_reason=None if row[13] is None else str(row[13]),
        reasons=tuple(json.loads(str(row[14]))),
        risk_flags=tuple(json.loads(str(row[15]))),
        checks=tuple((str(pair[0]), str(pair[1])) for pair in json.loads(str(row[16]))),
        ruleset=None if row[17] is None else str(row[17]),
        # SQLite has no boolean type, so the column is an INTEGER and this is
        # the one place it becomes a `bool` again. `None` stays `None`: an
        # unfinished job has no assertion to make, and `bool(None)` would be the
        # same laundering one layer down.
        no_message_data_sent=None if row[18] is None else bool(row[18]),
    )
