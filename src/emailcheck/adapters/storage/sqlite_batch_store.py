"""Batch state on disk, so a restart can continue rather than start again.

The `adapters/storage/sqlite_store.py` conventions, unchanged: one schema, an
explicit version, every statement a module constant so an inspection can see
that what reaches a cursor is a literal, and `sqlite3` behind `asyncio.to_thread`
because a blocking driver should not pretend otherwise.

**Ownership and expiry are predicates, never filters applied afterwards.** Both
are in the `WHERE` clause of every read, for the reason
`ports/verdict_store.py` gives about the ruleset: a row filtered after selection
is a row an implementation can still answer with — and here the two things being
filtered are "somebody else's batch" and "a result that has expired".

**Capacity is a refusal, not an eviction.** Expired batches are cleared first;
if the store is still full, `save_batch` raises. Evicting a live batch to admit
a new one would make submitting batches a way to erase somebody else's.
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
from typing import Final

from emailcheck.adapters.storage.account_fence import (
    BEGIN_IMMEDIATE,
    FENCE_SCHEMA,
    bind_authority,
    fenced_generation,
    raise_fence,
)
from emailcheck.domain.batch import BatchRowState
from emailcheck.ports.batch_store import (
    BatchArtifact,
    BatchStoreFull,
    StoredBatch,
    StoredBatchRow,
)

#: Bumped when the shape changes. A file written by another shape is refused at
#: start rather than migrated — `prompts/06-api-cli.md` says not to overbuild
#: migrations for a development store, and this follows the same rule.
#: Version 2 is Remediation D: the account fence and the authority binding, on
#: the shape `adapters/storage/account_fence.py` established for the job and
#: verdict stores. A version 1 file records neither — it predates the deletion
#: authority entirely — and adopting it under whichever one happens to be
#: configured is the mistake the binding exists to catch, so it is refused.
#: Version 3 binds each batch to the account generation it was admitted under.
#: Without it a resumed batch would have to ask what the generation is *now*,
#: which is exactly how stale work launders itself into current work after a
#: deletion.
SCHEMA_VERSION: Final = 3

#: How many batches one store holds by default, and the ceiling on that.
DEFAULT_MAX_BATCHES: Final = 256
MAX_BATCHES_CEILING: Final = 65_536

_TABLES: Final = """
CREATE TABLE IF NOT EXISTS batch_schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS batches (
    batch_id     TEXT PRIMARY KEY,
    account      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    input_rows   INTEGER NOT NULL,
    skipped_rows INTEGER NOT NULL,
    cancelled    INTEGER NOT NULL,
    generation   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS batch_rows (
    batch_id      TEXT NOT NULL,
    number        INTEGER NOT NULL,
    state         TEXT NOT NULL,
    target_digest TEXT,
    job_id        TEXT,
    idempotency   TEXT,
    submitted     TEXT,
    PRIMARY KEY (batch_id, number)
);

CREATE TABLE IF NOT EXISTS batch_artifacts (
    batch_id   TEXT PRIMARY KEY,
    account    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    media_type TEXT NOT NULL,
    content    TEXT NOT NULL,
    complete   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS batches_owner ON batches (account, expires_at);
"""

#: The store's own tables plus the fence and authority tables every store that
#: holds account-owned rows carries. Shared with the job and verdict stores
#: rather than reimplemented: one fencing model, one place it can be wrong.
_SCHEMA: Final = _TABLES + FENCE_SCHEMA
_SECURE_DELETE: Final = "PRAGMA secure_delete = ON"

#: **The atomic scheduling claim.** Conditional on the row still being
#: schedulable, so two replicas racing for one row produce exactly one winner —
#: `rowcount` is the answer, decided by SQLite rather than by a `SELECT` the
#: other replica can overtake. The previous design wrote `claimed`
#: unconditionally, which is a claim only in name.
#: The schedulable states arrive as one JSON parameter rather than as a
#: generated `IN (?, ?, ...)`. A statement assembled at the call site is the
#: shape an injection has, and `tests/unit/test_batch_isolation.py` reads the
#: tree to forbid one; `json_each` keeps the whole statement a literal while
#: still letting the caller name the states.
_CLAIM_ROW: Final = """
UPDATE batch_rows
   SET state = ?
 WHERE batch_id = ?
   AND number = ?
   AND state IN (SELECT value FROM json_each(?))
"""

#: **The child job identifier is written once.** `job_id = ?` guarded by
#: `job_id IS NULL`, so a row that already names a child can never be pointed at
#: a different one: a batch row whose binding moved would leave the first child
#: running with nothing observing it.
_BIND_CHILD: Final = """
UPDATE batch_rows
   SET job_id = ?
 WHERE batch_id = ?
   AND number = ?
   AND job_id IS NULL
"""

#: The parent's owner, read inside the mutating transaction. `None` means the
#: batch does not exist, which is a refusal rather than an authorization.
_ROW_ACCOUNT: Final = "SELECT account FROM batches WHERE batch_id = ?"

_VERSION: Final = "SELECT version FROM batch_schema_version"
_RECORD_VERSION: Final = "INSERT INTO batch_schema_version (version) VALUES (?)"

_COUNT_BATCHES: Final = "SELECT COUNT(*) FROM batches"

_INSERT_BATCH: Final = """
INSERT OR REPLACE INTO batches
    (batch_id, account, created_at, expires_at, input_rows, skipped_rows, cancelled, generation)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""

_INSERT_ROW: Final = """
INSERT OR REPLACE INTO batch_rows
    (batch_id, number, state, target_digest, job_id, idempotency, submitted)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

#: Ownership **and** expiry in the predicate. Removing either is a mutation a
#: test fails on.
_SELECT_BATCH: Final = """
SELECT batch_id, account, created_at, expires_at, input_rows, skipped_rows, cancelled,
       generation
  FROM batches
 WHERE batch_id = ? AND account = ? AND expires_at > ?
"""

_SELECT_ROWS: Final = """
SELECT number, state, target_digest, job_id, idempotency, submitted
  FROM batch_rows WHERE batch_id = ? ORDER BY number
"""

_CANCEL: Final = "UPDATE batches SET cancelled = 1 WHERE batch_id = ?"

_INSERT_ARTIFACT: Final = """
INSERT OR REPLACE INTO batch_artifacts
    (batch_id, account, created_at, expires_at, media_type, content, complete)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_ARTIFACT: Final = """
SELECT batch_id, account, created_at, expires_at, media_type, content, complete
  FROM batch_artifacts
 WHERE batch_id = ? AND account = ? AND expires_at > ?
"""

_OWNED: Final = "SELECT batch_id FROM batches WHERE batch_id = ? AND account = ?"

_DELETE_BATCH: Final = "DELETE FROM batches WHERE batch_id = ?"
_DELETE_ROWS: Final = "DELETE FROM batch_rows WHERE batch_id = ?"
_DELETE_ARTIFACT: Final = "DELETE FROM batch_artifacts WHERE batch_id = ?"

#: Every batch this account owns. The rows and the artifact go through the
#: existing per-batch removal so that one place decides what a batch consists
#: of — a second list of tables here is how one of them gets forgotten.
_ACCOUNT_BATCH_IDS: Final = "SELECT batch_id FROM batches WHERE account = ?"

#: A second, independent predicate over the artifact table. `batch_artifacts`
#: carries its own `account` column, so an artifact orphaned by any earlier bug
#: is still removed by the account's deletion rather than surviving it.
_DELETE_ACCOUNT_ARTIFACTS: Final = "DELETE FROM batch_artifacts WHERE account = ?"

#: Bounded, on the `_PURGE` precedent: an unbounded `DELETE` holds a write lock
#: for as long as the backlog is.
_EXPIRED_IDS: Final = "SELECT batch_id FROM batches WHERE expires_at <= ? LIMIT ?"

#: **`submitted IS NOT NULL` is the whole starvation fix.** The predicate used
#: to select by `created_at` alone, so a batch whose plaintext had already been
#: cleared was selected again on every sweep for ever. With a bounded `limit`
#: that is not merely wasteful: the first already-cleared batch occupied the
#: whole budget run after run, and a second batch's plaintext was never reached.
#: The final system audit measured it.
#:
#: `EXISTS` rather than a join, so one batch is one row however many rows it has.
#: The ordering is explicit for the same reason the recovery scan's is: an
#: unordered bounded selection returns a different subset each run, which is a
#: sweep whose progress a test cannot pin and an operator cannot reason about.
_STALE_INPUT_IDS: Final = """
SELECT batch_id FROM batches
 WHERE created_at <= ?
   AND EXISTS (
       SELECT 1 FROM batch_rows
        WHERE batch_rows.batch_id = batches.batch_id AND batch_rows.submitted IS NOT NULL
   )
 ORDER BY created_at ASC, batch_id ASC
 LIMIT ?
"""

#: Clearing plaintext is an `UPDATE`, not a `DELETE`: the row's accounting must
#: survive its input. A row that can no longer be submitted is recorded as
#: refused by the caller, never silently dropped.
_FORGET_INPUT: Final = (
    "UPDATE batch_rows SET submitted = NULL WHERE batch_id = ? AND submitted IS NOT NULL"
)


class BatchStoreSchemaError(RuntimeError):
    """The database on disk was written by a different schema version."""


@dataclass(frozen=True, slots=True)
class SQLiteBatchStore:
    """Batches, rows, and artifacts in one file, bounded and owner-checked."""

    path: Path
    max_batches: int = DEFAULT_MAX_BATCHES

    def __post_init__(self) -> None:
        if isinstance(self.max_batches, bool) or not isinstance(self.max_batches, int):
            raise ValueError("max_batches must be a whole number, not a boolean")
        if not 0 < self.max_batches <= MAX_BATCHES_CEILING:
            raise ValueError(f"max_batches must be 1..{MAX_BATCHES_CEILING}")

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            row = connection.execute(_VERSION).fetchone()
            if row is None:
                connection.execute(_RECORD_VERSION, (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise BatchStoreSchemaError(
                    f"this store is schema version {row[0]}, and this build writes {SCHEMA_VERSION}"
                )

    # --- the async surface --------------------------------------------------

    def bind_authority(self, authority_id: str) -> str:
        """Tie this file to one deletion authority, or refuse to open under another."""
        with self._connect() as connection:
            return bind_authority(connection, authority_id)

    async def fence(self, *, account: str, generation: int) -> int:
        """Raise this store's fence before its rows are deleted."""
        return await asyncio.to_thread(self._fence, account, generation)

    async def claim_row(
        self,
        *,
        batch_id: str,
        number: int,
        schedulable: tuple[str, ...],
        claimed: str,
        expected_generation: int | None = None,
    ) -> bool:
        """Take one row for scheduling, atomically. `False` means somebody else has it."""
        return await asyncio.to_thread(
            self._claim_row, batch_id, number, schedulable, claimed, expected_generation
        )

    async def bind_child(
        self,
        *,
        batch_id: str,
        number: int,
        job_id: str,
        expected_generation: int | None = None,
    ) -> bool:
        """Name this row's child job, once. `False` means it already names one."""
        return await asyncio.to_thread(
            self._bind_child, batch_id, number, job_id, expected_generation
        )

    async def save_batch(
        self, record: StoredBatch, *, expected_generation: int | None = None
    ) -> bool:
        return await asyncio.to_thread(self._save_batch, record, expected_generation)

    async def update_rows(
        self,
        batch_id: str,
        rows: tuple[StoredBatchRow, ...],
        *,
        expected_generation: int | None = None,
    ) -> bool:
        return await asyncio.to_thread(self._update_rows, batch_id, rows, expected_generation)

    async def set_cancelled(self, batch_id: str, *, expected_generation: int | None = None) -> bool:
        return await asyncio.to_thread(self._set_cancelled, batch_id, expected_generation)

    async def load_batch(self, batch_id: str, *, account: str, now: datetime) -> StoredBatch | None:
        return await asyncio.to_thread(self._load_batch, batch_id, account, now)

    async def save_artifact(
        self, artifact: BatchArtifact, *, expected_generation: int | None = None
    ) -> bool:
        return await asyncio.to_thread(self._save_artifact, artifact, expected_generation)

    async def load_artifact(
        self, batch_id: str, *, account: str, now: datetime
    ) -> BatchArtifact | None:
        return await asyncio.to_thread(self._load_artifact, batch_id, account, now)

    async def delete_batch(self, batch_id: str, *, account: str) -> bool:
        return await asyncio.to_thread(self._delete_batch, batch_id, account)

    async def delete_account(self, *, account: str) -> int:
        return await asyncio.to_thread(self._delete_account, account)

    async def forget_inputs(self, *, before: datetime, limit: int) -> int:
        _positive(limit)
        return await asyncio.to_thread(self._forget_inputs, before, limit)

    async def purge_expired(self, *, now: datetime, limit: int = 100) -> int:
        _positive(limit)
        return await asyncio.to_thread(self._purge_expired, now, limit)

    # --- the blocking half, in a worker thread ------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, isolation_level="DEFERRED")
        with closing(connection), connection:
            # The default varies by SQLite build. Plaintext removal must not.
            connection.execute(_SECURE_DELETE)
            yield connection

    def _fence(self, account: str, generation: int) -> int:
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            return raise_fence(connection, account, generation)

    def _account_of(self, connection: sqlite3.Connection, batch_id: str) -> str | None:
        row = connection.execute(_ROW_ACCOUNT, (batch_id,)).fetchone()
        return None if row is None else str(row[0])

    def _may_mutate(
        self, connection: sqlite3.Connection, batch_id: str, expected: int | None
    ) -> bool:
        """Whether a write **to an existing batch** may proceed, in this transaction.

        **A missing parent is a refusal, not a permission.** The first version of
        this helper treated an unresolvable account as "a batch that does not
        exist yet, whose own insert carries the check" — which is true of
        creation and false of every child mutation. The independent review used
        exactly that: after a completed deletion the parent was gone, so the
        account could not be resolved, so a stale `update_rows` was waved
        through and inserted an orphan `batch_rows` row for an account the
        operator had been told was erased. Creation is a separate path with its
        own account, and this one requires a parent.

        `expected is None` is a deployment with no deletion authority, which
        cannot delete and therefore has no fence to fail — the allowance
        `application/jobs.py` makes, for the same reason. The parent must still
        exist.
        """
        account = self._account_of(connection, batch_id)
        if account is None:
            return False
        if expected is None:
            return True
        return fenced_generation(connection, account) == expected

    def _claim_row(
        self,
        batch_id: str,
        number: int,
        schedulable: tuple[str, ...],
        claimed: str,
        expected_generation: int | None,
    ) -> bool:
        """One conditional `UPDATE`, so the winner is decided by the database.

        `BEGIN IMMEDIATE` first on this package's rule, and the predicate names
        the states a row may be claimed *from* — a row already `claimed` or
        `submitted` matches nothing and the loser is told so by `rowcount`.
        """
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            # The parent and the fence, read under this transaction's write lock
            # and before the update they guard. A claim is a mutation of an
            # existing batch, so it is fenced exactly as `update_rows` is.
            if not self._may_mutate(connection, batch_id, expected_generation):
                return False
            cursor = connection.execute(
                _CLAIM_ROW, (claimed, batch_id, number, json.dumps(list(schedulable)))
            )
            return int(cursor.rowcount) == 1

    def _bind_child(
        self, batch_id: str, number: int, job_id: str, expected_generation: int | None
    ) -> bool:
        """The fence and the immutable binding, both, in one transaction."""
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            if not self._may_mutate(connection, batch_id, expected_generation):
                return False
            cursor = connection.execute(_BIND_CHILD, (job_id, batch_id, number))
            return int(cursor.rowcount) == 1

    def _save_batch(self, record: StoredBatch, expected_generation: int | None) -> bool:
        """Create or replace one batch, fenced. `False` means the account is being erased."""
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            if expected_generation is not None and (
                fenced_generation(connection, record.account) != expected_generation
            ):
                return False
            existing = connection.execute(_OWNED, (record.batch_id, record.account)).fetchone()
            if existing is None:
                # Clear what the clock has already released before deciding the
                # store is full, so a long-lived process is not permanently at
                # capacity because of batches nobody can read any more.
                self._purge_within(connection, record.created_at, self.max_batches)
                held = int(connection.execute(_COUNT_BATCHES).fetchone()[0])
                if held >= self.max_batches:
                    raise BatchStoreFull("the batch store is at capacity")
            connection.execute(
                _INSERT_BATCH,
                (
                    record.batch_id,
                    record.account,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                    record.input_rows,
                    record.skipped_rows,
                    int(record.cancelled),
                    record.generation,
                ),
            )
            self._write_rows(connection, record.batch_id, record.rows)
        return True

    @staticmethod
    def _write_rows(
        connection: sqlite3.Connection, batch_id: str, rows: tuple[StoredBatchRow, ...]
    ) -> None:
        connection.executemany(
            _INSERT_ROW,
            [
                (
                    batch_id,
                    row.number,
                    row.state.value,
                    row.target_digest,
                    row.job_id,
                    row.idempotency,
                    row.submitted,
                )
                for row in rows
            ],
        )

    def _update_rows(
        self, batch_id: str, rows: tuple[StoredBatchRow, ...], expected_generation: int | None
    ) -> bool:
        """Row state and result, fenced in the same transaction as the write."""
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            if not self._may_mutate(connection, batch_id, expected_generation):
                return False
            self._write_rows(connection, batch_id, rows)
        return True

    def _set_cancelled(self, batch_id: str, expected_generation: int | None) -> bool:
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            if not self._may_mutate(connection, batch_id, expected_generation):
                return False
            connection.execute(_CANCEL, (batch_id,))
        return True

    def _load_batch(self, batch_id: str, account: str, now: datetime) -> StoredBatch | None:
        with self._connect() as connection:
            row = connection.execute(_SELECT_BATCH, (batch_id, account, now.isoformat())).fetchone()
            if row is None:
                return None
            rows = connection.execute(_SELECT_ROWS, (batch_id,)).fetchall()
        return StoredBatch(
            batch_id=row[0],
            account=row[1],
            created_at=datetime.fromisoformat(row[2]),
            expires_at=datetime.fromisoformat(row[3]),
            input_rows=int(row[4]),
            skipped_rows=int(row[5]),
            cancelled=bool(row[6]),
            generation=int(row[7]),
            rows=tuple(
                StoredBatchRow(
                    number=int(item[0]),
                    state=BatchRowState(item[1]),
                    target_digest=item[2],
                    job_id=item[3],
                    idempotency=item[4],
                    submitted=item[5],
                )
                for item in rows
            ),
        )

    def _save_artifact(self, artifact: BatchArtifact, expected_generation: int | None) -> bool:
        """The report is the account's data too, so it is fenced like the rows."""
        with self._connect() as connection:
            connection.execute(BEGIN_IMMEDIATE)
            if expected_generation is not None and (
                fenced_generation(connection, artifact.account) != expected_generation
            ):
                return False
            connection.execute(
                _INSERT_ARTIFACT,
                (
                    artifact.batch_id,
                    artifact.account,
                    artifact.created_at.isoformat(),
                    artifact.expires_at.isoformat(),
                    artifact.media_type,
                    artifact.content,
                    int(artifact.complete),
                ),
            )
        return True

    def _load_artifact(self, batch_id: str, account: str, now: datetime) -> BatchArtifact | None:
        with self._connect() as connection:
            row = connection.execute(
                _SELECT_ARTIFACT, (batch_id, account, now.isoformat())
            ).fetchone()
        if row is None:
            return None
        return BatchArtifact(
            batch_id=row[0],
            account=row[1],
            created_at=datetime.fromisoformat(row[2]),
            expires_at=datetime.fromisoformat(row[3]),
            media_type=row[4],
            content=row[5],
            complete=bool(row[6]),
        )

    def _delete_batch(self, batch_id: str, account: str) -> bool:
        with self._connect() as connection:
            if connection.execute(_OWNED, (batch_id, account)).fetchone() is None:
                # Another account's batch, or none. Nothing is removed and
                # nothing is reported about whether it exists.
                return False
            self._remove(connection, batch_id)
        return True

    @staticmethod
    def _remove(connection: sqlite3.Connection, batch_id: str) -> None:
        """Every trace of one batch: rows and their plaintext, and the artifact.

        Never a child job. A job is Phase 6's record, is bounded and expired by
        Phase 7's retention, and may be shared with a single check through the
        cache — deleting one here would delete somebody else's answer.
        """
        connection.execute(_DELETE_ROWS, (batch_id,))
        connection.execute(_DELETE_ARTIFACT, (batch_id,))
        connection.execute(_DELETE_BATCH, (batch_id,))

    def _delete_account(self, account: str) -> int:
        """Every batch, row, retained address, and artifact this account owns."""
        with self._connect() as connection:
            identifiers = [
                row[0] for row in connection.execute(_ACCOUNT_BATCH_IDS, (account,)).fetchall()
            ]
            for batch_id in identifiers:
                self._remove(connection, batch_id)
            connection.execute(_DELETE_ACCOUNT_ARTIFACTS, (account,))
        return len(identifiers)

    def _forget_inputs(self, before: datetime, limit: int) -> int:
        """Clear stale plaintext. Returns batches **actually changed**.

        The count used to be one per selected identifier, so a sweep that
        cleared nothing still reported work — which is what an operator reads as
        "retention is running" and what `more_remaining` reads as progress. It
        is now driven by `cursor.rowcount`: a batch whose rows were already
        `NULL` contributes zero, and the selection above no longer offers one.
        """
        with self._connect() as connection:
            identifiers = connection.execute(_STALE_INPUT_IDS, (before.isoformat(), limit))
            cleared = 0
            for (batch_id,) in identifiers.fetchall():
                cursor = connection.execute(_FORGET_INPUT, (batch_id,))
                if cursor.rowcount > 0:
                    cleared += 1
        return cleared

    def _purge_expired(self, now: datetime, limit: int) -> int:
        with self._connect() as connection:
            return self._purge_within(connection, now, limit)

    @staticmethod
    def _purge_within(connection: sqlite3.Connection, now: datetime, limit: int) -> int:
        removed = 0
        for (batch_id,) in connection.execute(_EXPIRED_IDS, (now.isoformat(), limit)).fetchall():
            SQLiteBatchStore._remove(connection, batch_id)
            removed += 1
        return removed


def _positive(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("a batch store batch size must be a positive whole number")
