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
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

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
SCHEMA_VERSION: Final = 1

#: How many batches one store holds by default, and the ceiling on that.
DEFAULT_MAX_BATCHES: Final = 256
MAX_BATCHES_CEILING: Final = 65_536

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS batch_schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS batches (
    batch_id     TEXT PRIMARY KEY,
    account      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    input_rows   INTEGER NOT NULL,
    skipped_rows INTEGER NOT NULL,
    cancelled    INTEGER NOT NULL
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

_VERSION: Final = "SELECT version FROM batch_schema_version"
_RECORD_VERSION: Final = "INSERT INTO batch_schema_version (version) VALUES (?)"

_COUNT_BATCHES: Final = "SELECT COUNT(*) FROM batches"

_INSERT_BATCH: Final = """
INSERT OR REPLACE INTO batches
    (batch_id, account, created_at, expires_at, input_rows, skipped_rows, cancelled)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_INSERT_ROW: Final = """
INSERT OR REPLACE INTO batch_rows
    (batch_id, number, state, target_digest, job_id, idempotency, submitted)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

#: Ownership **and** expiry in the predicate. Removing either is a mutation a
#: test fails on.
_SELECT_BATCH: Final = """
SELECT batch_id, account, created_at, expires_at, input_rows, skipped_rows, cancelled
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

#: Bounded, on the `_PURGE` precedent: an unbounded `DELETE` holds a write lock
#: for as long as the backlog is.
_EXPIRED_IDS: Final = "SELECT batch_id FROM batches WHERE expires_at <= ? LIMIT ?"

_STALE_INPUT_IDS: Final = "SELECT batch_id FROM batches WHERE created_at <= ? LIMIT ?"

#: Clearing plaintext is an `UPDATE`, not a `DELETE`: the row's accounting must
#: survive its input. A row that can no longer be submitted is recorded as
#: refused by the caller, never silently dropped.
_FORGET_INPUT: Final = "UPDATE batch_rows SET submitted = NULL WHERE batch_id = ?"


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

    async def save_batch(self, record: StoredBatch) -> None:
        await asyncio.to_thread(self._save_batch, record)

    async def update_rows(self, batch_id: str, rows: tuple[StoredBatchRow, ...]) -> None:
        await asyncio.to_thread(self._update_rows, batch_id, rows)

    async def set_cancelled(self, batch_id: str) -> None:
        await asyncio.to_thread(self._set_cancelled, batch_id)

    async def load_batch(self, batch_id: str, *, account: str, now: datetime) -> StoredBatch | None:
        return await asyncio.to_thread(self._load_batch, batch_id, account, now)

    async def save_artifact(self, artifact: BatchArtifact) -> None:
        await asyncio.to_thread(self._save_artifact, artifact)

    async def load_artifact(
        self, batch_id: str, *, account: str, now: datetime
    ) -> BatchArtifact | None:
        return await asyncio.to_thread(self._load_artifact, batch_id, account, now)

    async def delete_batch(self, batch_id: str, *, account: str) -> bool:
        return await asyncio.to_thread(self._delete_batch, batch_id, account)

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
            yield connection

    def _save_batch(self, record: StoredBatch) -> None:
        with self._connect() as connection:
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
                ),
            )
            self._write_rows(connection, record.batch_id, record.rows)

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

    def _update_rows(self, batch_id: str, rows: tuple[StoredBatchRow, ...]) -> None:
        with self._connect() as connection:
            self._write_rows(connection, batch_id, rows)

    def _set_cancelled(self, batch_id: str) -> None:
        with self._connect() as connection:
            connection.execute(_CANCEL, (batch_id,))

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

    def _save_artifact(self, artifact: BatchArtifact) -> None:
        with self._connect() as connection:
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

    def _forget_inputs(self, before: datetime, limit: int) -> int:
        with self._connect() as connection:
            identifiers = connection.execute(_STALE_INPUT_IDS, (before.isoformat(), limit))
            cleared = 0
            for (batch_id,) in identifiers.fetchall():
                connection.execute(_FORGET_INPUT, (batch_id,))
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
