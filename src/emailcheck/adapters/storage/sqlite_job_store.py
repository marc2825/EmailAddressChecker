"""Job identity, state, and result on disk, so a restart cannot duplicate work.

The `adapters/storage/sqlite_store.py` conventions, unchanged: one schema, an
explicit version, every statement a module constant so an inspection can see
that what reaches a cursor is a literal, and `sqlite3` behind `asyncio.to_thread`
because a blocking driver should not pretend otherwise.

**The idempotency lookup is an index, not a scan.** A resumed batch presents one
handle per row, so this is the hot path of a restart and a table scan per row
would make recovery cost the whole registry.

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

from emailcheck.domain.job import JobFailure, JobState
from emailcheck.ports.job_store import StoredJob

#: Bumped when the shape changes. A file written by another shape is refused at
#: start rather than migrated.
SCHEMA_VERSION: Final = 1

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS job_schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS jobs (
    job_id             TEXT PRIMARY KEY,
    owner              TEXT NOT NULL,
    state              TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    retries_used       INTEGER NOT NULL,
    idempotency_digest TEXT,
    target_digest      TEXT,
    failure            TEXT,
    status             TEXT,
    confidence         TEXT,
    primary_reason     TEXT,
    reasons            TEXT NOT NULL,
    risk_flags         TEXT NOT NULL,
    checks             TEXT NOT NULL,
    ruleset            TEXT
);

CREATE INDEX IF NOT EXISTS jobs_idempotency ON jobs (owner, idempotency_digest);
CREATE INDEX IF NOT EXISTS jobs_terminal ON jobs (state, updated_at);
"""

_VERSION: Final = "SELECT version FROM job_schema_version"
_RECORD_VERSION: Final = "INSERT INTO job_schema_version (version) VALUES (?)"

_COLUMNS: Final = """
SELECT job_id, owner, state, created_at, updated_at, retries_used,
       idempotency_digest, target_digest, failure, status, confidence,
       primary_reason, reasons, risk_flags, checks, ruleset
  FROM jobs
"""

_INSERT: Final = """
INSERT OR REPLACE INTO jobs (
    job_id, owner, state, created_at, updated_at, retries_used,
    idempotency_digest, target_digest, failure, status, confidence,
    primary_reason, reasons, risk_flags, checks, ruleset
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_ONE: Final = _COLUMNS + " WHERE job_id = ?"

#: Owner **and** digest in the predicate. The digest is unguessable, and the
#: owner is checked anyway — ADR 0014's rule that an identifier which leaks is
#: survivable only because the second barrier exists.
_SELECT_BY_IDEMPOTENCY: Final = (
    _COLUMNS + " WHERE owner = ? AND idempotency_digest = ? ORDER BY created_at DESC LIMIT 1"
)

_DELETE: Final = "DELETE FROM jobs WHERE job_id = ?"

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


@dataclass(frozen=True, slots=True)
class SQLiteJobStore:
    """One table, parameterized SQL, and an indexed idempotency lookup."""

    path: Path

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            row = connection.execute(_VERSION).fetchone()
            if row is None:
                connection.execute(_RECORD_VERSION, (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise JobStoreSchemaError(
                    f"this store is schema version {row[0]}, and this build writes {SCHEMA_VERSION}"
                )

    async def save(self, record: StoredJob) -> None:
        await asyncio.to_thread(self._save, record)

    async def load(self, job_id: str) -> StoredJob | None:
        return await asyncio.to_thread(self._load, job_id)

    async def find_by_idempotency(self, owner: str, idempotency_digest: str) -> StoredJob | None:
        return await asyncio.to_thread(self._find_by_idempotency, owner, idempotency_digest)

    async def delete(self, job_id: str) -> None:
        await asyncio.to_thread(self._delete, job_id)

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

    def _save(self, record: StoredJob) -> None:
        with self._connect() as connection:
            connection.execute(
                _INSERT,
                (
                    record.job_id,
                    record.owner,
                    record.state.value,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.retries_used,
                    record.idempotency_digest,
                    record.target_digest,
                    None if record.failure is None else record.failure.value,
                    record.status,
                    record.confidence,
                    record.primary_reason,
                    json.dumps(list(record.reasons)),
                    json.dumps(list(record.risk_flags)),
                    json.dumps([list(pair) for pair in record.checks]),
                    record.ruleset,
                ),
            )

    def _load(self, job_id: str) -> StoredJob | None:
        with self._connect() as connection:
            row = connection.execute(_SELECT_ONE, (job_id,)).fetchone()
        return None if row is None else _record(row)

    def _find_by_idempotency(self, owner: str, digest: str) -> StoredJob | None:
        with self._connect() as connection:
            row = connection.execute(_SELECT_BY_IDEMPOTENCY, (owner, digest)).fetchone()
        return None if row is None else _record(row)

    def _delete(self, job_id: str) -> None:
        with self._connect() as connection:
            connection.execute(_DELETE, (job_id,))

    def _purge_terminal(self, before: datetime, limit: int) -> int:
        with self._connect() as connection:
            cursor = connection.execute(_PURGE_TERMINAL, (before.isoformat(), limit))
            return int(cursor.rowcount)


def _record(row: tuple[Any, ...]) -> StoredJob:
    return StoredJob(
        job_id=str(row[0]),
        owner=str(row[1]),
        state=JobState(row[2]),
        created_at=datetime.fromisoformat(str(row[3])),
        updated_at=datetime.fromisoformat(str(row[4])),
        retries_used=int(row[5]),
        idempotency_digest=None if row[6] is None else str(row[6]),
        target_digest=None if row[7] is None else str(row[7]),
        failure=None if row[8] is None else JobFailure(row[8]),
        status=None if row[9] is None else str(row[9]),
        confidence=None if row[10] is None else str(row[10]),
        primary_reason=None if row[11] is None else str(row[11]),
        reasons=tuple(json.loads(str(row[12]))),
        risk_flags=tuple(json.loads(str(row[13]))),
        checks=tuple((str(pair[0]), str(pair[1])) for pair in json.loads(str(row[14]))),
        ruleset=None if row[15] is None else str(row[15]),
    )
