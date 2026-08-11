"""A development store, in the standard library, with the whole key in the match.

`docs/requirements.md` section 15 gives the local-passive profile a SQLite
cache; `prompts/06-api-cli.md` asks for a SQLite development store and says not
to overbuild migrations. This is that, and no more: one table, an explicit
schema version, and parameterized SQL.

**The key is in the `WHERE` clause, not beside it.** Section 13 composes a cache
key from the ruleset, the sender identity, and the normalized target HMAC; ADR
0015 keeps the account digest from this store's first version as well, because
`prompts/06-api-cli.md` forbids cross-account result access and a shared row is
the quietest way to hand one account another account's answer. Expiry is a
predicate for the same reason Phase 5 stop condition 4 made the ruleset one: a
row filtered after selection is a row an implementation can still answer with.

**What is stored is digests and published vocabulary.** No address, no account
identifier, no sender identity, no evidence detail, no SMTP transcript, no
certificate. `StoredVerdict` refuses most of that at construction; this adapter
adds nothing to what it is given.

Every statement below is a module constant. Not one is built at the call site,
so an inspection test can assert that what reaches a cursor is a literal rather
than something assembled from a value.

`sqlite3` is synchronous, so every call runs in a worker thread. That keeps the
port async — a PostgreSQL adapter is a drop-in — without pretending a blocking
driver is not blocking.
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

from emailcheck.domain.verdict import Status
from emailcheck.ports.verdict_store import StoredVerdict

#: Bumped when the table's shape changes. Explicit rather than inferred, so a
#: store written by a different shape is refused rather than misread.
#:
#: Version 2 adds the sender-identity component of the section 13 key and the
#: expiry ADR 0015 decided. `prompts/06-api-cli.md` says not to overbuild
#: migrations and no document requires a development database to survive, so an
#: older file is refused at start rather than migrated.
#:
#: Version 3 carries no shape change at all: Phase 7 put
#: `docs/privacy.md` section 5's `canonical_input_version` inside the HMAC
#: input, so **every digest in a version-2 file addresses a row that can no
#: longer be found**. A store whose rows are unreachable is worse than one that
#: refuses to open, because it looks like a cache that never hits — so the
#: version moves even though the columns do not. ADR 0016.
SCHEMA_VERSION: Final = 3

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS verdicts (
    record_id              TEXT PRIMARY KEY,
    account_digest         TEXT NOT NULL,
    target_digest          TEXT NOT NULL,
    sender_identity_digest TEXT NOT NULL,
    status                 TEXT NOT NULL,
    confidence             TEXT NOT NULL,
    primary_reason         TEXT,
    reasons                TEXT NOT NULL,
    risk_flags             TEXT NOT NULL,
    checks                 TEXT NOT NULL,
    aggregation_ruleset    TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS verdicts_lookup
    ON verdicts (account_digest, target_digest, sender_identity_digest,
                 aggregation_ruleset, expires_at DESC);
"""

_INSERT: Final = """
INSERT OR REPLACE INTO verdicts (
    record_id, account_digest, target_digest, sender_identity_digest, status,
    confidence, primary_reason, reasons, risk_flags, checks,
    aggregation_ruleset, created_at, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

#: Four key components and the expiry, all in the predicate. Removing any one of
#: them is a mutation a test fails on.
_SELECT: Final = """
SELECT record_id, account_digest, target_digest, sender_identity_digest, status,
       confidence, primary_reason, reasons, risk_flags, checks,
       aggregation_ruleset, created_at, expires_at
  FROM verdicts
 WHERE account_digest = ?
   AND target_digest = ?
   AND sender_identity_digest = ?
   AND aggregation_ruleset = ?
   AND expires_at > ?
 ORDER BY created_at DESC
 LIMIT 1
"""

#: Bounded, because an unbounded `DELETE` holds a write lock for as long as the
#: backlog is. `LIMIT` on `DELETE` needs a compile-time SQLite option that is
#: not always present, so the bound is a sub-select over the same index the
#: lookup uses — portable, and still one statement.
_PURGE: Final = """
DELETE FROM verdicts
 WHERE record_id IN (
       SELECT record_id FROM verdicts WHERE expires_at <= ? LIMIT ?
 )
"""

_VERSION: Final = "SELECT version FROM schema_version"

_RECORD_VERSION: Final = "INSERT INTO schema_version (version) VALUES (?)"


class StoreSchemaError(RuntimeError):
    """The database on disk was written by a different schema version."""


@dataclass(frozen=True, slots=True)
class SQLiteVerdictStore:
    """One table, parameterized SQL, and a lookup that carries the whole key."""

    path: Path

    def initialize(self) -> None:
        """Create or check the schema. Idempotent, and explicit about version.

        Called once by the composition root rather than lazily on first use, so
        a deployment learns about an incompatible database at start rather than
        on a request.
        """
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            row = connection.execute(_VERSION).fetchone()
            if row is None:
                connection.execute(_RECORD_VERSION, (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise StoreSchemaError(
                    f"this store is schema version {row[0]}, and this build writes {SCHEMA_VERSION}"
                )

    async def save(self, record: StoredVerdict) -> None:
        await asyncio.to_thread(self._save, record)

    async def find(
        self,
        *,
        account_digest: str,
        target_digest: str,
        sender_identity_digest: str,
        aggregation_ruleset: str,
        now: datetime,
    ) -> StoredVerdict | None:
        return await asyncio.to_thread(
            self._find,
            account_digest,
            target_digest,
            sender_identity_digest,
            aggregation_ruleset,
            now,
        )

    async def purge_expired(self, *, now: datetime, limit: int = 1_000) -> int:
        """Delete rows the clock has passed, at most `limit` of them.

        A cache that only ever grows is a retention policy nobody wrote:
        `docs/requirements.md` section 16 bounds what this project keeps, and an
        expired row is one no lookup can answer with anyway.

        The bound is what makes this safe to schedule. Returning a full batch
        tells `application/retention.py` that more remain, so a backlog is
        cleared over several runs rather than in one statement that blocks
        every write until it finishes.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("a purge batch must be a positive whole number")
        return await asyncio.to_thread(self._purge_expired, now, limit)

    # --- the blocking half, run in a worker thread --------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One connection, one transaction, committed or rolled back.

        `sqlite3`'s context manager commits on success and rolls back on an
        exception, and `closing` releases the handle either way — so an
        interrupted write leaves no partial row.
        """
        connection = sqlite3.connect(self.path, isolation_level="DEFERRED")
        with closing(connection), connection:
            yield connection

    def _save(self, record: StoredVerdict) -> None:
        with self._connect() as connection:
            connection.execute(
                _INSERT,
                (
                    record.record_id,
                    record.account_digest,
                    record.target_digest,
                    record.sender_identity_digest,
                    record.status.value,
                    record.confidence,
                    record.primary_reason,
                    json.dumps(list(record.reasons)),
                    json.dumps(list(record.risk_flags)),
                    json.dumps([list(pair) for pair in record.checks]),
                    record.aggregation_ruleset,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                ),
            )

    def _find(
        self,
        account_digest: str,
        target_digest: str,
        sender_identity_digest: str,
        aggregation_ruleset: str,
        now: datetime,
    ) -> StoredVerdict | None:
        with self._connect() as connection:
            row = connection.execute(
                _SELECT,
                (
                    account_digest,
                    target_digest,
                    sender_identity_digest,
                    aggregation_ruleset,
                    now.isoformat(),
                ),
            ).fetchone()
        if row is None:
            return None
        return StoredVerdict(
            record_id=row[0],
            account_digest=row[1],
            target_digest=row[2],
            sender_identity_digest=row[3],
            status=Status(row[4]),
            confidence=row[5],
            primary_reason=row[6],
            reasons=tuple(json.loads(row[7])),
            risk_flags=tuple(json.loads(row[8])),
            checks=tuple((str(pair[0]), str(pair[1])) for pair in json.loads(row[9])),
            aggregation_ruleset=row[10],
            created_at=datetime.fromisoformat(row[11]),
            expires_at=datetime.fromisoformat(row[12]),
        )

    def _purge_expired(self, now: datetime, limit: int) -> int:
        with self._connect() as connection:
            cursor = connection.execute(_PURGE, (now.isoformat(), limit))
            return int(cursor.rowcount)
