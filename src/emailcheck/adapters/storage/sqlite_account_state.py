"""The account deletion generation, on disk, shared by every replica.

The `adapters/storage/sqlite_store.py` conventions, unchanged: one schema, an
explicit version, every statement a module constant so an inspection can see
that what reaches a cursor is a literal, and `sqlite3` behind `asyncio.to_thread`
because a blocking driver should not pretend otherwise.

**One table, one row per account, and the only column that matters is a
number.** No target, no result, no key, no address: the whole record is "which
generation is this account on", which is exactly what a writer needs to know and
nothing a leak of this file would reveal about anybody's mail.

`advance` is `INSERT ... ON CONFLICT DO UPDATE SET generation = generation + 1`,
which is one statement and therefore one transaction. Two replicas deleting the
same account concurrently get two different new values and the row never moves
backwards — the property `ports/account_state.py` requires, enforced by SQLite
rather than by an application read-modify-write that a second connection can
interleave with.
"""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from emailcheck.ports.account_state import INITIAL_GENERATION, AccountStateError

#: Bumped when the shape changes. A file written by another shape is refused at
#: start rather than migrated, on this package's convention.
#:
#: Version 2 adds the authority identity. A version 1 file has no identity for a
#: data store to have been bound to, so it is refused rather than adopted.
SCHEMA_VERSION: Final = 2

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS account_state_schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS account_state (
    account    TEXT PRIMARY KEY,
    generation INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS account_authority (authority_id TEXT NOT NULL);
"""

#: How many random bytes name one authority. A name, not a secret: it identifies
#: which deletion authority a data store was bound to and is compared for
#: equality, never used to authorize anything.
_AUTHORITY_BYTES: Final = 16

_AUTHORITY_SELECT: Final = "SELECT authority_id FROM account_authority"
_AUTHORITY_INSERT: Final = "INSERT INTO account_authority (authority_id) VALUES (?)"

_VERSION: Final = "SELECT version FROM account_state_schema_version"
_VERSION_TABLE: Final = (
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'account_state_schema_version'"
)
_RECORD_VERSION: Final = "INSERT INTO account_state_schema_version (version) VALUES (?)"

_SELECT: Final = "SELECT generation FROM account_state WHERE account = ?"

#: **One statement, so it is one transaction.** A read-then-write in Python
#: would let a second replica's deletion land between the two and be lost, which
#: is a generation that never advanced and a worker that keeps its permission.
#: `RETURNING` gives the new value back without a second read that could observe
#: a third replica's advance instead of this one's.
_ADVANCE: Final = """
INSERT INTO account_state (account, generation) VALUES (?, ?)
ON CONFLICT (account) DO UPDATE SET generation = account_state.generation + 1
RETURNING generation
"""


class AccountStateSchemaError(AccountStateError):
    """The database on disk was written by a different schema version."""


@dataclass(frozen=True, slots=True)
class SQLiteAccountStateStore:
    """One table, parameterized SQL, and an atomic increment."""

    path: Path

    def initialize(self) -> None:
        """Create the schema, or refuse a file this build cannot write."""
        with self._connect() as connection:
            existing = self._stored_version(connection)
            if existing is not None and existing != SCHEMA_VERSION:
                raise AccountStateSchemaError(
                    f"this store is schema version {existing}, "
                    f"and this build writes {SCHEMA_VERSION}"
                )
            connection.executescript(_SCHEMA)
            if existing is None:
                connection.execute(_RECORD_VERSION, (SCHEMA_VERSION,))
            if connection.execute(_AUTHORITY_SELECT).fetchone() is None:
                connection.execute(_AUTHORITY_INSERT, (secrets.token_hex(_AUTHORITY_BYTES),))

    def authority_id(self) -> str:
        """Which deletion authority this file is. Stable for the file's lifetime.

        Synchronous, because the only caller is composition deciding whether a
        data store may be opened at all, and a start-up check that has to be
        awaited invites being skipped. Every persistent store that can hold
        account-owned rows is bound to this value once and refuses to open under
        another — the configuration the focused review broke, where two replicas
        shared one `jobs.db` while trusting different deletion authorities.
        """
        with self._connect() as connection:
            row = connection.execute(_AUTHORITY_SELECT).fetchone()
        if row is None:
            raise AccountStateError("this account state has no authority identity")
        return str(row[0])

    @staticmethod
    def _stored_version(connection: sqlite3.Connection) -> int | None:
        if connection.execute(_VERSION_TABLE).fetchone() is None:
            return None
        row = connection.execute(_VERSION).fetchone()
        return None if row is None else int(row[0])

    async def generation(self, account: str) -> int:
        return await asyncio.to_thread(self._generation, account)

    async def advance(self, account: str) -> int:
        return await asyncio.to_thread(self._advance, account)

    async def permits(self, account: str, generation: int) -> bool:
        """Exact equality with the current generation, and nothing looser.

        Not `generation >= current`, which would let a stale worker through
        whenever a deletion had not happened yet *and* would silently accept a
        value from the future; not "no row means yes", which would accept any
        generation at all for an account nobody has deleted. An unknown account
        is at `INITIAL_GENERATION` and only work carrying that value proceeds.
        """
        return await asyncio.to_thread(self._generation, account) == generation

    # --- the blocking half, in a worker thread ------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, isolation_level="DEFERRED")
        with closing(connection), connection:
            yield connection

    def _generation(self, account: str) -> int:
        with self._connect() as connection:
            row = connection.execute(_SELECT, (account,)).fetchone()
        return INITIAL_GENERATION if row is None else int(row[0])

    def _advance(self, account: str) -> int:
        with self._connect() as connection:
            row = connection.execute(_ADVANCE, (account, INITIAL_GENERATION + 1)).fetchone()
        if row is None:  # pragma: no cover - `RETURNING` always yields a row here
            raise AccountStateError("the account generation could not be advanced")
        return int(row[0])
