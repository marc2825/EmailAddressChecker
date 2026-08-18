"""The fence a persistent store holds over its own account-owned rows.

**A pre-check is not a fence, and the difference is a transaction.** The first
Remediation C design read the deletion generation from `accounts.db`, returned,
and then wrote `jobs.db` in a later transaction. The focused review paused a
replica in that gap and recreated a job row, a cached verdict, and an
idempotency binding after the operator had been told the deletion was complete.
Nothing about a second read would have helped: the same gap reopens after it.

So the generation moves **into every store that holds account-owned rows**, and
the write itself becomes conditional on it inside one `BEGIN IMMEDIATE`
transaction:

```text
BEGIN IMMEDIATE                     the write lock, before anything is read
  SELECT generation FROM account_fence WHERE account = ?
  mismatch -> refuse, write nothing
  INSERT/UPDATE the account-owned row
COMMIT
```

Deletion raises that same fence, in the same database, in its own write
transaction, **before** removing rows. SQLite serializes the two: either the
writer commits first and the deletion then removes what it wrote, or the
deletion's fence commits first and the writer's transaction reads the new
generation and refuses. The sequence the review reproduced — deletion reports
complete, then a stale write lands — is not reachable, because both operations
contend for one database's write lock rather than coordinating through a third
file they can both read stale.

**No cross-database atomicity is claimed.** `accounts.db`, `jobs.db`, and
`verdicts.db` are three files and cannot commit together. Each store fences
*itself*; `ports/account_state.py` remains the authority that says what the
current generation *is*, and `application/jobs.py` still refuses a write when it
cannot read that authority. The fence closes the gap between decision and write;
the authority decides.

**The authority binding is here for the same reason.** A fence is only worth the
identity it is measured against, and the review found two replicas able to share
one `jobs.db` while pointing at different `accounts.db` files — a deletion in one
authority invisible to a writer trusting the other. Each store therefore records
which authority it was bound to, once, and refuses at start-up to open under a
different one.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from emailcheck.ports.account_state import INITIAL_GENERATION

#: The two tables every fenced store adds to its own schema.
#:
#: In the data store rather than beside it: a fence in another file is a fence
#: another transaction can overtake, which is the defect this module exists to
#: remove.
FENCE_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS account_fence (
    account    TEXT PRIMARY KEY,
    generation INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS store_authority (authority_id TEXT NOT NULL);
"""

#: Read inside the caller's write transaction, never before it.
_FENCE_SELECT: Final = "SELECT generation FROM account_fence WHERE account = ?"

#: **`max`, so a fence never falls.** A deletion that arrives out of order, a
#: retry of an older one, or a replica carrying a stale generation must not be
#: able to re-authorize work the current generation already refuses.
_FENCE_RAISE: Final = """
INSERT INTO account_fence (account, generation) VALUES (?, ?)
ON CONFLICT (account) DO UPDATE
    SET generation = max(account_fence.generation, excluded.generation)
RETURNING generation
"""

_AUTHORITY_SELECT: Final = "SELECT authority_id FROM store_authority"
_AUTHORITY_INSERT: Final = "INSERT INTO store_authority (authority_id) VALUES (?)"

#: Taken before the first read, so the whole check-and-write is one write
#: transaction. A deferred `BEGIN` would let the fence read succeed and the
#: write contend afterwards, which is the gap in miniature.
BEGIN_IMMEDIATE: Final = "BEGIN IMMEDIATE"


class AccountAuthorityError(RuntimeError):
    """This store was bound to a different account-state authority.

    Raised at start-up rather than answered, because every alternative is worse:
    a store that silently accepts a second authority is a store whose deletions
    are invisible to half the replicas writing to it, and the operator finds out
    when someone's erased data comes back.
    """


def fenced_generation(connection: sqlite3.Connection, account: str) -> int:
    """This account's generation *in this store*, read inside the caller's transaction.

    `INITIAL_GENERATION` when no row exists, so "never deleted" and "generation
    zero" are one answer and no caller has to decide what a missing row means —
    the rule `ports/account_state.py` already sets.
    """
    row = connection.execute(_FENCE_SELECT, (account,)).fetchone()
    return INITIAL_GENERATION if row is None else int(row[0])


def raise_fence(connection: sqlite3.Connection, account: str, generation: int) -> int:
    """Move this store's fence for `account` to `generation`. Returns the value held.

    Called by account deletion before it removes anything, in this store's own
    write transaction. Monotonic: passing an older generation leaves the newer
    one in place.
    """
    row = connection.execute(_FENCE_RAISE, (account, generation)).fetchone()
    if row is None:  # pragma: no cover - `RETURNING` always yields a row here
        raise sqlite3.DatabaseError("the account fence could not be raised")
    return int(row[0])


def bind_authority(connection: sqlite3.Connection, authority_id: str) -> str:
    """Tie this store to one account-state authority, or refuse to open.

    Called once per store per start-up, from composition. A store file created
    by this build records the authority it was first opened under; every later
    open must present the same one.

    **A missing binding is not "whatever is configured now".** It cannot occur
    on a file this build created — the row is written when the schema is — so a
    file that reaches here without one was written by something else, and
    adopting it would be exactly the configuration mistake this check exists to
    catch. Older files are refused earlier still, by each store's schema-version
    rule, which is where a deliberate migration belongs.
    """
    row = connection.execute(_AUTHORITY_SELECT).fetchone()
    if row is None:
        connection.execute(_AUTHORITY_INSERT, (authority_id,))
        return authority_id
    held = str(row[0])
    if held != authority_id:
        raise AccountAuthorityError(
            "this store is bound to a different account-state authority; "
            "a deletion recorded by one authority is invisible to the other"
        )
    return held
