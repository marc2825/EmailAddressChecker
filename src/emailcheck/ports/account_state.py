"""The durable fact that says whether an account's data may still be written.

**This port exists because a deletion that only one process knows about is not a
deletion.** `application/account_deletion.py` removed an account's rows and a
second live `JobService` — the arrangement Remediation A exists to support —
finished the work it was already holding and wrote the account straight back,
after the operator had been told the deletion was complete. The focused review
reproduced it: one replica reported `complete=True`, the other recreated the
job. The barrier was `JobService._deleted_accounts`, a per-instance `set`, and
`AdminState` is per-process too, so neither could be seen by the replica that
did the writing.

**A generation counter, not a tombstone.** `docs/privacy.md` section 7 describes
account-*requested* deletion, which is a customer erasing their data rather than
an account being banned: a later legitimate request must be able to create new
data. A tombstone would have to be lifted by hand, and an operator who forgets is
an account that silently stops working. A generation says the same thing without
that failure mode — work admitted under generation `G` may write while the
current generation is still `G`, deletion advances it to `G+1`, and everything
admitted before is refused while everything admitted afterwards proceeds
normally.

```text
admit work        →  read generation G, carry it
delete account    →  advance to G+1 durably, THEN delete rows
old worker writes →  its G is stale, refused
new request       →  reads G+1, writes normally
```

**Advancement comes first.** Deleting rows and then raising the barrier leaves a
window in which a late write lands between the two, which is the race this whole
port exists to close.

**Digests, counts, and nothing else.** An account identifier is not a mailbox —
`check_subject` refuses an `@` — and nothing here holds a target, a result, or a
key.
"""

from __future__ import annotations

from typing import Protocol

#: The generation every account starts at, before anything has been deleted.
#:
#: A concrete number rather than `None`, so "no row yet" and "generation zero"
#: are the same answer and no caller has to decide what a missing row means.
INITIAL_GENERATION = 0


class AccountStateError(RuntimeError):
    """The durable account barrier could not be read or advanced.

    Raised rather than answered, because every caller of this port is deciding
    whether it is safe to write somebody's data and there is no safe default for
    "I could not tell". `application/account_deletion.py` refuses to delete
    anything when it cannot raise the barrier first, and a writer that cannot
    check it does not write.
    """


class AccountStateStore(Protocol):
    """Where the deletion generation lives, shared by every replica."""

    async def generation(self, account: str) -> int:
        """This account's current generation. `INITIAL_GENERATION` if untouched.

        Read when work is admitted, and carried by that work until it writes.
        """
        ...

    async def advance(self, account: str) -> int:
        """Move this account to the next generation. Returns the new value.

        **Monotonic and atomic.** Two operators deleting one account at the same
        moment must not be able to move it backwards or to observe the same new
        value, so an implementation increments inside one transaction rather
        than reading, adding one, and writing.

        Idempotent in the sense that matters: calling it twice advances twice,
        and every generation older than the current one stays refused. What must
        never happen is a *decrease*, because that would re-authorize a worker
        whose data has already been deleted.
        """
        ...

    async def permits(self, account: str, generation: int) -> bool:
        """Whether work admitted at `generation` may still write.

        `True` only when `generation` is the account's current one. An
        implementation must not treat a missing row as permission for an
        arbitrary generation: an unknown account is at `INITIAL_GENERATION`, and
        anything else is stale.
        """
        ...
