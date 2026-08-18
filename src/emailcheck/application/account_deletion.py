"""Erasing one account, across every store that holds anything of theirs.

`docs/privacy.md` section 7 promises account-requested deletion and
`docs/runbooks/privacy-deletion.md` describes an operator carrying it out. The
runbook's steps were manual and there was no production operation behind them:
the final system audit found the promise implemented nowhere. This is the
operation.

**One call, every store.** An operator who has to remember five deletion methods
will one day remember four, and the one they forget is the one nobody notices —
so the orchestration is here rather than in a runbook. The stores it covers are
exactly the ones that hold account-owned records:

| Store | What goes |
|---|---|
| `VerdictStore` | every cached verdict for the account, under **every** dataset fingerprint |
| `JobStore` | every job: binding, result projection, retry and admission state |
| `BatchStore` | every batch, its rows, its retained plaintext, and its artifact |
| `JobService` registry | the in-process copies of the above |

**Deletion is by owner, never by target.** Every one of those stores keeps an
account identifier beside the record precisely so that "everything belonging to
A" is a `WHERE` clause. Inferring ownership from a target would delete a row
belonging to whoever else checked the same mailbox.

**This is logical deletion.** Rows are removed. SQLite free pages, the
write-ahead log, and any backup taken beforehand are outside what this project
touches, and `docs/privacy.md` says so rather than this module implying
otherwise.

**The authority, then the fences, then the stores — in that order.**

```text
AccountStateStore.advance   the authority: G -> G+1, durable, cross-replica
JobStore.fence              that value into jobs.db,     in its own transaction
VerdictStore.fence          that value into verdicts.db, in its own transaction
delete rows                 only in stores whose fence went up
```

`AccountStateStore` says what the current generation *is*, and work carries the
generation it was admitted under. That much was true before, and it was not
enough: the check happened in one database and the write in another, so a
replica paused between them recreated a job row, a cached verdict, and an
idempotency binding after this report had already said `complete`. The focused
review reproduced all three.

So the generation also moves **into each store being emptied**, where every
write already contends for that database's write lock. A stale write either
commits before the fence and is deleted below, or waits for it and is refused —
see `adapters/storage/account_fence.py`. The fence is raised in its own
transaction so it stays up even if the cleanup behind it fails: a deletion an
operator must retry is still a deletion no stale replica can undo.

A store whose fence cannot be raised is **not emptied**. Removing rows that a
stale replica may put back is worse than telling an operator which store to
retry, so that store is named in `failed_stores` and left alone.

The account suspension and `JobService`'s in-process tombstone remain, and are
**local cleanup and latency rather than the authority**: each lives in one
process's memory, and a second replica sees neither.

**No cross-store transaction exists and none is claimed.** Three SQLite files
and one in-memory registry cannot commit together — which is exactly why each
store fences itself rather than trusting a value read from another file. Each
store is attempted independently, failures are named, and the report says
plainly whether the account is gone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import JobService
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.domain.admin import check_subject
from emailcheck.ports.account_state import AccountStateStore
from emailcheck.ports.batch_store import BatchStore
from emailcheck.ports.job_store import JobStore
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink


@dataclass(frozen=True, slots=True)
class AccountDeletionReport:
    """What one deletion removed, and whether the account is actually gone.

    Bounded counts and category names. No address, no job identifier, no result,
    no path, no idempotency key: a deletion report is read by an operator and
    written to an audit trail, and a report that carried the data it deleted
    would be a copy of it.
    """

    #: Cached verdicts removed, across every dataset fingerprint and ruleset.
    verdicts_removed: int = 0
    #: Persisted jobs removed, with their bindings and result projections.
    jobs_removed: int = 0
    #: Batches removed, with their rows, retained plaintext, and artifacts.
    batches_removed: int = 0
    #: Registry entries and idempotency bindings dropped from this process.
    memory_records_removed: int = 0
    #: Which stores failed, in this project's own vocabulary. Never an
    #: exception message, a query, or a filesystem path.
    failed_stores: tuple[str, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Whether every store in scope actually reported success.

        The field an operator reads, and the reason `failed` is not a bare
        boolean: "we tried" and "it is gone" are different statements, and
        `docs/privacy.md` promises the second one.
        """
        return not self.failed_stores

    @property
    def total_removed(self) -> int:
        return (
            self.verdicts_removed
            + self.jobs_removed
            + self.batches_removed
            + self.memory_records_removed
        )


@dataclass(frozen=True, slots=True)
class AccountDeletionService:
    """The operator-facing deletion operation. One account, every store.

    Every collaborator is optional because every deployment profile has a
    different set of them, exactly as `RetentionService` does: a deployment with
    no batch store has no batches to delete, and a deletion over nothing is a
    valid deletion that removes nothing.
    """

    admin: AdminControl
    operator: OperatorSink
    #: The durable cross-replica barrier. **The authority, and required.**
    #:
    #: `None` is a deployment that has none, and such a deployment cannot make
    #: the guarantee: `delete` refuses rather than emptying stores that another
    #: replica may refill. The focused review measured that exact sequence — one
    #: replica reporting `complete=True` while another wrote the account back —
    #: so "no barrier configured" is a refusal rather than a best effort.
    account_state: AccountStateStore | None = None
    cache: VerdictCache | None = None
    jobs: JobService | None = None
    job_store: JobStore | None = None
    batches: BatchStore | None = None

    async def delete(self, account: str) -> AccountDeletionReport:
        """Erase `account`. Suspends it first, then removes what it owns.

        **The suspension is part of the deletion rather than a courtesy.** A
        verification accepted while the stores are being emptied would write the
        account back the moment it finished, so new work is refused before
        anything is removed — through `AdminControl.suspend_account`, which is
        the existing switch for exactly that, with the audit trail it already
        keeps.

        Work already running in *this* process is handled by
        `JobService.forget_account`, which cancels what it can and, for anything
        already past cancellation, refuses the late write. Work running on
        another replica is handled by the durable generation raised above, and
        not by that call: a process-local tombstone lives in one process's
        memory, and the focused review demonstrated a second replica writing the
        account back through it.

        Never raises for a store failure. An operator needs the other stores
        emptied and a truthful report far more than they need an exception.
        """
        # Validated as an account subject, so the deletion key is the same
        # opaque identifier the switches and the stores use — and, as everywhere
        # else, an account is refused rather than normalized: two spellings
        # really are two accounts, and lowercasing one here would delete records
        # nobody asked about.
        subject = check_subject("account", account)

        # **The durable barrier goes up before a single row is deleted.**
        # Deleting first and raising it afterwards leaves a window in which a
        # late write from another replica lands between the two steps and is
        # kept — which is the race this whole mechanism exists to close. If it
        # cannot be raised, nothing is deleted: an operator who is told a
        # deletion failed can retry, and one who is told it succeeded while
        # another replica refills the stores cannot.
        if self.account_state is None:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR,
                    detail="account deletion: no durable account state",
                )
            )
            return AccountDeletionReport(failed_stores=("account_state",))
        try:
            generation = await self.account_state.advance(subject)
        except Exception:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR,
                    detail="account deletion: account state",
                )
            )
            return AccountDeletionReport(failed_stores=("account_state",))

        # **Then each store's own fence, still before a single row is removed.**
        # The generation above is the authority and lives in a third file; a
        # writer that read it and had not yet written could still land between
        # the deletion's steps, which is what the focused review measured. These
        # calls move the new generation *into* the stores being emptied, where
        # every write already contends for the same database's write lock — so
        # a stale write either commits before the fence and is deleted below, or
        # waits for it and is refused. A store whose fence cannot be raised is
        # not emptied at all: erasing rows a stale replica may refill is worse
        # than telling an operator which store to retry.
        failures: list[str] = []
        fenced = await self._raise_fences(failures, subject, generation)

        # Local, and after the durable barrier rather than instead of it: this
        # refuses new work in *this* process a round trip sooner and cleans up
        # what this process holds. It is not what makes the deletion safe.
        self.admin.suspend_account(subject)

        memory = 0
        if self.jobs is not None:
            # Before the durable stores, so nothing in flight can land in a
            # store this operation has already emptied.
            memory = self.jobs.forget_account(subject)
        verdicts = (
            await self._attempt(failures, "verdicts", self._delete_verdicts, subject)
            if "verdicts" in fenced
            else 0
        )
        jobs = (
            await self._attempt(failures, "jobs", self._delete_jobs, subject)
            if "jobs" in fenced
            else 0
        )
        batches = (
            await self._attempt(failures, "batches", self._delete_batches, subject)
            if "batches" in fenced
            else 0
        )

        report = AccountDeletionReport(
            verdicts_removed=verdicts,
            jobs_removed=jobs,
            batches_removed=batches,
            memory_records_removed=memory,
            failed_stores=tuple(failures),
        )
        self.admin.record_deletion(removed=report.total_removed, failed=not report.complete)
        if failures:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR,
                    detail=f"account deletion: {', '.join(failures)}",
                )
            )
        return report

    async def _raise_fences(
        self, failures: list[str], account: str, generation: int
    ) -> frozenset[str]:
        """Move the new generation into each store, and name the ones that refused.

        Returns which stores are safe to empty. **A fence that could not be
        raised is not followed by a deletion**: the rows would go and the writes
        that recreate them would not be refused, which is the state an operator
        would be told was complete.

        Raised even when the fence and the deletion could have been one
        statement, because they are two decisions: the fence must hold whether
        or not the cleanup that follows it succeeds. `docs/privacy.md`'s promise
        survives a failed cleanup and a retry; it does not survive a lowered
        fence.
        """
        safe: set[str] = set()
        if self.cache is not None:
            try:
                await self.cache.fence_account(account, generation=generation)
                safe.add("verdicts")
            except Exception:
                failures.append("verdicts")
        else:
            safe.add("verdicts")
        if self.job_store is not None:
            try:
                await self.job_store.fence(account=account, generation=generation)
                safe.add("jobs")
            except Exception:
                failures.append("jobs")
        else:
            safe.add("jobs")
        if self.batches is not None:
            # The third store, once a deployment composes one. Remediation C
            # left this out because no deployment held a batch store; a batch
            # row recreated after a deletion is the account's data exactly as a
            # job row is, so it gets the same fence and the same ordering.
            try:
                await self.batches.fence(account=account, generation=generation)
                safe.add("batches")
            except Exception:
                failures.append("batches")
        else:
            safe.add("batches")
        return frozenset(safe)

    async def _attempt(
        self,
        failures: list[str],
        name: str,
        operation: object,
        account: str,
    ) -> int:
        """One store's deletion. A failure is named and does not propagate.

        Per store rather than one handler for all of them, on
        `RetentionService`'s precedent and for its reason: one unreachable
        database must not leave the other two holding the account's data while
        the report says only "failed".
        """
        try:
            return await operation(account)  # type: ignore[operator, no-any-return]
        except Exception:
            failures.append(name)
            return 0

    async def _delete_verdicts(self, account: str) -> int:
        if self.cache is None:
            return 0
        return await self.cache.forget_account(account)

    async def _delete_jobs(self, account: str) -> int:
        if self.job_store is None:
            return 0
        return await self.job_store.delete_account(owner=account)

    async def _delete_batches(self, account: str) -> int:
        if self.batches is None:
            return 0
        return await self.batches.delete_account(account=account)
