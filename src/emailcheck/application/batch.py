"""The batch scheduler: fair over destinations, bounded in workers, resumable, complete.

ADR 0018. This is **orchestration over verifications that
already
exist** — the prompt's scheduler section says *reuse all existing budgets* and
*no increase in per-destination rate*, and the way to keep both is to own no
verification logic at all.

**Every row goes through `JobService.submit`.** Not through the verification
service, not through the probe, and not through a transport: the Phase 6 job
layer is the highest reviewed seam, and going through it means a batch row
inherits — without remembering to — the kill switch, the Phase 7 caller and
destination budgets, admission, **the one process-wide verdict cache**, the
destination policy, TLS, the sender identity, the one-`RCPT TO` bound, and
section 14's single retry. A batch of ten thousand rows is ten thousand ordinary
submissions, paced by the same limiter as ten thousand single checks. An
inspection test pins the dependency direction.

**Fairness is round-robin over exchangers, then over domains within one.**
ADR 0018: *fair scheduling by target domain and MX*. Those are
two
different bounds, and a scheduler that keeps only the first satisfies the prompt
by half: twenty domains behind one provider are twenty domain queues and one
destination, so per-domain rotation alone lets that provider hold every worker
while every per-domain rule is satisfied.

The exchanger a row will reach is **learned from the ordinary pipeline**, never
resolved here. `VerificationOutcome.scheduling_key` is the host Phase 2 already
picked and Phase 7 is already charged for, carried out through `SubmitOutcome`;
a batch resolving DNS itself would be a second routing path with none of Phase
2's caching, ordering, or destination policy, and a gap between what it learned
and what the probe reaches.

Neither rotation changes any **rate**. Phase 4's per-domain pacing is untouched
and is still what decides how fast a destination is approached; this decides
only which row is offered next. `docs/architecture.md` records that the limiter
partitions by domain alone, so there is no MX rate bound here to preserve or to
weaken — which is also why rotation is the only place MX fairness could come
from.

**Bounded workers, not one task per row.** A fixed set of `max_in_flight`
workers pulls from the scheduler. Creating fifty thousand coroutines and holding
them behind a semaphore would move the growth rather than stop it — the shape
`application/admission.py` already refuses for its queue.

**Every selected row ends in an explicit state, and the state is persisted.**
ADR 0018 asks for *resumable job state* and a *restart/resume*
test, and an in-process registry answers neither. Row state, the child job
identifier, and a deterministic idempotency handle go to a `BatchStore` before
and after each submission, so a fresh service over the same store continues
rather than starts again — and the handle is what makes the dangerous case
safe: a process that stopped between handing a row to the job service and
recording the outcome re-submits under the same handle and **recovers the
existing job** instead of starting a second verification.

**Nothing here decides a status.** A row's answer is the `Verdict` Phase 5
produced for that address, read through the same public allowlist an API
response uses. This module names no `Status`.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from emailcheck.application.batch_csv import (
    BatchInput,
    BatchReportRow,
    parse_batch_csv,
    render_batch_csv,
)
from emailcheck.application.jobs import CheckJob, JobService
from emailcheck.domain.batch import (
    RESULT_MEDIA_TYPE,
    RESUMABLE_ROW_STATES,
    BatchError,
    BatchId,
    BatchLimits,
    BatchRowState,
    BatchSettings,
)
from emailcheck.domain.job import IdempotencyKey, JobId, JobState
from emailcheck.domain.principal import Principal
from emailcheck.ports.account_state import INITIAL_GENERATION, AccountStateStore
from emailcheck.ports.batch_store import BatchArtifact, BatchStore, StoredBatch, StoredBatchRow
from emailcheck.ports.clock import Clock
from emailcheck.ports.random_source import RandomSource
from emailcheck.security.identifiers import correlation_digest

__all__ = ["BatchRefused", "BatchReport", "BatchService", "FairRotation"]

#: How many bytes of entropy a `BatchId` is made of. The `JobId` figure, for the
#: same reason ADR 0014 gives: an identifier that leaks is survivable because
#: ownership is checked anyway, and an identifier that is guessable is not.
_IDENTIFIER_BYTES = 16

#: What a per-row idempotency handle is prefixed with, so an operator reading a
#: binding can tell a batch's handle from a caller's own key.
_IDEMPOTENCY_PREFIX = "b10-"

#: The group a domain belongs to before its exchanger is known, and the group it
#: joins afterwards. Both prefixed, so a provisional per-domain group can never
#: collide with a real exchanger's name.
_UNKNOWN_GROUP = "domain:"
_MX_GROUP = "mx:"


class BatchRefused(Exception):
    """This batch may not run.

    Not a `TimeoutError` and not an `OSError`, on the precedent every refusal in
    this project sets — and never a `Verdict`: a batch that did not run is not a
    fact about anybody's mailbox.
    """


@dataclass(frozen=True, slots=True)
class _Pending:
    """One row waiting to be submitted, with everything needed to submit it."""

    number: int
    domain: str
    target_digest: str
    idempotency: str
    #: The submitted text. `repr=False`: a batch is a list of addresses, and the
    #: scheduler's own values are the last place one could leak from.
    submitted: str = field(repr=False, default="")
    #: Whether this row still has to be claimed. A row already `claimed` was
    #: taken by a process that did not finish; re-driving it is safe because its
    #: idempotency handle is already persisted and `JobService.submit` answers
    #: with the existing job, and it must **not** be claimed again because the
    #: claim is what excludes a second live replica.
    unclaimed: bool = True


@dataclass(slots=True)
class FairRotation:
    """Rows to submit, grouped by exchanger, then by domain, served in turn.

    Pure and synchronous, so fairness is testable without a scheduler, a clock,
    or a socket: hand it rows, ask it for the order, and read the answer.

    **Two levels, because the prompt names two.** The outer rotation is over
    exchangers and the inner one over the domains sharing each — so one busy
    provider cannot take every worker, *and* one busy domain behind it cannot
    take that provider's whole share. Behind both are hard caps, because a batch
    that is entirely one domain has nothing to rotate to and the property must
    still hold.

    A domain whose exchanger is not yet known is its own provisional group. That
    is not a special case, it is the first row of every domain: the key is
    *learned* from the pipeline's answer to that row, and `learn` then moves the
    domain's remaining rows into the real group. A new group is appended at the
    back rather than inserted, so learning never lets a domain jump the queue.
    """

    _groups: OrderedDict[str, OrderedDict[str, deque[_Pending]]] = field(
        default_factory=OrderedDict
    )
    _group_of: dict[str, str] = field(default_factory=dict)
    _in_flight_domain: dict[str, int] = field(default_factory=dict)
    _in_flight_group: dict[str, int] = field(default_factory=dict)
    _pending: int = 0

    def add(self, row: _Pending) -> None:
        group = self._group_of.setdefault(row.domain, _UNKNOWN_GROUP + row.domain)
        self._groups.setdefault(group, OrderedDict()).setdefault(row.domain, deque()).append(row)
        self._pending += 1

    def learn(self, domain: str, scheduling_key: str | None) -> None:
        """Record the exchanger a domain's rows will reach, and regroup them.

        Called with whatever the ordinary pipeline reported for a row of this
        domain. `None` — a domain with nowhere to connect — leaves the domain in
        its own group, which is correct: it shares no destination with anything.
        """
        if scheduling_key is None:
            return
        group = _MX_GROUP + scheduling_key
        current = self._group_of.get(domain)
        if current == group:
            return
        self._group_of[domain] = group
        if current is None:
            return
        holding = self._groups.get(current)
        queue = None if holding is None else holding.pop(domain, None)
        if holding is not None and not holding:
            del self._groups[current]
        joined = self._groups.setdefault(group, OrderedDict())
        if queue:
            joined[domain] = queue

    def __len__(self) -> int:
        return self._pending

    def take(self, *, limits: BatchLimits) -> _Pending | None:
        """The next row that may be submitted, or `None` if everything is capped.

        `None` is not "empty": it means the scheduler must wait for something in
        flight to finish. The two are different and a caller that confused them
        would spin.
        """
        for _ in range(len(self._groups)):
            group, domains = next(iter(self._groups.items()))
            # Rotate first, so a group that cannot be served now goes to the
            # back rather than being examined again on the next pass.
            self._groups.move_to_end(group)
            if not domains:
                del self._groups[group]
                continue
            if self._in_flight_group.get(group, 0) >= limits.max_in_flight_per_mx:
                continue
            taken = self._take_within(group, domains, limits=limits)
            if taken is not None:
                return taken
        return None

    def _take_within(
        self,
        group: str,
        domains: OrderedDict[str, deque[_Pending]],
        *,
        limits: BatchLimits,
    ) -> _Pending | None:
        for _ in range(len(domains)):
            domain, queue = next(iter(domains.items()))
            domains.move_to_end(domain)
            if not queue:
                del domains[domain]
                continue
            if self._in_flight_domain.get(domain, 0) >= limits.max_in_flight_per_domain:
                continue
            row = queue.popleft()
            self._pending -= 1
            self._in_flight_domain[domain] = self._in_flight_domain.get(domain, 0) + 1
            self._in_flight_group[group] = self._in_flight_group.get(group, 0) + 1
            if not queue:
                del domains[domain]
            return row
        return None

    def group_for(self, domain: str) -> str:
        return self._group_of.get(domain, _UNKNOWN_GROUP + domain)

    def release(self, row: _Pending, *, group: str) -> None:
        _decrement(self._in_flight_domain, row.domain)
        _decrement(self._in_flight_group, group)

    def drain(self) -> list[_Pending]:
        """Everything still waiting, for a cancelled batch to account for."""
        remaining = [
            row for domains in self._groups.values() for queue in domains.values() for row in queue
        ]
        self._groups.clear()
        self._pending = 0
        return remaining


def _decrement(counter: dict[str, int], key: str) -> None:
    held = counter.get(key, 0)
    if held <= 1:
        counter.pop(key, None)
    else:
        counter[key] = held - 1


@dataclass(frozen=True, slots=True)
class BatchReport:
    """One batch's outcome. Row-level, and complete.

    ADR 0018 Output: *row-level status/reasons/risk flags* and
    *summary counts*. The rows are in **input order** regardless of the order
    they were submitted or completed in, because a report a submitter cannot
    line up against their own file is one they cannot act on.
    """

    batch_id: BatchId
    #: The account this belongs to. Ownership is checked before a caller sees
    #: this object, and it is carried so the check has something to check.
    account: str
    submitted_at: datetime
    finished_at: datetime
    #: How many rows the input carried. The denominator every count balances
    #: against.
    input_rows: int
    #: Rows the file held that were not rows at all — blank lines, missing
    #: cells. Counted so the report balances against the *file*.
    skipped_rows: int
    rows: tuple[BatchReportRow, ...]
    cancelled: bool = False
    #: Whether every submitted row's child job has reached a terminal state.
    #:
    #: A batch stops *submitting* long before its verifications stop *running*,
    #: and a report rendered in between is a submission report rather than a
    #: deliverability result. Labelled rather than waited for: waiting would put
    #: a batch back inside the synchronous request Phase 6 removed.
    complete: bool = False

    def __post_init__(self) -> None:
        if len(self.rows) != self.input_rows:
            # Phase 8's invariant, applied to a batch: a row that was selected
            # and then vanished is the hole this refuses to leave.
            raise BatchError(f"{self.input_rows} rows were read and {len(self.rows)} are reported")

    @property
    def state_summary(self) -> dict[str, int]:
        """Where every row ended up. Sums to `input_rows`."""
        counts = {state.value: 0 for state in BatchRowState}
        for row in self.rows:
            counts[row.row_state.value] += 1
        return counts

    @property
    def status_summary(self) -> dict[str, int]:
        """The deliverability distribution, over rows that produced a verdict.

        Row states are not statuses and never appear here — the separation
        Phase 8 drew for its execution states, applied to rows.
        """
        counts: dict[str, int] = {}
        for row in self.rows:
            if row.status is not None:
                counts[row.status] = counts.get(row.status, 0) + 1
        return dict(sorted(counts.items()))

    def as_json_object(self) -> dict[str, object]:
        return {
            "batch_id": self.batch_id.value,
            "submitted_at": self.submitted_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "input_rows": self.input_rows,
            "skipped_rows": self.skipped_rows,
            "cancelled": self.cancelled,
            "complete": self.complete,
            "state_summary": self.state_summary,
            "status_summary": self.status_summary,
        }


@dataclass(slots=True)
class BatchService:
    """Submit, resume, report on, cancel, and delete one authorized CSV batch."""

    #: The **Phase 6 job service**, and nothing lower. Every safety control this
    #: project has is reached through it, including the one verdict cache.
    jobs: JobService
    #: Where resumable state and the expiring result live.
    store: BatchStore
    clock: Clock
    random_source: RandomSource
    settings: BatchSettings
    correlation_key: bytes = field(repr=False, default=b"")
    #: Batches cancelled in this process, so a running scheduler stops promptly
    #: rather than at its next persistence read. The persisted flag is the
    #: authority; this is the fast path. `repr=False`, like everything else here
    #: that could name a caller's work.
    #: The durable deletion authority, when this deployment has one.
    #:
    #: Optional exactly as it is for `RetentionService`: a deployment may run a
    #: batch stack over an in-memory store with no deletion contract at all. When
    #: it is present, every account-owned batch write carries the generation the
    #: batch was admitted under and the store refuses it in the same transaction
    #: once a deletion has raised the fence — the model
    #: `adapters/storage/account_fence.py` states, applied to the third store.
    account_state: AccountStateStore | None = None
    _cancelled: set[str] = field(default_factory=set, repr=False)
    #: The generation each live batch was admitted under, by batch id.
    _generations: dict[str, int] = field(default_factory=dict, repr=False)

    # --- submission ---------------------------------------------------------

    async def submit(self, content: bytes, *, principal: Principal) -> BatchReport:
        """Accept one CSV batch and run it, or explain why it did not start.

        **The two gates come before the file is read.** This takes bytes rather
        than a parsed input for exactly that reason: parsing is work a caller
        can ask for, and an unapproved account must not be able to ask for it.
        ADR 0018's preconditions are account review and a
        documented lawful purpose, neither of which authentication establishes.
        """
        account = self._authorize(principal)
        parsed = parse_batch_csv(content, limits=self.settings.limits)
        started = self.clock.now()
        batch_id = BatchId(self.random_source.token(_IDENTIFIER_BYTES))
        # **The fencing token is taken here, at admission, and then persisted.**
        # Every later write for this batch presents this value rather than
        # asking what the generation is now — a scheduler that re-read it after
        # a deletion would launder its own stale work into current work.
        generation = await self._admitted_generation(account)
        record = StoredBatch(
            batch_id=batch_id.value,
            account=account,
            created_at=started,
            expires_at=started + timedelta(seconds=self.settings.result_retention_seconds),
            input_rows=len(parsed.rows),
            skipped_rows=parsed.skipped,
            generation=generation,
            rows=self._initial_rows(parsed, batch_id=batch_id, account=account),
        )
        if not await self.store.save_batch(record, expected_generation=generation):
            raise BatchRefused("this account is not accepting new work")
        return await self._drive(record, principal=principal)

    async def resume(self, batch_id: BatchId, *, principal: Principal) -> BatchReport | None:
        """Continue this account's batch after a restart. `None` if there is none.

        A cancelled or expired batch is not resumed, terminal rows are not
        touched, a row naming a job is never submitted again, and a row that was
        *claimed* is re-submitted under its recorded handle — which recovers the
        existing job rather than starting a second verification.
        """
        account = self._authorize(principal)
        record = await self.store.load_batch(batch_id.value, account=account, now=self.clock.now())
        if record is None:
            return None
        if record.cancelled:
            # A restart that resumed a cancelled batch would make persistence
            # the way to undo a cancellation.
            self._cancelled.add(batch_id.value)
        return await self._drive(record, principal=principal)

    # --- reads, cancellation, deletion ---------------------------------------

    async def report(self, batch_id: BatchId, *, principal: Principal) -> BatchReport | None:
        """This account's batch, refreshed from its child jobs, or nothing.

        A batch belonging to another account answers exactly what an unknown
        identifier does — the Phase 6 rule, for the same reason: a distinct
        answer would confirm the identifier is real. An expired one answers the
        same, because expiry is a predicate of the read rather than a filter
        applied afterwards.

        Rebuilding here is what **finalizes** a result: a batch whose jobs were
        still running when it was submitted becomes complete the first time it
        is read after they finish, and the stored artifact is replaced then.
        """
        now = self.clock.now()
        record = await self.store.load_batch(
            batch_id.value, account=principal.rate_limit_account, now=now
        )
        if record is None:
            return None
        report = await self._compose(record, principal=principal, finished_at=now)
        await self._store_artifact(report, now=now)
        return report

    async def result(self, batch_id: BatchId, *, principal: Principal) -> BatchArtifact | None:
        """The expiring downloadable result, for its owner, before it expires.

        ADR 0018 Output. **The principal is a parameter, not a
        token**: an anonymous download handle would be the public anonymous
        surface the prompt's non-goals name, arrived at from the other end.
        """
        return await self.store.load_artifact(
            batch_id.value, account=principal.rate_limit_account, now=self.clock.now()
        )

    async def cancel(self, batch_id: BatchId, *, principal: Principal) -> bool:
        """Stop submitting new rows. Rows already handed over are the jobs' own.

        ADR 0018 asks for cancellation; Phase 6 owns what
        happens
        to a job that is already running, and this does not invent a second
        mechanism or a forceful socket termination nothing else guarantees.

        Every row that had not been submitted becomes `cancelled` explicitly and
        persistently, so a cancelled batch's report still balances and a restart
        finds nothing left to do.
        """
        now = self.clock.now()
        record = await self.store.load_batch(
            batch_id.value, account=principal.rate_limit_account, now=now
        )
        if record is None:
            return False
        self._cancelled.add(batch_id.value)
        await self.store.set_cancelled(batch_id.value, expected_generation=record.generation)
        await self.store.update_rows(
            batch_id.value,
            tuple(
                StoredBatchRow(
                    number=row.number,
                    state=BatchRowState.CANCELLED,
                    target_digest=row.target_digest,
                )
                for row in record.rows
                if row.state in RESUMABLE_ROW_STATES
            ),
        )
        return True

    async def delete(self, batch_id: BatchId, *, principal: Principal) -> bool:
        """Remove this account's batch: state, retained plaintext, and result.

        Deletes **no child job**. A job is Phase 6's record, is expired by
        Phase 7's retention, and may be shared with a single check through the
        cache — removing one here would delete somebody else's answer.
        """
        removed = await self.store.delete_batch(
            batch_id.value, account=principal.rate_limit_account
        )
        if removed:
            self._cancelled.discard(batch_id.value)
        return removed

    # --- the scheduler -------------------------------------------------------

    def _authorize(self, principal: Principal) -> str:
        account = principal.rate_limit_account
        if not self.settings.permits(account):
            raise BatchRefused(
                "batch submission is an operational permission this account does not hold"
            )
        return account

    async def _admitted_generation(self, account: str) -> int:
        """The account's generation now. `INITIAL_GENERATION` with no authority."""
        if self.account_state is None:
            return INITIAL_GENERATION
        return await self.account_state.generation(account)

    async def _drive(self, record: StoredBatch, *, principal: Principal) -> BatchReport:
        # The batch's own persisted token, never a fresh reading: a resume of a
        # batch admitted before a deletion must stay refused.
        self._generations[record.batch_id] = record.generation
        rotation = FairRotation()
        for row in record.rows:
            if row.state not in RESUMABLE_ROW_STATES:
                continue
            if row.submitted is None or row.target_digest is None or row.idempotency is None:
                # Retention cleared this row's input, so it can never be
                # submitted. Explicit, never absent: `docs/privacy.md` section
                # 3 expiring the plaintext is the policy working, and the row
                # records that it did not run.
                await self._persist(record.batch_id, row.number, BatchRowState.REFUSED)
                continue
            rotation.add(
                _Pending(
                    number=row.number,
                    domain=_domain_of(row.submitted),
                    target_digest=row.target_digest,
                    idempotency=row.idempotency,
                    submitted=row.submitted,
                    unclaimed=row.state is not BatchRowState.CLAIMED,
                )
            )

        await self._run(rotation, record, principal=principal)

        now = self.clock.now()
        refreshed = await self.store.load_batch(record.batch_id, account=record.account, now=now)
        report = await self._compose(refreshed or record, principal=principal, finished_at=now)
        await self._store_artifact(report, now=now)
        return report

    async def _run(
        self, rotation: FairRotation, record: StoredBatch, *, principal: Principal
    ) -> None:
        """A fixed worker set over the rotation. No task per row."""
        limits = self.settings.limits
        workers = min(limits.max_in_flight, max(1, len(rotation)))

        async def worker() -> None:
            while True:
                if record.batch_id in self._cancelled:
                    return
                row = rotation.take(limits=limits)
                if row is None:
                    if not len(rotation):
                        return
                    # Every destination is at its cap; yield rather than spin.
                    await asyncio.sleep(0)
                    continue
                group = rotation.group_for(row.domain)
                try:
                    await self._one(row, record, principal=principal, rotation=rotation)
                finally:
                    rotation.release(row, group=group)

        await asyncio.gather(*(worker() for _ in range(workers)))

        for row in rotation.drain():
            await self._persist(record.batch_id, row.number, BatchRowState.CANCELLED)

    async def _one(
        self,
        row: _Pending,
        record: StoredBatch,
        *,
        principal: Principal,
        rotation: FairRotation,
    ) -> None:
        """One row, through the ordinary job submission, write-ahead recorded.

        **The claim is written before the call**, and that ordering is the whole
        crash-safety argument: a process that stops between the two leaves a
        `claimed` row whose handle is already persisted, and a resume presenting
        that handle to `JobService.submit` is answered with the existing job.
        Recording afterwards would leave a row that looks untouched and a
        verification that is already running.

        Every failure mode of the submission is an **operational** row state,
        never a verdict: ADR 0013's rule, and the reason a full executor or an
        exhausted quota cannot become a claim about an address.
        """
        # **The store decides who schedules this row, not this loop.** Two
        # replicas driving one batch — a resume on each, an operator retry
        # beside a running scheduler — both reach here for the same row, and a
        # write that simply set `claimed` would let both submit the same
        # address. `claim_row` is one conditional write in one transaction, so
        # exactly one caller is told to proceed.
        # **`queued` only.** The transition is what excludes a second replica, so
        # the state a row is claimed *from* must be one it leaves: claiming a
        # `claimed` row would match for every caller and exclude nobody. A row
        # already `claimed` belongs to a process that did not finish, and is
        # re-driven below through its persisted idempotency handle rather than
        # taken again.
        if row.unclaimed and not await self.store.claim_row(
            batch_id=record.batch_id,
            number=row.number,
            schedulable=(BatchRowState.QUEUED.value,),
            claimed=BatchRowState.CLAIMED.value,
            expected_generation=record.generation,
        ):
            return
        await self._persist(record.batch_id, row.number, BatchRowState.CLAIMED, pending=row)
        try:
            outcome = await self.jobs.submit(
                row.submitted,
                principal=principal,
                idempotency_key=IdempotencyKey(row.idempotency),
            )
        except Exception:
            # A quota, the kill switch, admission, a full executor, an
            # idempotency conflict. Which one is operator information and is
            # already audited by Phase 7; the row records that it did not run.
            await self._persist(record.batch_id, row.number, BatchRowState.REFUSED, pending=row)
            return
        rotation.learn(row.domain, outcome.scheduling_key)
        # Written once and never moved: a row already naming a child keeps it,
        # so a second scheduler cannot repoint this row at a second
        # verification of the same address.
        await self.store.bind_child(
            batch_id=record.batch_id,
            number=row.number,
            job_id=outcome.job.id.value,
            expected_generation=record.generation,
        )
        await self._persist(
            record.batch_id,
            row.number,
            BatchRowState.SUBMITTED,
            pending=row,
            job_id=outcome.job.id.value,
        )

    async def _persist(
        self,
        batch_id: str,
        number: int,
        state: BatchRowState,
        *,
        pending: _Pending | None = None,
        job_id: str | None = None,
    ) -> None:
        """Write one row's state.

        A row that has reached a terminal state keeps no submitted text: it will
        never be submitted again, so retaining the plaintext would be keeping it
        for no purpose, which `docs/privacy.md` section 2's minimization
        refuses. The digest and the handle survive, because duplicate detection
        and idempotency both have to outlive the address.
        """
        terminal = state not in RESUMABLE_ROW_STATES
        await self.store.update_rows(
            batch_id,
            (
                StoredBatchRow(
                    number=number,
                    state=state,
                    target_digest=None if pending is None else pending.target_digest,
                    job_id=job_id,
                    idempotency=None if pending is None else pending.idempotency,
                    submitted=None if terminal or pending is None else pending.submitted,
                ),
            ),
            expected_generation=self._generations.get(batch_id),
        )

    # --- composing a report --------------------------------------------------

    def _initial_rows(
        self, parsed: BatchInput, *, batch_id: BatchId, account: str
    ) -> tuple[StoredBatchRow, ...]:
        """Every input row, as the state it starts in.

        Duplicate detection is on the Phase 7 correlation digest, and the
        duplicate keeps its own position so the report still lines up with the
        file. ADR 0018 Input: *duplicate detection by HMAC*.
        """
        rows: list[StoredBatchRow] = []
        seen: set[str] = set()
        for row in parsed.rows:
            if row.address is None:
                rows.append(StoredBatchRow(number=row.number, state=BatchRowState.REJECTED))
                continue
            digest = self._digest(row.address.address.hmac_material)
            if digest in seen:
                rows.append(
                    StoredBatchRow(
                        number=row.number,
                        state=BatchRowState.DUPLICATE,
                        target_digest=digest,
                    )
                )
                continue
            seen.add(digest)
            rows.append(
                StoredBatchRow(
                    number=row.number,
                    state=BatchRowState.QUEUED,
                    target_digest=digest,
                    idempotency=self._handle(batch_id, row.number, account, digest),
                    submitted=row.submitted,
                )
            )
        return tuple(rows)

    async def _compose(
        self, record: StoredBatch, *, principal: Principal, finished_at: datetime
    ) -> BatchReport:
        """Build the report from persisted rows and their current child jobs.

        Reads through `JobService.fetch` rather than `get`, because a resumed
        batch is exactly the caller that outlived the process which created its
        jobs: `get` sees one registry, and `fetch` sees the registry **and** the
        store behind it. A row whose job cannot be found either way keeps its
        row state and publishes no status.
        """
        rows: list[BatchReportRow] = []
        complete = True
        for stored in record.rows:
            job = None
            if stored.job_id is not None:
                job = await self.jobs.fetch(JobId(stored.job_id), principal=principal)
            if job is not None and not job.is_terminal:
                complete = False
            rows.append(_report_row(stored, job))
        return BatchReport(
            batch_id=BatchId(record.batch_id),
            account=record.account,
            submitted_at=record.created_at,
            finished_at=finished_at,
            input_rows=record.input_rows,
            skipped_rows=record.skipped_rows,
            rows=tuple(rows),
            cancelled=record.cancelled or record.batch_id in self._cancelled,
            complete=complete,
        )

    async def _store_artifact(self, report: BatchReport, *, now: datetime) -> None:
        await self.store.save_artifact(
            BatchArtifact(
                batch_id=report.batch_id.value,
                account=report.account,
                created_at=now,
                expires_at=now + timedelta(seconds=self.settings.result_retention_seconds),
                media_type=RESULT_MEDIA_TYPE,
                content=render_batch_csv(report.rows),
                complete=report.complete,
            ),
            expected_generation=self._generations.get(report.batch_id.value),
        )

    def _handle(self, batch_id: BatchId, number: int, account: str, digest: str) -> str:
        """The deterministic per-row idempotency identity.

        `docs/architecture.md` section 6 makes an active request's identity a
        key and a derived target HMAC. This derives the key half from the batch,
        the row's position, the account, and the target digest — so the same row
        of the same batch always presents the same handle, and no two rows,
        batches, or accounts share one. It is itself a digest, so the binding
        `application/jobs.py` keeps carries no address.
        """
        material = f"batch|{batch_id.value}|{number}|{account}|{digest}"
        return _IDEMPOTENCY_PREFIX + self._digest(material)

    def _digest(self, material: str) -> str:
        return correlation_digest(self.correlation_key, material)


def _report_row(stored: StoredBatchRow, job: CheckJob | None) -> BatchReportRow:
    """One report row, from persisted state and the child job's own answer.

    **A status is published only for a job that completed.** A submitted row
    whose verification is still running has no answer yet, and filling the
    status column from the passive half would export a partial result as a
    final one — ADR 0018's output is a deliverability report,
    and the column a reader acts on must not be filled in early.

    The submitted address is deliberately **not** carried. It is retained only
    while a row may still need submitting, so a report rendered after
    `forget_inputs` would carry it for some rows and not others; the row number
    is the stable handle a submitter matches against their own file, and it
    costs no retention.
    """
    state = None if job is None else job.state.value
    result = None if job is None or job.state is not JobState.COMPLETED else job.result
    return BatchReportRow(
        number=stored.number,
        row_state=stored.state,
        job_state=state,
        status=None if result is None else result.status,
        confidence=None if result is None else result.confidence,
        primary_reason=None if result is None else result.primary_reason,
        reason_codes=() if result is None else tuple(result.reasons),
        risk_flags=() if result is None else tuple(result.risk_flags),
        job_id=stored.job_id,
    )


def _domain_of(submitted: str) -> str:
    """The recipient domain, for grouping only.

    Deliberately not a parser: the row already parsed through
    `application/batch_csv.py`, and a second grammar here would be the "silently
    broaden accepted syntax" this project refuses. This splits on the last `@`
    of text that has already been accepted, and is used for nothing but which
    queue a row waits in.
    """
    return submitted.rpartition("@")[2].lower()
