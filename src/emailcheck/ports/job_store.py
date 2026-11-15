"""What a job must survive a process restart, and what it may never persist.

`docs/adr/0018-controlled-batch-execution.md` asks for *resumable job state* and a *restart/resume*
test. Phase 10 persisted the batch's own rows and found that insufficient: a
restarted process could recover a row's `JobId` and its handle, but the
`JobService` registry that turns a handle back into a job lived only in memory —
so the same deterministic handle was **forgotten**, and the resume started a
second verification for a row whose verification had already run. That is a
duplicate `RCPT TO` for one address arranged by restarting the process, which is
the pattern `docs/threat-model.md` lists first.

So idempotency and job state become a store, on the `ports/verdict_store.py`
precedent: the record type fixes what may be kept, the adapter adds nothing, and
a second implementation is a drop-in.

**Digests, published vocabulary, and nothing else.** No address, no caller-chosen
idempotency key, no correlation secret, no SMTP transcript, no `Evidence`
detail, and no exception text. The idempotency identity is stored as a *digest*
of the caller's key rather than the key: `IdempotencyKey` permits an `@` and
Phase 7's privacy corpus found `alice@example.test` used as one, so a store that
kept the key would keep an address.

**This is not a second job-state machine.** `domain/job.py` owns the six states
and the transition table; this records which one a job is in. Nothing here
decides a transition, and nothing reads this to decide a status.

**This is not a durable execution queue either, and the distinction is the whole
recovery policy.** What survives a process is *state*: identity, the idempotency
binding, the retry budget, the recipient-touch checkpoint, and a completed
result. What does not survive is the work. `ports/job_executor.py`'s only
implementation is in-process and dies with it, so a later process finding a
`pending` or `running` row has nothing to resume it on — and must not invent one.
`application/jobs.py` reconciles such a row into an operational failure rather
than re-enqueueing it, because "we do not know whether the `RCPT TO` went out"
resolves to *do not send another*.

**The idempotency claim is atomic or it is nothing.** An in-process lock cannot
see a second replica, and the final system audit measured one owner, one key,
one address across two `JobService` instances producing two jobs and two
probes. `claim_idempotency` is the operation that makes the decision once, in
the store, under a uniqueness constraint that survives both processes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from emailcheck.domain.job import JobAdmission, JobError, JobFailure, JobState
from emailcheck.domain.recipient_touch import RecipientTouch

#: Fields that must be a non-empty digest carrying no address.
DIGEST_FIELDS = ("idempotency_digest", "target_digest")


@dataclass(frozen=True, slots=True)
class StoredJob:
    """One persisted job: who owns it, where it got to, and what it answered.

    The result fields mirror `application/public_result.py`'s allowlist rather
    than a `Verdict`, exactly as `CheckJob` does — so there is no surface on
    which an `Evidence` detail could reach a restarted process by being added to
    a producer later.
    """

    job_id: str
    #: The authenticated account. Checked on every read, as `CheckJob.owner` is.
    owner: str
    state: JobState
    created_at: datetime
    updated_at: datetime
    #: Executor-handoff state, separate from the public six-state job model.
    admission: JobAdmission = JobAdmission.CLAIMED
    #: `docs/requirements.md` section 14's budget, carried so a restart cannot
    #: reset it. A job that has spent its one retry must not get another by
    #: outliving the process that granted it.
    retries_used: int = 0
    #: HMAC of `(owner, the caller's idempotency key)`. **Never the key.**
    idempotency_digest: str | None = None
    #: HMAC of the normalized target. What makes "same handle, different
    #: address" a conflict rather than a wrong answer, after a restart.
    target_digest: str | None = None
    #: Whether this operation may already have put its recipient on a wire.
    #:
    #: **The durable half of the one-`RCPT TO` bound, and the reason it survives
    #: a crash.** `application/jobs.py` writes `MAYBE_TOUCHED` *before* the
    #: active verification starts rather than after its answer arrives: a
    #: checkpoint taken on the way out would be missing for exactly the crash it
    #: exists to describe — the one between writing `RCPT TO` to a socket and
    #: learning what happened. So the record is conservative on entry and
    #: refined on exit, and a process that finds `MAYBE_TOUCHED` knows the
    #: operation must not be replayed even though it cannot know what happened.
    recipient_touch: RecipientTouch = RecipientTouch.NOT_TOUCHED
    failure: JobFailure | None = None
    #: The public projection, present only for a completed job — the same
    #: pairing `CheckJob` enforces, re-checked here because this is assembled
    #: from a row rather than from a value that already validated itself.
    status: str | None = None
    confidence: str | None = None
    primary_reason: str | None = None
    reasons: tuple[str, ...] = ()
    risk_flags: tuple[str, ...] = ()
    checks: tuple[tuple[str, str], ...] = ()
    ruleset: str | None = None
    #: The completed result's `no_message_data_sent`, persisted rather than
    #: assumed.
    #:
    #: **It was absent, and a reload rebuilt it as `True`.** That is
    #: `docs/requirements.md` section 2's promise to the user being made by a
    #: database read rather than by the code that ran the dialogue, which the
    #: final system audit found. Paired with `status`: present exactly when a
    #: result is, so neither a completed row can lose it nor an unfinished row
    #: can carry a safety assertion about work that has not happened.
    no_message_data_sent: bool | None = None
    #: The submitted text is **absent by design**. Recovering a job's identity
    #: and answer needs no address, and a store that held one would be a second
    #: plaintext location with its own retention argument to make.
    _no_plaintext: bool = field(default=True, repr=False)

    def __post_init__(self) -> None:
        for name in ("job_id", "owner"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise JobError(f"a stored job needs a non-empty {name}")
        if "@" in self.owner:
            raise JobError("a job owner is an account, never a mailbox")
        if not isinstance(self.state, JobState):
            raise JobError("a stored job must carry a published state")
        if not isinstance(self.admission, JobAdmission):
            raise JobError("a stored job must carry an executor-admission fact")
        for name in DIGEST_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, str) or not value:
                raise JobError(f"a stored job {name} must be a non-empty digest")
            if "@" in value:
                raise JobError(f"a stored job {name} may not carry an address")
        if isinstance(self.retries_used, bool) or not isinstance(self.retries_used, int):
            raise JobError("a retry count must be a whole number, not a boolean")
        if self.retries_used < 0:
            raise JobError("a retry count may not be negative")
        if not isinstance(self.recipient_touch, RecipientTouch):
            raise JobError("a stored job must carry a recipient-touch fact")
        for name in ("created_at", "updated_at"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise JobError(f"a stored job {name} must be timezone-aware")
        if self.no_message_data_sent is not None and not isinstance(
            self.no_message_data_sent, bool
        ):
            raise JobError("no_message_data_sent must be a boolean")
        if (self.no_message_data_sent is None) != (self.status is None):
            # Paired with the result, both directions. A completed row without
            # it would be rebuilt with an invented assertion, and an unfinished
            # row carrying one would be a safety claim about work that has not
            # run.
            raise JobError("a stored result carries its no_message_data_sent assertion")
        if (self.status is not None) != (self.state is JobState.COMPLETED):
            # The `CheckJob` pairing, re-stated: a status outside `completed`
            # would be a published answer for a verification that has not
            # finished, which is the re-derivation Phase 5 forbids.
            raise JobError("only a completed job carries a result")
        if (self.failure is not None) != (self.state is JobState.FAILED):
            raise JobError("only a failed job names a failure category")
        if self.admission is JobAdmission.ADMISSION_FAILED and self.state is not JobState.FAILED:
            raise JobError("a refused admission must be a failed job")
        if self.admission is JobAdmission.NOT_REQUIRED and self.state is not JobState.COMPLETED:
            raise JobError("only an already-completed job needs no executor admission")
        if self.admission is JobAdmission.INTERRUPTED and (
            self.state is not JobState.FAILED or self.failure is not JobFailure.INTERRUPTED
        ):
            raise JobError("an interrupted admission must be a failed interrupted job")


class ClaimStatus(StrEnum):
    """How an atomic idempotency claim ended. Four answers and no fifth."""

    #: This caller won. The proposed job now exists, and it owns the key.
    NEW_CLAIM = "new_claim"
    #: Somebody else had already claimed the key for the **same** target. The
    #: existing job is returned, and the proposed one was not written.
    EXISTING_SAME_TARGET = "existing_same_target"
    #: The key is already bound to a **different** target. `IdempotencyConflict`
    #: territory: the proposed job was not written, and the existing binding is
    #: untouched.
    CONFLICT_DIFFERENT_TARGET = "conflict_different_target"
    #: This account's data is being erased and the store refused to create any.
    #: Not a conflict and not a win: nothing was written, nothing holds the key,
    #: and the caller's admitted generation is no longer the current one. The
    #: focused review reproduced a stale claim recreating a deleted binding, so
    #: this answer is decided inside the claim's own transaction rather than by
    #: a check the caller made earlier.
    ACCOUNT_FENCED = "account_fenced"


@dataclass(frozen=True, slots=True)
class ClaimResult:
    """What one `claim_idempotency` decided, and what already held the key."""

    status: ClaimStatus
    #: The job that already owns the key, for the two answers where one does,
    #: and `None` for a win and for a fenced account. Present so a caller can
    #: reconnect to the existing job without a second, non-atomic lookup that
    #: could observe a different row.
    existing: StoredJob | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ClaimStatus):
            raise JobError("a claim result must carry a published status")
        if self.status is ClaimStatus.NEW_CLAIM and self.existing is not None:
            raise JobError("a winning claim names no existing job")
        if self.status is ClaimStatus.ACCOUNT_FENCED and self.existing is not None:
            # A fenced claim wrote nothing and read nothing: the account's rows
            # are being erased, and answering with one of them would hand back
            # data the deletion is in the middle of removing.
            raise JobError("a fenced claim names no existing job")
        holds_key = self.status in {
            ClaimStatus.EXISTING_SAME_TARGET,
            ClaimStatus.CONFLICT_DIFFERENT_TARGET,
        }
        if holds_key and self.existing is None:
            raise JobError("a claim that did not win must name the job that holds the key")


class JobStore(Protocol):
    """Persisted job identity, state, and result.

    Every read is owner-checked by the caller rather than here, on the Phase 6
    rule: `application/jobs.py` decides what a caller may learn, and a store
    that answered differently for "not yours" than for "no such job" would leak
    the distinction the ownership rule exists to withhold.
    """

    async def claim_idempotency(
        self, record: StoredJob, *, expected_generation: int
    ) -> ClaimResult:
        """Take `(owner, idempotency_digest)` for `record`, atomically.

        **The single decision point for whether a submission is new.** It exists
        because the previous one was a process-local `asyncio.Lock`, and the
        final system audit measured what that is worth across two `JobService`
        instances sharing one database: one owner, one key, one address,
        concurrent submissions — and **two** job identifiers, **two** executor
        admissions, and **two** persistent bindings. Two active verifications
        for one address is a duplicate `RCPT TO` arranged by running a second
        replica, which is the enumeration pattern `docs/threat-model.md` lists
        first, and no amount of in-process locking can see the other process.

        An implementation must decide and write inside **one** transaction. A
        `SELECT` that ends its transaction before the `INSERT` is the same race
        with more steps, and it is the shape this replaced.

        `record` must carry both digests: a submission with no idempotency key,
        or one whose address did not parse, has no identity to claim and goes
        through `save`.

        `expected_generation` is the account deletion generation this work was
        admitted under, and the implementation must compare it against its own
        fence **inside the same transaction** as the insert, answering
        `ACCOUNT_FENCED` on a mismatch.

        Returns rather than raises for all four answers, including the
        conflict: which of them happened is the caller's decision to
        translate — `application/jobs.py` owns the mapping onto
        `IdempotencyConflict` and onto the `409` a caller sees, and a store that
        raised would be deciding an API response.
        """
        ...

    async def fence(self, *, account: str, generation: int) -> int:
        """Raise this store's own deletion fence for `account`. Returns the value held.

        Called by `application/account_deletion.py` **before** it deletes this
        store's rows, so that no write admitted under an older generation can
        land between the two steps. Monotonic: a lower generation leaves the
        held one alone, because a fence that can fall re-authorizes work whose
        data is already gone.
        """
        ...

    async def save(self, record: StoredJob, *, expected_generation: int) -> bool:
        """Create or update one job. `False` means the account fence refused it.

        **Identity is immutable.** For an existing `job_id`, `owner`,
        `created_at`, `idempotency_digest`, and `target_digest` must match the
        inserted row exactly. Only operational state, result, retry/touch,
        admission, and `updated_at` may change. An implementation fails closed
        on an identity mismatch and never deletes or rebinds the winner.

        **The fence is part of the write, not a question asked before it.**
        `expected_generation` must be compared with this store's own fence
        inside the same transaction as the insert. The first Remediation C
        design compared a generation held in another database and then wrote
        this one; the focused review paused a replica between those two steps
        and recreated a deleted account's job row after the operator had been
        told the deletion was complete. A `False` return is that refusal, and
        is not an error: there is nothing to retry.
        """
        ...

    async def load(self, job_id: str) -> StoredJob | None: ...

    async def find_by_idempotency(self, owner: str, idempotency_digest: str) -> StoredJob | None:
        """The job an `(owner, key)` pair already names, across a restart.

        This is the whole reason the port exists. Without it, a deterministic
        handle presented by a resumed batch means nothing to a fresh process.
        """
        ...

    async def find_nonterminal(self, *, before: datetime, limit: int) -> tuple[StoredJob, ...]:
        """Unfinished jobs last updated at or before `before`, oldest first.

        What a process reads to reconcile what a previous one left behind. It is
        **not** a work queue: the caller is required to classify rather than to
        enqueue, and `application/jobs.py` does exactly that.

        `before` is required and has no default, because the hazard this
        operation carries is entirely in that parameter. A store can be shared by
        two live replicas — that is the premise `claim_idempotency` exists for —
        and a scan with no cutoff would hand one replica the other's *running*
        jobs, which it would then declare interrupted. A cutoff older than any
        plausible in-flight verification makes a returned row one that nothing is
        working on.

        Bounded, on the `purge_terminal` precedent: a store holding a day of
        interrupted jobs must not be read into memory in one call.
        """
        ...

    async def delete(self, job_id: str) -> None:
        """Forget one job through an explicit deletion/retention operation.

        Never executor-admission compensation: once a claim is committed,
        another replica may have observed it and the identity must stay stable.
        """
        ...

    async def delete_account(self, *, owner: str) -> int:
        """Remove **everything** this account owns. Returns how many records went.

        `docs/privacy.md` section 7 promises account-requested deletion and
        `docs/runbooks/privacy-deletion.md` describes an operator performing it.
        No production operation did it: the runbook's steps were manual, and the
        final system audit found the promise had no implementation. This is that
        implementation for one store; `application/account_deletion.py`
        orchestrates the set.

        **The owner is the key, and it is the only key.** Never a target, never
        a digest of an address, never a scan of retained text: this project
        stores an account identifier alongside every record precisely so that
        "everything belonging to A" is a `WHERE` clause rather than an
        inference. Deleting by anything else could remove another account's row
        that happens to name the same mailbox.

        Unbounded on purpose, unlike the retention sweep. A retention sweep is
        routine housekeeping that must not hold a write lock; an account
        deletion is a rare operator action whose whole value is that it finishes.
        """
        ...

    async def purge_terminal(self, *, before: datetime, limit: int) -> int:
        """Delete terminal jobs last updated before `before`, at most `limit`.

        The same window `JobService.purge_finished` applies in memory, so
        persistence does not quietly extend `docs/privacy.md` section 3's
        retention in order to make a resume work.
        """
        ...
