"""What a job must survive a process restart, and what it may never persist.

`prompts/10-batch.md` asks for *resumable job state* and a *restart/resume*
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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from emailcheck.domain.job import JobError, JobFailure, JobState

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
    #: `docs/requirements.md` section 14's budget, carried so a restart cannot
    #: reset it. A job that has spent its one retry must not get another by
    #: outliving the process that granted it.
    retries_used: int = 0
    #: HMAC of `(owner, the caller's idempotency key)`. **Never the key.**
    idempotency_digest: str | None = None
    #: HMAC of the normalized target. What makes "same handle, different
    #: address" a conflict rather than a wrong answer, after a restart.
    target_digest: str | None = None
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
        for name in ("created_at", "updated_at"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise JobError(f"a stored job {name} must be timezone-aware")
        if (self.status is not None) != (self.state is JobState.COMPLETED):
            # The `CheckJob` pairing, re-stated: a status outside `completed`
            # would be a published answer for a verification that has not
            # finished, which is the re-derivation Phase 5 forbids.
            raise JobError("only a completed job carries a result")
        if (self.failure is not None) != (self.state is JobState.FAILED):
            raise JobError("only a failed job names a failure category")


class JobStore(Protocol):
    """Persisted job identity, state, and result.

    Every read is owner-checked by the caller rather than here, on the Phase 6
    rule: `application/jobs.py` decides what a caller may learn, and a store
    that answered differently for "not yours" than for "no such job" would leak
    the distinction the ownership rule exists to withhold.
    """

    async def save(self, record: StoredJob) -> None:
        """Create or replace one job."""
        ...

    async def load(self, job_id: str) -> StoredJob | None: ...

    async def find_by_idempotency(self, owner: str, idempotency_digest: str) -> StoredJob | None:
        """The job an `(owner, key)` pair already names, across a restart.

        This is the whole reason the port exists. Without it, a deterministic
        handle presented by a resumed batch means nothing to a fresh process.
        """
        ...

    async def delete(self, job_id: str) -> None:
        """Forget one job. Used to roll back a claim the executor refused."""
        ...

    async def purge_terminal(self, *, before: datetime, limit: int) -> int:
        """Delete terminal jobs last updated before `before`, at most `limit`.

        The same window `JobService.purge_finished` applies in memory, so
        persistence does not quietly extend `docs/privacy.md` section 3's
        retention in order to make a resume work.
        """
        ...
