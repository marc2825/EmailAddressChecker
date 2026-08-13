"""What a batch must survive a restart, and what it may never persist.

`prompts/10-batch.md`'s scheduler asks for *resumable job state* and its tests
ask for *restart/resume*. An in-process registry cannot answer either: the
process is exactly what a restart destroys. So batch state is a store behind a
port, on the `ports/verdict_store.py` precedent — the record type fixes what may
be kept, the adapter adds nothing, and a second implementation is a drop-in.

**What is persisted is the minimum needed to resume safely**, and each field
below earns its place by naming a resume decision it makes possible. Nothing is
here for convenience.

**What is deliberately absent** is longer than what is present: no SMTP reply,
no `Evidence`, no evidence detail, no correlation key, no credential, no
idempotency material a caller chose, and no verdict beyond the published
projection an API response already carries.

**One field holds plaintext, on purpose and under a clock.** A row that has not
been submitted yet must still be submittable after a restart, and
`JobService.submit` takes the submitted text — so a batch that discarded it
could account for the row but never finish it. `docs/privacy.md` section 3
gives plaintext request data 24 hours and `docs/requirements.md` section 16
permits it "only for an explicit short-lived job or history feature"; this is
one, it expires, and `forget_inputs` is what makes the expiry real rather than
documented. There is no setting that retains it indefinitely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from emailcheck.domain.batch import BatchError, BatchRowState

#: Fields that must be a non-empty identifier carrying no address, on the
#: `ports/verdict_store.py` precedent. An account is an account: `@` is refused
#: rather than stripped, exactly as `BatchApproval` and `rate_limit_key` do.
ACCOUNT_FIELDS = ("account",)


def _aware(name: str, moment: object) -> None:
    if not isinstance(moment, datetime) or moment.utcoffset() is None:
        raise BatchError(f"a batch {name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class StoredBatchRow:
    """One row of a persisted batch: where it got to, and how to continue it."""

    #: The 1-based input position. The row's identity within its batch, and half
    #: of the deterministic idempotency identity below.
    number: int
    state: BatchRowState
    #: HMAC of the normalized target. Duplicate detection survives a restart
    #: through this rather than by re-reading addresses. Never the address.
    target_digest: str | None = None
    #: The child job this row became, when it became one. The other half of
    #: what makes a resume safe: a row naming a job is never submitted again.
    job_id: str | None = None
    #: The deterministic per-row idempotency handle, as an opaque digest.
    #:
    #: Written **before** the submission is attempted, which is the whole point:
    #: a row recorded as `claimed` may or may not have reached the job service,
    #: and re-submitting it under the same handle recovers the existing job
    #: instead of starting a second verification. It carries no raw target — the
    #: digest is taken over the batch, the row number, the account, and the
    #: target digest — so the idempotency binding stores nothing an address
    #: could be read out of.
    idempotency: str | None = None
    #: The submitted text, retained only while this row may still need to be
    #: submitted, and cleared by `forget_inputs`. `repr=False`: a batch is a
    #: list of addresses and its `repr` must not be one.
    submitted: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.number, bool) or not isinstance(self.number, int):
            raise BatchError("a row number must be a whole number, not a boolean")
        if self.number <= 0:
            raise BatchError("a row number is 1-based")
        if not isinstance(self.state, BatchRowState):
            raise BatchError("a stored row must carry a published row state")
        for name in ("target_digest", "idempotency"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, str) or not value:
                raise BatchError(f"a stored row {name} must be a non-empty digest")
            if "@" in value:
                raise BatchError(f"a stored row {name} may not carry an address")


@dataclass(frozen=True, slots=True)
class StoredBatch:
    """One persisted batch. Ownership, bounds, and when it stops existing."""

    batch_id: str
    #: The account that submitted it, as `CheckJob.owner` keeps one: an account
    #: identifier is not a mailbox and `BatchApproval` already refuses an `@`.
    #: Every read, resume, cancellation, and deletion is checked against it.
    account: str
    created_at: datetime
    #: When this batch stops being resumable and its rows stop being readable.
    expires_at: datetime
    #: How many rows the input carried, and how many the reader skipped. The
    #: denominators the report balances against, so a resumed batch reports
    #: against the original file rather than against what survived.
    input_rows: int
    skipped_rows: int
    #: Set by `cancel`. Persisted, so a restart cannot resume a cancelled batch.
    cancelled: bool = False
    rows: tuple[StoredBatchRow, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.batch_id, str) or not self.batch_id:
            raise BatchError("a stored batch needs an identifier")
        if not isinstance(self.account, str) or not self.account:
            raise BatchError("a stored batch needs an owning account")
        if "@" in self.account:
            raise BatchError("a batch account is an account, never a mailbox")
        for name in ("created_at", "expires_at"):
            _aware(name, getattr(self, name))
        if self.expires_at <= self.created_at:
            raise BatchError("a stored batch must expire after it was created")
        for name in ("input_rows", "skipped_rows"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise BatchError(f"{name} must be a whole number, not a boolean")
        if not isinstance(self.cancelled, bool):
            raise BatchError("cancelled is a boolean")

    def live_at(self, now: datetime) -> bool:
        return now < self.expires_at


@dataclass(frozen=True, slots=True)
class BatchArtifact:
    """The expiring downloadable result. `prompts/10-batch.md` Output.

    A bounded blob with an owner and a clock, retrievable through an application
    port. **Not a second `VerdictCache`**: a cache answers "what is this
    address's status" and is consulted before work is done; this answers "what
    did that batch report" and is written after. Nothing reads it to decide a
    verdict, and it is keyed by a batch identifier rather than by a target.
    """

    batch_id: str
    account: str
    created_at: datetime
    expires_at: datetime
    media_type: str
    content: str = field(repr=False)
    #: Whether every submitted row's child job had reached a terminal state when
    #: this was rendered.
    #:
    #: **False is not a defect, it is the honest label.** A batch finishes
    #: submitting long before its verifications finish, and exporting rows whose
    #: jobs are still running as though they were finished deliverability
    #: results is the one output error `prompts/10-batch.md`'s "no raw SMTP
    #: replies / row-level status" cannot catch. A non-final artifact is a
    #: submission report and says so.
    complete: bool = False

    def __post_init__(self) -> None:
        for name in ("batch_id", "account", "media_type"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise BatchError(f"an artifact needs a non-empty {name}")
        if "@" in self.account:
            raise BatchError("a batch account is an account, never a mailbox")
        if not isinstance(self.content, str):
            raise BatchError("an artifact body is text")
        for name in ("created_at", "expires_at"):
            _aware(name, getattr(self, name))
        if self.expires_at <= self.created_at:
            raise BatchError("an artifact must expire after it was created")
        if not isinstance(self.complete, bool):
            raise BatchError("complete is a boolean")


class BatchStore(Protocol):
    """Persisted batch state, artifacts, and their expiry.

    Every read takes `now` and every read is filtered by it, for the reason
    `ports/verdict_store.py` gives: a record filtered after selection is a
    record an implementation can still answer with.
    """

    async def save_batch(self, record: StoredBatch) -> None:
        """Create or replace one batch and all of its rows.

        Raises `BatchStoreFull` when the store is at capacity and every batch in
        it is still live. Refusing is the contract: silently evicting a live
        batch to admit another is how a running batch stops existing.
        """
        ...

    async def update_rows(self, batch_id: str, rows: tuple[StoredBatchRow, ...]) -> None:
        """Replace these rows of an existing batch, leaving the others alone."""
        ...

    async def set_cancelled(self, batch_id: str) -> None: ...

    async def load_batch(self, batch_id: str, *, account: str, now: datetime) -> StoredBatch | None:
        """This account's live batch, or `None`.

        `None` covers "no such batch", "somebody else's batch", and "expired",
        on the Phase 6 rule: a distinct answer would confirm the identifier is
        real.
        """
        ...

    async def save_artifact(self, artifact: BatchArtifact) -> None: ...

    async def load_artifact(
        self, batch_id: str, *, account: str, now: datetime
    ) -> BatchArtifact | None: ...

    async def delete_batch(self, batch_id: str, *, account: str) -> bool:
        """Remove this account's batch, its rows, its retained plaintext, and
        its artifact. Returns whether anything was removed.

        Touches nothing belonging to another batch or another account, and
        deletes no child job: a job is Phase 6's and may be shared with a single
        check through the cache.
        """
        ...

    async def forget_inputs(self, *, before: datetime, limit: int) -> int:
        """Clear retained plaintext from batches created before `before`."""
        ...

    async def purge_expired(self, *, now: datetime, limit: int) -> int:
        """Delete expired batches and artifacts, at most `limit` batches."""
        ...


class BatchStoreFull(Exception):
    """The store is at capacity and every batch in it is still live.

    Not a `TimeoutError` and not an `OSError`, on the precedent `JobsFull`,
    `AdmissionRefused`, and `RateLimitTimeout` set.
    """
