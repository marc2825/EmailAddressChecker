"""What a batch is, what it may hold, and who may run one.

ADR 0018. Pure domain values — no CSV parsing, no scheduling,
no I/O. The parser is `application/batch_csv.py` and the scheduler is
`application/batch.py`.

**Batch is an operational permission, not a profile switch.** That is the
prompt's own first line and `docs/requirements.md` section 15 repeats it for the
`bulk` profile. So the central value here is not a size limit — it is
`BatchApproval`, and it is empty by default: a deployment that has built this
subsystem still runs no batch, because the accounts allowed to submit one are a
separate operator record. The prompt's test list ends with *"batch disabled for
unapproved account"*, and this is where that is decided.

**A batch is orchestration over verifications that already exist.** It is not a
second SMTP implementation, not a faster path, and not a way to spend one
budget for many probes. Every row becomes an ordinary Phase 6 job through the
ordinary service, so admission, the Phase 4 limiter, the Phase 7 quota layers,
the destination policy, TLS, the sender identity, the one-`RCPT TO` bound, the
kill switch, and section 14's single retry all apply per row exactly as they
apply to a single check. ADR 0018's scheduler section says so
in four words: *reuse all existing budgets*.

**Nothing here decides a status.** A row's answer is the `Verdict` the Phase 5
aggregator produced for that address. This module names no `Status`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

__all__ = [
    "ADDRESS_COLUMN",
    "MAX_INPUT_BYTES",
    "MAX_INPUT_RETENTION",
    "MAX_ROWS",
    "RESULT_MEDIA_TYPE",
    "RESUMABLE_ROW_STATES",
    "TERMINAL_ROW_STATES",
    "BatchApproval",
    "BatchError",
    "BatchId",
    "BatchLimits",
    "BatchRowState",
    "BatchSettings",
    "address_column_index",
]

#: The one column ADR 0018 names: *one address column*.
#:
#: A fixed header rather than a caller-supplied index, because a column chosen
#: by the submitter is a column somebody points at the wrong field — and the
#: wrong field in this project is somebody's data being probed.
ADDRESS_COLUMN: Final = "email"

#: ADR 0018 Input: *file size and row limits*. Both, because
#: either alone is bypassable — a million single-character rows is small, and one row
#: can be a megabyte.
#:
#: The numbers are this implementation's, and the prompt asks for limits without
#: naming them. They are chosen to be **operationally small**: a batch is an
#: approved operational act, and `docs/threat-model.md`'s residual risk is that
#: this project resembles a harvesting source. Fifty thousand rows against the
#: default per-account budget is already several windows of work, so a larger
#: default would be a number nobody could actually spend. Both are operator
#: settings on `BatchLimits`; these are the ceilings a setting may not exceed.
MAX_ROWS: Final = 50_000
MAX_INPUT_BYTES: Final = 8 * 1024 * 1024

#: The longest a submitted address may be retained for resumability, in
#: seconds. `docs/privacy.md` section 3's plaintext retention, as a **ceiling**
#: rather than a default — an operator may shorten it and cannot lengthen it.
MAX_INPUT_RETENTION: Final = 24 * 60 * 60

#: What a rendered batch result is. Named here so the store, the renderer, and
#: any future transport agree without one of them inventing a second value.
RESULT_MEDIA_TYPE: Final = "text/csv; charset=utf-8"


class BatchError(ValueError):
    """A batch this project may not accept or construct."""


def address_column_index(header: Sequence[str]) -> int:
    """The position of the address column, for every CSV reader in this project.

    The local CLI and the service batch parser both call this, so one file is
    accepted or refused the same way by both. Names are compared after trimming
    and lowercasing. The header must name `email` exactly once and repeat no
    name: with a repeated name a dict-based reader silently keeps the last cell,
    so which value counts as the address would depend on the reader.
    """
    names = [name.strip().lower() for name in header]
    if len(set(names)) != len(names):
        raise BatchError("a CSV header may not repeat a column name")
    if names.count(ADDRESS_COLUMN) != 1:
        raise BatchError(f"a CSV header needs exactly one {ADDRESS_COLUMN!r} column")
    return names.index(ADDRESS_COLUMN)


@dataclass(frozen=True, slots=True)
class BatchId:
    """An unguessable handle, on the `JobId` precedent.

    The same split: this type fixes what an identifier may look like, and
    `application/batch.py` decides where one comes from — so the entropy
    guarantee lives with the `RandomSource` that produces it. A sequential
    integer would let one account enumerate another's batches, and the ownership
    check is the second barrier rather than the first.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise BatchError("a batch identifier is text")
        if not 16 <= len(self.value) <= 64:
            raise BatchError("a batch identifier must be 16..64 characters")
        if not self.value.replace("-", "").replace("_", "").isalnum():
            raise BatchError("a batch identifier is URL-safe text")


class BatchRowState(StrEnum):
    """Where one row of the input ended up.

    **Not a second job-state machine.** `domain/job.py` publishes the six states
    a *verification* moves through and this does not duplicate them: a row that
    became a job carries its `JobId` and the job's state is read from the job.
    These are the states of a **row**, which is a different thing — a row can be
    rejected before any job exists, and a job cannot be "invalid syntax".

    Every selected row lands in exactly one of these, and the report balances
    against the input. Phase 8 learned that the hard way: a run that started
    work and reported nothing about it is a record with a hole in it.
    A row moves `queued → claimed → submitted`, or straight to one of the four
    terminal states. The middle one exists for a single reason and it is the
    reason a resume can be safe at all — see `CLAIMED`.
    """

    #: Read, accepted, and waiting for a worker. The state a persisted row is
    #: in before anything has been attempted for it, and the only state a
    #: restart may continue from by submitting.
    QUEUED = "queued"
    #: **Written before the submission is attempted, and this is a crash
    #: boundary rather than bookkeeping.**
    #:
    #: A row recorded as claimed may or may not have reached the job service:
    #: the process can stop between the call and the record of its result. A
    #: resume therefore cannot know whether a verification is already running,
    #: and answering that with "unlikely" would be answering it with nothing.
    #: So a claimed row carries a **deterministic** idempotency handle, and
    #: re-submitting it under that handle returns the existing job rather than
    #: starting a second verification — Phase 6's own mechanism, used for the
    #: thing it exists for.
    CLAIMED = "claimed"
    #: Accepted and handed to the job service, with the child job recorded. The
    #: verification's own state is the job's; this says the row got that far.
    SUBMITTED = "submitted"
    #: A duplicate of an earlier row in the same input, detected by HMAC.
    #: ADR 0018 Input: *duplicate detection by HMAC*.
    DUPLICATE = "duplicate"
    #: The address did not parse. Phase 1's rejection, carried as a reason code
    #: rather than re-derived — no second parser exists.
    #:
    #: **Deliberately not called `invalid`.** `Status.INVALID` already means
    #: something else and stronger — that a *mailbox* does not exist — and
    #: `docs/requirements.md` section 6 sends unsupported syntax to `unknown`
    #: rather than to `invalid`. A report carrying a `row_state` column beside a
    #: `status` column, both reading `invalid`, would be inviting the confusion
    #: Phase 8 had to force apart for its execution states. `AddressRejected` is
    #: Phase 1's own word for this.
    REJECTED = "rejected"
    #: An operational refusal: a quota, the admission gate, the kill switch, a
    #: full executor. ADR 0013's rule — never a fact about the address.
    REFUSED = "refused"
    #: The batch was cancelled before this row was submitted.
    CANCELLED = "cancelled"


#: Rows a resume may still act on. Neither is terminal, and they are continued
#: differently: a queued row is submitted, a claimed row is submitted under its
#: recorded idempotency handle, which recovers rather than duplicates.
RESUMABLE_ROW_STATES: Final[frozenset[BatchRowState]] = frozenset(
    {BatchRowState.QUEUED, BatchRowState.CLAIMED}
)


#: Rows that will not change again. A row is finished when it is one of these,
#: or when the job a `SUBMITTED` row named reaches a terminal job state.
TERMINAL_ROW_STATES: Final[frozenset[BatchRowState]] = frozenset(
    {
        BatchRowState.DUPLICATE,
        BatchRowState.REJECTED,
        BatchRowState.REFUSED,
        BatchRowState.CANCELLED,
    }
)


@dataclass(frozen=True, slots=True)
class BatchLimits:
    """The bounds on one batch. Every one is a whole number, and none is a hint.

    Validated in the style Phases 4, 7, 8, and 9 use — a whole number, not a
    boolean, positive, and under a ceiling — because `True` is an `int` in
    Python and a bound nobody would reach is not a bound.
    """

    #: Rows one input may carry.
    max_rows: int = 10_000
    #: Bytes one input may carry, before it is decoded.
    max_input_bytes: int = 4 * 1024 * 1024
    #: How many rows may be in flight at once, across the whole batch.
    #:
    #: **Bounded workers, not one task per row.** ADR 0018 asks
    #: for
    #: *bounded global workers*, and a scheduler that created fifty thousand
    #: coroutines and held them behind a semaphore would have moved the growth
    #: rather than stopped it — the shape `application/admission.py` already
    #: refuses for the queue.
    max_in_flight: int = 8
    #: How many rows of one recipient domain may be in flight at once.
    #:
    #: ADR 0018: *one domain cannot monopolize workers*. The
    #: scheduler's round-robin is what spreads the work; this is the hard cap
    #: behind it, so the property holds even when a batch is one domain and a
    #: rotation has nothing to rotate to.
    max_in_flight_per_domain: int = 2
    #: How many rows heading for one **exchanger** may be in flight at once.
    #:
    #: ADR 0018 asks for fair scheduling by target domain *and
    #: MX*,
    #: and the two are not the same bound: twenty domains behind one provider
    #: are twenty domain queues and one destination. A per-domain cap alone lets
    #: that provider hold every worker while satisfying every per-domain rule.
    max_in_flight_per_mx: int = 4

    def __post_init__(self) -> None:
        _whole("max_rows", self.max_rows, MAX_ROWS)
        _whole("max_input_bytes", self.max_input_bytes, MAX_INPUT_BYTES)
        _whole("max_in_flight", self.max_in_flight, 64)
        _whole("max_in_flight_per_domain", self.max_in_flight_per_domain, 16)
        _whole("max_in_flight_per_mx", self.max_in_flight_per_mx, 32)
        if self.max_in_flight_per_domain > self.max_in_flight:
            raise BatchError("a per-domain bound above the global one bounds nothing")
        if self.max_in_flight_per_mx > self.max_in_flight:
            raise BatchError("a per-exchanger bound above the global one bounds nothing")
        if self.max_in_flight_per_domain > self.max_in_flight_per_mx:
            # One domain may not be allowed more of an exchanger than the
            # exchanger itself allows, or the narrower bound is the wider one.
            raise BatchError("a per-domain bound above the per-exchanger one bounds nothing")


def _whole(name: str, value: int, ceiling: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BatchError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise BatchError(f"{name} must be positive")
    if value > ceiling:
        raise BatchError(f"{name} above {ceiling} is not a bound")


@dataclass(frozen=True, slots=True)
class BatchApproval:
    """Which accounts an operator has approved for batch submission.

    **Membership is the permission**, on the precedent `BetaCorpus` and
    `AcceptAllAuthorization` set, and the default is empty.
    ADR 0018's preconditions are *account review/approval* and
    *domain ownership or documented lawful purpose* — neither of which a program
    can establish, and both of which a person records here.

    An authenticated account is **not** an approved one. Phase 6 authenticates a
    caller; this says an operator has separately reviewed them for bulk. The
    prompt's non-goals list *public anonymous uploads* first, and the shortest
    route to one is treating authentication as approval.
    """

    accounts: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.accounts, frozenset):
            raise BatchError("approved accounts are a fixed set")
        for account in self.accounts:
            if not isinstance(account, str) or not account:
                raise BatchError("an approved account is a non-empty identifier")
            if "@" in account:
                # An account is not a mailbox, and the budget keys already
                # refuse an `@` for the same reason.
                raise BatchError("an approved account is an account, never a mailbox")

    def permits(self, account: str) -> bool:
        return account in self.accounts


@dataclass(frozen=True, slots=True)
class BatchSettings:
    """The deployment's batch configuration. **Disabled by default.**

    Two independent things, and both must be true: the feature is enabled, and
    the submitting account is approved. `docs/requirements.md` section 15 keeps
    `bulk` deferred as "an operational permission, not merely a configuration
    toggle", so the toggle alone is deliberately not enough.
    """

    enabled: bool = False
    approval: BatchApproval = field(default_factory=BatchApproval)
    limits: BatchLimits = field(default_factory=BatchLimits)
    #: How long a finished batch's result stays downloadable.
    #: ADR 0018 Output: *expiring downloadable result*.
    result_retention_seconds: int = 24 * 60 * 60
    #: How long a batch's **submitted addresses** are retained so that an
    #: unfinished row can still be submitted after a restart.
    #:
    #: `docs/privacy.md` section 3: plaintext request data, 24 hours.
    #: `docs/requirements.md` section 16 permits it "only for an explicit
    #: short-lived job or history feature", and resumability is one. The
    #: ceiling is the same 24 hours rather than the retention maximum: there is
    #: no configuration of this project that keeps a submitted address longer
    #: than the policy allows, which is a stronger guarantee than a default.
    input_retention_seconds: int = 24 * 60 * 60

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise BatchError("the batch feature flag is a boolean an operator sets")
        _whole("result_retention_seconds", self.result_retention_seconds, 30 * 24 * 60 * 60)
        _whole("input_retention_seconds", self.input_retention_seconds, MAX_INPUT_RETENTION)

    def permits(self, account: str) -> bool:
        """Both conditions. Either alone is a way to be wrong."""
        return self.enabled and self.approval.permits(account)
