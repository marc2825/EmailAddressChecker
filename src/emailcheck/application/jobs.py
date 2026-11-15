"""Accepting an active check, running it later, and answering about it.

`docs/requirements.md` section 11 makes `POST /v1/checks` create an asynchronous
job and `GET /v1/checks/{id}` return its state and result;
`docs/architecture.md` adds idempotency, a bounded retry, cancellation, and
cache lookup before enqueue. ADR 0014 records the decisions and ADR 0015 the
cache.

**Nothing here waits for SMTP.** `submit` runs the passive half — which is what
section 11's "returns passive evidence immediately when available" asks for —
and hands the active half to a `JobExecutor`. That is the requirement
`docs/architecture.md` states as "no synchronous waiting for active SMTP in API
workers", and the first Phase 6 build failed it.

**Nothing here decides a status either.** A job's result is
`application/public_result.py`'s projection of whatever `aggregate_evidence`
produced, and a job that has not completed carries no status at all: inventing
one before a verdict exists is exactly the re-derivation Phase 5 stop condition
1 forbids.

**Order of operations, as the code actually runs them:**

```text
passive check         parse + DNS; also produces the normalized target
  → idempotency       in the store when there is one, in memory otherwise
  → cache             one indexed row
  → claim             durable identity first, registry second; never delete it
  → handoff           persist one irrevocable executor opportunity
  → enqueue           the SMTP half, later
```

The passive check comes **first**, because both lookups below it are keyed by
the normalized target and that target does not exist until the address has been
parsed. So a cache hit or an idempotent repeat still costs the passive DNS work;
what it avoids is the enqueue and the SMTP probe, which is the property
`docs/architecture.md` requires and the expensive half by orders of magnitude.

An earlier version of this docstring claimed the cache was consulted before the
passive step and that a hit therefore cost nothing. It was not true, and an
independent review measured three DNS lookups on a cache hit. A behavioural test
now pins the honest statement so the overclaim cannot come back.

**Three properties are Remediation A's, and each replaced something that only
held inside one process.**

*Idempotency is the store's decision, not this object's.* The claim used to be a
read and a write under `self._lock`, which is correct for two coroutines and
worth nothing against two replicas: the final system audit ran one owner, one
key, one address through two `JobService` instances over one database and got two
job identifiers, two executor admissions, and two persistent bindings — two
active verifications, which is a duplicate `RCPT TO` arranged by scaling out.
`JobStore.claim_idempotency` decides it once, under a uniqueness constraint both
processes are subject to. The lock stays for the registry, which is genuinely
process-local.

*A retry may only replay an attempt that did not reach the recipient.*
`docs/requirements.md` section 14's delays are unchanged; what changed is that
`VerificationOutcome.recipient_touch` is now a precondition of using them. The
previous rule — "a `450` is an explicitly temporary SMTP response, so retry it" —
produced a second `RCPT TO` for one submitted address, because
`smtp_temporary_failure` and `mailbox_full` are reachable only *through* the
recipient stage. Counted on the wire, one job made two recipient commands.

*Durable state is written before the work it describes, and the work is not
started when that write fails.* `running` is persisted — carrying
`MAYBE_TOUCHED` — before the active verification begins, so a process that dies
between writing `RCPT TO` to a socket and learning the answer leaves a record
saying *do not replay this*. A failed persist stops the job instead of probing
under a state nothing durable can express.

**What this module does not claim.** The store is job *state*; it is not a
durable execution queue, and `ports/job_executor.py`'s only implementation dies
with its process. Nothing here re-enqueues a job found in the store.
`recover_interrupted` classifies such rows into an operational failure, which is
the honest answer when the alternative is to guess whether a recipient was
already contacted.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Final

from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.public_result import PublicCheck, PublicResult, public_result
from emailcheck.application.retry import jitter_span_seconds, retry_delay_seconds
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.application.verification import (
    AddressVerificationService,
    VerificationOutcome,
    VerificationRefused,
)
from emailcheck.domain.job import (
    MAX_RETRIES,
    IdempotencyKey,
    JobAdmission,
    JobError,
    JobFailure,
    JobId,
    JobState,
    check_transition,
)
from emailcheck.domain.principal import Principal
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.source import SourceIdentity
from emailcheck.ports.account_state import INITIAL_GENERATION, AccountStateStore
from emailcheck.ports.clock import Clock
from emailcheck.ports.job_executor import ExecutorFull, JobExecutor
from emailcheck.ports.job_store import ClaimStatus, JobStore, StoredJob
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink
from emailcheck.ports.random_source import RandomSource
from emailcheck.security.identifiers import correlation_digest

#: Bytes of entropy in a job identifier. ADR 0014: unguessable, because an
#: ownership check is the second barrier and not the first.
JOB_ID_BYTES: Final = 32

#: How many jobs the registry holds, and the ceiling on that. A registry that
#: only grows is a memory leak addressed by nothing else: admission bounds what
#: runs at once, not what is remembered afterwards.
DEFAULT_MAX_JOBS: Final = 512
MAX_JOBS_CEILING: Final = 65_536


class IdempotencyConflict(Exception):
    """One key, two different addresses.

    `docs/architecture.md` section 6 makes an active request's identity "an
    idempotency key **and** a derived target HMAC". A key that named one address
    and is then presented with another is almost certainly caller error — a
    retry loop or a batch runner reusing a handle — and answering with the first
    address's job would hand back a confident verdict about a mailbox the caller
    did not ask about. That is the worst answer this service can give, so it
    fails loudly instead.

    Carries no target, no digest, and no job identifier: the caller learns that
    the key is already in use, and nothing about what it was used for.
    """


class JobsFull(Exception):
    """The registry is at capacity and every job in it is still live.

    Not a `TimeoutError` and not an `OSError`, on the precedent
    `RateLimitTimeout` and `AdmissionRefused` set.
    """


class JobRecordMismatch(Exception):
    """The store answered a claim with a record belonging to another account.

    Unreachable by design and refused anyway. The idempotency digest already
    carries the owner and the adapter's `WHERE` already names it, so a store that
    gets here has answered a question it was not asked — and the two safe
    readings of that are "somebody else's job" and "a corrupt index", neither of
    which may be turned into this caller's job.

    Carries no identifier, no digest, and no owner. The caller sees a service
    failure, which is what it is; the operator sees the event, which is who can
    act on it.
    """


@dataclass(frozen=True, slots=True)
class JobSettings:
    """Every bound, validated the way every other bound in this project is."""

    max_jobs: int = DEFAULT_MAX_JOBS

    def __post_init__(self) -> None:
        if isinstance(self.max_jobs, bool) or not isinstance(self.max_jobs, int):
            raise ValueError("max_jobs must be a whole number, not a boolean")
        if self.max_jobs <= 0:
            raise ValueError("max_jobs must be positive")
        if self.max_jobs > MAX_JOBS_CEILING:
            raise ValueError(f"max_jobs above {MAX_JOBS_CEILING} is not a bound")


@dataclass(frozen=True, slots=True)
class CheckJob:
    """One asynchronous active check, and everything a caller may learn of it.

    `result` is present only in `completed` and `failure` only in `failed`, both
    asserted here rather than remembered by a handler: a job carrying a result
    in any other state would be a status published before a verdict existed.

    It holds the public projection rather than a `Verdict`, so there is no
    surface on which an `Evidence` detail could reach a response by being added
    to a producer later.
    """

    id: JobId
    #: The authenticated account that submitted it. Never a request field.
    owner: str
    state: JobState
    created_at: datetime
    updated_at: datetime
    retries_used: int = 0
    result: PublicResult | None = None
    failure: JobFailure | None = None
    #: Caller-chosen text, so `repr=False`: an address is a legal idempotency
    #: key and a job printed into a log would carry it. See `JobService`.
    idempotency_key: IdempotencyKey | None = field(default=None, repr=False)
    #: Whether this job's active work may already have contacted the recipient.
    #:
    #: Set to `MAYBE_TOUCHED` when the job enters `running`, and refined to what
    #: the finished verification actually observed. That order is the point: a
    #: fact recorded only *after* an answer arrives is missing for the one crash
    #: it exists to describe. It gates the automatic retry and it is persisted,
    #: so neither a second attempt nor a later process can replay an operation
    #: that may already have named the recipient to a mail server.
    recipient_touch: RecipientTouch = RecipientTouch.NOT_TOUCHED

    def __post_init__(self) -> None:
        if not isinstance(self.state, JobState):
            raise JobError("a job must carry a published state")
        if not isinstance(self.owner, str) or not self.owner:
            raise JobError("a job must be owned by an account")
        if isinstance(self.retries_used, bool) or not isinstance(self.retries_used, int):
            raise JobError("a retry count must be a whole number, not a boolean")
        if not 0 <= self.retries_used <= MAX_RETRIES:
            # Structural rather than scheduled: a second retry cannot be
            # arranged by re-enqueueing, because the value refuses to exist.
            raise JobError(f"a job may be retried at most {MAX_RETRIES} time(s)")
        for name in ("created_at", "updated_at"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise JobError(f"a job {name} must be an aware datetime")
        if self.result is not None and self.state is not JobState.COMPLETED:
            raise JobError("only a completed job carries a result")
        if self.state is JobState.COMPLETED and self.result is None:
            raise JobError("a completed job must carry a result")
        if self.failure is not None and self.state is not JobState.FAILED:
            raise JobError("only a failed job carries a failure category")
        if self.state is JobState.FAILED and self.failure is None:
            raise JobError("a failed job must name a failure category")

    @property
    def is_terminal(self) -> bool:
        return self.state in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}

    @property
    def may_retry(self) -> bool:
        """Whether a retry budget is left. The count, not the eligibility.

        Whether this job's *outcome* is retryable is `application/retry.py`'s
        question, read out of `docs/requirements.md` section 14.
        """
        return self.retries_used < MAX_RETRIES

    @property
    def replay_is_safe(self) -> bool:
        """Whether re-running this job's verification can avoid a second touch."""
        return self.recipient_touch.replay_is_safe

    def moved_to(
        self,
        state: JobState,
        *,
        now: datetime,
        result: PublicResult | None = None,
        failure: JobFailure | None = None,
        count_retry: bool = False,
        recipient_touch: RecipientTouch | None = None,
    ) -> CheckJob:
        """Move to `state`, or raise if `domain/job.py`'s table forbids it.

        `recipient_touch` defaults to *unchanged* rather than to either member.
        A default of `NOT_TOUCHED` would let any transition that forgot the
        argument quietly declare the recipient untouched, and a default of
        `MAYBE_TOUCHED` would make a job unretryable by being cancelled and
        would lose the fact on every ordinary write. Carrying the existing value
        is the only option that says nothing new.
        """
        check_transition(self.state, state)
        touch = self.recipient_touch if recipient_touch is None else recipient_touch
        if state is JobState.RETRY_SCHEDULED and not touch.replay_is_safe:
            # **The second barrier, and it is structural rather than scheduled.**
            # `retry_scheduled` is a promise to run this verification again, and
            # an operation whose recipient may already have been contacted has
            # no such promise to make: `docs/threat-model.md` bounds it at one
            # `RCPT TO` in total. `application/retry.py` refuses to produce a
            # delay for it, which is the policy; this refuses to *hold* the
            # state, which is the same rule expressed where no scheduling code
            # can route around it — the precedent `retries_used` set by refusing
            # to exist above `MAX_RETRIES` rather than by being checked.
            raise JobError("a job whose recipient may have been contacted may not be replayed")
        return replace(
            self,
            state=state,
            updated_at=now,
            result=result,
            failure=failure,
            retries_used=self.retries_used + 1 if count_retry else self.retries_used,
            recipient_touch=touch,
        )


@dataclass(frozen=True, slots=True)
class _KeyBinding:
    """What one `(account, idempotency key)` pair already names.

    The digest is held beside the job identifier so a repeat can be checked
    against the address the key was first used for, without the raw address
    being kept anywhere.
    """

    job_id: str
    target_digest: str


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    """What one reconciliation pass found and what it did with it.

    Counts rather than identifiers: an operator needs to know how much work a
    stopped process left behind and how much of it had reached the point where
    replay would be unsafe, and neither question needs a job identifier — which
    would be a handle to somebody's check in an operational log.
    """

    scanned: int = 0
    #: Rows ended as `failed` / `interrupted`.
    interrupted: int = 0
    #: How many of those had a durable checkpoint saying a recipient may already
    #: have been contacted. Reported because it is the number that says whether
    #: an incident touched anybody's mail server, and because a build that
    #: stopped writing the checkpoint would report zero here for ever.
    unsafe_to_replay: int = 0
    #: Rows this process still holds itself, and therefore left alone.
    skipped_live: int = 0


@dataclass(frozen=True, slots=True)
class SubmitOutcome:
    """What a submission produced, and whether it cost anything."""

    job: CheckJob
    #: The passive half, when it was computed. `docs/requirements.md` section 11:
    #: passive evidence is returned immediately when available.
    passive: PublicResult | None
    #: Whether this submission created work. `False` for an idempotent repeat
    #: and for a cache hit, which is the property `docs/architecture.md`
    #: requires a test for.
    enqueued: bool
    #: Whether the job already existed. A caller distinguishes `202` from `200`.
    existing: bool
    #: The exchanger the passive pass found this target's route leads to, or
    #: `None`. Carried straight from `VerificationOutcome.scheduling_key` and
    #: never re-derived; it decides nothing here either. A caller submitting
    #: many checks uses it to order the *next* ones fairly across destinations,
    #: which is what `docs/adr/0018-controlled-batch-execution.md` asks for and what no caller can
    #: learn
    #: without resolving DNS through a second, unreviewed path.
    scheduling_key: str | None = None


@dataclass(slots=True)
class JobService:
    """The registry, the submission rules, and the worker body.

    One instance per process, built by the composition root beside the executor
    it submits to.
    """

    verification: AddressVerificationService
    executor: JobExecutor
    clock: Clock
    random: RandomSource
    operator: OperatorSink
    #: The operator secret the target HMAC is taken under. The same key the
    #: cache uses, so one address has one digest across both.
    correlation_key: bytes = field(repr=False)
    cache: VerdictCache | None = None
    #: Where job identity, state, and result survive a process restart.
    #:
    #: `None` is a deployment that has none — the local-passive profile, and
    #: every test that does not care — and every call site checks, so an absent
    #: store is visibly absent rather than a silently forgetful one.
    #:
    #: **What it exists for is one property.** Without it, `_by_key` is the only
    #: record that a handle already names a job, and that record dies with the
    #: process: a resumed Phase 10 batch presenting the same deterministic
    #: handle would be answered "new" and would start a **second verification**
    #: for a row whose verification had already run. A duplicate `RCPT TO`
    #: arranged by restarting is the enumeration pattern
    #: `docs/threat-model.md` lists first, so this is a safety seam rather than
    #: a convenience.
    store: JobStore | None = None
    #: Phase 7's abuse controls, used here only for the early administrative
    #: refusal. Every budget is charged by the verification itself, so this
    #: field cannot become a second, divergent accounting of the same work.
    guard: AbuseGuard | None = None
    settings: JobSettings = field(default_factory=JobSettings)
    #: `repr=False` on both, and it is a privacy property rather than tidiness.
    #: An idempotency key is **caller-chosen text** — `IdempotencyKey` requires
    #: it to be printable and space-free and permits `@`, so
    #: `alice@example.test` is a legal key — and the generated `repr` of this
    #: service printed every one of them along with every job. Phase 7's privacy
    #: corpus found it. `docs/requirements.md` section 16 forbids a full address
    #: in an ordinary log, and a key a caller chose is exactly as sensitive as
    #: whatever they chose to put in it.
    _jobs: OrderedDict[str, CheckJob] = field(default_factory=OrderedDict, repr=False)
    _by_key: dict[tuple[str, str], _KeyBinding] = field(default_factory=dict, repr=False)
    #: `job id -> (target digest, idempotency digest)`, so a state change can be
    #: written without recomputing a digest from values it no longer holds.
    #: Digests only, and `repr=False` like everything else here.
    _persisted: dict[str, tuple[str | None, str | None]] = field(default_factory=dict, repr=False)
    #: Durable executor-handoff facts, kept separate from the public six states.
    _admissions: dict[str, JobAdmission] = field(default_factory=dict, repr=False)
    #: Jobs whose executor handoff this process owns. Rehydrated nonterminal jobs
    #: are observers and must re-read the store before being returned again.
    _owned: set[str] = field(default_factory=set, repr=False)
    #: The durable account-deletion barrier, when a deployment has one.
    #:
    #: **The cross-replica authority.** `_deleted_accounts` below is this
    #: process's own memory and a second replica cannot see it, which is exactly
    #: how a deleted account was recreated after an operator was told the
    #: deletion had finished. Every persistent write for an account is checked
    #: against the generation the work was admitted under, and this store is
    #: what every replica reads.
    #:
    #: `None` is a deployment with no such store — a single-process development
    #: stack — and every call site checks, so an absent barrier is visibly
    #: absent rather than silently permissive.
    account_state: AccountStateStore | None = None
    #: `job id -> the account generation this job was admitted under`.
    _generations: dict[str, int] = field(default_factory=dict, repr=False)
    #: Accounts whose data has been deleted in this process.
    #:
    #: **A tombstone, and the smallest one that is actually complete.** A
    #: verification already running when an account is deleted finishes some
    #: milliseconds later and writes its result — recreating, in a store the
    #: operator has just emptied, exactly the record they asked to be removed.
    #: Cancellation alone cannot close that: a worker past its last cancellation
    #: point still returns. So the write is refused instead.
    #:
    #: **Defence in depth, and not the authority.** It closes the same-process
    #: case one round trip earlier than the durable barrier would, which is
    #: worth having; it closes nothing at all across replicas, because a second
    #: `JobService` has its own empty set. `account_state` above is what makes
    #: the guarantee true, and the focused review measured what happens when a
    #: process-local set is asked to carry it alone.
    _deleted_accounts: set[str] = field(default_factory=set, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        """A persistent service without the deletion authority does not exist.

        **Fail closed at composition, not during a deletion race.** The focused
        review started a `JobService` holding a real `JobStore` and no
        `AccountStateStore`, and it wrote a deleted account's rows straight back
        — every write permitted, because there was nothing to ask. A deployment
        that persists account-owned rows participates in the deletion contract
        whether or not it was configured to, so the missing collaborator is a
        construction error with a sentence rather than a silent permission.

        A service with no store persists nothing and needs no authority: the
        local-passive profile builds no `JobService` at all, and the in-memory
        registry used by tests and by synchronous callers holds nothing a
        deletion could fail to erase.
        """
        if self.store is not None and self.account_state is None:
            raise JobError(
                "a job service with a durable store needs the account state that "
                "makes account deletion enforceable"
            )

    # --- submission ---------------------------------------------------------

    async def submit(
        self,
        submitted: str,
        *,
        principal: Principal,
        idempotency_key: IdempotencyKey | None = None,
        source: SourceIdentity | None = None,
    ) -> SubmitOutcome:
        """Accept one active check. Returns without running the SMTP half.

        Raises `IdempotencyConflict` when the key already names a different
        address, and `JobsFull` or `ExecutorFull` when there is no room. Once a
        durable identity is observable it is never deleted on admission
        failure; the same JobId remains as an operationally failed job.
        """
        account = principal.rate_limit_account

        if self.guard is not None:
            # The kill switch, before anything is spent. `docs/operations.md`
            # section 2 wants disabling active checks to be immediate, and a
            # deployment that has stopped probing should not resolve DNS to
            # discover it. The same check runs again inside the verification, so
            # this is an early exit rather than the barrier.
            self.guard.check_caller(principal=principal, active=True)

        # The passive half first: both lookups below are keyed by the normalized
        # target, and that target does not exist until the address is parsed.
        passive_outcome = await self.verification.verify(
            submitted, principal=principal, active=False, source=source
        )
        target = passive_outcome.target
        passive = public_result(passive_outcome.verdict)
        target_digest = None if target is None else self._digest(target.hmac_material)

        if idempotency_key is not None and target_digest is not None:
            existing = await self._resolve_binding(account, idempotency_key, target_digest)
            if existing is not None:
                # Same principal, same key, same address: the same job. ADR 0014
                # scopes the key to a principal, so another account's identical
                # key is a different request rather than a way to reach this one.
                return SubmitOutcome(
                    job=existing,
                    passive=passive,
                    enqueued=False,
                    existing=True,
                    scheduling_key=passive_outcome.scheduling_key,
                )

        if target is not None and self.cache is not None:
            cached = await self.cache.find(
                target, account=account, ruleset=passive_outcome.verdict.ruleset
            )
            if cached is not None:
                # `docs/architecture.md` section 6: a repeat inside the cache
                # window returns the existing result. Nothing is enqueued, and
                # nothing is probed.
                job = self._new_job(
                    account=account, state=JobState.COMPLETED, result=cached, key=idempotency_key
                )
                claimed = await self._claim(job, target_digest=target_digest)
                return SubmitOutcome(
                    job=claimed or job,
                    passive=passive,
                    enqueued=False,
                    existing=claimed is not None,
                    scheduling_key=passive_outcome.scheduling_key,
                )

        job = self._new_job(account=account, state=JobState.PENDING, key=idempotency_key)
        # **Captured before the claim, carried until the job settles.** This is
        # the value every later write for this job is checked against, so it has
        # to be read once, at admission, rather than re-read at write time —
        # re-reading would always agree with itself and would authorize a worker
        # whose account was deleted while it ran.
        self._generations[job.id.value] = await self._current_generation(account)
        # **The claim is durable before it is local**, on the same write-ahead
        # argument Phase 10's batch row uses and for one further reason
        # Remediation A added: a process that stops between enqueueing and
        # recording leaves a running verification no later process can
        # recognize, and the next presentation of the same handle would start a
        # second one. `_claim` writes the store first and registers second. Once
        # the first write commits it is observable, so a later registry refusal
        # preserves that identity as a terminal operational failure rather than
        # deleting it from underneath another replica.
        claimed = await self._claim(job, target_digest=target_digest)
        if claimed is not None:
            return SubmitOutcome(
                job=claimed,
                passive=passive,
                enqueued=False,
                existing=True,
                scheduling_key=passive_outcome.scheduling_key,
            )
        # The cross-system commit is deliberately on the conservative side.
        # `HANDOFF_COMMITTED` is durable before the executor is called, so there
        # is no "accepted, then marker write failed" boundary from which another
        # replica could infer that a second admission is safe. A crash after this
        # point may lose work; it never duplicates work.
        await self._commit_handoff(job.id)
        try:
            await self.executor.submit(job.id, self._work(job.id, submitted, principal))
        except BaseException as refusal:
            await self._fail_admission(
                job.id,
                JobFailure.CAPACITY_UNAVAILABLE
                if isinstance(refusal, ExecutorFull)
                else JobFailure.SERVICE_ERROR,
                detail="executor admission",
            )
            raise
        return SubmitOutcome(
            job=job,
            passive=passive,
            enqueued=True,
            existing=False,
            scheduling_key=passive_outcome.scheduling_key,
        )

    # --- reads and cancellation ---------------------------------------------

    def get(self, job_id: JobId, *, principal: Principal) -> CheckJob | None:
        """This caller's job, or `None`.

        `None` covers both "no such job" and "somebody else's job", and the
        caller answers `404` for both. ADR 0014: `403` would confirm that the
        identifier names a real job belonging to another account, which is the
        fact the ownership rule exists to withhold.
        """
        job = self._jobs.get(job_id.value)
        if job is None or job.owner != principal.rate_limit_account:
            return None
        return job

    async def cancel(self, job_id: JobId, *, principal: Principal) -> CheckJob | None:
        """Cancel this caller's job. Idempotent; `None` if there is no such job.

        A job already in a terminal state is returned unchanged: cancelling a
        completed job is not an error, and it must not overwrite a result.
        """
        # Refresh a nonterminal observer before acting on it. A different
        # replica may have completed or failed admission since this process
        # reconstructed the pending snapshot.
        await self.fetch(job_id, principal=principal)
        async with self._lock:
            job = self.get(job_id, principal=principal)
            if job is None:
                return None
            if job.is_terminal:
                return job
            cancelled = job.moved_to(JobState.CANCELLED, now=self._now())
            self._jobs[job_id.value] = cancelled
        await self._persist(cancelled)
        # Outside the lock: cancelling a running job resumes its coroutine,
        # which will take the lock on its way out.
        await self.executor.cancel(job_id)
        return cancelled

    # --- the worker body ----------------------------------------------------

    def _work(
        self, job_id: JobId, submitted: str, principal: Principal
    ) -> Callable[[], Awaitable[None]]:
        """Build the callable the executor will run. Captures nothing else.

        The principal is the authenticated object from the submitting request,
        carried rather than reconstructed — `domain/principal.py` grants
        identity through the authenticator alone.
        """

        async def run() -> None:
            await self._run_once(job_id, submitted, principal)

        return run

    async def _run_once(self, job_id: JobId, submitted: str, principal: Principal) -> None:
        if not await self._begin(job_id):
            return
        try:
            outcome = await self.verification.verify(submitted, principal=principal, active=True)
        except asyncio.CancelledError:
            # The job's state was set to `cancelled` before the cancellation was
            # delivered. Nothing to record, and the exception must propagate so
            # the executor knows this worker stopped on purpose.
            raise
        except VerificationRefused as refusal:
            await self._fail(job_id, JobFailure.CAPACITY_UNAVAILABLE)
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.ADMISSION_REFUSED, detail=refusal.scope)
            )
            return
        except Exception:
            # A failure of this project's own. The caller gets a category; the
            # operator gets an event; neither gets an exception message.
            await self._fail(job_id, JobFailure.SERVICE_ERROR)
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail="job execution")
            )
            return
        await self._settle(job_id, submitted, principal, outcome)

    async def _settle(
        self,
        job_id: JobId,
        submitted: str,
        principal: Principal,
        outcome: VerificationOutcome,
    ) -> None:
        """Complete the job, or schedule the one retry section 14 still allows.

        Two independently effective barriers stand between a touched recipient
        and a second one: `retry_delay_seconds` produces no delay, and
        `CheckJob.moved_to` refuses to represent `retry_scheduled`. This method's
        `touch.replay_is_safe` check remains as defense in depth at the scheduling
        seam. Removing it alone changes no reachable behaviour while the two
        stronger barriers remain; it is a local assertion, not a third
        independently mutation-pinned guarantee.
        """
        touch = outcome.recipient_touch
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state is not JobState.RUNNING:
                # Cancelled while running. The terminal state stands.
                return
            span = jitter_span_seconds(outcome.verdict, recipient_touch=touch)
            delay = retry_delay_seconds(
                outcome.verdict,
                recipient_touch=touch,
                jitter_seconds=self.random.jitter(span) if span else 0.0,
            )
            if delay is not None and touch.replay_is_safe and job.may_retry:
                scheduled = job.moved_to(
                    JobState.RETRY_SCHEDULED,
                    now=self._now(),
                    count_retry=True,
                    recipient_touch=touch,
                )
                self._jobs[job_id.value] = scheduled
            else:
                completed = job.moved_to(
                    JobState.COMPLETED,
                    now=self._now(),
                    result=public_result(outcome.verdict),
                    recipient_touch=touch,
                )
                self._jobs[job_id.value] = completed
                delay = None

        if delay is None:
            # A terminal state carrying a real verdict. The write is best effort:
            # the answer exists and refusing to return it because a disk is
            # unavailable would turn a storage fault into a lost result.
            await self._persist_best_effort(job_id)
            await self._cache(outcome, account=principal.rate_limit_account, job_id=job_id)
            return

        # A retry is different: it is a promise that something will run later, so
        # the durable record comes first and a failure to write it cancels the
        # promise rather than leaving one nobody can keep.
        if not await self._persist_step(job_id, "retry state"):
            return
        try:
            await self.executor.schedule(
                job_id, self._work(job_id, submitted, principal), delay_seconds=delay
            )
        except Exception as refusal:
            # **`retry_scheduled` with nothing scheduled is not a state this job
            # may keep.** The final system audit found it surviving here: the
            # state was persisted, the executor refused, the worker swallowed the
            # exception, and the job stayed nonterminal for ever with no work
            # anywhere that would advance it. It is terminalized instead —
            # `retry_scheduled -> failed`, added to the transition table for this
            # — with a category and no status, because failing to arrange a retry
            # is a fact about this service and not about the address.
            await self._abandon(
                job_id,
                JobFailure.CAPACITY_UNAVAILABLE
                if isinstance(refusal, ExecutorFull)
                else JobFailure.SERVICE_ERROR,
                detail="retry scheduling",
            )

    async def _cache(self, outcome: VerificationOutcome, *, account: str, job_id: JobId) -> None:
        """Store a completed active verdict, when ADR 0015 prices it."""
        if self.cache is None or outcome.target is None:
            return
        if not await self._may_write(account, job_id.value):
            # The authority check, which is what refuses a write when the
            # generation has already moved or cannot be read at all. It is not
            # the fence: the fence is inside the store's own transaction below.
            return
        written = await self.cache.save(
            outcome.target,
            account=account,
            verdict=outcome.verdict,
            route_ttl=outcome.route_ttl_seconds,
            expected_generation=await self._admitted_generation(account, job_id.value),
        )
        if not written:
            # Either the verdict was not cacheable or the store's fence refused
            # it. Only the second is worth an operator event, and the cache
            # cannot tell them apart from here, so this stays silent: the
            # refusal already did its job, which was to write nothing.
            return

    # --- registry -----------------------------------------------------------

    async def _commit_handoff(self, job_id: JobId) -> None:
        """Durably spend this logical job's one executor-admission opportunity.

        The marker precedes the executor call. That ordering turns an ambiguous
        cross-system acknowledgement into a conservative lost-work case: every
        observer sees that this JobId already owns the handoff, and no observer
        may admit it again even if the owning process disappears immediately.
        """
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state is not JobState.PENDING:
                raise JobError("only a pending job may commit an executor handoff")
            if self._admissions.get(job_id.value) is not JobAdmission.CLAIMED:
                raise JobError("a job may commit its executor handoff only once")
            self._admissions[job_id.value] = JobAdmission.HANDOFF_COMMITTED
        try:
            await self._persist_id(job_id)
        except BaseException:
            # No executor call has happened. Preserve the identity, end the
            # local job operationally, and propagate the storage failure.
            await self._fail_admission(
                job_id, JobFailure.SERVICE_ERROR, detail="job handoff commit"
            )
            raise

    async def _fail_admission(self, job_id: JobId, failure: JobFailure, *, detail: str) -> None:
        """Preserve one identity as a terminal operational admission failure."""
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.is_terminal:
                return
            self._jobs[job_id.value] = job.moved_to(
                JobState.FAILED, now=self._now(), failure=failure
            )
            self._admissions[job_id.value] = JobAdmission.ADMISSION_FAILED
        self.operator.record(OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail=detail))
        await self._persist_best_effort(job_id)

    async def _begin(self, job_id: JobId) -> bool:
        """Arm the recipient checkpoint durably, then move to `running`.

        **The checkpoint is written before the verification starts, not after it
        answers.** The crash this exists to survive is the one between writing
        `RCPT TO` to a socket and reading the reply, and a fact recorded on the
        way out is exactly the fact that crash destroys. So `running` is
        persisted carrying `MAYBE_TOUCHED` — conservative, because the
        verification *may* reach the recipient stage and nothing here can know
        whether it will — and `_settle` refines it to what actually happened.

        Returns `False` when the job is no longer runnable **and when the durable
        write failed**. The second is the point: SMTP must not proceed under a
        state the durable record cannot express, because the record is what a
        later process reads to decide whether replay is safe. Probing anyway
        would put a recipient on a wire with nothing on disk saying so.
        """
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state not in {JobState.PENDING, JobState.RETRY_SCHEDULED}:
                return False
            if self._admissions.get(job_id.value) is not JobAdmission.HANDOFF_COMMITTED:
                return False
            self._jobs[job_id.value] = job.moved_to(
                JobState.RUNNING,
                now=self._now(),
                recipient_touch=RecipientTouch.MAYBE_TOUCHED,
            )
        return await self._persist_step(job_id, "running state")

    async def _fail(self, job_id: JobId, failure: JobFailure) -> None:
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state is not JobState.RUNNING:
                return
            self._jobs[job_id.value] = job.moved_to(
                JobState.FAILED, now=self._now(), failure=failure
            )
        await self._persist_best_effort(job_id)

    async def _abandon(self, job_id: JobId, failure: JobFailure, *, detail: str) -> None:
        """End a job that cannot continue. Terminal, categorical, and no status.

        Reachable from three places, all of them this service failing rather
        than the address being anything: a durable state write that did not
        land, a retry that could not be scheduled, and a job a previous process
        left behind. None of them may become `unknown` or `temporary_unknown` —
        those are published statements about a mailbox, and this is a statement
        about a machine.
        """
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.is_terminal:
                return
            self._jobs[job_id.value] = job.moved_to(
                JobState.FAILED, now=self._now(), failure=failure
            )
        self.operator.record(OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail=detail))
        await self._persist_best_effort(job_id)

    def _new_job(
        self,
        *,
        account: str,
        state: JobState,
        result: PublicResult | None = None,
        key: IdempotencyKey | None = None,
    ) -> CheckJob:
        now = self._now()
        return CheckJob(
            id=JobId(self.random.token(JOB_ID_BYTES)),
            owner=account,
            state=state,
            created_at=now,
            updated_at=now,
            result=result,
            idempotency_key=key,
        )

    async def _claim(self, job: CheckJob, *, target_digest: str | None) -> CheckJob | None:
        """Take this job's identity, durably and then locally, or find the holder.

        Returns the job this key already names, or `None` when this caller won.
        Raises `IdempotencyConflict` when the key names a different address.

        **The order is the fix, and both halves of it matter.**

        The durable claim goes first. It is the only barrier a second process is
        subject to: an `asyncio.Lock` is invisible across replicas, and the final
        system audit measured two of them minting two jobs and two probes for one
        owner, key, and address. `JobStore.claim_idempotency` resolves that
        against a uniqueness constraint inside one transaction, so exactly one
        caller anywhere gets `NEW_CLAIM`.

        The registry goes second. Once the durable row commits it is observable
        to another replica, so a later local refusal must not delete it. A
        nonterminal proposed job is instead persisted as an operational
        admission failure under the same identity.

        The in-memory path is unchanged for deployments with no store — the lock
        still reads and writes the binding in one critical section, which is what
        two coroutines in one process need — and `submit`'s earlier lookup stays
        the fast path rather than the authority.
        """
        binding_key = self._binding_key(job.owner, job.idempotency_key, target_digest)
        claimed_durably = False
        self._admissions[job.id.value] = (
            JobAdmission.NOT_REQUIRED if job.state is JobState.COMPLETED else JobAdmission.CLAIMED
        )
        try:
            if self.store is not None:
                if binding_key is not None:
                    assert target_digest is not None
                    existing = await self._claim_durably(job, target_digest=target_digest)
                    if existing is not None:
                        self._admissions.pop(job.id.value, None)
                        return existing
                else:
                    # No key, or an address that did not parse: nothing to claim,
                    # but the record is still durable before it becomes local.
                    await self._persist(job, target_digest=target_digest)
                claimed_durably = True
            held = await self._register(job, binding_key=binding_key, target_digest=target_digest)
        except BaseException as refusal:
            if claimed_durably and self.store is not None and not job.is_terminal:
                failed = job.moved_to(
                    JobState.FAILED,
                    now=self._now(),
                    failure=(
                        JobFailure.CAPACITY_UNAVAILABLE
                        if isinstance(refusal, JobsFull)
                        else JobFailure.SERVICE_ERROR
                    ),
                )
                self._admissions[job.id.value] = JobAdmission.ADMISSION_FAILED
                held_identity = self._persisted.get(job.id.value, (target_digest, None))
                try:
                    await self.store.save(
                        _stored(
                            failed,
                            target_digest=held_identity[0],
                            idempotency=held_identity[1],
                            admission=JobAdmission.ADMISSION_FAILED,
                        ),
                        expected_generation=await self._admitted_generation(
                            job.owner, job.id.value
                        ),
                    )
                except Exception:
                    self.operator.record(
                        OperatorEvent(
                            kind=OperatorEventKind.INTERNAL_ERROR,
                            detail="job registry admission failure",
                        )
                    )
            self._persisted.pop(job.id.value, None)
            self._admissions.pop(job.id.value, None)
            self._owned.discard(job.id.value)
            raise
        if held is not None and claimed_durably:
            # The pre-lookup should make this unreachable. Deleting the newly
            # observable durable row would recreate RA-01, so fail closed.
            raise JobRecordMismatch("the local and durable idempotency bindings disagree")
        return held

    async def _claim_durably(self, job: CheckJob, *, target_digest: str) -> CheckJob | None:
        """The store's decision, translated into this layer's vocabulary."""
        assert self.store is not None
        assert job.idempotency_key is not None
        digest = self._idempotency_digest(job.owner, job.idempotency_key)
        result = await self.store.claim_idempotency(
            _stored(
                job,
                target_digest=target_digest,
                idempotency=digest,
                admission=self._admissions[job.id.value],
            ),
            expected_generation=await self._admitted_generation(job.owner, job.id.value),
        )
        if result.status is ClaimStatus.ACCOUNT_FENCED:
            # The account was erased between this submission's admission and its
            # claim. Nothing was written and nothing holds the key.
            self._refuse_write(detail="claim after account deletion")
            raise JobError("this account is not accepting new work")
        if result.status is ClaimStatus.NEW_CLAIM:
            self._persisted[job.id.value] = (target_digest, digest)
            return None
        stored = result.existing
        assert stored is not None
        if stored.owner != job.owner:
            # **The third barrier, and it is deliberately independent.** The
            # digest already carries the owner and the adapter's `WHERE` already
            # names it, so reaching here means a store answered a question it was
            # not asked. Failing closed costs one submission; trusting it hands
            # one account another account's job.
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR, detail="idempotency owner mismatch"
                )
            )
            raise JobRecordMismatch("the job store answered with another account's record")
        if result.status is ClaimStatus.CONFLICT_DIFFERENT_TARGET:
            raise IdempotencyConflict("this idempotency key is already in use")
        async with self._lock:
            return self._rehydrate(stored, key=job.idempotency_key)

    async def _register(
        self, job: CheckJob, *, binding_key: tuple[str, str] | None, target_digest: str | None
    ) -> CheckJob | None:
        """Put `job` in the registry, or return the job this key already names.

        The binding is read **and** written under one lock, so two concurrent
        submissions carrying the same key cannot both miss and both register.
        """
        async with self._lock:
            if binding_key is not None:
                assert target_digest is not None
                existing = self._existing_for(binding_key, target_digest)
                if existing is not None:
                    return existing
            self._evict()
            if len(self._jobs) >= self.settings.max_jobs:
                raise JobsFull("the job registry is at capacity")
            self._jobs[job.id.value] = job
            self._owned.add(job.id.value)
            if binding_key is not None:
                assert target_digest is not None
                self._by_key[binding_key] = _KeyBinding(job.id.value, target_digest)
            return None

    async def _resolve_binding(
        self, account: str, key: IdempotencyKey, target_digest: str
    ) -> CheckJob | None:
        """The job this key already names, or `None`. Raises on a mismatch.

        Memory is a fast path only for jobs this process owns and for terminal
        snapshots. A nonterminal job reconstructed from another replica is
        re-read: its owner may have moved `claimed` through handoff to running
        or to a terminal admission failure since this process cached it.
        """
        binding_key = (account, key.value)
        in_memory = self._existing_for(binding_key, target_digest)
        if self.store is None:
            return in_memory
        if in_memory is not None and (in_memory.id.value in self._owned or in_memory.is_terminal):
            return in_memory
        stored = await self.store.find_by_idempotency(
            account, self._idempotency_digest(account, key)
        )
        if stored is None:
            if in_memory is not None:
                self.operator.record(
                    OperatorEvent(
                        kind=OperatorEventKind.INTERNAL_ERROR,
                        detail="observed job disappeared from durable storage",
                    )
                )
                raise JobRecordMismatch("an observed durable job disappeared")
            return None
        if stored.owner != account:
            # **The third barrier, and it is deliberately independent.** The
            # digest already carries the owner and the adapter's `WHERE` already
            # names it, so reaching here means a store answered a question it
            # was not asked. Failing closed costs one duplicate submission;
            # trusting it hands one account another account's job.
            #
            # `None` rather than an error, on the Phase 6 rule: a distinct
            # answer would tell the caller that somebody else's job exists. The
            # operator is told instead, which is who can act on it.
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR, detail="idempotency owner mismatch"
                )
            )
            return None
        if stored.target_digest != target_digest:
            raise IdempotencyConflict("this idempotency key is already in use")
        async with self._lock:
            return self._rehydrate(stored, key=key)

    def _existing_for(self, binding_key: tuple[str, str], target_digest: str) -> CheckJob | None:
        binding = self._by_key.get(binding_key)
        if binding is None:
            return None
        existing = self._jobs.get(binding.job_id)
        if existing is None:
            # The job was evicted, so the logical operation is gone and the key
            # is free again. `_evict` normally removes the binding with it.
            del self._by_key[binding_key]
            return None
        if binding.target_digest != target_digest:
            raise IdempotencyConflict("this idempotency key is already in use")
        return existing

    @staticmethod
    def _binding_key(
        owner: str, key: IdempotencyKey | None, target_digest: str | None
    ) -> tuple[str, str] | None:
        """The map key, or `None` when this submission is not idempotent.

        A submission whose address did not parse has no normalized target and so
        no digest, and it is deliberately **not** recorded: idempotency exists to
        avoid duplicating expensive active work, a syntax rejection costs zero
        lookups and zero sockets, and inventing a second canonical form for
        unparseable text would be new normalization vocabulary. ADR 0014.
        """
        if key is None or target_digest is None:
            return None
        return (owner, key.value)

    def _digest(self, value: str) -> str:
        return correlation_digest(self.correlation_key, value)

    def _idempotency_digest(self, owner: str, key: IdempotencyKey) -> str:
        """The stored form of an `(owner, key)` pair.

        A **digest**, never the key. `IdempotencyKey` requires printable
        space-free text and permits an `@`, so `alice@example.test` is a legal
        key — Phase 7's privacy corpus found exactly that being printed — and a
        store holding one would be a store holding an address.
        """
        return self._digest(f"idempotency|{owner}|{key.value}")

    async def _persist(self, job: CheckJob, *, target_digest: str | None = None) -> None:
        """Write one job's current state, when this deployment has a store."""
        if self.store is None:
            return
        if not await self._may_write(job.owner, job.id.value):
            return
        held = self._persisted.get(job.id.value)
        digest = target_digest if target_digest is not None else (held or (None, None))[0]
        idempotency = (held or (None, None))[1]
        if job.idempotency_key is not None and idempotency is None:
            idempotency = self._idempotency_digest(job.owner, job.idempotency_key)
        admission = self._admissions.get(job.id.value)
        if admission is None:
            raise JobError("a persisted job must carry an executor-admission fact")
        written = await self.store.save(
            _stored(
                job,
                target_digest=digest,
                idempotency=idempotency,
                admission=admission,
            ),
            expected_generation=await self._admitted_generation(job.owner, job.id.value),
        )
        if not written:
            # The store's fence refused it inside its own write transaction.
            # This is the case no earlier check can cover: the account was
            # deleted after `_may_write` answered and before this write reached
            # the disk.
            self._refuse_write(detail="write after account deletion")
            return
        # Only a successful write authorizes later state writes to reuse these
        # immutable identity values.
        self._persisted[job.id.value] = (digest, idempotency)

    async def _admitted_generation(self, account: str, job_id: str | None) -> int:
        """The generation a write must present to this account's store fences.

        The value recorded when this process admitted the job, so a worker
        carries the generation it started under all the way to the disk. Work
        this process did not admit — a rehydrated observer, a recovery scan —
        has none recorded and presents the account's current generation, which
        is the conservative reading: it may write only while nothing has been
        deleted underneath it.
        """
        recorded = self._generations.get(job_id) if job_id is not None else None
        if recorded is not None:
            return recorded
        return await self._current_generation(account)

    async def _current_generation(self, account: str) -> int:
        """This account's generation now, or the initial one with no store."""
        if self.account_state is None:
            return INITIAL_GENERATION
        return await self.account_state.generation(account)

    async def _may_write(self, account: str, job_id: str | None) -> bool:
        """Whether work admitted for `job_id` may still persist this account's data.

        Two checks, and only the second one crosses a process boundary:

        - the local tombstone, which answers immediately for work this process
          knows was deleted;
        - the durable generation, which is the authority. The job's admitted
          generation is compared with the account's current one, so a worker
          that started before a deletion is refused even though its own process
          never saw the deletion happen.

        A store that cannot answer refuses the write. There is no safe default
        for "I could not tell whether this account still exists": persisting
        anyway is how a deletion an operator has already reported comes undone.
        """
        if account in self._deleted_accounts:
            self._refuse_write(detail="write after account deletion")
            return False
        if self.account_state is None:
            return True
        admitted = await self._admitted_generation(account, job_id)
        try:
            permitted = await self.account_state.permits(account, admitted)
        except Exception:
            self._refuse_write(detail="account state unavailable")
            return False
        if not permitted:
            self._refuse_write(detail="write after account deletion")
        return permitted

    def _refuse_write(self, *, detail: str) -> None:
        self.operator.record(OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail=detail))

    async def _persist_id(self, job_id: JobId) -> None:
        """Write whatever the registry now holds for `job_id`."""
        job = self._jobs.get(job_id.value)
        if job is not None:
            await self._persist(job)

    async def _persist_step(self, job_id: JobId, what: str) -> bool:
        """Write a state the next irreversible step depends on. `False` stops it.

        The distinction from `_persist_best_effort` is the whole protocol: a
        state that *authorizes* something — `running` authorizes an SMTP
        dialogue, `retry_scheduled` authorizes a second one — must exist on disk
        before that something happens, because the disk is what a later process
        reads. A state that merely *records* an outcome does not, and refusing to
        return a verdict because a disk was unavailable would be a worse answer
        than an unwritten row.
        """
        try:
            await self._persist_id(job_id)
        except Exception:
            await self._abandon(job_id, JobFailure.SERVICE_ERROR, detail=f"job {what}")
            return False
        return True

    async def _persist_best_effort(self, job_id: JobId) -> None:
        """Record a state that authorizes nothing. A failure is told, not raised."""
        try:
            await self._persist_id(job_id)
        except Exception:
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail="job state")
            )

    def _rehydrate(self, stored: StoredJob, *, key: IdempotencyKey | None) -> CheckJob:
        """A stored job back into the registry, with its binding restored.

        The caller has just presented the key, so the in-memory binding can be
        rebuilt from it — the store keeps only the digest, and this is the one
        moment the raw key is legitimately in hand.
        """
        job = CheckJob(
            id=JobId(stored.job_id),
            owner=stored.owner,
            state=stored.state,
            created_at=stored.created_at,
            updated_at=stored.updated_at,
            retries_used=stored.retries_used,
            result=_public(stored),
            failure=stored.failure,
            idempotency_key=key,
            recipient_touch=stored.recipient_touch,
        )
        self._jobs[job.id.value] = job
        self._admissions[job.id.value] = stored.admission
        self._owned.discard(job.id.value)
        self._persisted[job.id.value] = (stored.target_digest, stored.idempotency_digest)
        if key is not None and stored.target_digest is not None:
            self._by_key[(stored.owner, key.value)] = _KeyBinding(
                job.id.value, stored.target_digest
            )
        return job

    async def fetch(self, job_id: JobId, *, principal: Principal) -> CheckJob | None:
        """This caller's job, from the registry or from the store.

        The asynchronous half of `get`. `get` stays synchronous and in-memory
        because an API request holds a live registry; this exists for a caller
        that outlived the process which created the job — a resumed batch
        reading what its rows became.
        """
        held = self.get(job_id, principal=principal)
        if held is not None and (
            self.store is None or held.id.value in self._owned or held.is_terminal
        ):
            return held
        if self.store is None:
            return None if held is None and self.store is None else held
        stored = await self.store.load(job_id.value)
        if stored is None or stored.owner != principal.rate_limit_account:
            # The Phase 6 rule, unchanged by persistence: another account's job
            # answers exactly what an unknown identifier does.
            return None
        return self._rehydrate(stored, key=None)

    async def recover_interrupted(self, *, before: datetime, limit: int) -> RecoveryReport:
        """Classify jobs a previous process left unfinished. Enqueues nothing.

        **This is reconciliation, not resumption, and the difference is a safety
        property rather than a limitation of effort.** `ports/job_executor.py`'s
        only implementation runs in this process and dies with it, so a
        `pending`, `running`, or `retry_scheduled` row found on disk has no work
        anywhere that will advance it. Two things could be done with such a row,
        and only one of them is honest:

        - re-enqueue it, which for a `running` row means running a verification
          that may already have issued its one `RCPT TO` — a second recipient
          contact for one submitted address, decided by guessing;
        - end it as an operational failure, which says what is true: the
          operation did not finish, and this service will not finish it.

        This does the second, for **every** nonterminal row rather than only the
        armed ones. A `pending` row is provably safe to replay and is still not
        replayed here, because there is nowhere to replay it *to*; inventing a
        durable queue out of an in-memory one is the overclaim
        `docs/architecture.md` refuses to make.

        `JobFailure.INTERRUPTED` and no status. `unknown` and
        `temporary_unknown` are published statements about a mailbox, and "the
        machine stopped" is not one.

        **Cancelled and completed rows are never returned by the scan**, so this
        cannot resurrect a cancellation — a structural property of the store's
        predicate rather than a check here that could be edited away.

        `before` is a cutoff and not a convenience. A store may be shared with a
        live replica, and a scan with no cutoff would let one process declare
        another's running jobs interrupted. A handoff this process owns is
        skipped for the same reason, which covers a caller that runs this against
        a service that is already serving. Merely reconstructing another
        replica's row does not make this process its owner.
        """
        if self.store is None:
            return RecoveryReport()
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise JobError("a recovery batch must be a positive whole number")
        stored_jobs = await self.store.find_nonterminal(before=before, limit=limit)
        interrupted = 0
        unsafe = 0
        live = 0
        for stored in stored_jobs:
            if stored.job_id in self._owned:
                # This process owns its executor handoff. A merely rehydrated
                # observer has no work and may reconcile it once the cutoff says
                # the real owner is no longer plausibly live.
                live += 1
                continue
            await self.store.save(
                replace(
                    stored,
                    state=JobState.FAILED,
                    failure=JobFailure.INTERRUPTED,
                    admission=JobAdmission.INTERRUPTED,
                    updated_at=self._now(),
                ),
                # Recovery never admitted this job, so it carries the account's
                # generation as it stands now. A row whose account was deleted
                # while this scan ran is refused rather than marked interrupted,
                # which is the same answer as "there is nothing to recover".
                expected_generation=await self._current_generation(stored.owner),
            )
            interrupted += 1
            if not stored.recipient_touch.replay_is_safe:
                unsafe += 1
        if interrupted:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR, detail="interrupted jobs recovered"
                )
            )
        return RecoveryReport(
            scanned=len(stored_jobs),
            interrupted=interrupted,
            unsafe_to_replay=unsafe,
            skipped_live=live,
        )

    def forget_account(self, account: str) -> int:
        """Drop this account's registry state and refuse its later writes.

        Returns how many in-process records went — jobs and idempotency
        bindings — so a deletion report can say what the durable counts do not.

        **Three things happen, and the order is the point.** The account is
        tombstoned first, so a worker that finishes during the next two steps is
        already refused. Its live jobs are then cancelled, which stops what can
        still be stopped. Its registry entries and bindings go last, so nothing
        is republished by `get` or `fetch` after the durable rows are removed.

        Cancellation here is state only: `executor.cancel` is async and this is
        not, and a job whose worker keeps running is covered by the tombstone
        rather than by the cancellation. That is the conservative half — a
        cancelled job that ran to completion writes nothing, which is the
        property the deletion needs.
        """
        self._deleted_accounts.add(account)
        removed = 0
        for job_id, job in list(self._jobs.items()):
            if job.owner != account:
                continue
            del self._jobs[job_id]
            self._forget_bindings(job_id)
            self._forget_job_metadata(job_id)
            removed += 1
        for binding_key in [key for key in self._by_key if key[0] == account]:
            del self._by_key[binding_key]
            removed += 1
        return removed

    def purge_finished(self, *, before: datetime, limit: int) -> int:
        """Forget terminal jobs older than `before`. Returns how many went.

        `docs/privacy.md` section 3 gives plaintext request data 24 hours, and a
        finished job record is the only thing here that outlives the request
        that made it. `application/retention.py` owns the schedule and the
        lifetime; this owns the rule about *which* records may go.

        **Only terminal jobs, and their idempotency bindings with them.** A
        `pending` or `running` job removed by a sweep is work that stops
        existing while something is still waiting for it, and a binding left
        behind would point at a job nobody can fetch — the same pairing
        `_evict` already keeps, for the same two reasons.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise JobError("a purge batch must be a positive whole number")
        removed = 0
        for job_id, job in list(self._jobs.items()):
            if removed >= limit:
                break
            if not job.is_terminal or job.updated_at > before:
                continue
            del self._jobs[job_id]
            self._forget_bindings(job_id)
            self._forget_job_metadata(job_id)
            removed += 1
        return removed

    def _forget_bindings(self, job_id: str) -> None:
        """Drop every idempotency binding naming this job."""
        for binding_key, binding in list(self._by_key.items()):
            if binding.job_id == job_id:
                del self._by_key[binding_key]

    def _forget_job_metadata(self, job_id: str) -> None:
        """Drop process-local persistence and handoff metadata for one job."""
        self._persisted.pop(job_id, None)
        self._admissions.pop(job_id, None)
        self._generations.pop(job_id, None)
        self._owned.discard(job_id)

    def _evict(self) -> None:
        """Drop the oldest terminal jobs to make room. Never a live one.

        Insertion-ordered, so this removes the jobs least likely to still be
        polled. A live job is skipped rather than evicted: dropping one would
        leave the executor running work nothing can report on, and would make a
        flood of submissions a way to erase somebody else's pending job.
        """
        while len(self._jobs) >= self.settings.max_jobs:
            evictable = next(
                (key for key, job in self._jobs.items() if job.is_terminal),
                None,
            )
            if evictable is None:
                return
            removed = self._jobs.pop(evictable)
            self._forget_job_metadata(evictable)
            if removed.idempotency_key is None:
                continue
            binding_key = (removed.owner, removed.idempotency_key.value)
            binding = self._by_key.get(binding_key)
            if binding is not None and binding.job_id == removed.id.value:
                del self._by_key[binding_key]

    def _now(self) -> datetime:
        return self.clock.now()


def _stored(
    job: CheckJob,
    *,
    target_digest: str | None,
    idempotency: str | None,
    admission: JobAdmission,
) -> StoredJob:
    """A `CheckJob` as the store may keep it. A projection, never a copy.

    The submitted address is not among the parameters, so it cannot reach the
    store by being added to `CheckJob` later — the same structural argument
    `application/public_result.py` makes about `Evidence.details`.
    """
    result = job.result
    return StoredJob(
        job_id=job.id.value,
        owner=job.owner,
        state=job.state,
        admission=admission,
        created_at=job.created_at,
        updated_at=job.updated_at,
        retries_used=job.retries_used,
        idempotency_digest=idempotency,
        target_digest=target_digest,
        recipient_touch=job.recipient_touch,
        failure=job.failure,
        status=None if result is None else result.status,
        confidence=None if result is None else result.confidence,
        primary_reason=None if result is None else result.primary_reason,
        reasons=() if result is None else tuple(result.reasons),
        risk_flags=() if result is None else tuple(result.risk_flags),
        checks=(
            ()
            if result is None
            else tuple((name, check.result) for name, check in result.checks.items())
        ),
        ruleset=None if result is None else result.ruleset,
        #: **Carried, never re-asserted.** The projection used to omit this and
        #: `_public` rebuilt it as `True`, so a result that said message content
        #: *had* been sent came back from disk claiming the opposite — the
        #: strongest promise this project makes, manufactured by a reload. The
        #: final system audit measured it. `None` for a job with no result at
        #: all, which `StoredJob` pairs with a `None` status.
        no_message_data_sent=None if result is None else result.no_message_data_sent,
    )


def _public(stored: StoredJob) -> PublicResult | None:
    """The stored projection back into the type a caller is handed.

    `None` for anything but a completed job, which `StoredJob` already refuses
    to hold — so this reads a guarantee rather than making one.
    """
    if stored.status is None or stored.confidence is None or stored.ruleset is None:
        return None
    if stored.no_message_data_sent is None:
        # A completed row must carry the safety assertion it was completed with.
        # Substituting `True` here is exactly the laundering this branch
        # replaced; refusing is the only answer that does not invent one.
        raise JobError("a stored result must carry its no_message_data_sent assertion")
    return PublicResult(
        status=stored.status,
        confidence=stored.confidence,
        primary_reason=stored.primary_reason,
        reasons=stored.reasons,
        risk_flags=stored.risk_flags,
        checks={name: PublicCheck(result=value) for name, value in stored.checks},
        no_message_data_sent=stored.no_message_data_sent,
        ruleset=stored.ruleset,
    )
