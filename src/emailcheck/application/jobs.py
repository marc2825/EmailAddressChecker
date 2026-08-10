"""Accepting an active check, running it later, and answering about it.

`docs/requirements.md` section 11 makes `POST /v1/checks` create an asynchronous
job and `GET /v1/checks/{id}` return its state and result;
`prompts/06-api-cli.md` adds idempotency, a bounded retry, cancellation, and
cache lookup before enqueue. ADR 0014 records the decisions and ADR 0015 the
cache.

**Nothing here waits for SMTP.** `submit` runs the passive half — which is what
section 11's "returns passive evidence immediately when available" asks for —
and hands the active half to a `JobExecutor`. That is the requirement
`prompts/06-api-cli.md` states as "no synchronous waiting for active SMTP in API
workers", and the first Phase 6 build failed it.

**Nothing here decides a status either.** A job's result is
`application/public_result.py`'s projection of whatever `aggregate_evidence`
produced, and a job that has not completed carries no status at all: inventing
one before a verdict exists is exactly the re-derivation Phase 5 stop condition
1 forbids.

**Order of operations, as the code actually runs them:**

```text
passive check         parse + DNS; also produces the normalized target
  → idempotency       in memory, keyed by (account, key, target HMAC)
  → cache             one indexed row
  → enqueue           the SMTP half, later
```

The passive check comes **first**, because both lookups below it are keyed by
the normalized target and that target does not exist until the address has been
parsed. So a cache hit or an idempotent repeat still costs the passive DNS work;
what it avoids is the enqueue and the SMTP probe, which is the property
`prompts/06-api-cli.md` requires and the expensive half by orders of magnitude.

An earlier version of this docstring claimed the cache was consulted before the
passive step and that a hit therefore cost nothing. It was not true, and an
independent review measured three DNS lookups on a cache hit. A behavioural test
now pins the honest statement so the overclaim cannot come back.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Final

from emailcheck.application.public_result import PublicResult, public_result
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
    JobError,
    JobFailure,
    JobId,
    JobState,
    check_transition,
)
from emailcheck.domain.principal import Principal
from emailcheck.ports.clock import Clock
from emailcheck.ports.job_executor import JobExecutor
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
    idempotency_key: IdempotencyKey | None = None

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

    def moved_to(
        self,
        state: JobState,
        *,
        now: datetime,
        result: PublicResult | None = None,
        failure: JobFailure | None = None,
        count_retry: bool = False,
    ) -> CheckJob:
        """Move to `state`, or raise if `domain/job.py`'s table forbids it."""
        check_transition(self.state, state)
        return replace(
            self,
            state=state,
            updated_at=now,
            result=result,
            failure=failure,
            retries_used=self.retries_used + 1 if count_retry else self.retries_used,
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
class SubmitOutcome:
    """What a submission produced, and whether it cost anything."""

    job: CheckJob
    #: The passive half, when it was computed. `docs/requirements.md` section 11:
    #: passive evidence is returned immediately when available.
    passive: PublicResult | None
    #: Whether this submission created work. `False` for an idempotent repeat
    #: and for a cache hit, which is the property `prompts/06-api-cli.md`
    #: requires a test for.
    enqueued: bool
    #: Whether the job already existed. A caller distinguishes `202` from `200`.
    existing: bool


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
    correlation_key: bytes
    cache: VerdictCache | None = None
    settings: JobSettings = field(default_factory=JobSettings)
    _jobs: OrderedDict[str, CheckJob] = field(default_factory=OrderedDict)
    _by_key: dict[tuple[str, str], _KeyBinding] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # --- submission ---------------------------------------------------------

    async def submit(
        self,
        submitted: str,
        *,
        principal: Principal,
        idempotency_key: IdempotencyKey | None = None,
    ) -> SubmitOutcome:
        """Accept one active check. Returns without running the SMTP half.

        Raises `IdempotencyConflict` when the key already names a different
        address, and `JobsFull` or `ExecutorFull` when there is no room. None of
        the three leaves anything behind in the registry.
        """
        account = principal.rate_limit_account

        # The passive half first: both lookups below are keyed by the normalized
        # target, and that target does not exist until the address is parsed.
        passive_outcome = await self.verification.verify(
            submitted, principal=principal, active=False
        )
        target = passive_outcome.target
        passive = public_result(passive_outcome.verdict)
        target_digest = None if target is None else self._digest(target.hmac_material)

        if idempotency_key is not None and target_digest is not None:
            existing = self._resolve_binding(account, idempotency_key, target_digest)
            if existing is not None:
                # Same principal, same key, same address: the same job. ADR 0014
                # scopes the key to a principal, so another account's identical
                # key is a different request rather than a way to reach this one.
                return SubmitOutcome(job=existing, passive=passive, enqueued=False, existing=True)

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
                )

        job = self._new_job(account=account, state=JobState.PENDING, key=idempotency_key)
        claimed = await self._claim(job, target_digest=target_digest)
        if claimed is not None:
            return SubmitOutcome(job=claimed, passive=passive, enqueued=False, existing=True)
        try:
            await self.executor.submit(job.id, self._work(job.id, submitted, principal))
        except BaseException:
            # **The registry is rolled back.** A `pending` job the executor never
            # accepted can never run, and `_evict` only removes *terminal* jobs —
            # so leaving one behind would occupy a registry slot permanently, and
            # a burst of refusals would make the service answer `JobsFull` for
            # ever, long after the executor recovered. An independent review
            # measured exactly that. `BaseException` because a cancellation
            # between registering and enqueueing leaves the same wreckage.
            await self._release(job)
            raise
        return SubmitOutcome(job=job, passive=passive, enqueued=True, existing=False)

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
        async with self._lock:
            job = self.get(job_id, principal=principal)
            if job is None:
                return None
            if job.is_terminal:
                return job
            cancelled = job.moved_to(JobState.CANCELLED, now=self._now())
            self._jobs[job_id.value] = cancelled
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
        """Complete the job, or schedule the one retry section 14 allows."""
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state is not JobState.RUNNING:
                # Cancelled while running. The terminal state stands.
                return
            span = jitter_span_seconds(outcome.verdict)
            delay = retry_delay_seconds(
                outcome.verdict, jitter_seconds=self.random.jitter(span) if span else 0.0
            )
            if delay is not None and job.may_retry:
                scheduled = job.moved_to(
                    JobState.RETRY_SCHEDULED, now=self._now(), count_retry=True
                )
                self._jobs[job_id.value] = scheduled
            else:
                completed = job.moved_to(
                    JobState.COMPLETED, now=self._now(), result=public_result(outcome.verdict)
                )
                self._jobs[job_id.value] = completed
                delay = None

        if delay is not None:
            await self.executor.schedule(
                job_id, self._work(job_id, submitted, principal), delay_seconds=delay
            )
            return
        await self._cache(outcome, account=principal.rate_limit_account)

    async def _cache(self, outcome: VerificationOutcome, *, account: str) -> None:
        """Store a completed active verdict, when ADR 0015 prices it."""
        if self.cache is None or outcome.target is None:
            return
        await self.cache.save(
            outcome.target,
            account=account,
            verdict=outcome.verdict,
            route_ttl=outcome.route_ttl_seconds,
        )

    # --- registry -----------------------------------------------------------

    async def _begin(self, job_id: JobId) -> bool:
        """Move to `running`, or report that the job is no longer runnable."""
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state not in {JobState.PENDING, JobState.RETRY_SCHEDULED}:
                return False
            self._jobs[job_id.value] = job.moved_to(JobState.RUNNING, now=self._now())
            return True

    async def _fail(self, job_id: JobId, failure: JobFailure) -> None:
        async with self._lock:
            job = self._jobs.get(job_id.value)
            if job is None or job.state is not JobState.RUNNING:
                return
            self._jobs[job_id.value] = job.moved_to(
                JobState.FAILED, now=self._now(), failure=failure
            )

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
        """Register `job`, or return the job this key already names.

        The binding is read **and** written under one lock, so two concurrent
        submissions carrying the same key cannot both miss and both register.
        The read-only check in `submit` is the fast path; this is the
        authoritative one.
        """
        async with self._lock:
            binding_key = self._binding_key(job.owner, job.idempotency_key, target_digest)
            if binding_key is not None:
                assert target_digest is not None
                existing = self._existing_for(binding_key, target_digest)
                if existing is not None:
                    return existing
            self._evict()
            if len(self._jobs) >= self.settings.max_jobs:
                raise JobsFull("the job registry is at capacity")
            self._jobs[job.id.value] = job
            if binding_key is not None:
                assert target_digest is not None
                self._by_key[binding_key] = _KeyBinding(job.id.value, target_digest)
            return None

    async def _release(self, job: CheckJob) -> None:
        """Undo a claim. Used when the work could not be handed to an executor.

        Removes the binding only when it still points at *this* job, so a
        rollback can never free a key another submission has since taken.
        """
        async with self._lock:
            self._jobs.pop(job.id.value, None)
            if job.idempotency_key is None:
                return
            binding_key = (job.owner, job.idempotency_key.value)
            binding = self._by_key.get(binding_key)
            if binding is not None and binding.job_id == job.id.value:
                del self._by_key[binding_key]

    def _resolve_binding(
        self, account: str, key: IdempotencyKey, target_digest: str
    ) -> CheckJob | None:
        """The job this key already names, or `None`. Raises on a mismatch."""
        return self._existing_for((account, key.value), target_digest)

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
            if removed.idempotency_key is None:
                continue
            binding_key = (removed.owner, removed.idempotency_key.value)
            binding = self._by_key.get(binding_key)
            if binding is not None and binding.job_id == removed.id.value:
                del self._by_key[binding_key]

    def _now(self) -> datetime:
        return self.clock.now()
