"""The job service: submission order, ownership, retry, and the registry bound.

`prompts/06-api-cli.md` fixes the behaviour and ADR 0014 the decisions. The two
measurements that recur are the ones only checkable here: the executor counts
whether anything was enqueued, and the SMTP fake counts whether anything was
probed. "A cache hit skips the enqueue" is a count of zero rather than a claim
that the work was cheap.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from tests.phase6_fixtures import (
    OBSERVED_AT,
    PRINCIPAL,
    BarrierVerdictStore,
    FakeClock,
    FakeRandomSource,
    GatedSMTPVerification,
    InMemoryVerdictStore,
    RecordingExecutor,
    ScriptedSMTPVerification,
    build_service,
    connection_timeout_evidence,
    empty_result,
    resolver_with_route,
    resolver_with_temporary_failure,
)

from emailcheck.application.jobs import (
    CheckJob,
    IdempotencyConflict,
    JobService,
    JobSettings,
    JobsFull,
)
from emailcheck.application.retry import RETRY_AFTER_SECONDS
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.job import IdempotencyKey, JobError, JobFailure, JobId, JobState
from emailcheck.domain.principal import Principal
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.verdict import Status
from emailcheck.ports.job_executor import ExecutorFull
from emailcheck.security.identifiers import correlation_digest

pytestmark = pytest.mark.asyncio

VALID = "user@example.test"
OTHER = Principal(account_id="acct-other")
CORRELATION_KEY = b"correlation-secret-of-thirty-two"
OUTER_BOUND = 5.0


class Harness:
    def __init__(
        self,
        *,
        smtp: ScriptedSMTPVerification | None = None,
        store: InMemoryVerdictStore | None = None,
        **kwargs: object,
    ) -> None:
        self.smtp = (
            smtp if smtp is not None else ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
        )
        self.service, self.resolver, self.sink = build_service(
            resolver=resolver_with_route(), smtp=self.smtp
        )
        self.executor = RecordingExecutor()
        self.store = store if store is not None else InMemoryVerdictStore()
        self.random = FakeRandomSource()
        self.cache = VerdictCache(
            store=self.store,
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec"),
            correlation_key=CORRELATION_KEY,
        )
        self.jobs = JobService(
            verification=self.service,
            executor=self.executor,
            clock=FakeClock(),
            random=self.random,
            operator=self.sink,
            correlation_key=CORRELATION_KEY,
            cache=self.cache,
            **kwargs,  # type: ignore[arg-type]
        )

    async def submit(self, principal: Principal = PRINCIPAL, **kwargs: object) -> CheckJob:
        outcome = await self.jobs.submit(VALID, principal=principal, **kwargs)  # type: ignore[arg-type]
        self.last = outcome
        return outcome.job


# --- submission returns without probing -------------------------------------


async def test_submission_creates_a_pending_job_and_probes_nothing() -> None:
    """`prompts/06-api-cli.md`: no synchronous waiting for active SMTP."""
    harness = Harness()
    job = await harness.submit()

    assert job.state is JobState.PENDING
    assert job.result is None
    assert job.owner == PRINCIPAL.rate_limit_account
    assert harness.smtp.calls == []
    assert harness.executor.submitted == [job.id.value]


async def test_submission_returns_the_passive_evidence_it_already_had() -> None:
    """`docs/requirements.md` section 11: passive evidence when available."""
    harness = Harness()
    await harness.submit()

    assert harness.last.passive is not None
    assert harness.last.passive.status == Status.UNKNOWN.value


async def test_running_the_job_completes_it_with_the_aggregators_verdict() -> None:
    harness = Harness()
    job = await harness.submit()
    await harness.executor.run_pending()

    finished = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert finished is not None
    assert finished.state is JobState.COMPLETED
    assert finished.result is not None
    assert finished.result.status == Status.LIKELY_DELIVERABLE.value
    assert len(harness.smtp.calls) == 1


async def test_a_job_identifier_is_unguessable_rather_than_sequential() -> None:
    """ADR 0014: not an incrementing integer, a timestamp, or a hash of the
    address. The generator is a `RandomSource`; here it only has to be the
    thing that produced the identifier."""
    harness = Harness()
    job = await harness.submit()

    assert harness.random.issued == 1
    assert job.id.value.startswith("job-")
    assert "example.test" not in job.id.value
    assert PRINCIPAL.account_id not in job.id.value


# --- idempotency ------------------------------------------------------------


async def test_the_same_key_from_the_same_principal_returns_the_same_job() -> None:
    """`prompts/06-api-cli.md`: idempotency returns the same job."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    first = await harness.submit(idempotency_key=key)
    second = await harness.submit(idempotency_key=key)

    assert first.id == second.id
    assert harness.executor.submitted == [first.id.value]
    assert harness.last.enqueued is False
    assert harness.last.existing is True


async def test_the_same_key_from_another_principal_is_a_different_job() -> None:
    """ADR 0014 scopes the key to a principal. A global key space would return
    one caller's job to another."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    mine = await harness.submit(PRINCIPAL, idempotency_key=key)
    theirs = await harness.submit(OTHER, idempotency_key=key)

    assert mine.id != theirs.id
    assert theirs.owner == OTHER.rate_limit_account
    assert len(harness.executor.submitted) == 2


async def test_a_submission_without_a_key_is_never_deduplicated() -> None:
    harness = Harness()
    first = await harness.submit()
    second = await harness.submit()

    assert first.id != second.id
    assert len(harness.executor.submitted) == 2


# --- the cache comes before the enqueue -------------------------------------


async def test_a_cache_hit_enqueues_nothing_and_probes_nothing() -> None:
    """`prompts/06-api-cli.md`: cache lookup before enqueue; cache hit skips it.

    The first submission runs and stores; the second finds the row and never
    reaches the executor. Both counts are asserted, because "it was fast" is not
    the property.
    """
    harness = Harness()
    first = await harness.submit()
    await harness.executor.run_pending()
    assert harness.store.saves == 1

    probes_before = len(harness.smtp.calls)
    second = await harness.submit()

    assert second.id != first.id
    assert second.state is JobState.COMPLETED
    assert second.result is not None
    assert second.result.status == Status.LIKELY_DELIVERABLE.value
    assert harness.last.enqueued is False
    assert harness.executor.submitted == [first.id.value]
    assert len(harness.smtp.calls) == probes_before


async def test_the_cache_is_consulted_before_the_executor_is_touched() -> None:
    """Ordering as an ordering, not as an outcome.

    A build that enqueued first and looked afterwards would still answer from
    the cache — and would still have spent an executor slot and an SMTP session
    doing it.
    """
    harness = Harness()
    await harness.submit()
    await harness.executor.run_pending()
    harness.store.finds = 0
    harness.executor.submitted.clear()

    await harness.submit()

    assert harness.store.finds == 1
    assert harness.executor.submitted == []


async def test_another_account_does_not_read_this_accounts_cached_row() -> None:
    """ADR 0015 keeps the account in the key. A shared row is the quietest way
    to hand one account another account's answer."""
    harness = Harness()
    await harness.submit(PRINCIPAL)
    await harness.executor.run_pending()
    harness.executor.submitted.clear()

    theirs = await harness.submit(OTHER)

    assert theirs.state is JobState.PENDING
    assert harness.executor.submitted == [theirs.id.value]


async def test_an_expired_row_is_not_a_hit() -> None:
    harness = Harness()
    await harness.submit()
    await harness.executor.run_pending()
    row = harness.store.rows[0]
    harness.store.rows = [
        type(row)(
            **{
                **{name: getattr(row, name) for name in row.__dataclass_fields__},
                "created_at": OBSERVED_AT - timedelta(days=2),
                "expires_at": OBSERVED_AT - timedelta(days=1),
            }
        )
    ]
    harness.executor.submitted.clear()

    job = await harness.submit()

    assert job.state is JobState.PENDING
    assert harness.executor.submitted == [job.id.value]


async def test_an_unpriced_verdict_is_never_stored() -> None:
    """ADR 0015: a class section 13 does not price is not cached at all."""
    harness = Harness(smtp=ScriptedSMTPVerification(reply_lines=("252 cannot verify",)))
    await harness.submit()
    await harness.executor.run_pending()

    assert harness.store.saves == 0


# --- the one retry section 14 allows ----------------------------------------


async def test_a_temporary_dns_failure_schedules_exactly_one_retry() -> None:
    """`docs/requirements.md` section 14: DNS SERVFAIL, one retry."""
    harness = Harness()
    harness.service, _, harness.sink = build_service(
        resolver=resolver_with_temporary_failure(), smtp=harness.smtp
    )
    harness.jobs.verification = harness.service

    job = await harness.submit()
    await harness.executor.run_pending()

    scheduled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert scheduled is not None
    assert scheduled.state is JobState.RETRY_SCHEDULED
    assert scheduled.retries_used == 1
    assert harness.executor.scheduled == [
        (job.id.value, float(RETRY_AFTER_SECONDS[ReasonCode.DNS_TEMPORARY_FAILURE]))
    ]


async def test_a_second_retry_is_impossible() -> None:
    """The budget is on the job, so it cannot be arranged by re-enqueueing."""
    harness = Harness()
    harness.service, _, _ = build_service(
        resolver=resolver_with_temporary_failure(), smtp=harness.smtp
    )
    harness.jobs.verification = harness.service

    job = await harness.submit()
    await harness.executor.run_pending()  # first attempt -> retry_scheduled
    await harness.executor.run_pending()  # the retry itself

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.COMPLETED
    assert settled.retries_used == 1
    assert len(harness.executor.scheduled) == 1


@pytest.mark.parametrize(
    "lines",
    [
        ("250 2.1.5 ok",),
        ("252 cannot verify",),
        ("550 5.1.1 user unknown",),
        ("550 rejected",),
        ("550 5.7.1 not permitted",),
    ],
    ids=["accepted", "unverifiable", "rejected address", "bare 550", "policy"],
)
async def test_a_recipient_answer_is_never_re_probed(lines: tuple[str, ...]) -> None:
    """Section 14 permits a retry for three named conditions. A recipient
    answer of any class is not one of them, and re-probing after one would be a
    second `RCPT TO` for the same address twenty minutes later."""
    harness = Harness(smtp=ScriptedSMTPVerification(reply_lines=lines))
    job = await harness.submit()
    await harness.executor.run_pending()

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.COMPLETED
    assert harness.executor.scheduled == []
    assert len(harness.smtp.calls) == 1


# --- ownership --------------------------------------------------------------


async def test_only_the_owner_reads_the_job() -> None:
    harness = Harness()
    job = await harness.submit(PRINCIPAL)

    assert harness.jobs.get(job.id, principal=PRINCIPAL) is not None
    assert harness.jobs.get(job.id, principal=OTHER) is None


async def test_only_the_owner_cancels_the_job() -> None:
    harness = Harness()
    job = await harness.submit(PRINCIPAL)

    assert await harness.jobs.cancel(job.id, principal=OTHER) is None
    assert harness.executor.cancelled == []

    cancelled = await harness.jobs.cancel(job.id, principal=PRINCIPAL)
    assert cancelled is not None
    assert cancelled.state is JobState.CANCELLED
    assert harness.executor.cancelled == [job.id.value]


async def test_an_unknown_identifier_is_indistinguishable_from_a_foreign_one() -> None:
    harness = Harness()
    job = await harness.submit(PRINCIPAL)
    unknown = JobId("nosuchjobnosuchjobnosuch")

    assert harness.jobs.get(job.id, principal=OTHER) is None
    assert harness.jobs.get(unknown, principal=OTHER) is None


# --- cancellation semantics -------------------------------------------------


async def test_cancelling_a_cancelled_job_changes_nothing() -> None:
    harness = Harness()
    job = await harness.submit()

    first = await harness.jobs.cancel(job.id, principal=PRINCIPAL)
    second = await harness.jobs.cancel(job.id, principal=PRINCIPAL)

    assert first is not None and second is not None
    assert first.state is second.state is JobState.CANCELLED
    assert second.updated_at == first.updated_at


async def test_cancelling_a_completed_job_does_not_overwrite_its_result() -> None:
    harness = Harness()
    job = await harness.submit()
    await harness.executor.run_pending()

    cancelled = await harness.jobs.cancel(job.id, principal=PRINCIPAL)

    assert cancelled is not None
    assert cancelled.state is JobState.COMPLETED
    assert cancelled.result is not None


async def test_a_cancelled_job_that_still_runs_does_not_become_completed() -> None:
    """The race the lock exists for: a worker finishing after a cancellation.

    `completed` after `cancelled` would be a terminal state overwritten, and a
    caller told the work stopped and then told it did not.
    """
    harness = Harness()
    job = await harness.submit()
    await harness.jobs.cancel(job.id, principal=PRINCIPAL)
    await harness.executor.run_pending()

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.CANCELLED
    assert settled.result is None


# --- failure ----------------------------------------------------------------


async def test_a_failure_of_our_own_becomes_a_category_and_an_operator_event() -> None:
    harness = Harness(smtp=ScriptedSMTPVerification(raises=RuntimeError("a secret detail")))
    job = await harness.submit()
    await harness.executor.run_pending()

    failed = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert failed is not None
    assert failed.state is JobState.FAILED
    assert failed.failure is not None
    assert failed.result is None
    assert "a secret detail" not in failed.failure.value
    assert "internal_error" in harness.sink.kinds()


# --- the registry is bounded ------------------------------------------------


async def test_the_registry_evicts_finished_jobs_rather_than_growing() -> None:
    harness = Harness(settings=JobSettings(max_jobs=4))
    for _ in range(20):
        job = await harness.submit()
        await harness.jobs.cancel(job.id, principal=PRINCIPAL)

    assert len(harness.jobs._jobs) <= 4


async def test_the_registry_never_evicts_a_live_job() -> None:
    """Dropping a pending job would leave the executor running work nothing can
    report on, and would make a flood of submissions a way to erase somebody
    else's job."""
    harness = Harness(settings=JobSettings(max_jobs=3))
    kept = await harness.submit()
    for _ in range(2):
        extra = await harness.submit()
        await harness.jobs.cancel(extra.id, principal=PRINCIPAL)

    with pytest.raises(JobsFull):
        for _ in range(10):
            await harness.submit()

    assert harness.jobs.get(kept.id, principal=PRINCIPAL) is not None


async def test_evicting_a_job_forgets_its_idempotency_key_too() -> None:
    """Otherwise the key map is the unbounded thing instead."""
    harness = Harness(settings=JobSettings(max_jobs=3))
    for index in range(20):
        job = await harness.submit(idempotency_key=IdempotencyKey(f"key-{index:04d}"))
        await harness.jobs.cancel(job.id, principal=PRINCIPAL)

    assert len(harness.jobs._by_key) <= 3


# --- the record type --------------------------------------------------------


async def test_a_job_may_not_carry_a_result_outside_completed() -> None:
    with pytest.raises(JobError, match="only a completed job"):
        CheckJob(
            id=JobId("a" * 24),
            owner="acct-1",
            state=JobState.PENDING,
            created_at=OBSERVED_AT,
            updated_at=OBSERVED_AT,
            result=empty_result(),
        )


async def test_a_completed_job_must_carry_one() -> None:
    with pytest.raises(JobError, match="must carry a result"):
        CheckJob(
            id=JobId("a" * 24),
            owner="acct-1",
            state=JobState.COMPLETED,
            created_at=OBSERVED_AT,
            updated_at=OBSERVED_AT,
        )


async def test_a_job_refuses_more_retries_than_section_14_allows() -> None:
    with pytest.raises(JobError, match="at most 1"):
        CheckJob(
            id=JobId("a" * 24),
            owner="acct-1",
            state=JobState.PENDING,
            created_at=OBSERVED_AT,
            updated_at=OBSERVED_AT,
            retries_used=2,
        )


async def test_a_job_refuses_a_naive_timestamp() -> None:
    from datetime import datetime

    with pytest.raises(JobError, match="aware datetime"):
        CheckJob(
            id=JobId("a" * 24),
            owner="acct-1",
            state=JobState.PENDING,
            created_at=datetime(2026, 8, 10),
            updated_at=OBSERVED_AT,
        )


async def test_two_submissions_do_not_block_each_other() -> None:
    """The registry lock is held around bookkeeping, never around a probe."""
    harness = Harness()
    async with asyncio.timeout(OUTER_BOUND):
        jobs = await asyncio.gather(
            harness.jobs.submit(VALID, principal=PRINCIPAL),
            harness.jobs.submit(VALID, principal=OTHER),
        )
    assert jobs[0].job.id != jobs[1].job.id


async def test_a_cancellation_landing_mid_flight_is_not_overwritten_by_the_result() -> None:
    """The race `_settle`'s guard exists for, driven rather than assumed.

    The worker is inside the SMTP step when the cancellation arrives, so it
    finishes its verification afterwards and reaches the settling code with a
    verdict in hand. `completed` after `cancelled` would be a terminal state
    overwritten and a caller told the work stopped and then told it did not.

    An earlier version of this test cancelled a job that was still *queued*, so
    the fake executor simply removed the work and the settling code was never
    reached at all — a mutation of that guard escaped the whole suite.
    """
    gate = asyncio.Event()
    harness = Harness(smtp=GatedSMTPVerification(gate=gate, reply_lines=("250 2.1.5 ok",)))
    job = await harness.submit()

    async with asyncio.timeout(OUTER_BOUND):
        worker = asyncio.create_task(harness.executor.run_pending())
        await harness.smtp.entered.wait()

        cancelled = await harness.jobs.cancel(job.id, principal=PRINCIPAL)
        assert cancelled is not None
        assert cancelled.state is JobState.CANCELLED

        gate.set()
        await worker

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.CANCELLED
    assert settled.result is None
    assert harness.store.saves == 0


async def test_a_cancellation_landing_mid_flight_schedules_no_retry() -> None:
    """The other half: a cancelled job must not come back as `retry_scheduled`."""
    gate = asyncio.Event()
    # A temporary *SMTP* answer rather than a temporary DNS one, so the gate is
    # inside the verification: with no route there is no SMTP step to hold, and
    # the cancellation would land after the job had already settled — which is
    # legal, and not the race being tested.
    harness = Harness(
        smtp=GatedSMTPVerification(gate=gate, reply_lines=("450 4.2.1 mailbox busy",))
    )
    job = await harness.submit()

    async with asyncio.timeout(OUTER_BOUND):
        worker = asyncio.create_task(harness.executor.run_pending())
        await harness.smtp.entered.wait()
        await harness.jobs.cancel(job.id, principal=PRINCIPAL)
        gate.set()
        await worker

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled is not None
    assert settled.state is JobState.CANCELLED
    assert harness.executor.scheduled == []


# --- F2: the idempotency identity includes the target ----------------------
#
# `docs/architecture.md` section 6: "An active request has an idempotency key
# **and a derived target HMAC**." An earlier build keyed on `(account, key)`
# alone, so reusing a key with a different address returned the *first*
# address's job — a confident verdict about a mailbox nobody asked about.


async def test_the_same_key_and_the_same_address_return_the_same_job() -> None:
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    first = await harness.jobs.submit(
        "alice@example.test", principal=PRINCIPAL, idempotency_key=key
    )
    second = await harness.jobs.submit(
        "alice@example.test", principal=PRINCIPAL, idempotency_key=key
    )

    assert first.job.id == second.job.id
    assert second.enqueued is False
    assert second.existing is True
    assert harness.executor.submitted == [first.job.id.value]


async def test_the_same_key_with_a_different_address_is_a_conflict() -> None:
    """It must never answer with the first address's job."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")
    first = await harness.jobs.submit(
        "alice@example.test", principal=PRINCIPAL, idempotency_key=key
    )

    with pytest.raises(IdempotencyConflict):
        await harness.jobs.submit("bob@example.test", principal=PRINCIPAL, idempotency_key=key)

    # Nothing new was created, and Alice's job is untouched.
    assert harness.executor.submitted == [first.job.id.value]
    assert len(harness.jobs._jobs) == 1
    assert harness.jobs.get(first.job.id, principal=PRINCIPAL).state is JobState.PENDING


async def test_a_conflict_reveals_nothing_about_the_other_address() -> None:
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")
    await harness.jobs.submit("alice@secret-domain.test", principal=PRINCIPAL, idempotency_key=key)

    with pytest.raises(IdempotencyConflict) as conflict:
        await harness.jobs.submit("bob@example.test", principal=PRINCIPAL, idempotency_key=key)

    message = str(conflict.value)
    for forbidden in ("alice", "secret-domain", "bob", "@"):
        assert forbidden not in message


async def test_the_same_key_from_another_principal_is_an_independent_namespace() -> None:
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    mine = await harness.jobs.submit("alice@example.test", principal=PRINCIPAL, idempotency_key=key)
    theirs = await harness.jobs.submit("bob@example.test", principal=OTHER, idempotency_key=key)

    assert mine.job.id != theirs.job.id
    assert theirs.job.owner == OTHER.rate_limit_account
    assert len(harness.executor.submitted) == 2


async def test_addresses_phase_1_normalizes_together_share_one_identity() -> None:
    """The digest is taken over `NormalizedAddress.hmac_material`, so the
    identity follows Phase 1's normalization exactly: the domain is lower-cased
    and the local part is not rewritten."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    first = await harness.jobs.submit(
        "alice@EXAMPLE.test", principal=PRINCIPAL, idempotency_key=key
    )
    second = await harness.jobs.submit(
        "alice@example.test", principal=PRINCIPAL, idempotency_key=key
    )
    assert first.job.id == second.job.id

    # The local part is case-significant, so this is a different address.
    with pytest.raises(IdempotencyConflict):
        await harness.jobs.submit("ALICE@example.test", principal=PRINCIPAL, idempotency_key=key)


async def test_a_rejected_address_records_no_idempotency_binding() -> None:
    """No normalized target means no digest, and idempotency exists to avoid
    duplicating expensive active work — a syntax rejection costs none."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")

    await harness.jobs.submit("not-an-address", principal=PRINCIPAL, idempotency_key=key)
    assert harness.jobs._by_key == {}

    # A later valid submission with the same key is free to claim it.
    later = await harness.jobs.submit(
        "alice@example.test", principal=PRINCIPAL, idempotency_key=key
    )
    assert later.existing is False


# --- F3: an executor refusal leaves one stable terminal identity ------------


async def test_an_executor_refusal_leaves_one_terminal_operational_job() -> None:
    harness = Harness(settings=JobSettings(max_jobs=6))
    harness.executor.full = True

    with pytest.raises(ExecutorFull):
        await harness.jobs.submit(VALID, principal=PRINCIPAL)

    assert len(harness.jobs._jobs) == 1
    failed = next(iter(harness.jobs._jobs.values()))
    assert failed.state is JobState.FAILED
    assert failed.failure is JobFailure.CAPACITY_UNAVAILABLE
    assert failed.result is None
    assert harness.jobs._by_key == {}


async def test_repeated_executor_refusals_do_not_poison_the_registry() -> None:
    """The behavioural proof. An earlier build registered before enqueueing, and
    `_evict` only removes *terminal* jobs — so every refusal left an
    un-evictable `pending` orphan and the service answered `JobsFull` for ever,
    long after the executor recovered."""
    harness = Harness(settings=JobSettings(max_jobs=4))
    harness.executor.full = True

    for _ in range(50):
        with pytest.raises(ExecutorFull):
            await harness.jobs.submit(VALID, principal=PRINCIPAL)

    assert len(harness.jobs._jobs) == harness.jobs.settings.max_jobs
    assert all(job.is_terminal for job in harness.jobs._jobs.values())

    harness.executor.full = False
    healthy = await harness.jobs.submit(VALID, principal=PRINCIPAL)
    assert healthy.job.state is JobState.PENDING
    assert harness.executor.submitted == [healthy.job.id.value]
    assert len(harness.jobs._jobs) <= harness.jobs.settings.max_jobs


async def test_an_executor_refusal_preserves_the_idempotency_winner() -> None:
    """An observable identity never becomes available to a second operation."""
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")
    harness.executor.full = True

    with pytest.raises(ExecutorFull):
        await harness.jobs.submit(VALID, principal=PRINCIPAL, idempotency_key=key)
    binding = harness.jobs._by_key[(PRINCIPAL.rate_limit_account, key.value)]
    failed = harness.jobs._jobs[binding.job_id]
    assert failed.state is JobState.FAILED

    harness.executor.full = False
    recovered = await harness.jobs.submit(VALID, principal=PRINCIPAL, idempotency_key=key)
    assert recovered.job.id == failed.id
    assert recovered.enqueued is False
    assert recovered.existing is True
    assert harness.executor.submitted == []


async def test_a_repeat_never_changes_the_existing_successful_binding() -> None:
    harness = Harness()
    key = IdempotencyKey("order-4711-attempt-1")
    winner = await harness.jobs.submit(VALID, principal=PRINCIPAL, idempotency_key=key)

    harness.executor.full = True
    repeated = await harness.jobs.submit(VALID, principal=PRINCIPAL, idempotency_key=key)

    binding = harness.jobs._by_key[(PRINCIPAL.rate_limit_account, key.value)]
    assert binding.job_id == winner.job.id.value
    assert repeated.job.id == winner.job.id
    assert repeated.enqueued is False


async def test_a_job_is_discoverable_before_the_executor_is_told_about_it() -> None:
    """A worker must never run a job the registry cannot answer for.

    Registration happens first, and `InMemoryJobExecutor.submit` reaches no
    `await` before it enqueues, so no worker can start earlier. This asserts the
    ordering at the seam rather than trusting it.
    """
    harness = Harness()
    seen: list[bool] = []

    async def submit(job_id, work):  # type: ignore[no-untyped-def]
        seen.append(job_id.value in harness.jobs._jobs)

    harness.executor.submit = submit  # type: ignore[method-assign]
    await harness.jobs.submit(VALID, principal=PRINCIPAL)
    assert seen == [True]


# --- F4: the documented order is the one the code has ----------------------


async def test_a_cache_hit_still_costs_the_passive_lookup_and_that_is_documented() -> None:
    """The honest statement, pinned so the overclaim cannot come back.

    Both lookups are keyed by the normalized target, which does not exist until
    the address is parsed — so the passive step runs first and a cache hit costs
    it. What a hit avoids is the enqueue and the SMTP probe, and that is the
    property `prompts/06-api-cli.md` actually requires.
    """
    harness = Harness()
    await harness.submit()
    await harness.executor.run_pending()
    harness.resolver.calls.clear()
    harness.executor.submitted.clear()
    probes = len(harness.smtp.calls)

    hit = await harness.submit()

    assert hit.state is JobState.COMPLETED
    assert harness.executor.submitted == []
    assert len(harness.smtp.calls) == probes
    # And the part an earlier docstring denied:
    assert harness.resolver.calls != []


# --- the one-retry bound, for every retryable reason -----------------------


@pytest.mark.parametrize(
    "lines",
    [
        ("450 4.2.1 busy",),
        ("451 4.3.0 local error",),
        ("452 4.2.2 over quota",),
        ("552 5.2.2 mailbox full",),
    ],
    ids=["450", "451", "452", "552 5.2.2"],
)
async def test_a_temporary_recipient_reply_is_settled_rather_than_replayed(
    lines: tuple[str, ...],
) -> None:
    """The finding, as the behaviour that now holds.

    These four replies are `docs/requirements.md` section 14's "explicit
    temporary SMTP response", and the previous build retried every one of them.
    Each is also, necessarily, a reply to `RCPT TO` — `smtp_temporary_failure`
    and `mailbox_full` are produced nowhere else — so the retry was a **second
    recipient contact for one submitted address**, twenty minutes later. The
    final system audit counted two `RCPT TO` commands on the wire for one job.

    So the job settles on the first answer. `retries_used` stays at zero,
    because no retry was spent rather than one being spent and refused, and the
    verification ran exactly once.
    """
    harness = Harness(smtp=ScriptedSMTPVerification(reply_lines=lines))
    job = await harness.submit()

    await harness.executor.run_pending()
    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled.state is JobState.COMPLETED
    assert settled.retries_used == 0
    assert harness.executor.scheduled == [], "a touched recipient was scheduled for a second visit"
    assert len(harness.smtp.calls) == 1

    # Running the work again cannot revive it: the table refuses every exit
    # from a terminal state.
    await harness.executor.run_pending()
    assert harness.jobs.get(job.id, principal=PRINCIPAL).state is JobState.COMPLETED
    assert len(harness.smtp.calls) == 1


async def test_the_recipient_touch_is_recorded_on_the_job_that_settled() -> None:
    """Not inferred from the status later. `temporary_unknown` is reachable from
    a DNS SERVFAIL that opened no socket and from a `451` at `RCPT TO`, so the
    fact has to travel with the job rather than being re-derived from it."""
    harness = Harness(smtp=ScriptedSMTPVerification(reply_lines=("451 4.3.0 later",)))
    job = await harness.submit()
    await harness.executor.run_pending()

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled.recipient_touch is RecipientTouch.MAYBE_TOUCHED
    assert settled.replay_is_safe is False


async def test_one_retry_and_never_a_second_before_the_recipient_stage() -> None:
    """Section 14's budget, on the condition that can still use it.

    A DNS SERVFAIL happens before any socket, so the first attempt provably
    contacted nobody and replay is safe. One retry is scheduled, the second
    answer settles the job, and the budget on the record refuses a third
    verification however the work is re-run.
    """
    harness = Harness()
    harness.service, _, harness.sink = build_service(
        resolver=resolver_with_temporary_failure(), smtp=harness.smtp
    )
    harness.jobs.verification = harness.service
    job = await harness.submit()

    await harness.executor.run_pending()
    scheduled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert scheduled.state is JobState.RETRY_SCHEDULED
    assert scheduled.retries_used == 1
    assert scheduled.recipient_touch is RecipientTouch.NOT_TOUCHED
    assert len(harness.executor.scheduled) == 1

    await harness.executor.run_pending()
    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled.state is JobState.COMPLETED
    assert settled.retries_used == 1
    assert len(harness.executor.scheduled) == 1

    await harness.executor.run_pending()
    assert harness.jobs.get(job.id, principal=PRINCIPAL).state is JobState.COMPLETED
    assert len(harness.executor.scheduled) == 1


async def test_a_connection_timeout_settles_without_a_retry() -> None:
    """ADR 0014's exclusion, at the service level rather than only in the table."""
    harness = Harness(smtp=ScriptedSMTPVerification(evidence=connection_timeout_evidence()))
    job = await harness.submit()
    await harness.executor.run_pending()

    settled = harness.jobs.get(job.id, principal=PRINCIPAL)
    assert settled.state is JobState.COMPLETED
    assert settled.retries_used == 0
    assert harness.executor.scheduled == []


# --- R1: the claim boundary is atomic, and that is now measured -------------
#
# `_claim` reads the existing binding and writes the new one under one lock. The
# final independent review confirmed the lock is load-bearing — a mutation that
# removed it *and* yielded between the read and the write produced two jobs, two
# enqueues, and a key naming two targets — and confirmed that nothing in the
# suite noticed. These are the two tests that notice.
#
# Both use `BarrierVerdictStore`, because the interleaving has to be the test's
# doing rather than the scheduler's: gathered submissions run one after the
# other in practice, which is why the first attempt at this mutation came back
# inert.


def target_digest_of(address: str) -> str:
    """The digest `_claim` would store for this address, computed independently."""
    parsed = parse_address(RawAddressInput(address))
    assert isinstance(parsed, AddressAccepted)
    return correlation_digest(CORRELATION_KEY, parsed.address.hmac_material)


async def test_two_concurrent_submissions_of_one_key_and_target_create_one_of_everything() -> None:
    """Same principal, same key, same address, both inside `_claim` together.

    Asserting only that the two job identifiers match is not enough: a build
    that registered twice and returned the second job would satisfy that and
    still have spent two registry slots and two executor slots. Every side
    effect is counted.
    """
    harness = Harness(store=BarrierVerdictStore(parties=2))
    key = IdempotencyKey("order-4711-attempt-1")

    async with asyncio.timeout(OUTER_BOUND):
        first, second = await asyncio.gather(
            harness.jobs.submit("alice@example.test", principal=PRINCIPAL, idempotency_key=key),
            harness.jobs.submit("alice@example.test", principal=PRINCIPAL, idempotency_key=key),
        )

    assert first.job.id == second.job.id
    assert len(harness.jobs._jobs) == 1
    assert len(harness.jobs._by_key) == 1
    assert harness.executor.submitted == [first.job.id.value]
    # Exactly one submission created the work; the other found it.
    assert sorted([first.enqueued, second.enqueued]) == [False, True]
    assert sorted([first.existing, second.existing]) == [False, True]

    binding = harness.jobs._by_key[(PRINCIPAL.rate_limit_account, key.value)]
    assert binding.job_id == first.job.id.value
    assert binding.target_digest == target_digest_of("alice@example.test")


async def test_two_concurrent_submissions_of_one_key_and_two_targets_conflict_exactly_once() -> (
    None
):
    """The race that would recreate the original defect if it were lost.

    One submission must win and one must be refused. Which one wins is the
    scheduler's business and this test does not care — what it fixes is that
    there is never a second job, a second enqueue, or one key naming two
    addresses, and that the surviving binding names the address that won.
    """
    harness = Harness(store=BarrierVerdictStore(parties=2))
    key = IdempotencyKey("order-4711-attempt-1")

    async def submit(address: str) -> tuple[str, str, object]:
        try:
            return (
                "accepted",
                address,
                await harness.jobs.submit(address, principal=PRINCIPAL, idempotency_key=key),
            )
        except IdempotencyConflict:
            return ("conflict", address, None)

    async with asyncio.timeout(OUTER_BOUND):
        results = await asyncio.gather(submit("alice@example.test"), submit("bob@example.test"))

    assert sorted(kind for kind, _, _ in results) == ["accepted", "conflict"]
    _, winner, accepted = next(row for row in results if row[0] == "accepted")

    assert len(harness.jobs._jobs) == 1
    assert len(harness.jobs._by_key) == 1
    assert harness.executor.submitted == [accepted.job.id.value]  # type: ignore[union-attr]

    binding = harness.jobs._by_key[(PRINCIPAL.rate_limit_account, key.value)]
    assert binding.job_id == accepted.job.id.value  # type: ignore[union-attr]
    # The one key names the winner's address and only that one.
    assert binding.target_digest == target_digest_of(winner)
    loser = "bob@example.test" if winner == "alice@example.test" else "alice@example.test"
    assert binding.target_digest != target_digest_of(loser)


# --- the second, structural barrier on replay --------------------------------


async def test_a_touched_job_cannot_hold_the_retry_scheduled_state_at_all() -> None:
    """`application/retry.py` refuses to produce a delay; this refuses to hold
    the state.

    Two barriers of different kinds, and this is the one no scheduling code can
    route around: `retry_scheduled` is a promise to run the verification again,
    and an operation that may already have contacted its recipient has no such
    promise to make. The precedent is `retries_used`, which refuses to exist
    above `MAX_RETRIES` rather than being checked before each increment.
    """
    now = OBSERVED_AT
    running = CheckJob(
        id=JobId("touched-job-0001xxxxxxxx"),
        owner=PRINCIPAL.rate_limit_account,
        state=JobState.RUNNING,
        created_at=now,
        updated_at=now,
        recipient_touch=RecipientTouch.MAYBE_TOUCHED,
    )

    with pytest.raises(JobError, match="replayed"):
        running.moved_to(JobState.RETRY_SCHEDULED, now=now, count_retry=True)

    # The same move is permitted for an attempt that reached no recipient, so
    # this refuses the unsafe case rather than the state.
    safe = running.moved_to(
        JobState.RETRY_SCHEDULED,
        now=now,
        count_retry=True,
        recipient_touch=RecipientTouch.NOT_TOUCHED,
    )
    assert safe.state is JobState.RETRY_SCHEDULED
    assert safe.retries_used == 1


async def test_a_touched_job_may_still_complete_be_cancelled_and_be_failed() -> None:
    """The barrier is on replay, not on the job. Every terminal exit stays open,
    because a touched recipient is a perfectly ordinary answer to report."""
    now = OBSERVED_AT
    running = CheckJob(
        id=JobId("touched-job-0002xxxxxxxx"),
        owner=PRINCIPAL.rate_limit_account,
        state=JobState.RUNNING,
        created_at=now,
        updated_at=now,
        recipient_touch=RecipientTouch.MAYBE_TOUCHED,
    )

    assert (
        running.moved_to(JobState.COMPLETED, now=now, result=empty_result()).state
        is JobState.COMPLETED
    )
    assert running.moved_to(JobState.CANCELLED, now=now).state is JobState.CANCELLED
    assert (
        running.moved_to(JobState.FAILED, now=now, failure=JobFailure.SERVICE_ERROR).state
        is JobState.FAILED
    )
