"""The two bounds Phase 6 adds, and what happens when they are reached.

Neither is tested by waiting. Admission is measured by observing how many
coroutines are inside the gate at once, and the total deadline is driven by a
scripted delay against `asyncio`'s own clock through a task that is cancelled —
so nothing here sleeps for a wall-clock second.

**A refusal from either is a local operational fact.** The assertions that
matter most are the negative ones: no `Evidence` is produced, no verdict is
returned, and the exception is not a `TimeoutError` or an `OSError` that a
handler written for a remote failure would catch.
"""

from __future__ import annotations

import asyncio

import pytest
from tests.phase6_fixtures import (
    PRINCIPAL,
    BlockingSMTPVerification,
    ScriptedSMTPVerification,
    build_service,
    rate_limited_report,
    resolver_with_route,
)

from emailcheck.application.admission import (
    AdmissionControl,
    AdmissionError,
    AdmissionRefused,
    AdmissionSettings,
)
from emailcheck.application.verification import (
    SubmittedInputTooLong,
    VerificationLimits,
    VerificationRefused,
)
from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.principal import Principal
from emailcheck.domain.verdict import Status
from emailcheck.ports.observability import OperatorEventKind

pytestmark = pytest.mark.asyncio

VALID = "user@example.test"
OTHER = Principal(account_id="acct-other")

#: Every test carries its own outer bound, on the Phase 4E precedent: a gate
#: that waits when it should refuse must fail rather than hang.
OUTER_BOUND = 5.0


# --- the settings refuse what is not a bound --------------------------------


@pytest.mark.parametrize(
    "settings",
    [
        {"max_in_flight": 0},
        {"max_in_flight": -1},
        {"max_in_flight": True},
        {"max_in_flight": 10_000},
        {"max_waiting": 0},
        {"max_waiting": True},
        {"max_per_principal": 0},
        {"max_per_principal": True},
    ],
    ids=[
        "zero in flight",
        "negative",
        "boolean in flight",
        "above the ceiling",
        "zero waiting",
        "boolean waiting",
        "zero per principal",
        "boolean per principal",
    ],
)
async def test_an_unusable_bound_is_refused_at_construction(settings: dict[str, object]) -> None:
    """A bound nobody could reach is not a bound, and `True` is not a number."""
    with pytest.raises(AdmissionError):
        AdmissionSettings(**settings)  # type: ignore[arg-type]


async def test_a_per_principal_bound_above_the_global_one_is_refused() -> None:
    """Otherwise it is decorative: one caller could hold every slot legally."""
    with pytest.raises(AdmissionError, match="bounds nothing"):
        AdmissionSettings(max_in_flight=2, max_per_principal=4)


# --- the in-flight bound ----------------------------------------------------


async def test_no_more_than_the_configured_number_run_at_once() -> None:
    """Measured by counting who is inside, not by trusting the semaphore."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=2, max_waiting=8, max_per_principal=2))
    inside = 0
    peak = 0
    release = asyncio.Event()

    async def worker() -> None:
        nonlocal inside, peak
        async with gate.admit("acct"):
            inside += 1
            peak = max(peak, inside)
            await release.wait()
            inside -= 1

    async with asyncio.timeout(OUTER_BOUND):
        workers = [asyncio.create_task(worker()) for _ in range(6)]
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert gate.in_flight == 2
        release.set()
        await asyncio.gather(*workers)

    assert peak == 2
    assert gate.in_flight == 0
    assert gate.waiting == 0


async def test_a_full_queue_refuses_immediately_rather_than_admitting_a_waiter() -> None:
    """The bound that makes the first bound a bound.

    Capping concurrency while queueing without limit moves the growth rather
    than stopping it: a thousand waiters are a thousand coroutines and a
    thousand upstream sockets held open.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=1, max_per_principal=1))
    release = asyncio.Event()

    async def worker() -> None:
        async with gate.admit("acct"):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        holder = asyncio.create_task(worker())
        waiter = asyncio.create_task(worker())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert gate.in_flight == 1
        assert gate.waiting == 1

        with pytest.raises(AdmissionRefused, match="queue"):
            async with gate.admit("acct"):
                pass  # pragma: no cover - the refusal is the assertion

        release.set()
        await asyncio.gather(holder, waiter)

    assert gate.in_flight == 0
    assert gate.waiting == 0


async def test_one_principal_cannot_occupy_every_slot() -> None:
    """Per-account isolation, which `docs/requirements.md` section 15 requires.

    It lives here rather than in the Phase 4 token bucket: that bucket
    partitions on the recipient domain, which is a reviewed contract, and
    re-keying it would change what a reviewed gate measures.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=4, max_waiting=8, max_per_principal=1))
    release = asyncio.Event()

    async def worker(account: str) -> None:
        async with gate.admit(account):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        greedy = [asyncio.create_task(worker("noisy")) for _ in range(3)]
        polite = asyncio.create_task(worker("quiet"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # One slot for the noisy account, one for the quiet one — not three.
        assert gate.held_by("noisy") == 1
        assert gate.held_by("quiet") == 1
        assert gate.in_flight == 2

        release.set()
        await asyncio.gather(*greedy, polite)

    assert gate.in_flight == 0


async def test_a_permit_is_returned_when_the_body_raises() -> None:
    """A permit that is not given back removes capacity permanently."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=1, max_per_principal=1))

    with pytest.raises(RuntimeError):
        async with gate.admit("acct"):
            raise RuntimeError("the body failed")

    assert gate.in_flight == 0
    assert gate.held_by("acct") == 0


async def test_a_permit_is_returned_when_the_waiter_is_cancelled() -> None:
    """Cancellation is the case the Phase 4E review found leaking elsewhere."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=4, max_per_principal=1))
    release = asyncio.Event()

    async def worker() -> None:
        async with gate.admit("acct"):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        holder = asyncio.create_task(worker())
        waiter = asyncio.create_task(worker())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert gate.waiting == 1

        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert gate.waiting == 0

        release.set()
        await holder

    assert gate.in_flight == 0
    assert gate.held_by("acct") == 0


async def test_the_per_principal_counter_does_not_grow_without_a_bound() -> None:
    """A counter keyed by a caller-chosen value is a memory leak if it persists."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=4, max_waiting=4, max_per_principal=1))
    for index in range(50):
        async with gate.admit(f"acct-{index}"):
            pass
    assert gate.held_by("acct-0") == 0
    assert len(gate._per_principal) == 0


# --- the bounds reach the service -------------------------------------------


async def test_a_refused_request_produces_no_verdict_and_reaches_the_operator() -> None:
    """Capacity is not an answer about an address.

    `VerificationRefused` rather than a `Verdict`: a partial answer computed
    from whatever arrived before capacity ran out would present this service's
    limits as a statement about the user's address, and `unknown` is exactly the
    status a caller retries. ADR 0013.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=1, max_per_principal=1))
    service, resolver, sink = build_service(admission=gate)
    release = asyncio.Event()

    async def hold() -> None:
        async with gate.admit(PRINCIPAL.rate_limit_account):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        first = asyncio.create_task(hold())
        second = asyncio.create_task(hold())
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        with pytest.raises(VerificationRefused) as refusal:
            await service.verify(VALID, principal=PRINCIPAL)

        release.set()
        await asyncio.gather(first, second)

    assert "queue" in refusal.value.scope
    assert not isinstance(refusal.value, TimeoutError | OSError)
    assert OperatorEventKind.ADMISSION_REFUSED.value in sink.kinds()
    assert resolver.calls == []


async def test_the_total_deadline_refuses_rather_than_answering() -> None:
    """The bound on the sum of every Phase 4 bound.

    Driven by a scripted delay rather than a real one: `asyncio.timeout` is
    given a deadline shorter than the fake SMTP layer's own sleep, so the wait
    is measured in event-loop time.
    """
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",), delay_seconds=30.0)
    service, _, sink = build_service(
        smtp=smtp, limits=VerificationLimits(total_deadline_seconds=0.01)
    )

    async with asyncio.timeout(OUTER_BOUND):
        with pytest.raises(VerificationRefused) as refusal:
            await service.verify(VALID, principal=PRINCIPAL)

    assert refusal.value.scope == "the verification deadline"
    assert not isinstance(refusal.value, TimeoutError | OSError)
    assert OperatorEventKind.DEADLINE_EXCEEDED.value in sink.kinds()


async def test_the_deadline_releases_the_admission_permit() -> None:
    """A deadline that leaked a permit would shrink capacity on every timeout."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=2, max_waiting=2, max_per_principal=2))
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",), delay_seconds=30.0)
    service, _, _ = build_service(
        smtp=smtp, admission=gate, limits=VerificationLimits(total_deadline_seconds=0.01)
    )

    async with asyncio.timeout(OUTER_BOUND):
        for _ in range(3):
            with pytest.raises(VerificationRefused):
                await service.verify(VALID, principal=PRINCIPAL)

    assert gate.in_flight == 0
    assert gate.held_by(PRINCIPAL.rate_limit_account) == 0


async def test_cancelling_the_caller_releases_the_permit_and_stops_the_work() -> None:
    """A cancelled request must leave nothing running and nothing held.

    `CancelledError` propagates rather than becoming `unknown`: a worker told to
    stop must not be answered with a fact about someone's mailbox.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=2, max_waiting=2, max_per_principal=2))
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",), delay_seconds=30.0)
    service, _, _ = build_service(smtp=smtp, admission=gate)

    async with asyncio.timeout(OUTER_BOUND):
        task = asyncio.create_task(service.verify(VALID, principal=PRINCIPAL))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert gate.in_flight == 0
    assert gate.held_by(PRINCIPAL.rate_limit_account) == 0


async def test_this_projects_pacing_reaches_the_operator_and_is_not_evidence() -> None:
    """Our own queueing is an operational fact, never an observation.

    Read from the `AttemptRecord`s the Phase 4E loop really produces, not from a
    `RateLimitTimeout` reaching this layer — it cannot.
    `application/smtp_verification.py` catches that exception and converts it
    into `AttemptOutcome.RATE_LIMITED`, so a handler for it here would be dead
    code only a fake could exercise. An independent review found exactly that,
    and found that the event therefore never fired in production.

    The verdict is untouched: a paced-out attempt produces no `Evidence`, so
    aggregation sees an empty set and answers `unknown`.
    """
    smtp = ScriptedSMTPVerification(report=rate_limited_report())
    service, _, sink = build_service(resolver=resolver_with_route(), smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert OperatorEventKind.RATE_LIMITED.value in sink.kinds()
    assert outcome.verdict.status is Status.UNKNOWN
    # The route was resolved, so DNS evidence exists; the point is that the
    # paced-out attempt contributed none of its own.
    assert not [item for item in outcome.verdict.evidence if item.layer is EvidenceLayer.SMTP]


async def test_an_ordinary_verification_reports_no_pacing() -> None:
    """A sink that fires every time is a sink nobody reads."""
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    _, _, sink = build_service(resolver=resolver_with_route(), smtp=smtp)
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp, operator=sink)

    await service.verify(VALID, principal=PRINCIPAL)

    assert OperatorEventKind.RATE_LIMITED.value not in sink.kinds()


# --- the input bound --------------------------------------------------------


async def test_an_over_long_submission_is_refused_before_parsing() -> None:
    """Phase 1 recorded the absence of an early size guard; this is that guard.

    The refusal carries no part of what was submitted.
    """
    service, resolver, _ = build_service()

    with pytest.raises(SubmittedInputTooLong) as refusal:
        await service.verify("a" * 5000 + "@example.test", principal=PRINCIPAL)

    assert "aaa" not in str(refusal.value)
    assert resolver.calls == []


@pytest.mark.parametrize(
    "limits",
    [
        {"total_deadline_seconds": 0},
        {"total_deadline_seconds": -1.0},
        {"total_deadline_seconds": True},
        {"total_deadline_seconds": float("inf")},
        {"total_deadline_seconds": float("nan")},
        {"total_deadline_seconds": 1_000.0},
        {"max_submitted_length": 0},
        {"max_submitted_length": True},
    ],
    ids=[
        "zero",
        "negative",
        "boolean",
        "infinite",
        "not a number",
        "above the ceiling",
        "zero length",
        "boolean length",
    ],
)
async def test_an_unusable_deadline_is_refused_at_construction(limits: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        VerificationLimits(**limits)  # type: ignore[arg-type]


async def test_two_principals_are_isolated_from_each_other_end_to_end() -> None:
    """The property section 15 asks for, at the service rather than the gate."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=2, max_waiting=1, max_per_principal=1))
    service, _, _ = build_service(admission=gate)
    release = asyncio.Event()

    async def hold(account: str) -> None:
        async with gate.admit(account):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        noisy = asyncio.create_task(hold(PRINCIPAL.rate_limit_account))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # The other principal still gets served while the first holds its slot.
        outcome = await service.verify(VALID, principal=OTHER)
        release.set()
        await noisy

    assert outcome.verdict is not None


# --- the global bound, pinned where the per-principal one cannot reach -------
#
# An independent review found this unpinned. Every admission test used a single
# account, and `max_per_principal` was the binding constraint in all of them --
# so removing the global check entirely left the whole suite passing. Two
# barriers are only two barriers if each is pinned by its own test, which is the
# discipline gates 4A, 4D, 4E, and Phase 5 all had to learn separately.


async def test_the_global_bound_is_the_only_thing_refusing_a_third_account() -> None:
    """`max_in_flight` alone decides here, and the shape makes that true.

    Three principals with a per-principal cap of two: each is comfortably inside
    its own budget, and the fourth and fifth admissions can only be refused by
    the global count. Asserted on the measured peak rather than on a counter, so
    a bound that admits and then corrects itself still fails.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=4, max_waiting=16, max_per_principal=2))
    inside = 0
    peak = 0
    release = asyncio.Event()

    async def worker(account: str) -> None:
        nonlocal inside, peak
        async with gate.admit(account):
            inside += 1
            peak = max(peak, inside)
            await release.wait()
            inside -= 1

    async with asyncio.timeout(OUTER_BOUND):
        workers = [
            asyncio.create_task(worker(f"acct-{index % 3}"))
            for index in range(6)  # two each for three accounts
        ]
        for _ in range(6):
            await asyncio.sleep(0)

        assert gate.in_flight == 4
        assert gate.waiting == 2
        # No account is at its own cap, so nothing but the global bound is
        # holding the other two back.
        for index in range(3):
            assert gate.held_by(f"acct-{index}") <= 2

        release.set()
        await asyncio.gather(*workers)

    assert peak == 4
    assert gate.in_flight == 0
    assert gate.waiting == 0


async def test_the_global_bound_holds_however_many_accounts_arrive() -> None:
    """The failure mode the single-account tests could not see: capacity
    growing with the number of distinct callers."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=3, max_waiting=32, max_per_principal=1))
    inside = 0
    peak = 0
    release = asyncio.Event()

    async def worker(account: str) -> None:
        nonlocal inside, peak
        async with gate.admit(account):
            inside += 1
            peak = max(peak, inside)
            await release.wait()
            inside -= 1

    async with asyncio.timeout(OUTER_BOUND):
        workers = [asyncio.create_task(worker(f"acct-{index}")) for index in range(12)]
        for _ in range(8):
            await asyncio.sleep(0)
        assert gate.in_flight == 3
        release.set()
        await asyncio.gather(*workers)

    assert peak == 3


# --- an explicit cancellation reaches the SMTP step -------------------------


async def test_cancelling_a_request_stops_the_smtp_step_rather_than_detaching_it() -> None:
    """The invariant with no test until an independent review mutated it.

    Wrapping the SMTP step in `asyncio.shield` left the entire suite passing,
    and it would leave a probe running after the caller is gone: an unpaced
    connection nobody is waiting for, a permit nobody returns, and a `RCPT TO`
    issued on behalf of a request that no longer exists.

    So the fake records both entry *and* completion, and the completion counter
    is what this asserts.
    """
    smtp = BlockingSMTPVerification()
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp)
    gate = service.admission

    async with asyncio.timeout(OUTER_BOUND):
        task = asyncio.create_task(service.verify(VALID, principal=PRINCIPAL))
        await smtp.entered.wait()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Give anything detached a generous number of turns to finish.
        for _ in range(10):
            await asyncio.sleep(0)

    assert smtp.started == 1
    assert smtp.completed == 0
    assert smtp.cancelled == 1
    assert gate.in_flight == 0
    assert gate.held_by(PRINCIPAL.rate_limit_account) == 0


async def test_the_total_deadline_stops_the_smtp_step_too() -> None:
    """The same property, reached by the clock instead of by a caller."""
    smtp = BlockingSMTPVerification()
    service, _, sink = build_service(
        resolver=resolver_with_route(),
        smtp=smtp,
        limits=VerificationLimits(total_deadline_seconds=0.01),
    )

    async with asyncio.timeout(OUTER_BOUND):
        with pytest.raises(VerificationRefused):
            await service.verify(VALID, principal=PRINCIPAL)
        for _ in range(10):
            await asyncio.sleep(0)

    assert smtp.completed == 0
    assert smtp.cancelled == 1
    assert OperatorEventKind.DEADLINE_EXCEEDED.value in sink.kinds()
    assert service.admission.in_flight == 0


# --- the deadline covers the wait for a permit ------------------------------
#
# An independent review found that `asyncio.timeout` sat *inside*
# `admission.admit`, so a caller queued behind a full gate was bounded in queue
# depth and not in time -- while ADR 0013 and this module's own docstring both
# said the deadline covered admission. The ordering is now the other way round,
# and this is the test that fails if it is put back.


async def test_a_caller_waiting_for_a_permit_is_bounded_by_the_total_deadline() -> None:
    """Queue depth is not a time bound.

    With the gate full, this caller can only leave by the clock. The test
    carries its own outer bound, so the ordering being reverted fails here
    rather than hanging the suite -- which is exactly what it did when measured.
    """
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=4, max_per_principal=1))
    service, resolver, sink = build_service(
        admission=gate, limits=VerificationLimits(total_deadline_seconds=0.05)
    )
    release = asyncio.Event()

    async def hold() -> None:
        async with gate.admit(PRINCIPAL.rate_limit_account):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        holder = asyncio.create_task(hold())
        for _ in range(4):
            await asyncio.sleep(0)
        assert gate.in_flight == 1

        with pytest.raises(VerificationRefused) as refusal:
            await service.verify(VALID, principal=PRINCIPAL)

        release.set()
        await holder

    assert refusal.value.scope == "the verification deadline"
    assert OperatorEventKind.DEADLINE_EXCEEDED.value in sink.kinds()
    # Nothing past admission ran: no lookup, and so no socket either.
    assert resolver.calls == []
    assert gate.waiting == 0
    assert gate.in_flight == 0


async def test_a_deadline_reached_while_queued_is_not_a_remote_failure() -> None:
    """`docs/status-model.md`'s separation, at the one place it is easiest to
    lose: our own queue is not the remote server being slow."""
    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=4, max_per_principal=1))
    service, _, _ = build_service(
        admission=gate, limits=VerificationLimits(total_deadline_seconds=0.05)
    )
    release = asyncio.Event()

    async def hold() -> None:
        async with gate.admit(PRINCIPAL.rate_limit_account):
            await release.wait()

    async with asyncio.timeout(OUTER_BOUND):
        holder = asyncio.create_task(hold())
        for _ in range(4):
            await asyncio.sleep(0)
        with pytest.raises(VerificationRefused) as refusal:
            await service.verify(VALID, principal=PRINCIPAL)
        release.set()
        await holder

    assert not isinstance(refusal.value, TimeoutError)
    assert not isinstance(refusal.value, OSError)
