"""What happens when the things that watch break.

`docs/threat-model.md` tests the enforcement paths; this file tests the
paths that are *not* enforcement. `docs/architecture.md` section 5 is the rule:
a dependency being unavailable must not become an answer about somebody's
mailbox, and telemetry is the clearest case — a metrics failure that propagated
would turn an observability problem into a verification failure.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
from tests.phase6_fixtures import (
    PRINCIPAL as PHASE6_PRINCIPAL,
)
from tests.phase6_fixtures import (
    RecordingExecutor,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    PRINCIPAL,
    SOURCE,
    BrokenMetrics,
    BrokenOperator,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
    quota_settings,
    target,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics, NullMetrics
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.application.abuse import AbuseGuard, AbuseRefused
from emailcheck.application.verification import VerificationRefused
from emailcheck.domain.verdict import Status

asyncio_test = pytest.mark.asyncio


# --- telemetry never changes an answer ---------------------------------------


@asyncio_test
async def test_a_broken_metrics_sink_does_not_stop_a_verification() -> None:
    """A sink that raises is an observability problem. Letting it propagate
    would make it a verification failure."""
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=BrokenMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(),
    )
    service, _, _ = build_service(resolver=resolver_with_route(), guard=guard)
    outcome = await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=False)
    assert outcome.verdict.status in set(Status)


@asyncio_test
async def test_a_broken_metrics_sink_does_not_stop_a_refusal_being_a_refusal() -> None:
    """The refusal path touches the sink too, and must still refuse."""
    metrics = BrokenMetrics()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_target=1),
    )
    await guard.authorize_submission(
        principal=PRINCIPAL, target=target(), source=SOURCE, active=True
    )
    with pytest.raises(AbuseRefused):
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )


@asyncio_test
async def test_a_broken_operator_sink_does_not_stop_the_guard() -> None:
    """The guard reports to the operator on every refusal path, so a sink that
    raises there would convert a budget refusal into a service error."""
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=BrokenOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_target=1),
    )
    await guard.authorize_submission(
        principal=PRINCIPAL, target=target(), source=SOURCE, active=True
    )
    with pytest.raises(AbuseRefused):
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )


@asyncio_test
async def test_a_broken_sink_does_not_swallow_a_cancellation() -> None:
    """`Exception`, not `BaseException`. A worker told to stop must not be kept
    alive by a `try` around a counter — the distinction the Phase 4E limiter
    draws, in the opposite direction and for the same reason."""

    class CancellingMetrics:
        def increment(self, name: object, *, labels: object = None) -> None:
            raise asyncio.CancelledError

        def observe(self, name: object, value: float, *, labels: object = None) -> None:
            raise asyncio.CancelledError

    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=CancellingMetrics(),  # type: ignore[arg-type]
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    with pytest.raises(asyncio.CancelledError):
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )


@asyncio_test
async def test_a_broken_operator_sink_does_not_change_a_verdict() -> None:
    """`docs/architecture.md`: the operator sink is write-only and nothing reads
    it back, so a failure there cannot reach an answer."""
    sink = BrokenOperator()
    service, _, _ = build_service(resolver=resolver_with_route(), operator=sink)
    outcome = await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=False)
    assert outcome.verdict.status in set(Status)


# --- the quota store ---------------------------------------------------------


@asyncio_test
async def test_quota_pressure_refuses_active_and_leaves_passive_alone() -> None:
    guard = AbuseGuard(
        quota=CountingQuotaStore(unavailable=True),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    service, _, _ = build_service(
        resolver=resolver_with_route(),
        smtp=ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",)),
        guard=guard,
    )

    passive = await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=False)
    assert passive.verdict.status in set(Status)

    with pytest.raises(VerificationRefused) as refusal:
        await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=True)
    assert refusal.value.scope == "an abuse control"


@asyncio_test
async def test_a_refused_active_check_never_becomes_a_mailbox_verdict() -> None:
    """A local operational refusal is not a fact about an address. ADR 0013 set
    the precedent for capacity; this is the same rule for an abuse control."""
    guard = AbuseGuard(
        quota=CountingQuotaStore(unavailable=True),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp, guard=guard)

    with pytest.raises(VerificationRefused):
        await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=True)

    # Nothing was probed, so nothing was observed and nothing could be a verdict.
    assert smtp.calls == []


def test_a_verification_refusal_is_not_a_timeout_or_an_os_error() -> None:
    assert not issubclass(VerificationRefused, TimeoutError)
    assert not issubclass(VerificationRefused, OSError)


# --- an absent guard ---------------------------------------------------------


@asyncio_test
async def test_a_deployment_with_no_guard_still_works() -> None:
    """`None` is a real configuration — the local-passive profile — and every
    call site checks, so an absent guard is visibly absent rather than a
    silently permissive one."""
    service, _, _ = build_service(resolver=resolver_with_route(), guard=None)
    outcome = await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=False)
    assert outcome.verdict.status in set(Status)


@asyncio_test
async def test_the_null_metrics_sink_records_nothing_and_never_raises() -> None:
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=NullMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    await guard.authorize_submission(
        principal=PRINCIPAL, target=target(), source=SOURCE, active=True
    )


# --- executor and registry pressure ------------------------------------------


@asyncio_test
async def test_registry_pressure_is_a_service_refusal_and_not_a_verdict() -> None:
    """`docs/threat-model.md` section 13's rule, still true with the guard in
    the path: capacity reached is a local refusal."""
    from tests.phase6_fixtures import FakeClock, FakeRandomSource

    from emailcheck.application.jobs import JobService, JobSettings, JobsFull

    service, _, sink = build_service(resolver=resolver_with_route())
    jobs = JobService(
        verification=service,
        executor=RecordingExecutor(),
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=sink,
        correlation_key=CORRELATION_KEY,
        settings=JobSettings(max_jobs=1),
    )
    await jobs.submit("a@example.test", principal=PHASE6_PRINCIPAL)
    with pytest.raises(JobsFull):
        await jobs.submit("b@example.test", principal=PHASE6_PRINCIPAL)


# --- F5: any backend failure fails closed, not only ours ---------------------
#
# `ports/quota.py` asks an implementation to raise `QuotaStoreUnavailable`. An
# independent review pointed out that trusting it is the wrong posture for the
# one dependency with a documented fail-closed contract: a Redis client raises
# `redis.ConnectionError`, and the earlier build let that propagate as a `500`
# carrying a library message rather than refusing.


@dataclass(slots=True)
class ExplodingQuota:
    """A backend that fails the way a third-party client would."""

    error: BaseException

    async def consume(self, requests: object, *, now: float) -> object:
        raise self.error

    async def purge_expired(self, *, now: float) -> int:
        return 0


def guard_over(store: object) -> tuple[AbuseGuard, RecordingOperator]:
    operator = RecordingOperator()
    return (
        AbuseGuard(
            quota=store,  # type: ignore[arg-type]
            clock=SteppableClock(),
            metrics=InMemoryMetrics(),
            operator=operator,
            correlation_key=CORRELATION_KEY,
        ),
        operator,
    )


@asyncio_test
async def test_an_unexpected_backend_failure_refuses_an_active_check() -> None:
    guard, _ = guard_over(ExplodingQuota(RuntimeError("db unreachable at /var/lib/quota.db")))
    with pytest.raises(AbuseRefused) as refusal:
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )
    assert refusal.value.unavailable is True
    assert refusal.value.category == "quota_unavailable"


@asyncio_test
async def test_an_unexpected_backend_failure_still_serves_a_passive_check() -> None:
    """`docs/architecture.md` section 5. A passive check opens no socket and
    spends no reputation, so failing it closed protects nothing."""
    guard, _ = guard_over(ExplodingQuota(RuntimeError("db unreachable")))
    await guard.authorize_submission(
        principal=PRINCIPAL, target=target(), source=SOURCE, active=False
    )


@asyncio_test
async def test_a_backend_message_never_reaches_operator_telemetry() -> None:
    """A backend message can carry a path, a query, or a value, and
    `docs/requirements.md` section 11's rule about exception text is not weaker
    because the reader is an operator."""
    guard, operator = guard_over(
        ExplodingQuota(RuntimeError("select * from quota where target='alice@example.test'"))
    )
    with pytest.raises(AbuseRefused):
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )
    rendered = operator.rendered()
    for fragment in ("select", "alice", "@example.test", "quota where"):
        assert fragment not in rendered
    assert "quota_unavailable" in operator.details


@asyncio_test
@pytest.mark.parametrize(
    "control",
    [asyncio.CancelledError(), KeyboardInterrupt(), SystemExit()],
    ids=["cancelled", "keyboard-interrupt", "system-exit"],
)
async def test_process_control_still_propagates_through_the_backend_boundary(
    control: BaseException,
) -> None:
    """`Exception`, never `BaseException`.

    A worker told to stop must not be answered with a budget refusal, which is
    the same distinction the Phase 4E limiter draws in the opposite direction.
    """
    guard, _ = guard_over(ExplodingQuota(control))
    with pytest.raises(type(control)):
        await guard.authorize_submission(
            principal=PRINCIPAL, target=target(), source=SOURCE, active=True
        )


@asyncio_test
async def test_an_unexpected_backend_failure_never_becomes_a_mailbox_verdict() -> None:
    guard, _ = guard_over(ExplodingQuota(RuntimeError("db unreachable")))
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp, guard=guard)

    with pytest.raises(VerificationRefused) as refusal:
        await service.verify("user@example.test", principal=PHASE6_PRINCIPAL, active=True)

    assert refusal.value.scope == "an abuse control"
    assert smtp.calls == []
