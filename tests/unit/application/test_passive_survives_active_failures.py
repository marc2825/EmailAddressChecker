"""The passive answer survives every way the active half can fail.

`prompts/08-limited-beta.md` work item 9: *verify passive API remains available
when active components fail*. `docs/architecture.md` section 5 names the five
conditions, and there is one test per condition here, named after it:

1. Redis is unavailable;
2. the active worker is disabled;
3. port 25 is blocked;
4. one provider tarpits;
5. the sender identity is suspended.

The property is one sentence: **a dependency being unavailable must never
become an answer about somebody's mailbox.** So each test asserts three things,
and the third is the one that matters most:

- the passive check still answers;
- it carries the passive evidence it would have carried anyway;
- the status is never `invalid`. `AGENTS.md` requires unknown or ambiguous
  evidence to resolve to `unknown` or `temporary_unknown`, and a failure of
  *our own infrastructure* is the least target-specific evidence there is.

Every test carries an outer bound, so a condition that hangs fails instead.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Final

import pytest
from tests.phase6_fixtures import (
    OBSERVED_AT,
    PRINCIPAL,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    RecordingOperator,
    SteppableClock,
    quota_settings,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.smtp_evidence import map_connect_failure
from emailcheck.application.verification import VerificationRefused
from emailcheck.domain.admin import AdminState
from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.domain.verdict import Status
from emailcheck.ports.quota import QuotaDecision, QuotaStoreUnavailable

asyncio_test = pytest.mark.asyncio

OUTER_BOUND_SECONDS: Final = 5.0

ADDRESS: Final = "user@example.test"

#: The statuses a passive answer may carry when the active half is unavailable.
#: `invalid` is absent on purpose and is the point of every test in this file.
SURVIVABLE: Final = frozenset({Status.LIKELY_DELIVERABLE, Status.UNKNOWN, Status.TEMPORARY_UNKNOWN})


@dataclass
class UnavailableQuotaStore:
    """A budget backend that is down, in the way `ports/quota.py` documents."""

    calls: int = 0

    async def consume(self, requests: object, *, now: object) -> QuotaDecision:
        self.calls += 1
        raise QuotaStoreUnavailable("the budget backend is unreachable")


@dataclass
class ForeignFailureQuotaStore:
    """A backend that raises something this project has never heard of.

    A real Redis client raises `redis.ConnectionError`, not ours. The guard
    treats any `Exception` identically, and this is the store that proves it —
    passive still answers, and it does so without the library's message reaching
    anything.
    """

    calls: int = 0

    async def consume(self, requests: object, *, now: object) -> QuotaDecision:
        self.calls += 1
        raise RuntimeError("connection reset by peer: 10.0.0.5:6379")


def guard_over(quota: object, *, state: AdminState | None = None) -> AbuseGuard:
    return AbuseGuard(
        quota=quota,  # type: ignore[arg-type]
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(),
        state=state if state is not None else AdminState(),
    )


async def passive_answer(**kwargs: object):  # type: ignore[no-untyped-def]
    """One passive check through the production graph, shaped from fakes."""
    service, _, _ = build_service(**kwargs)  # type: ignore[arg-type]
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        return await service.verify(ADDRESS, principal=PRINCIPAL, active=False)


def assert_passive_survived(outcome: object) -> None:
    """The three assertions every condition in this file makes."""
    verdict = outcome.verdict  # type: ignore[attr-defined]
    assert verdict.status in SURVIVABLE
    assert verdict.status is not Status.INVALID
    # The DNS layer, because that is what a passive check of a well-formed
    # address produces. There is no syntax evidence to look for: a valid address
    # yields none, which is the syntax layer working rather than skipped, and
    # the shipped datasets are declared unavailable so passive classification
    # produces none either.
    layers = {evidence.layer for evidence in verdict.evidence}
    assert EvidenceLayer.DNS in layers, "the passive route layer did not run"
    assert verdict.checks, "the answer carries no record of what was checked"


# --- 1. Redis is unavailable ------------------------------------------------


@asyncio_test
async def test_the_passive_check_answers_when_the_budget_store_is_unavailable() -> None:
    """A passive check spends no reputation, so a down budget store is not its problem.

    Active work fails **closed** when the store cannot be reached — that is
    `prompts/07-hardening.md`'s requirement and it is tested elsewhere. This is
    the other half of the same decision: a passive check opens no socket,
    touches no remote host, and must keep answering.
    """
    store = UnavailableQuotaStore()

    outcome = await passive_answer(resolver=resolver_with_route(), guard=guard_over(store))

    assert_passive_survived(outcome)
    assert store.calls, "the guard did not consult the store at all"


@asyncio_test
async def test_the_passive_check_answers_when_the_store_raises_a_foreign_error() -> None:
    """A backend library's own exception is handled like our documented one.

    Trusting a backend to raise `QuotaStoreUnavailable` is the wrong posture for
    the one dependency with a fail-closed contract, and the failure mode is
    specific: the library's message would otherwise reach the caller as a `500`.
    """
    store = ForeignFailureQuotaStore()

    outcome = await passive_answer(resolver=resolver_with_route(), guard=guard_over(store))

    assert_passive_survived(outcome)
    assert store.calls, "the guard did not consult the store at all"


# --- 2. the active worker is disabled ---------------------------------------


@asyncio_test
async def test_the_passive_check_answers_when_active_probing_is_switched_off() -> None:
    """The global kill switch stops probing, not the service.

    `docs/operations.md` section 2's global switch is checked **only for active
    work**. An operator who throws it has stopped outbound SMTP, which is
    `docs/architecture.md` section 5's isolation arrived at deliberately rather
    than as a failure — and taking the passive API down with it would turn one
    operator action into an outage.
    """
    stopped = AdminState(active_probing_enabled=False)

    outcome = await passive_answer(
        resolver=resolver_with_route(),
        guard=guard_over(InProcessQuotaStore(), state=stopped),
    )

    assert_passive_survived(outcome)


@asyncio_test
async def test_active_work_is_refused_by_the_same_switch_that_left_passive_alone() -> None:
    """The other side of the switch, so "passive survived" is not "nothing happened".

    A test that only showed passive working would also pass if the switch did
    nothing at all.
    """
    stopped = AdminState(active_probing_enabled=False)
    guard = guard_over(InProcessQuotaStore(), state=stopped)
    service, _, _ = build_service(
        resolver=resolver_with_route(), smtp=ScriptedSMTPVerification(), guard=guard
    )

    # `VerificationRefused`, not `AbuseRefused`: which of nine budgets or
    # switches refused is information about this deployment, and the pipeline
    # converts it at the boundary rather than letting the internal category
    # reach a caller.
    with pytest.raises(VerificationRefused):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await service.verify(ADDRESS, principal=PRINCIPAL, active=True)


@asyncio_test
async def test_the_passive_check_answers_with_no_smtp_service_configured_at_all() -> None:
    """The local-passive profile: the active component is absent, not disabled.

    An absent object cannot be switched back on by accident, which is why the
    CLI's default profile builds a service with no SMTP component rather than a
    configured-off one.
    """
    outcome = await passive_answer(resolver=resolver_with_route(), smtp=None)

    assert_passive_survived(outcome)


# --- 3. port 25 is blocked --------------------------------------------------


@asyncio_test
async def test_the_passive_check_answers_when_port_25_is_blocked() -> None:
    """Every connection fails, and no address becomes invalid because of it.

    A blocked port 25 is a property of this deployment's network. It says
    nothing whatever about the recipient, so the answer it may produce is
    `unknown` or `temporary_unknown` and never `invalid`.
    """
    blocked = ScriptedSMTPVerification(raises=OSError("connection refused"))

    outcome = await passive_answer(resolver=resolver_with_route(), smtp=blocked)

    assert_passive_survived(outcome)
    assert blocked.calls == [], "a passive check must not reach the SMTP layer"


@asyncio_test
async def test_an_active_request_with_port_25_blocked_does_not_produce_invalid() -> None:
    """The active path under the same condition. The status is the assertion.

    This is where a blocked port could plausibly turn into a verdict, because
    the active path *does* reach the SMTP layer and gets a connect failure back.
    The evidence is built through the real Phase 4D mapper rather than written
    by hand, so what is aggregated here is what a blocked port would actually
    produce: `smtp_connection_refused`, which
    `docs/status-model.md` classifies as temporary and non-target.
    """
    refused = map_connect_failure(TransportFailure.CONNECTION_REFUSED, observed_at=OBSERVED_AT)
    blocked = ScriptedSMTPVerification(evidence=refused)
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=blocked)

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        outcome = await service.verify(ADDRESS, principal=PRINCIPAL, active=True)

    assert blocked.calls, "the active path did not reach the SMTP layer"
    assert outcome.verdict.status is not Status.INVALID
    assert outcome.verdict.status in SURVIVABLE


# --- 4. one provider tarpits ------------------------------------------------


@asyncio_test
async def test_the_passive_check_answers_while_one_provider_tarpits() -> None:
    """A provider holding a connection open does not hold the passive path.

    The tarpit is the condition `docs/architecture.md` section 5 names, and the
    reason it is listed separately from a blocked port is that it consumes
    *time* rather than failing: an implementation that shared one deadline
    across both halves would let a slow remote host starve a check that never
    talks to it.
    """
    tarpit = ScriptedSMTPVerification(delay_seconds=OUTER_BOUND_SECONDS * 10)

    outcome = await passive_answer(resolver=resolver_with_route(), smtp=tarpit)

    assert_passive_survived(outcome)
    assert tarpit.calls == []


@asyncio_test
async def test_a_tarpitting_provider_does_not_delay_a_second_passive_check() -> None:
    """Two passive checks while the tarpit is in progress. Neither waits for it."""
    tarpit = ScriptedSMTPVerification(delay_seconds=OUTER_BOUND_SECONDS * 10)
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=tarpit)

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        first, second = await asyncio.gather(
            service.verify(ADDRESS, principal=PRINCIPAL, active=False),
            service.verify("other@example.test", principal=PRINCIPAL, active=False),
        )

    assert_passive_survived(first)
    assert_passive_survived(second)


# --- 5. the sender identity is suspended ------------------------------------


@asyncio_test
async def test_the_passive_check_answers_when_the_sender_identity_is_suspended() -> None:
    """A disabled sender stops probing with it. It does not stop classifying.

    The sender identity is what this deployment presents to a receiving host, so
    suspending it is the correct response to a reputation incident — and a
    reputation incident is not a reason to stop answering questions that reach
    no remote host at all.
    """
    disabled = AdminState(disabled_sender_identities=frozenset({"none"}))

    outcome = await passive_answer(
        resolver=resolver_with_route(),
        guard=guard_over(InProcessQuotaStore(), state=disabled),
    )

    assert_passive_survived(outcome)


@asyncio_test
async def test_active_work_is_refused_while_the_sender_identity_is_suspended() -> None:
    """The switch does something, so the passive survival above means something."""
    disabled = AdminState(disabled_sender_identities=frozenset({"none"}))
    guard = guard_over(InProcessQuotaStore(), state=disabled)
    smtp = ScriptedSMTPVerification()
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp, guard=guard)

    with pytest.raises(VerificationRefused):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await service.verify(ADDRESS, principal=PRINCIPAL, active=True)

    assert smtp.calls == [], "a suspended sender identity still reached the SMTP layer"


# --- all five at once -------------------------------------------------------


@asyncio_test
async def test_the_passive_check_answers_with_every_active_component_failing() -> None:
    """The five conditions together.

    Each is tested on its own above, because a combined test that passes tells
    you nothing about which condition holds the property up. This one exists for
    the opposite reason: the conditions are not independent in production, and a
    recovery path that only works when exactly one thing is broken is not a
    recovery path.
    """
    everything_off = AdminState(
        active_probing_enabled=False,
        disabled_sender_identities=frozenset({"none"}),
        blocked_domains=frozenset({"example.test"}),
    )
    tarpit_then_refused = ScriptedSMTPVerification(
        delay_seconds=OUTER_BOUND_SECONDS * 10, raises=OSError("connection refused")
    )

    outcome = await passive_answer(
        resolver=resolver_with_route(),
        smtp=tarpit_then_refused,
        guard=guard_over(UnavailableQuotaStore(), state=everything_off),
    )

    assert_passive_survived(outcome)
    assert tarpit_then_refused.calls == []
