"""The order a probe happens in, and the two things that must always be true.

**A budget is acquired before a socket.** `docs/test-strategy.md` section 4
lists it as an invariant, and the ordering is asserted here rather than reviewed:
the limiter is asked, the lease is entered, and only then does anything connect.

**The connection is closed.** On success, on a refusal, on a bug, and on a
cancellation.

**One budget covers the connect and the dialogue.** The 4C review found the
session deadline starting only once a connection existed, so the worst case was
`connect_seconds + budget` while the documentation said the total dominates
everything. It now starts before the connect, and these tests fix which of the
two bounds applies in each direction.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from dialogue_fixtures import (
    AdvancingClock,
    FakeMonotonicClock,
    RecordingRateLimiter,
    address,
    candidate,
    identity_provider,
    peer_endpoint,
)
from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPTransport
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.application.smtp_probe import ProbeRefused, SMTPProbeService
from emailcheck.domain.smtp_contract import SMTPCommand
from emailcheck.domain.smtp_deadline import SessionBudget
from emailcheck.domain.smtp_destination import ApprovedDestination
from emailcheck.domain.smtp_protocol import DialogueStage, SessionReport
from emailcheck.domain.smtp_result import RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSPolicy
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.ports.smtp import ConnectionFailed, ConnectionOutcome
from fake_smtp_server import (
    RCPT_ACCEPTED,
    RCPT_NO_SUCH_USER,
    ScriptedSMTPTransport,
    tls_session_peer,
)

pytestmark = pytest.mark.asyncio

PUBLIC_V4 = "93.184.216.34"
TLS_SETTINGS = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)
REQUIRE_TLS = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)

#: What a probe whose connect never answers may cost. A mutation that puts the
#: connect back outside the session budget makes the probe wait on the
#: transport's own timeout instead, and this is what turns that into a failing
#: test rather than a slow one.
OUTER_BOUND_SECONDS = 5.0


def service(
    transport: object,
    limiter: RecordingRateLimiter | None = None,
    settings: DialogueSettings = TLS_SETTINGS,
    clock: object | None = None,
) -> tuple[SMTPProbeService, RecordingRateLimiter]:
    limiter = limiter or RecordingRateLimiter()
    return (
        SMTPProbeService(
            transport=transport,  # type: ignore[arg-type]
            identity_provider=identity_provider(),
            rate_limiter=limiter,
            clock=clock or FakeMonotonicClock(),  # type: ignore[arg-type]
            settings=settings,
        ),
        limiter,
    )


def transport_for(peer_template: object) -> ScriptedSMTPTransport:
    return ScriptedSMTPTransport(template=peer_template)  # type: ignore[arg-type]


@dataclass(slots=True)
class SilentTransport:
    """A transport whose connect never completes.

    A connect that is slow but finishes proves nothing about which bound applied.
    One that never finishes ends only because something interrupted it, and the
    probe service has exactly one thing that can.
    """

    connect_calls: list[ApprovedDestination] = field(default_factory=list)
    reached: asyncio.Event = field(default_factory=asyncio.Event)

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        self.connect_calls.append(destination)
        self.reached.set()
        await asyncio.get_running_loop().create_future()
        raise AssertionError("unreachable: the future is never resolved")


@dataclass(slots=True)
class SlowTransport:
    """Spends `seconds` of the clock connecting, then does what `inner` does.

    The clock is fake, so "spends" is exact: this is how a test says the connect
    took most of the budget without waiting for it.
    """

    inner: ScriptedSMTPTransport | None
    clock: FakeMonotonicClock
    seconds: float
    failure: TransportFailure | None = None
    connect_calls: list[ApprovedDestination] = field(default_factory=list)

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        self.connect_calls.append(destination)
        self.clock.advance(self.seconds)
        if self.failure is not None:
            return ConnectionFailed(failure=self.failure)
        assert self.inner is not None
        return await self.inner.connect(destination)


# --- the whole path --------------------------------------------------------


async def test_a_probe_reaches_the_recipient_stage_and_closes() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(transport)

    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(report, SessionReport)
    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert transport.all_closed is True


async def test_the_tls_path_works_end_to_end() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(transport, settings=REQUIRE_TLS)

    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(report, SessionReport)
    assert report.tls.negotiated is True
    assert transport.connections[0].transcript == [
        SMTPCommand.EHLO,
        SMTPCommand.STARTTLS,
        SMTPCommand.EHLO,
        SMTPCommand.MAIL_FROM,
        SMTPCommand.RCPT_TO,
        SMTPCommand.RSET,
        SMTPCommand.QUIT,
    ]


# --- the budget comes first ------------------------------------------------


async def test_the_rate_limiter_is_asked_before_anything_connects() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, limiter = service(transport)

    await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert limiter.events[:2] == ["acquire", "enter"]
    assert limiter.acquisitions == [("acct-1", "recipient.test.example", "mx.test.example")]
    assert len(transport.connect_calls) == 1


async def test_the_lease_is_released_even_when_the_probe_fails() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    transport.connect_failure = TransportFailure.CONNECTION_REFUSED
    probe, limiter = service(transport)

    outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert limiter.events == ["acquire", "enter", "exit"]
    assert limiter.released == 1


async def test_a_destination_the_candidate_never_offered_is_refused_before_the_socket() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, limiter = service(transport)

    outcome = await probe.probe(candidate(PUBLIC_V4), "8.8.8.8", address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert transport.connect_calls == []
    assert limiter.released == 1


async def test_the_service_cannot_be_built_without_a_rate_limiter() -> None:
    """There is no default. A future API cannot reach an unmetered probe."""
    import dataclasses

    fields = {field.name: field for field in dataclasses.fields(SMTPProbeService)}
    assert "rate_limiter" in fields
    assert fields["rate_limiter"].default is dataclasses.MISSING
    assert fields["rate_limiter"].default_factory is dataclasses.MISSING
    with pytest.raises(TypeError):
        SMTPProbeService(  # type: ignore[call-arg]
            transport=transport_for(tls_session_peer(peer_endpoint())),
            identity_provider=identity_provider(),
            clock=FakeMonotonicClock(),
        )


#: The one module allowed to implement `acquire`. Gate 4C required this list to
#: be empty, because a limiter that existed before the budgets did would have
#: been a permissive default. Gate 4E implements one, so the rule tightens rather
#: than disappears: exactly one implementation, in the module that was reviewed.
APPROVED_LIMITER = "adapters/system/rate_limit.py"


def _rate_limiter_implementations() -> list[str]:
    """Every `acquire` defined in `src/`, outside the port that declares it."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    found: list[str] = []
    for module in sorted(root.rglob("*.py")):
        if module.name == "rate_limit.py" and module.parent.name == "ports":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "acquire":
                found.append(f"{module.relative_to(root).as_posix()}:{node.lineno}")
    return found


async def test_only_the_reviewed_limiter_ships_in_production() -> None:
    """A second implementation is how a permissive one arrives unnoticed.

    Gate 4C's version of this test required *no* implementation at all, and it
    is what made adding one a deliberate act rather than a convenience. The
    property it protected was never "there is no limiter" but "there is no
    limiter nobody reviewed", so the assertion narrows to the module 4E added.
    """
    implementations = _rate_limiter_implementations()

    assert [item.split(":")[0] for item in implementations] == [APPROVED_LIMITER], (
        f"a rate limiter is implemented outside {APPROVED_LIMITER}: {implementations}"
    )


async def test_the_production_limiter_is_not_permissive() -> None:
    """It has to be able to say no, or the ordering contract buys nothing.

    An implementation that granted everything would satisfy every test in this
    file — the lease is acquired, entered, and released in the right order — and
    would be exactly the unmetered path `SMTPProbeService`'s required limiter
    exists to make impossible. So this asks it for more than it has.
    """
    from dialogue_fixtures import FakeSleeper
    from emailcheck.adapters.system.rate_limit import InProcessRateLimiter
    from emailcheck.domain.rate_limit import RateLimitSettings, RateLimitTimeout

    clock = FakeMonotonicClock()
    limits = InProcessRateLimiter(
        clock=clock,
        sleeper=FakeSleeper(clock=clock),
        settings=RateLimitSettings(
            domain_capacity=1, domain_refill_seconds=60.0, wait_budget_seconds=1.0
        ),
    )

    async with limits.acquire(account="a", domain="example.com", mx_host="mx.example.com"):
        pass
    with pytest.raises(RateLimitTimeout):
        async with limits.acquire(account="a", domain="example.com", mx_host="mx.example.com"):
            pass


# --- the target's local part never reaches a budget key --------------------


async def test_the_budget_key_carries_no_local_part() -> None:
    """`docs/requirements.md` section 16: no full address in metrics or keys."""
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, limiter = service(transport)
    target = address("Secret.Person+tag@recipient.test.example")

    await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, target, account="acct-1")

    (acquisition,) = limiter.acquisitions
    for part in acquisition:
        assert "Secret.Person" not in part
        assert "@" not in part


# --- closing ---------------------------------------------------------------


async def test_the_connection_closes_when_the_dialogue_raises() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(transport)

    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    from emailcheck.application import smtp_probe

    original = smtp_probe.SMTPDialogue.run
    smtp_probe.SMTPDialogue.run = broken  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError):
            await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")
    finally:
        smtp_probe.SMTPDialogue.run = original  # type: ignore[method-assign]

    assert transport.all_closed is True


async def test_a_cancelled_probe_closes_the_connection_and_propagates() -> None:
    """4B's cancellation rule, carried through the dialogue."""
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(transport)

    from emailcheck.application import smtp_probe

    started = asyncio.Event()

    async def hangs(*args: object, **kwargs: object) -> None:
        started.set()
        await asyncio.sleep(3600)

    original = smtp_probe.SMTPDialogue.run
    smtp_probe.SMTPDialogue.run = hangs  # type: ignore[method-assign]
    try:
        task = asyncio.create_task(
            probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        smtp_probe.SMTPDialogue.run = original  # type: ignore[method-assign]

    assert transport.all_closed is True


# --- what a refusal reports ------------------------------------------------


async def test_a_refusal_says_nothing_about_the_target() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint()))
    transport.connect_failure = TransportFailure.CONNECT_TIMEOUT
    probe, _ = service(transport)

    outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.is_about_the_target is False
    assert outcome.refusal.is_about_the_target is False
    assert outcome.refusal.transport_failure is TransportFailure.CONNECT_TIMEOUT
    assert outcome.elapsed_milliseconds is not None
    # The transport's own bound, not this project's total.
    assert outcome.deadline_exhausted is False


async def test_a_refusal_carries_the_timing_the_deadline_measured() -> None:
    """The measurement exists, so a refusal reports it rather than `None`.

    Before this gate's follow-up there were three pieces of timing code in this
    module and a refusal still reported no elapsed time at all.
    """
    clock = FakeMonotonicClock()
    transport = SlowTransport(
        inner=None, clock=clock, seconds=2.0, failure=TransportFailure.CONNECTION_REFUSED
    )
    probe, _ = service(transport, clock=clock)

    outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.elapsed_milliseconds == 2000


# --- the connect happens inside the session budget -------------------------


async def test_a_connect_that_never_answers_is_stopped_by_the_session_budget() -> None:
    """The whole point of the total: it covers the connect, not only the talk."""
    transport = SilentTransport()
    probe, limiter = service(
        transport,
        settings=DialogueSettings(
            tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=0.05)
        ),
    )

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.deadline_exhausted is True
    assert outcome.refusal.transport_failure is TransportFailure.CONNECT_TIMEOUT
    assert outcome.is_about_the_target is False
    assert len(transport.connect_calls) == 1
    assert limiter.released == 1


async def test_the_total_budget_wins_when_it_is_smaller_than_the_connect_timeout() -> None:
    """`min(connect timeout, remaining budget)` — measured in this direction."""
    shipped = AsyncioSMTPTransport().timeouts.connect_seconds
    budget = SessionBudget(total_seconds=0.05)
    assert budget.total_seconds < shipped, "the transport's own bound is the larger one"

    transport = SilentTransport()
    probe, _ = service(
        transport,
        settings=DialogueSettings(tls_policy=TLSPolicy.REQUIRED, budget=budget),
    )

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.deadline_exhausted is True


async def test_a_connect_timeout_smaller_than_the_budget_stays_the_transports_own() -> None:
    """The lower-level bound is kept, not replaced, and is named as itself."""
    clock = FakeMonotonicClock()
    transport = SlowTransport(
        inner=None, clock=clock, seconds=10.0, failure=TransportFailure.CONNECT_TIMEOUT
    )
    probe, _ = service(
        transport,
        settings=DialogueSettings(
            tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=30.0)
        ),
        clock=clock,
    )

    outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.refusal.transport_failure is TransportFailure.CONNECT_TIMEOUT
    assert outcome.deadline_exhausted is False, "the transport's bound, not ours"
    assert outcome.elapsed_milliseconds == 10_000


async def test_a_connect_that_finishes_just_inside_the_budget_still_runs_the_dialogue() -> None:
    clock = FakeMonotonicClock()
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(
        SlowTransport(inner=transport, clock=clock, seconds=4.5),
        settings=DialogueSettings(
            tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
        ),
        clock=clock,
    )

    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(report, SessionReport)
    assert report.deadline_exhausted is False
    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert report.commands_issued[0] is SMTPCommand.EHLO
    # Measured on the deadline that has been running since before the connect.
    assert report.observation.elapsed_milliseconds == 4500


async def test_time_spent_connecting_is_taken_out_of_the_dialogue_budget() -> None:
    """The budget the dialogue gets is the one the connect did not spend.

    A connect that uses the whole budget leaves a dialogue with nothing, so not
    one command is written — which is also what shows that the two share a
    budget rather than each having its own.
    """
    clock = FakeMonotonicClock()
    transport = transport_for(tls_session_peer(peer_endpoint()))
    probe, _ = service(
        SlowTransport(inner=transport, clock=clock, seconds=5.0),
        settings=DialogueSettings(
            tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
        ),
        clock=clock,
    )

    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(report, SessionReport)
    assert report.deadline_exhausted is True
    assert report.stage_reached is DialogueStage.BANNER
    assert report.commands_issued == ()
    assert transport.connections[0].transcript == []
    # The socket that was opened is still released.
    assert transport.all_closed is True


async def test_a_budget_already_spent_opens_no_socket_at_all() -> None:
    """No connection is made when there is no time to speak on it."""
    transport = SilentTransport()
    probe, limiter = service(
        transport,
        settings=DialogueSettings(
            tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=30.0)
        ),
        clock=AdvancingClock(step=100.0),
    )

    outcome = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(outcome, ProbeRefused)
    assert outcome.deadline_exhausted is True
    assert transport.connect_calls == []
    assert limiter.released == 1


async def test_a_cancelled_connect_propagates_and_releases_the_lease() -> None:
    """4B's rule, now that a cancellation can also arrive from the budget."""
    transport = SilentTransport()
    probe, limiter = service(transport)

    task = asyncio.create_task(
        probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")
    )
    await transport.reached.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert limiter.released == 1


# --- one attempt, one recipient --------------------------------------------


async def test_a_probe_is_one_attempt_with_no_retry() -> None:
    """A rejected recipient is not tried again, here or anywhere in this gate."""
    transport = transport_for(tls_session_peer(peer_endpoint(), rcpt=RCPT_NO_SUCH_USER))
    probe, limiter = service(transport)

    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    assert isinstance(report, SessionReport)
    assert report.observation.outcome is RecipientStageOutcome.REJECTED
    assert len(transport.connect_calls) == 1
    assert len(transport.connections) == 1
    assert limiter.acquisitions == [("acct-1", "recipient.test.example", "mx.test.example")]


async def test_a_probe_offers_exactly_one_recipient() -> None:
    transport = transport_for(tls_session_peer(peer_endpoint(), rcpt=RCPT_ACCEPTED))
    probe, _ = service(transport)

    await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")

    connection = transport.connections[0]
    assert connection.recipient_commands == 1
    assert connection.wire_text().count("RCPT TO:") == 1


async def test_no_second_candidate_is_tried_by_this_gate() -> None:
    """MX orchestration is gate 4E. One `probe` call is one dialogue."""
    import inspect

    signature = inspect.signature(SMTPProbeService.probe)
    assert "candidate" in signature.parameters
    assert "candidates" not in signature.parameters
    assert "route" not in signature.parameters


async def test_temporary_reply_defers_future_operations_without_replaying() -> None:
    from dataclasses import replace

    from fake_smtp_server import RCPT_TEMPORARY

    transport = transport_for(tls_session_peer(peer_endpoint(), rcpt=RCPT_TEMPORARY))
    probe, _ = service(transport)
    deferred = []
    probe = replace(probe, on_temporary_reply=lambda domain, mx: deferred.append((domain, mx)))
    report = await probe.probe(candidate(PUBLIC_V4), PUBLIC_V4, address(), account="acct-1")
    assert isinstance(report, SessionReport)
    assert report.observation.basic_code == 450
    assert len(deferred) == 1
    assert report.commands_issued.count(SMTPCommand.RCPT_TO) == 1
    assert transport.all_closed
