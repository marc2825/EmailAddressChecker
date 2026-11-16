"""One verification over several exchangers, and one `RCPT TO` in total.

The scenario matrix is the point of this file. Gate 4C could only be tested one
dialogue at a time; this is the first code that decides whether there *is* a
second dialogue, and every wrong answer it could give is a plausible one:

- asking the next exchanger after a `450` looks like a retry and is a second
  probe of the same recipient;
- asking the next exchanger after a `RCPT TO` that was written but never
  answered looks like "nothing happened" and is the same thing;
- walking a hostile DNS answer's twenty MX records looks like thoroughness and
  is twenty outbound connections from one request.

So the invariant is measured on the wire — `RoutedSMTPTransport.recipient_commands`
counts what was actually written across every connection — rather than on the
report, which is derived from the same code under test.
"""

from __future__ import annotations

import asyncio

import pytest

from dialogue_fixtures import (
    FakeMonotonicClock,
    RecordingRateLimiter,
    ScriptedRateLimiter,
    address,
    candidate,
    identity_provider,
    route,
)
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.application.smtp_probe import SMTPProbeService
from emailcheck.application.smtp_verification import (
    AttemptOutcome,
    SMTPVerificationService,
    VerificationSettings,
    VerificationStop,
)
from emailcheck.domain.evidence import EvidenceLayer
from emailcheck.domain.mail_route import MailRouteOutcome
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_contract import SMTPCommand
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage
from emailcheck.domain.smtp_tls import TLSPolicy
from emailcheck.domain.smtp_transport import TransportFailure
from fake_smtp_server import (
    MAIL_FROM_REJECTED,
    RCPT_ACCEPTED,
    RCPT_GREYLISTED,
    RCPT_NO_SUCH_USER,
    RCPT_TEMPORARY,
    RCPT_UNVERIFIABLE,
    RoutedSMTPTransport,
    reply,
    tls_failure,
    tls_session_peer,
)

pytestmark = pytest.mark.asyncio

FIRST = "93.184.216.34"
SECOND = "93.184.216.35"
THIRD = "93.184.216.36"
TLS_SETTINGS = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)

#: Every scenario carries an outer bound, so a loop that waits when it should
#: stop fails rather than hangs.
OUTER_BOUND_SECONDS = 5.0


class _WallClock:
    """An aware UTC clock that never moves, so `observed_at` is comparable."""

    def now(self) -> object:
        from datetime import UTC, datetime

        return datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def endpoint(address_value: str):  # type: ignore[no-untyped-def]
    from emailcheck.domain.smtp_destination import PeerEndpoint

    return PeerEndpoint(address=address_value, port=25)


def peer_for(
    address_value: str,
    *,
    rcpt: object = RCPT_ACCEPTED,
    banner: object | None = None,
    mail_from: object | None = None,
):  # type: ignore[no-untyped-def]
    """A plain server at one address, with one step optionally rewritten."""
    peer = tls_session_peer(endpoint(address_value), rcpt=rcpt)  # type: ignore[arg-type]
    if banner is not None:
        peer.banner = banner  # type: ignore[assignment]
    if mail_from is not None:
        peer.responses[SMTPCommand.MAIL_FROM] = mail_from  # type: ignore[assignment]
    return peer


def service(
    transport: RoutedSMTPTransport,
    *,
    limiter: object | None = None,
    max_attempts: int = 3,
) -> tuple[SMTPVerificationService, object]:
    limiter = limiter or RecordingRateLimiter()
    probe = SMTPProbeService(
        transport=transport,  # type: ignore[arg-type]
        identity_provider=identity_provider(),
        rate_limiter=limiter,  # type: ignore[arg-type]
        clock=FakeMonotonicClock(),
        settings=TLS_SETTINGS,
    )
    return (
        SMTPVerificationService(
            probe=probe,
            clock=_WallClock(),  # type: ignore[arg-type]
            settings=VerificationSettings(max_attempts=max_attempts),
        ),
        limiter,
    )


def two_host_route():  # type: ignore[no-untyped-def]
    """A primary and a secondary, in preference order."""
    return route(
        candidate(FIRST, host="mx1.test.example", preference=10),
        candidate(SECOND, host="mx2.test.example", preference=20),
    )


async def verify(transport: RoutedSMTPTransport, mail_route=None, **kwargs: object):  # type: ignore[no-untyped-def]
    verifier, limiter = service(transport, **kwargs)  # type: ignore[arg-type]
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        report = await verifier.verify(address(), mail_route or two_host_route(), account="acct-1")
    return report, limiter


# --- the matrix: what stops, and what falls through -------------------------


async def test_a_recipient_answer_on_the_first_candidate_stops_there() -> None:
    """The second exchanger is never connected to at all."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST), SECOND: peer_for(SECOND)})

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST]
    assert transport.recipient_commands == 1
    assert report.stopped_because is VerificationStop.RECIPIENT_ATTEMPTED
    assert [item.reason for item in report.evidence] == [ReasonCode.RCPT_ACCEPTED]


async def test_a_connect_failure_falls_through_to_the_next_candidate() -> None:
    """Nothing was asked about the recipient, so asking is not asking twice."""
    transport = RoutedSMTPTransport(
        peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: peer_for(SECOND)}
    )

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST, SECOND]
    assert transport.recipient_commands == 1
    assert report.stopped_because is VerificationStop.RECIPIENT_ATTEMPTED
    assert [item.reason for item in report.evidence] == [
        ReasonCode.SMTP_CONNECTION_REFUSED,
        ReasonCode.RCPT_ACCEPTED,
    ]


async def test_a_tls_failure_falls_through_to_the_next_candidate() -> None:
    """A server this project will not speak plaintext to says nothing about the
    address, so the next exchanger asks the question for the first time."""
    from emailcheck.domain.smtp_destination import PeerEndpoint

    failing = tls_session_peer(
        PeerEndpoint(address=FIRST, port=25),
        tls_outcome=tls_failure(TransportFailure.TLS_CERTIFICATE_INVALID),
    )
    transport = RoutedSMTPTransport(peers={FIRST: failing, SECOND: peer_for(SECOND)})

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST, SECOND]
    assert transport.recipient_commands == 1
    assert [item.reason for item in report.evidence] == [
        ReasonCode.SMTP_TLS_FAILURE,
        ReasonCode.RCPT_ACCEPTED,
    ]


async def test_a_rejected_sender_falls_through_to_the_next_candidate() -> None:
    """`docs/requirements.md` section 9: a sender rejection is not about the target."""
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_for(FIRST, mail_from=MAIL_FROM_REJECTED),
            SECOND: peer_for(SECOND),
        }
    )

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST, SECOND]
    assert transport.recipient_commands == 1
    assert report.evidence[0].reason is ReasonCode.MAIL_FROM_REJECTED
    assert report.evidence[0].details["about_the_target"] is False


async def test_a_refused_banner_falls_through_to_the_next_candidate() -> None:
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_for(FIRST, banner=reply("421 service not available")),
            SECOND: peer_for(SECOND),
        }
    )

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST, SECOND]
    assert report.evidence[0].reason is ReasonCode.SMTP_POLICY_BLOCKED


@pytest.mark.parametrize(
    ("rcpt", "reason"),
    [
        (RCPT_ACCEPTED, ReasonCode.RCPT_ACCEPTED),
        (RCPT_TEMPORARY, ReasonCode.SMTP_TEMPORARY_FAILURE),
        (RCPT_GREYLISTED, ReasonCode.SMTP_TEMPORARY_FAILURE),
        (RCPT_NO_SUCH_USER, ReasonCode.RCPT_REJECTED_ADDRESS),
        (RCPT_UNVERIFIABLE, ReasonCode.RCPT_UNVERIFIABLE),
    ],
)
async def test_any_recipient_answer_stops_the_verification(
    rcpt: object, reason: ReasonCode
) -> None:
    """**The rule that outranks every reason code.**

    A `450` is temporary and a `252` is unverifiable, and neither buys a second
    opinion from another exchanger: the recipient has been put in front of a
    server, and doing it again is what `docs/threat-model.md` lists first under
    address enumeration. Re-asking would also be a retry, which this gate does
    not do at all.
    """
    transport = RoutedSMTPTransport(
        peers={FIRST: peer_for(FIRST, rcpt=rcpt), SECOND: peer_for(SECOND)}  # type: ignore[arg-type]
    )

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST]
    assert transport.recipient_commands == 1
    assert report.stopped_because is VerificationStop.RECIPIENT_ATTEMPTED
    assert [item.reason for item in report.evidence] == [reason]


async def test_a_recipient_command_lost_before_its_reply_still_stops() -> None:
    """The case the whole invariant is written for.

    The command went out and the connection died before an answer came back, so
    nothing was learned — and the recipient was still put in front of that
    server. Trying the next exchanger would be the second probe.
    """
    from emailcheck.domain.smtp_destination import PeerEndpoint

    silent = tls_session_peer(PeerEndpoint(address=FIRST, port=25))
    silent.responses.pop(SMTPCommand.RCPT_TO)
    silent.exhausted = TransportFailure.CONNECTION_RESET
    transport = RoutedSMTPTransport(peers={FIRST: silent, SECOND: peer_for(SECOND)})

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST]
    assert transport.recipient_commands == 1
    assert report.stopped_because is VerificationStop.RECIPIENT_ATTEMPTED
    assert report.recipients_attempted == 1


async def test_a_recipient_command_that_fails_to_write_still_stops() -> None:
    """Conservative on purpose: this project cannot know what reached the peer.

    A failed write may have put some of `RCPT TO` on the wire. The cost of
    stopping wrongly is one verification that reports `unknown`; the cost of
    continuing wrongly is a second recipient probe on another server.
    """
    from emailcheck.domain.smtp_destination import PeerEndpoint

    failing = tls_session_peer(PeerEndpoint(address=FIRST, port=25))
    failing.write_failure_on = SMTPCommand.RCPT_TO
    transport = RoutedSMTPTransport(peers={FIRST: failing, SECOND: peer_for(SECOND)})

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST]
    assert report.stopped_because is VerificationStop.RECIPIENT_ATTEMPTED
    assert report.attempts[0].stage_reached == DialogueStage.RCPT_TO.value


async def test_every_candidate_failing_before_the_recipient_is_not_an_invalid_mailbox() -> None:
    """`candidates_exhausted` is an operational fact, not a verdict.

    Every reason produced is non-target, so section 4 resolves the lot to
    `unknown`. Nothing here may look like evidence about the address.
    """
    transport = RoutedSMTPTransport(
        peers={
            FIRST: TransportFailure.CONNECTION_REFUSED,
            SECOND: TransportFailure.CONNECT_TIMEOUT,
        }
    )

    report, _ = await verify(transport)

    assert report.stopped_because is VerificationStop.CANDIDATES_EXHAUSTED
    assert transport.recipient_commands == 0
    assert report.recipients_attempted == 0
    for item in report.evidence:
        assert item.details["about_the_target"] is False
        assert item.details["recipient_stage"] is False
    assert not hasattr(report, "status")
    assert not hasattr(report, "verdict")


async def test_an_internal_failure_never_falls_through_to_another_exchanger() -> None:
    """A bug of ours must not be hidden behind a second server's answer."""
    from emailcheck.domain.smtp_destination import PeerEndpoint

    broken = tls_session_peer(PeerEndpoint(address=FIRST, port=25))
    broken.responses[SMTPCommand.MAIL_FROM] = "not a response"  # type: ignore[assignment]
    transport = RoutedSMTPTransport(peers={FIRST: broken, SECOND: peer_for(SECOND)})

    report, _ = await verify(transport)

    assert transport.addresses_reached == [FIRST]
    assert report.stopped_because is VerificationStop.INTERNAL_ERROR
    assert report.evidence[0].reason is ReasonCode.INTERNAL_ERROR
    assert report.evidence[0].layer is EvidenceLayer.INTERNAL


# --- bounds -----------------------------------------------------------------


async def test_the_attempt_cap_bounds_the_connections_one_request_makes() -> None:
    """A hostile DNS answer must not decide how many sockets this project opens."""
    hosts = [f"93.184.216.{index}" for index in range(40, 60)]
    many = route(
        *(
            candidate(host_address, host=f"mx{index}.test.example", preference=10 + index)
            for index, host_address in enumerate(hosts)
        )
    )
    transport = RoutedSMTPTransport(peers=dict.fromkeys(hosts, TransportFailure.CONNECTION_REFUSED))

    report, _ = await verify(transport, many, max_attempts=3)

    assert len(transport.addresses_reached) == 3
    assert len(report.attempts) == 3
    assert report.stopped_because is VerificationStop.ATTEMPT_CAP_REACHED


async def test_the_cap_and_exhaustion_are_reported_separately() -> None:
    """An operator reads them differently: unreachable, or not fully walked."""
    transport = RoutedSMTPTransport(
        peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: TransportFailure.CONNECT_TIMEOUT}
    )

    report, _ = await verify(transport, two_host_route(), max_attempts=3)

    assert report.stopped_because is VerificationStop.CANDIDATES_EXHAUSTED


async def test_no_usable_route_starts_no_smtp_at_all() -> None:
    """Phase 2 already said why, and this must not produce a second copy.

    A Null MX is hard-invalid DNS evidence. Re-deriving it as an SMTP reason
    would double-count it in the aggregation Phase 5 has yet to write.
    """
    transport = RoutedSMTPTransport(peers={})

    report, limiter = await verify(
        transport, route(candidate(FIRST), outcome=MailRouteOutcome.NULL_MX)
    )

    assert transport.connect_calls == []
    assert report.attempts == ()
    assert report.evidence == ()
    assert report.stopped_because is VerificationStop.NO_USABLE_ROUTE
    assert limiter.acquisitions == []  # type: ignore[attr-defined]


# --- rate limiting is in the path -------------------------------------------


async def test_every_attempt_acquires_its_own_budget() -> None:
    """One lease does not authorize a walk of the whole route.

    Each candidate attempt costs a fresh acquisition, so pacing applies per
    connection rather than per request — otherwise one authorization would buy
    as many outbound connections as the attempt cap allows.
    """
    transport = RoutedSMTPTransport(
        peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: peer_for(SECOND)}
    )
    limiter = RecordingRateLimiter()

    report, _ = await verify(transport, limiter=limiter)

    assert len(limiter.acquisitions) == 2
    assert limiter.released == 2
    assert len(report.attempts) == 2


async def test_a_budget_is_acquired_before_every_socket() -> None:
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST)})
    limiter = RecordingRateLimiter()

    await verify(transport, route(candidate(FIRST)), limiter=limiter)

    assert limiter.events[:2] == ["acquire", "enter"]


async def test_a_refused_budget_stops_the_verification_without_a_socket() -> None:
    """This project's own queueing, and never reported as a remote timeout."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST), SECOND: peer_for(SECOND)})
    limiter = ScriptedRateLimiter(refuse_on=frozenset({0}))

    report, _ = await verify(transport, limiter=limiter)

    assert transport.connect_calls == []
    assert report.stopped_because is VerificationStop.RATE_LIMIT_WAIT_EXCEEDED
    assert report.attempts[0].outcome is AttemptOutcome.RATE_LIMITED
    assert report.attempts[0].reached_the_network is False
    # No SMTP evidence: nothing was observed, and calling it a connection
    # timeout would attribute this project's scheduling to a mail server.
    assert report.evidence == ()


async def test_a_refused_budget_mid_route_keeps_what_was_already_observed() -> None:
    transport = RoutedSMTPTransport(
        peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: peer_for(SECOND)}
    )
    limiter = ScriptedRateLimiter(refuse_on=frozenset({1}))

    report, _ = await verify(transport, limiter=limiter)

    assert transport.addresses_reached == [FIRST]
    assert report.stopped_because is VerificationStop.RATE_LIMIT_WAIT_EXCEEDED
    assert [item.reason for item in report.evidence] == [ReasonCode.SMTP_CONNECTION_REFUSED]


async def test_the_budget_key_carries_no_local_part() -> None:
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST)})
    limiter = RecordingRateLimiter()

    await verify(transport, route(candidate(FIRST)), limiter=limiter)

    for acquisition in limiter.acquisitions:
        for part in acquisition:
            assert "@" not in part
            assert "probe.target" not in part


async def test_a_cancelled_lease_is_never_converted_into_a_fallback() -> None:
    """A worker told to stop must not be answered with the next exchanger."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST), SECOND: peer_for(SECOND)})
    limiter = ScriptedRateLimiter(cancel_on=frozenset({0}))
    verifier, _ = service(transport, limiter=limiter)

    with pytest.raises(asyncio.CancelledError):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await verifier.verify(address(), two_host_route(), account="acct-1")

    assert transport.connect_calls == []


async def test_the_service_cannot_be_built_without_a_limited_probe() -> None:
    """The authorization contract is inherited rather than repeated.

    `SMTPProbeService` has required a `RateLimiter` since gate 4C, so a
    verification service cannot exist without one either — and there is no
    parameter here through which to supply a different, permissive one.
    """
    import dataclasses

    fields = {field.name: field for field in dataclasses.fields(SMTPVerificationService)}
    assert fields["probe"].default is dataclasses.MISSING
    assert fields["probe"].default_factory is dataclasses.MISSING
    assert "rate_limiter" not in fields
    with pytest.raises(TypeError):
        SMTPVerificationService(clock=_WallClock())  # type: ignore[call-arg]


# --- evidence, provenance, and ordering -------------------------------------


async def test_evidence_is_in_attempt_order() -> None:
    transport = RoutedSMTPTransport(
        peers={
            FIRST: TransportFailure.CONNECTION_REFUSED,
            SECOND: TransportFailure.CONNECT_TIMEOUT,
            THIRD: peer_for(THIRD),
        }
    )
    many = route(
        candidate(FIRST, host="mx1.test.example", preference=10),
        candidate(SECOND, host="mx2.test.example", preference=20),
        candidate(THIRD, host="mx3.test.example", preference=30),
    )

    report, _ = await verify(transport, many)

    assert [item.reason for item in report.evidence] == [
        ReasonCode.SMTP_CONNECTION_REFUSED,
        ReasonCode.SMTP_CONNECTION_TIMEOUT,
        ReasonCode.RCPT_ACCEPTED,
    ]
    assert [record.index for record in report.attempts] == [0, 1, 2]


async def test_provenance_comes_from_the_attempt_record() -> None:
    """`Evidence` gained no field, so its privacy bound is untouched.

    Which attempt produced which evidence is answered by the record that holds
    it, rather than by a new detail key on a 4D value.
    """
    transport = RoutedSMTPTransport(
        peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: peer_for(SECOND)}
    )

    report, _ = await verify(transport)

    assert report.attempts[0].mx_host == "mx1.test.example"
    assert report.attempts[1].mx_host == "mx2.test.example"
    assert [item.reason for item in report.attempts[1].evidence] == [ReasonCode.RCPT_ACCEPTED]
    assert report.evidence == tuple(item for record in report.attempts for item in record.evidence)


async def test_the_same_inputs_produce_the_same_report() -> None:
    """Nothing iterates a set, and the clock is fixed."""

    async def once() -> object:
        transport = RoutedSMTPTransport(
            peers={FIRST: TransportFailure.CONNECTION_REFUSED, SECOND: peer_for(SECOND)}
        )
        report, _ = await verify(transport)
        return (
            tuple(record.outcome for record in report.attempts),
            tuple((item.reason, item.strength, item.temporary) for item in report.evidence),
            tuple(tuple(item.details.items()) for item in report.evidence),
            report.stopped_because,
        )

    assert await once() == await once()


async def test_observed_at_is_aware_utc_from_the_clock() -> None:
    """The 4D mapper takes a timestamp so it stays pure; this supplies one."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST)})

    report, _ = await verify(transport, route(candidate(FIRST)))

    for item in report.evidence:
        assert item.observed_at.utcoffset() is not None
        assert item.observed_at.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


async def test_the_cleanup_detail_survives_the_wiring() -> None:
    """Nothing between the dialogue and the report drops a 4D detail."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST)})

    report, _ = await verify(transport, route(candidate(FIRST)))

    details = report.evidence[0].details
    assert details["cleanup"] == CleanupStatus.COMPLETED.value
    assert details["no_message_data_sent"] is True
    assert details["recipients_attempted"] == 1


async def test_the_orchestrator_still_produces_no_status_of_its_own() -> None:
    """Phase 5 aggregates; gate 4E observes. The separation outlives Phase 5.

    Until Phase 5 existed this test asserted that `aggregate_evidence` raised
    `NotImplementedError`, which was a fact about the calendar rather than about
    this module. What it was really protecting is unchanged and is asserted
    directly instead: a `VerificationReport` carries evidence and an operational
    stop reason, and no status, confidence, or verdict anywhere in it. An
    inspection test adds the other half — the orchestration tree imports no
    aggregation vocabulary at all.
    """
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST)})

    report, _ = await verify(transport, route(candidate(FIRST)))

    rendered = repr(report)
    for vocabulary in ("likely_deliverable", "temporary_unknown", "Confidence", "Verdict"):
        assert vocabulary not in rendered
    assert not hasattr(report, "status")
    assert not hasattr(report, "confidence")
    assert not hasattr(report, "verdict")


# --- privacy ----------------------------------------------------------------


async def test_no_report_surface_carries_the_recipient() -> None:
    """Every attempt, every record, and the whole report as one string."""
    from emailcheck.domain.smtp_destination import PeerEndpoint

    echoing = tls_session_peer(
        PeerEndpoint(address=FIRST, port=25),
        rcpt=reply("550 5.1.1 <probe.target@recipient.test.example> unknown"),
    )
    transport = RoutedSMTPTransport(peers={FIRST: echoing})

    report, _ = await verify(transport, route(candidate(FIRST)))

    for surface in (repr(report), str(report.attempts), repr(report.evidence)):
        assert "probe.target" not in surface
        assert "@" not in surface


async def test_a_mapper_failure_after_the_recipient_never_reaches_another_exchanger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The recipient was touched, so nothing may try the next exchanger.

    A bug in the evidence mapper is a bug of ours. Treating it as a
    pre-recipient failure — the shape a `try/except` around the mapper produces
    — would send a **second `RCPT TO`** for the same recipient to a different
    server, which is the one thing this gate exists to prevent. It must fail
    loudly instead.

    The Phase 4 final review mutated exactly this and nothing failed, because
    the touch decision was computed *after* the mapper ran.
    """
    from emailcheck.application import smtp_verification

    def explode(report: object, *, observed_at: object) -> tuple[object, ...]:
        raise RuntimeError("the evidence mapper failed")

    monkeypatch.setattr(smtp_verification, "map_session_evidence", explode)
    transport = RoutedSMTPTransport(peers={FIRST: peer_for(FIRST), SECOND: peer_for(SECOND)})
    verifier, limiter = service(transport)

    with pytest.raises(RuntimeError, match="the evidence mapper failed"):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await verifier.verify(address(), two_host_route(), account="acct-1")

    assert transport.addresses_reached == [FIRST], "it fell through to the next exchanger"
    assert transport.recipient_commands == 1, "a second RCPT TO was written"
    assert limiter.released == 1  # type: ignore[attr-defined]


async def test_a_mapper_failure_before_the_recipient_also_fails_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Our bug is never a remote failure, wherever in the dialogue it happens.

    This candidate failed at the banner, so the loop *would* have been allowed
    to try the next exchanger. It still must not, because what failed second is
    this project rather than the server.
    """
    from emailcheck.application import smtp_verification

    calls: list[str] = []

    def explode(report: object, *, observed_at: object) -> tuple[object, ...]:
        calls.append("mapped")
        raise RuntimeError("the evidence mapper failed")

    monkeypatch.setattr(smtp_verification, "map_session_evidence", explode)
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_for(FIRST, banner=reply("421 4.3.2 not available")),
            SECOND: peer_for(SECOND),
        }
    )
    verifier, _ = service(transport)

    with pytest.raises(RuntimeError, match="the evidence mapper failed"):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await verifier.verify(address(), two_host_route(), account="acct-1")

    assert transport.addresses_reached == [FIRST]
    assert calls == ["mapped"]


@pytest.mark.inspection
async def test_the_touch_decision_is_taken_before_the_mapper_runs() -> None:
    """Pinned on the source, because behaviour cannot show an *ordering*.

    Both lines could be present and correct in either order while every
    behavioural test passes — the difference only shows when the mapper raises,
    and a later edit that adds a `try/except` is exactly what would introduce
    that. So the order itself is the assertion.
    """
    import ast
    import inspect

    from emailcheck.application import smtp_verification

    source = inspect.getsource(smtp_verification._session_record)
    tree = ast.parse(source.lstrip())
    touch_line = mapper_line = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "touched_the_recipient":
                touch_line = node.lineno
            if node.func.id == "map_session_evidence":
                mapper_line = node.lineno

    assert touch_line is not None, "the touch decision is not taken at all"
    assert mapper_line is not None, "the mapper is not called"
    assert touch_line < mapper_line, (
        "the recipient-touch decision must be taken before the evidence mapper "
        "runs, so that no exception handling around the mapper can change it"
    )


async def test_an_attempt_record_carries_no_transcript_or_reply() -> None:
    """The MX host is operational metadata; the wire is not.

    An attempt record names where this project chose to connect, which an
    operator needs. It does not name what was said, which
    `docs/requirements.md` section 11 keeps out of a response.
    """
    import dataclasses

    from emailcheck.application.smtp_verification import AttemptRecord

    names = {field.name for field in dataclasses.fields(AttemptRecord)}
    for forbidden in ("transcript", "reply", "commands_issued", "peer", "address", "target"):
        assert forbidden not in names
