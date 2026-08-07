"""The connection chain, and what it refuses to do.

No socket is involved: the fake transport implements the port, so the ordering
is exercised without an address, a timeout, or a real peer. What is being tested
is that the only path to a session runs the three policy checks and closes on
anything short of success.
"""

from __future__ import annotations

import pytest

from emailcheck.application.smtp_connect import (
    ConnectRefused,
    ConnectStage,
    SessionOpened,
    SMTPConnector,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.mail_route import CandidateStatus, RouteCandidate, RouteSource
from emailcheck.domain.smtp_contract import SMTPState
from emailcheck.domain.smtp_destination import (
    ConfirmedPeer,
    DestinationRejection,
    PeerEndpoint,
    PeerRejection,
)
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.ports.smtp import ConnectionOpened
from emailcheck.security.destination import DestinationDecision
from fake_smtp_transport import FakeSMTPTransport, unvalidated_peer

pytestmark = pytest.mark.asyncio

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def candidate(
    *addresses: str,
    status: CandidateStatus = CandidateStatus.USABLE,
    host: str = "mx.example.com",
) -> RouteCandidate:
    decisions = tuple(
        DestinationDecision(
            allowed=True,
            address=address,
            version=6 if ":" in address else 4,
            deny_reason=None,
        )
        for address in addresses
    )
    return RouteCandidate(
        host=HostName(host),
        preference=10,
        source=RouteSource.MX,
        status=status,
        decisions=decisions,
    )


def connector(**kwargs: object) -> tuple[SMTPConnector, FakeSMTPTransport]:
    transport = FakeSMTPTransport(**kwargs)  # type: ignore[arg-type]
    return SMTPConnector(transport=transport), transport


# --- the path that works ---------------------------------------------------


async def test_a_matching_peer_opens_a_session() -> None:
    service, transport = connector()
    outcome = await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert isinstance(outcome, SessionOpened)
    assert isinstance(outcome.session.peer, ConfirmedPeer)
    assert outcome.session.state is SMTPState.CONNECTING
    assert outcome.session.peer.peer_address == PUBLIC_V4
    assert outcome.session.peer.peer_port == 25
    # The session is open, so the connection is deliberately not closed.
    assert transport.connections[0].is_closed is False


async def test_the_transport_is_asked_for_the_approved_destination_only() -> None:
    """It receives an `ApprovedDestination`, never a host or a bare address."""
    service, transport = connector()
    await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    (asked,) = transport.connect_calls
    assert asked.address == PUBLIC_V4
    assert asked.port == 25
    assert asked.host == HostName("mx.example.com")


async def test_an_ipv6_candidate_works_the_same_way() -> None:
    service, _ = connector()
    outcome = await service.open_session(candidate(PUBLIC_V6), PUBLIC_V6)
    assert isinstance(outcome, SessionOpened)
    assert outcome.session.peer.peer_address == PUBLIC_V6


# --- refused before the network --------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("1.1.1.1", DestinationRejection.ADDRESS_NOT_IN_CANDIDATE),
        ("8.8.8.8", DestinationRejection.ADDRESS_NOT_IN_CANDIDATE),
        ("127.0.0.1", DestinationRejection.DENIED_BY_POLICY),
        ("10.0.0.1", DestinationRejection.DENIED_BY_POLICY),
        ("169.254.169.254", DestinationRejection.DENIED_BY_POLICY),
    ],
)
async def test_an_unapprovable_address_never_reaches_the_transport(
    address: str, expected: DestinationRejection
) -> None:
    """No socket is attempted at all: the refusal is before `connect`."""
    service, transport = connector()
    outcome = await service.open_session(candidate(PUBLIC_V4), address)

    assert isinstance(outcome, ConnectRefused)
    assert outcome.stage is ConnectStage.APPROVE_DESTINATION
    assert outcome.destination_reason is expected
    assert outcome.reached_the_network is False
    assert transport.connect_calls == []


async def test_a_candidate_with_no_usable_address_never_reaches_the_transport() -> None:
    unusable = RouteCandidate(
        host=HostName("mx.example.com"),
        preference=10,
        source=RouteSource.MX,
        status=CandidateStatus.NO_ADDRESSES,
    )
    service, transport = connector()
    outcome = await service.open_session(unusable, PUBLIC_V4)

    assert isinstance(outcome, ConnectRefused)
    assert outcome.destination_reason is DestinationRejection.CANDIDATE_NOT_USABLE
    assert transport.connect_calls == []


# --- refused by the transport ----------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        TransportFailure.CONNECT_TIMEOUT,
        TransportFailure.CONNECTION_REFUSED,
        TransportFailure.NETWORK_UNREACHABLE,
        TransportFailure.DESTINATION_DENIED_BY_POLICY,
        TransportFailure.PEER_MALFORMED,
    ],
)
async def test_a_transport_failure_is_reported_with_its_stage(
    failure: TransportFailure,
) -> None:
    service, _ = connector(failure=failure)
    outcome = await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert isinstance(outcome, ConnectRefused)
    assert outcome.stage is ConnectStage.CONNECT
    assert outcome.transport_failure is failure
    assert outcome.is_about_the_target is False


# --- refused by the peer, after a socket opened ----------------------------


@pytest.mark.parametrize(
    ("peer", "expected", "label"),
    [
        (PeerEndpoint("8.8.8.8", 25), PeerRejection.ADDRESS_MISMATCH, "another public address"),
        (PeerEndpoint("127.0.0.1", 25), PeerRejection.DENIED_BY_POLICY, "loopback"),
        (PeerEndpoint("10.0.0.1", 25), PeerRejection.DENIED_BY_POLICY, "private"),
        (
            PeerEndpoint("169.254.169.254", 25),
            PeerRejection.DENIED_BY_POLICY,
            "cloud metadata",
        ),
        (
            PeerEndpoint("::ffff:93.184.216.34", 25),
            PeerRejection.DENIED_BY_POLICY,
            "an IPv4-mapped form, refused rather than unwrapped",
        ),
        (PeerEndpoint(PUBLIC_V4, 2525), PeerRejection.PORT_MISMATCH, "the wrong port"),
        (PeerEndpoint(PUBLIC_V4, 587), PeerRejection.PORT_MISMATCH, "submission"),
        # A malformed address cannot be built as a `PeerEndpoint` at all now, so
        # this one is handed in with its own validation bypassed: the policy is
        # the second barrier and has to be shown refusing it on its own.
        (unvalidated_peer("nonsense", 25), PeerRejection.DENIED_BY_POLICY, "unparsable"),
        (unvalidated_peer("", 25), PeerRejection.DENIED_BY_POLICY, "an empty address"),
    ],
)
async def test_a_refused_peer_closes_the_connection(
    peer: PeerEndpoint, expected: PeerRejection, label: str
) -> None:
    service, transport = connector(peer=peer)
    outcome = await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert isinstance(outcome, ConnectRefused), label
    assert outcome.stage is ConnectStage.CONFIRM_PEER
    assert outcome.peer_reason is expected
    assert outcome.reached_the_network is True
    assert transport.all_closed, f"the connection was left open after {label}"


@pytest.mark.parametrize(
    "peer",
    [
        PeerEndpoint("8.8.8.8", 25),
        PeerEndpoint("127.0.0.1", 25),
        PeerEndpoint(PUBLIC_V4, 2525),
        PeerEndpoint("::ffff:93.184.216.34", 25),
    ],
)
async def test_nothing_is_written_when_the_peer_is_refused(peer: PeerEndpoint) -> None:
    """The invariant the whole gate exists for: no byte before confirmation.

    The fake records a write if one happens, so a zero here is a measurement
    rather than an assumption. Structurally it cannot happen either — the
    `SMTPConnection` protocol has no write method — and both are checked.
    """
    service, transport = connector(peer=peer)
    outcome = await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert isinstance(outcome, ConnectRefused)
    assert transport.total_write_line_calls == 0
    assert all(connection.written == [] for connection in transport.connections)


async def test_nothing_is_written_even_when_the_peer_is_accepted() -> None:
    """Gate 4B speaks no SMTP at all. 4C is what starts writing."""
    service, transport = connector()
    outcome = await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert isinstance(outcome, SessionOpened)
    assert transport.total_write_line_calls == 0


# --- cleanup on an exception -----------------------------------------------


async def test_an_exception_between_connect_and_confirm_still_closes() -> None:
    """The close is in a `finally`, so it covers a raise as well as a refusal.

    Gate 4C will raise from inside this window when a banner is unusable, and a
    socket must not survive that.
    """

    class ExplodingPeerConnection:
        """Reading `peer` raises, which is where 4C's banner failure will land."""

        def __init__(self) -> None:
            self.close_calls = 0

        @property
        def peer(self) -> PeerEndpoint:
            raise RuntimeError("getpeername failed after connect")

        async def close(self) -> None:
            self.close_calls += 1

    exploding = ExplodingPeerConnection()

    class ExplodingTransport:
        async def connect(self, destination: object) -> object:
            return ConnectionOpened(connection=exploding)  # type: ignore[arg-type]

    service = SMTPConnector(transport=ExplodingTransport())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="getpeername failed"):
        await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)

    assert exploding.close_calls == 1, "the socket leaked when an exception passed through"


async def test_a_transport_that_raises_leaves_nothing_open() -> None:
    service, transport = connector(raise_on_connect=RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)
    assert transport.connections == []


async def test_a_connection_is_closed_exactly_once_on_refusal() -> None:
    service, transport = connector(peer=PeerEndpoint("8.8.8.8", 25))
    await service.open_session(candidate(PUBLIC_V4), PUBLIC_V4)
    assert transport.connections[0].close_calls == 1


# --- the refusal type itself -----------------------------------------------


async def test_a_refusal_names_exactly_one_reason() -> None:
    with pytest.raises(ValueError, match="exactly one reason"):
        ConnectRefused(stage=ConnectStage.CONNECT)
    with pytest.raises(ValueError, match="exactly one reason"):
        ConnectRefused(
            stage=ConnectStage.CONNECT,
            transport_failure=TransportFailure.CONNECT_TIMEOUT,
            peer_reason=PeerRejection.ADDRESS_MISMATCH,
        )


async def test_no_refusal_is_evidence_about_the_address() -> None:
    for failure in TransportFailure:
        assert failure.is_about_the_target is False


# --- the double is not more permissive than the original -------------------


async def test_the_fake_transport_refuses_what_the_real_one_refuses() -> None:
    """A double that accepts a lookalike would hide the gate it stands in for."""
    from emailcheck.domain.smtp_contract import SMTPContractError

    transport = FakeSMTPTransport()
    for value in (PUBLIC_V4, None, (PUBLIC_V4, 25)):
        with pytest.raises(SMTPContractError):
            await transport.connect(value)  # type: ignore[arg-type]
    assert transport.connect_calls == []
