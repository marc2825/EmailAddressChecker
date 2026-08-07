"""The one path from a DNS candidate to an open SMTP session.

Every step of the chain exists as a type already. This module is what puts them
in order, and it is the only production code that does:

```text
RouteCandidate
  → approve_destination()   the address must be one the candidate offered
  → ApprovedDestination     the policy runs again
  → transport.connect()     the policy runs a third time, then a socket opens
  → PeerEndpoint            what the socket actually reached
  → confirm_peer()          address and port judged against what was approved
  → ConfirmedPeer
  → SMTPSession
```

Two properties are worth stating because they are what a reviewer should check.

**Nothing is written before the peer is confirmed.** Not because this code is
careful about the order, but because `SMTPConnection` has no write method at
all: gate 4B publishes no way to put a byte on the wire. The capability arrives
in 4C, wired to the six encoders, after this function has already returned a
confirmed session.

**A refused peer closes the connection.** Every path that does not return a
session closes first, and the close is in a `finally`, so an exception between
connecting and confirming does not leak a socket either.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from emailcheck.domain.mail_route import RouteCandidate
from emailcheck.domain.smtp_destination import (
    ApprovedDestination,
    DestinationApproved,
    DestinationRejection,
    PeerAccepted,
    PeerRejection,
    approve_destination,
    confirm_peer,
)
from emailcheck.domain.smtp_session import SMTPSession, begin_session
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.ports.smtp import ConnectionOpened, SMTPConnection, SMTPTransport


class ConnectStage(StrEnum):
    """Which step refused, so a caller can tell the three apart.

    They mean different things. An approval refusal is about DNS and policy and
    never touched the network; a connect failure is about reachability; a peer
    refusal means a socket opened and was closed again without a byte written.
    """

    APPROVE_DESTINATION = "approve_destination"
    CONNECT = "connect"
    CONFIRM_PEER = "confirm_peer"


@dataclass(frozen=True, slots=True)
class SessionOpened:
    """A confirmed peer and the connection it was confirmed on."""

    session: SMTPSession
    connection: SMTPConnection


@dataclass(frozen=True, slots=True)
class ConnectRefused:
    """No session. The connection, if one was opened, is already closed.

    Exactly one of the three reason fields is set, matching `stage`.
    """

    stage: ConnectStage
    destination_reason: DestinationRejection | None = None
    transport_failure: TransportFailure | None = None
    peer_reason: PeerRejection | None = None

    def __post_init__(self) -> None:
        reasons = [self.destination_reason, self.transport_failure, self.peer_reason]
        if sum(reason is not None for reason in reasons) != 1:
            raise ValueError("a refusal names exactly one reason")

    @property
    def reached_the_network(self) -> bool:
        """Whether a socket was opened before this refusal."""
        return self.stage is not ConnectStage.APPROVE_DESTINATION

    @property
    def is_about_the_target(self) -> bool:
        """Always false. None of these say anything about the address probed."""
        return False


ConnectOutcome = SessionOpened | ConnectRefused


@dataclass(frozen=True, slots=True)
class SMTPConnector:
    """Opens one session, or explains which step refused."""

    transport: SMTPTransport

    async def open_session(self, candidate: RouteCandidate, address: str) -> ConnectOutcome:
        """Reach `address` on `candidate` and return a confirmed session.

        `address` must be one the candidate resolved to; `approve_destination`
        is what enforces that, and it is the first thing this does. There is no
        overload taking a host name, a bare address, or a port.
        """
        approval = approve_destination(candidate, address)
        if not isinstance(approval, DestinationApproved):
            return ConnectRefused(
                stage=ConnectStage.APPROVE_DESTINATION,
                destination_reason=approval.reason,
            )
        return await self._open_confirmed(approval.destination)

    async def _open_confirmed(self, destination: ApprovedDestination) -> ConnectOutcome:
        """Connect, confirm the peer, and close on anything short of success."""
        opened = await self.transport.connect(destination)
        if not isinstance(opened, ConnectionOpened):
            return ConnectRefused(stage=ConnectStage.CONNECT, transport_failure=opened.failure)

        connection = opened.connection
        confirmed = False
        try:
            verdict = confirm_peer(destination, connection.peer)
            if not isinstance(verdict, PeerAccepted):
                return ConnectRefused(stage=ConnectStage.CONFIRM_PEER, peer_reason=verdict.reason)
            confirmed = True
            return SessionOpened(session=begin_session(verdict.peer), connection=connection)
        finally:
            if not confirmed:
                # Covers the refusal above and any exception raised between
                # connecting and confirming.
                await connection.close()
