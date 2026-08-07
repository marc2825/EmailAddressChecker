"""A scripted `SMTPTransport` that opens no socket.

This is the default for every transport test, as `docs/test-strategy.md` fixes.
It implements the port with a scripted sequence, so the connector and — from
gate 4C — the dialogue can be exercised with no address, no policy in the path,
no timing, and no flake.

It lives under `tests/` and production code cannot import it. That is the
property that makes the loopback problem safe to leave unsolved in production:
the escape is not in a package the application can reach.

The fake carries a `write_line_calls` counter and a private `_write_line`,
mirroring the real adapter. Gate 4B never writes, and a test asserts the counter
is zero after a peer is refused — which is only meaningful because the fake
*would* have recorded a write if one had happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType

from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_destination import ApprovedDestination, PeerEndpoint
from emailcheck.domain.smtp_transport import (
    LineRead,
    ReadFailed,
    ReadOutcome,
    TransportFailure,
)
from emailcheck.ports.smtp import ConnectionFailed, ConnectionOpened, ConnectionOutcome


@dataclass(slots=True)
class FakeSMTPConnection:
    """One scripted connection. Records what was asked of it."""

    peer: PeerEndpoint
    scripted_reads: list[ReadOutcome] = field(default_factory=list)
    read_calls: int = 0
    close_calls: int = 0
    write_line_calls: int = 0
    written: list[bytes] = field(default_factory=list)
    entered: int = 0
    exited: int = 0

    async def read_line(self) -> ReadOutcome:
        self.read_calls += 1
        if self.close_calls:
            return ReadFailed(failure=TransportFailure.CONNECTION_CLOSED)
        if not self.scripted_reads:
            return ReadFailed(failure=TransportFailure.CONNECTION_CLOSED)
        return self.scripted_reads.pop(0)

    async def _write_line(self, payload: bytes) -> None:
        """Present only so a test can prove nothing calls it."""
        self.write_line_calls += 1
        self.written.append(payload)

    async def close(self) -> None:
        self.close_calls += 1

    @property
    def is_closed(self) -> bool:
        return self.close_calls > 0

    async def __aenter__(self) -> FakeSMTPConnection:
        self.entered += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.exited += 1
        await self.close()


@dataclass(slots=True)
class FakeSMTPTransport:
    """Answers `connect` from a script, and records every destination asked for."""

    peer: PeerEndpoint | None = None
    failure: TransportFailure | None = None
    scripted_reads: list[ReadOutcome] = field(default_factory=list)
    raise_on_connect: BaseException | None = None
    connect_calls: list[ApprovedDestination] = field(default_factory=list)
    connections: list[FakeSMTPConnection] = field(default_factory=list)

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        if not isinstance(destination, ApprovedDestination):
            # The real adapter refuses a lookalike at run time, so this one does
            # too. A double that accepts what the original rejects lets a test
            # pass on a path production would refuse, which is the one way a
            # fake can be more dangerous than the thing it stands in for.
            raise SMTPContractError("connect requires an ApprovedDestination")
        self.connect_calls.append(destination)
        if self.raise_on_connect is not None:
            raise self.raise_on_connect
        if self.failure is not None:
            return ConnectionFailed(failure=self.failure)
        peer = self.peer or PeerEndpoint(address=destination.address, port=destination.port)
        connection = FakeSMTPConnection(peer=peer, scripted_reads=list(self.scripted_reads))
        self.connections.append(connection)
        return ConnectionOpened(connection=connection)

    # --- what a test asserts afterwards ------------------------------------

    @property
    def total_write_line_calls(self) -> int:
        return sum(connection.write_line_calls for connection in self.connections)

    @property
    def all_closed(self) -> bool:
        return all(connection.is_closed for connection in self.connections)


def unvalidated_peer(address: str, port: int) -> PeerEndpoint:
    """A `PeerEndpoint` built without running its own checks.

    `PeerEndpoint` validates its shape on construction — a numeric address, no
    CR/LF/NUL, a real port number — so a malformed endpoint cannot be built the
    ordinary way. That is the point of it, and it is also why the second barrier
    needs a way to be tested: `confirm_peer` re-runs the destination policy, and
    a test has to be able to hand it something the value type would have
    refused in order to prove that it does.

    Nothing in `src/` can reach this. It exists so the two layers — the value
    guarantees the shape, the policy grants the permission — can be shown to be
    independent rather than assumed to be.
    """
    peer = object.__new__(PeerEndpoint)
    object.__setattr__(peer, "address", address)
    object.__setattr__(peer, "port", port)
    return peer


def line(text: str) -> LineRead:
    """A scripted line, written the way a server would frame it."""
    return LineRead(line=text.encode("ascii"))


def read_failure(failure: TransportFailure) -> ReadFailed:
    return ReadFailed(failure=failure)
