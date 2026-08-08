"""The SMTP boundary, shaped so the destination policy cannot be bypassed.

The important part of this file is what these ports do *not* offer.

`SMTPTransport.connect` takes an `ApprovedDestination` and nothing else: there
is no overload taking a host name, an address string, or a port, so no caller
can reach a destination the policy has not judged. What comes back is a
connection carrying the `PeerEndpoint` the socket actually reached, and
`application/smtp_connect.py` is the only thing that turns that into a session —
by way of `confirm_peer`.

`SMTPConnection` has **no arbitrary-bytes write method**, and gate 4C did not
add one. It takes a `WireCommand`, which is a value carrying one of exactly six
enum members together with the bytes the matching encoder produced, and which
verifies that the bytes begin with the verb it names. A caller cannot name a
seventh command, because there is no parameter through which to name one.

That the reachable wire lines are exactly the six encoders' output takes three
layers, not one: the type fixes the framing and the verb, the six factories in
`domain/smtp_wire.py` fix the argument forms, and an inspection test fixes that
production constructs a `WireCommand` only through those factories. The type on
its own constrains the verb and not the argument.

`write(payload: bytes)` would have been the obvious signature and it is the
arbitrary-command API this whole design exists to prevent: once it exists, any
holder of a connection can put any verb on the wire, and the closed enum, the
encoders, and the scanner all become advisory.

TLS is the same shape. `start_tls` takes a request built from a `ConfirmedPeer`,
so the name used for SNI and hostname verification is the MX host the
destination chain already validated — never the recipient's domain, never a
caller-supplied string.

No socket, stream, reader, writer, file descriptor, or `SSLContext` crosses this
boundary. The adapter holds those; the application sees a `PeerEndpoint`, typed
outcomes, and a close.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.smtp_destination import ApprovedDestination, ConfirmedPeer, PeerEndpoint
from emailcheck.domain.smtp_result import RecipientObservation
from emailcheck.domain.smtp_transport import (
    ReadOutcome,
    TLSOutcome,
    TransportFailure,
    WriteOutcome,
)
from emailcheck.domain.smtp_wire import WireCommand


@dataclass(frozen=True, slots=True)
class TLSUpgradeRequest:
    """Ask a connection to negotiate TLS on the peer it already confirmed.

    The peer is a `ConfirmedPeer` rather than a host name, and that is the whole
    safety content of this type: the name used for SNI and for hostname
    verification is `peer.host`, which came from the DNS candidate and survived
    `approve_destination` and `confirm_peer`. There is no parameter for a
    hostname, so the recipient's domain and any caller-supplied string are
    unrepresentable here.

    `timeout_seconds` bounds the handshake alone. The session deadline bounds it
    again from outside, and the smaller of the two is what applies.
    """

    peer: ConfirmedPeer
    timeout_seconds: float

    @property
    def server_hostname(self) -> str:
        """The MX host name, and the only name this project will verify against."""
        return self.peer.host.value


class SMTPConnection(Protocol):
    """One open connection, bounded and closeable.

    An async context manager, so a failure anywhere after the connection opens
    still closes it. The dialogue raises from inside such a block when a reply
    is unusable, and the connection must not survive that.
    """

    @property
    def peer(self) -> PeerEndpoint:
        """The endpoint the socket actually reached. Untrusted until confirmed."""
        ...

    @property
    def tls_active(self) -> bool:
        """Whether this connection is currently encrypted."""
        ...

    async def read_line(self) -> ReadOutcome:
        """Read one bounded line, or report a typed failure.

        Never unbounded: a line beyond the limit, a total beyond the limit, a
        timeout, a reset, and an EOF are all typed outcomes rather than an
        exception carrying a library's words.
        """
        ...

    async def write_command(self, command: WireCommand) -> WriteOutcome:
        """Put one encoded command line on the wire.

        The argument is the entire capability. It is not `bytes`, not a string,
        and not a command name: a `WireCommand` names a member of the closed
        six-command enum and carries bytes that begin with that verb, checked at
        construction. An implementation writes `command.payload` unchanged and
        appends nothing — the encoder already added the one CRLF.
        """
        ...

    async def start_tls(self, request: TLSUpgradeRequest) -> TLSOutcome:
        """Negotiate TLS in place, verifying the certificate and the host name.

        **Requirements on an implementation**, none of them optional:

        - certificate verification enabled, against the system trust store;
        - host name verification enabled, against `request.server_hostname`;
        - no fallback to plaintext on failure. A failed upgrade is terminal and
          the caller closes;
        - the endpoint underneath the upgrade is re-confirmed, so a connection
          cannot become a different peer's by being wrapped.
        """
        ...

    async def close(self) -> None:
        """Release the connection. Safe to call twice and after a cancellation."""
        ...

    async def __aenter__(self) -> SMTPConnection: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ConnectionOpened:
    """A socket is open. The peer has not been judged yet.

    Holding one of these authorizes nothing. `application/smtp_connect.py`
    immediately puts `connection.peer` through `confirm_peer` and closes on any
    refusal, and only a `ConfirmedPeer` opens a session.
    """

    connection: SMTPConnection


@dataclass(frozen=True, slots=True)
class ConnectionFailed:
    """No connection is open, and why, in this project's vocabulary."""

    failure: TransportFailure


ConnectionOutcome = ConnectionOpened | ConnectionFailed


class SMTPTransport(Protocol):
    """Opens one bounded connection to an approved destination."""

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        """Connect, and report either a connection or a typed failure.

        **Family rule for the implementation.** Connect with `AF_INET` for an
        IPv4 destination and `AF_INET6` for an IPv6 one, and do not use
        `AI_V4MAPPED`. A dual-stack socket reports an IPv4 peer as
        `::ffff:93.184.216.34`, which the destination policy refuses on purpose,
        so a mapped peer would turn a healthy IPv4 connection into an unsafe
        destination. Report the peer in the family the connection used; never
        unwrap a mapped form and treat it as a public IPv4.

        **Re-check rule.** Apply `evaluate_destination` once more immediately
        before opening the socket. `ApprovedDestination` checked it when it was
        built, and a worker may pick the job up much later.

        The address is already numeric and validated, so an implementation must
        not resolve a name here.
        """
        ...


class SMTPProber(Protocol):
    """Observes the recipient stage for one address.

    The result is structured protocol evidence. It carries no status: the
    aggregator in Phase 5 decides what a code means, with the DNS and passive
    evidence in front of it.
    """

    async def probe_recipient(
        self, address: NormalizedAddress, route: MailRoute
    ) -> RecipientObservation:
        """Observe the recipient stage without transmitting message content."""
        ...
