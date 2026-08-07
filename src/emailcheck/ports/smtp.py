"""The SMTP boundary, shaped so the destination policy cannot be bypassed.

The important part of this file is what these ports do *not* offer.

`SMTPTransport.connect` takes an `ApprovedDestination` and nothing else: there
is no overload taking a host name, an address string, or a port, so no caller
can reach a destination the policy has not judged. What comes back is a
connection carrying the `PeerEndpoint` the socket actually reached, and
`application/smtp_connect.py` is the only thing that turns that into a session —
by way of `confirm_peer`.

`SMTPConnection` has **no write method**. Gate 4B does not speak SMTP, so the
capability to write a line is not part of the published contract; the adapter
keeps a private primitive for gate 4C to wire to the six encoders in
`domain/smtp_command.py`. A port with a `write(payload: bytes)` on it would be
the arbitrary-command API the whole design exists to prevent, and it would be
reachable from application code the moment it existed.

No socket, stream, reader, writer, or file descriptor crosses this boundary. The
adapter holds those; the application sees a `PeerEndpoint`, typed read outcomes,
and a close.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.smtp_destination import ApprovedDestination, PeerEndpoint
from emailcheck.domain.smtp_result import RecipientObservation
from emailcheck.domain.smtp_transport import ReadOutcome, TransportFailure


class SMTPConnection(Protocol):
    """One open connection, bounded and closeable.

    An async context manager, so a failure anywhere after the connection opens
    still closes it. Gate 4C will raise from inside such a block when a reply is
    unusable, and the connection must not survive that.
    """

    @property
    def peer(self) -> PeerEndpoint:
        """The endpoint the socket actually reached. Untrusted until confirmed."""
        ...

    async def read_line(self) -> ReadOutcome:
        """Read one bounded line, or report a typed failure.

        Never unbounded: a line beyond the limit, a total beyond the limit, a
        timeout, a reset, and an EOF are all typed outcomes rather than an
        exception carrying a library's words.
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
