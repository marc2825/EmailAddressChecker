"""The one place in this project that opens a socket.

Its job is deliberately small: reach an already-approved destination, report the
endpoint it actually reached, read bounded lines, and close reliably. It makes
no protocol decisions. It does not know what `EHLO` is, when `STARTTLS` would be
appropriate, what a reply code means, or that SMTP has a recipient stage at all.
Gate 4C adds that on top; keeping it out of here is what makes the transport
reviewable as an I/O component rather than as a mail client.

Three rules from ADR 0008 are implemented here rather than merely respected:

- **the family is chosen, not inherited.** `AF_INET` for an IPv4 destination and
  `AF_INET6` for an IPv6 one, with no `AI_V4MAPPED` and no dual-stack listener
  behaviour. A dual-stack socket reports an IPv4 peer as `::ffff:…`, which the
  destination policy refuses on purpose, so letting the OS pick would turn a
  healthy IPv4 connection into an unsafe destination;
- **the policy runs once more before the socket exists.** `ApprovedDestination`
  checked it at construction, and a worker may pick the job up much later;
- **nothing is written.** There is no public write method, and gate 4B writes no
  bytes at all. `_write_line` exists as a private primitive for 4C to wire to
  the six encoders, and is not on the `SMTPConnection` protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final

from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_destination import (
    MAX_PORT_NUMBER,
    MIN_PORT_NUMBER,
    ApprovedDestination,
    PeerEndpoint,
)
from emailcheck.domain.smtp_transport import (
    READ_CHUNK_BYTES,
    LineRead,
    ReadFailed,
    ReadOutcome,
    TransportError,
    TransportFailure,
    TransportLimits,
    TransportTimeouts,
)
from emailcheck.ports.smtp import ConnectionFailed, ConnectionOpened, ConnectionOutcome
from emailcheck.security.destination import evaluate_destination

#: SMTP frames on CRLF. Reading tolerates a bare LF and strips a trailing CR,
#: because a lenient read costs nothing here: `domain/smtp_reply.py` decides
#: whether the framed line is a usable reply. Writing is strict and belongs to
#: the encoder, which appends the only CRLF this project produces.
_LINE_TERMINATOR: Final = b"\n"
_CARRIAGE_RETURN: Final = b"\r"

#: Errno-free mapping from the exceptions an OS raises to this project's words.
#: `docs/requirements.md` section 11 forbids full exception text in a result, and
#: an `OSError` message is not a stable contract to match on.
_CONNECT_FAILURES: Final[tuple[tuple[type[BaseException], TransportFailure], ...]] = (
    (ConnectionRefusedError, TransportFailure.CONNECTION_REFUSED),
    (TimeoutError, TransportFailure.CONNECT_TIMEOUT),
)

#: Exceptions that are never a transport failure and must reach the caller.
#:
#: The first four are process and task control: a `Ctrl-C` during a connect is
#: not a network condition, and turning one into `ConnectionFailed` would let a
#: worker keep going after it was told to stop. `CancelledError` matters most,
#: because swallowing it hands back a result to a caller that no longer exists.
#:
#: `AssertionError` is here for the same reason Phase 2's DNS adapter re-raises
#: it: this project's own invariant failures, and the test suite's network
#: guard, must fail loudly rather than be reported as something the network did.
_NEVER_A_TRANSPORT_FAILURE: Final[tuple[type[BaseException], ...]] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    AssertionError,
)


def _family_for(destination: ApprovedDestination) -> int:
    """Pick the socket family from the destination's own address family.

    Never `AF_UNSPEC`, never a dual-stack `AF_INET6` carrying an IPv4 address.
    """
    return socket.AF_INET if destination.version == 4 else socket.AF_INET6


def _peer_from_sockaddr(sockaddr: object, family: int) -> PeerEndpoint | TransportFailure:
    """Turn what `getpeername()` reports into a value, or name why it cannot be.

    The address is normalized within its own family and never across one. An
    IPv4-mapped or 6to4 form arriving on an `AF_INET6` socket is refused rather
    than unwrapped: unwrapping is the fallback that would trust a mapped address
    as a public IPv4, which is exactly what the policy refuses mapped forms to
    stop.

    That case gets `PEER_UNEXPECTED_FAMILY` rather than a policy denial, because
    this transport never connects dual-stack — seeing one means the family
    selection broke, and that is worth reporting as itself rather than as a
    refused address.
    """
    if not isinstance(sockaddr, tuple) or len(sockaddr) < 2:
        return TransportFailure.PEER_MALFORMED
    host, port = sockaddr[0], sockaddr[1]
    if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
        return TransportFailure.PEER_MALFORMED
    if not MIN_PORT_NUMBER <= port <= MAX_PORT_NUMBER:
        # An unconnected socket reports port 0. `PeerEndpoint` refuses it, and a
        # refusal must be a typed failure here rather than an exception escaping
        # the transport.
        return TransportFailure.PEER_MALFORMED
    if "%" in host:
        # A scope identifier means a link-local peer, which the policy refuses
        # anyway. Refuse it here rather than parsing an interface name.
        return TransportFailure.PEER_UNEXPECTED_FAMILY
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return TransportFailure.PEER_MALFORMED

    expected_version = 4 if family == socket.AF_INET else 6
    if parsed.version != expected_version:
        return TransportFailure.PEER_UNEXPECTED_FAMILY
    if isinstance(parsed, ipaddress.IPv6Address) and (
        parsed.ipv4_mapped is not None or parsed.sixtofour is not None
    ):
        # Only a dual-stack socket produces these, and this transport never
        # opens one. Refused here, unwrapped nowhere.
        return TransportFailure.PEER_UNEXPECTED_FAMILY
    return PeerEndpoint(address=str(parsed), port=port)


@dataclass(slots=True)
class AsyncioSMTPConnection:
    """One open socket, with bounded reads and a close that always runs.

    Built only by `_over_socket`, which `connect` calls with the socket it has
    just opened. It is an I/O handle rather than a domain value, so it is not
    frozen — but the fields a reviewer would have to trust are checked, because
    `_peer` is what the connection reports to `confirm_peer`.
    """

    _socket: socket.socket
    _peer: PeerEndpoint
    _limits: TransportLimits
    _timeouts: TransportTimeouts
    _buffer: bytearray
    _total_read: int = 0
    _closed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self._peer, PeerEndpoint):
            # The value the application puts through `confirm_peer`. An
            # annotation is a promise to a type checker that runs on `src` only.
            raise SMTPContractError("a connection must carry a PeerEndpoint")
        if not isinstance(self._limits, TransportLimits):
            raise SMTPContractError("a connection must carry validated limits")
        if not isinstance(self._timeouts, TransportTimeouts):
            raise SMTPContractError("a connection must carry validated timeouts")
        if isinstance(self._total_read, bool) or not isinstance(self._total_read, int):
            raise SMTPContractError("a byte count must be a whole number")
        if self._total_read < 0:
            raise SMTPContractError("a connection cannot have read a negative number of bytes")
        if self._total_read > self._limits.max_total_bytes:
            raise SMTPContractError("a connection cannot begin beyond its own total limit")
        if self._closed and self._socket.fileno() != -1:
            raise SMTPContractError("a connection reported as closed cannot hold an open socket")

    @classmethod
    def _over_socket(
        cls,
        open_socket: socket.socket,
        peer: PeerEndpoint,
        *,
        limits: TransportLimits | None = None,
        timeouts: TransportTimeouts | None = None,
    ) -> AsyncioSMTPConnection:
        """Wrap a socket that is already connected. Internal I/O primitive.

        `connect` calls this with the socket it just opened, and the integration
        tests in `tests/integration/` call it with a loopback socket they opened
        themselves. It is not an authorization bypass and never was — it takes
        no destination, so it grants no reachability a caller did not already
        have by holding a connected socket, and what it returns is a connection
        with no write method rather than a session. It is named privately so it
        cannot be mistaken for the way in: `connect` is the only public entry.
        """
        open_socket.setblocking(False)
        return cls(
            _socket=open_socket,
            _peer=peer,
            _limits=limits or TransportLimits(),
            _timeouts=timeouts or TransportTimeouts(),
            _buffer=bytearray(),
        )

    @property
    def peer(self) -> PeerEndpoint:
        return self._peer

    # --- reading -----------------------------------------------------------

    async def read_line(self) -> ReadOutcome:
        """Read one line, bounded three ways: per line, per connection, in time."""
        if self._closed:
            return ReadFailed(failure=TransportFailure.CONNECTION_CLOSED)
        loop = asyncio.get_running_loop()
        while True:
            framed = self._take_line()
            if isinstance(framed, TransportFailure):
                return ReadFailed(failure=framed)
            if framed is not None:
                return LineRead(line=framed)
            if len(self._buffer) > self._limits.max_line_bytes:
                return ReadFailed(failure=TransportFailure.LINE_TOO_LONG)
            if self._total_read >= self._limits.max_total_bytes:
                # The budget is spent, so no further byte may be asked for. This
                # is checked before the socket read rather than after it: a
                # connection that has already exceeded its total must fail now
                # rather than spend a whole read deadline discovering it again.
                # Anything already framed above is still delivered first.
                return ReadFailed(failure=TransportFailure.TOTAL_LIMIT_EXCEEDED)

            try:
                async with asyncio.timeout(self._timeouts.read_seconds):
                    chunk = await loop.sock_recv(self._socket, READ_CHUNK_BYTES)
            except TimeoutError:
                return ReadFailed(failure=TransportFailure.READ_TIMEOUT)
            except ConnectionResetError:
                return ReadFailed(failure=TransportFailure.CONNECTION_RESET)
            except OSError:
                return ReadFailed(failure=TransportFailure.CONNECTION_RESET)

            if not chunk:
                return ReadFailed(failure=TransportFailure.CONNECTION_CLOSED)
            self._total_read += len(chunk)
            if self._total_read > self._limits.max_total_bytes:
                return ReadFailed(failure=TransportFailure.TOTAL_LIMIT_EXCEEDED)
            self._buffer.extend(chunk)

    def _take_line(self) -> bytes | TransportFailure | None:
        """Remove one complete line, name why it is unusable, or report None.

        `None` means no terminator has arrived yet. A failure is returned rather
        than raised: `read_line` promises typed outcomes, and an over-long line
        that arrives complete must not become an exception when the same line
        arriving in pieces becomes a `ReadFailed`. An integration test against a
        real socket found exactly that inconsistency.
        """
        index = self._buffer.find(_LINE_TERMINATOR)
        if index < 0:
            return None
        framed = bytes(self._buffer[:index])
        del self._buffer[: index + 1]
        if framed.endswith(_CARRIAGE_RETURN):
            framed = framed[:-1]
        if len(framed) > self._limits.max_line_bytes:
            return TransportFailure.LINE_TOO_LONG
        return framed

    # --- writing: private, and unused in gate 4B ---------------------------

    async def _write_line(self, payload: bytes) -> None:
        """Write one already-encoded command line.

        Private on purpose. `SMTPConnection` does not declare it, so no
        application or domain code can reach it, and gate 4B calls it nowhere.
        Gate 4C wires it to the output of the six encoders in
        `domain/smtp_command.py` and to nothing else.
        """
        if self._closed:
            raise TransportError(TransportFailure.CONNECTION_CLOSED)
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(self._timeouts.write_seconds):
                await loop.sock_sendall(self._socket, payload)
        except TimeoutError as error:
            raise TransportError(TransportFailure.WRITE_TIMEOUT) from error
        except OSError as error:
            raise TransportError(TransportFailure.CONNECTION_RESET) from error

    # --- closing -----------------------------------------------------------

    async def close(self) -> None:
        """Release the socket. Idempotent, and the descriptor is always released.

        A close that can raise is a close that gets skipped in a `finally`, and
        a close that can block is a worker a tarpit can hold. Neither happens
        here, and the reason is the shape rather than a guard:

        - **there is no await.** Both operations are non-blocking calls on a
          non-blocking socket, so this coroutine never suspends, which means it
          offers no point at which a cancellation can be delivered. That is a
          stronger property than a deadline around it: an earlier version wrapped
          a no-op `await` in `asyncio.timeout` to look bounded, and all it
          actually did was create the one cancellation point in the function;
        - **the release is in a `finally`.** A cancellation arriving from
          anywhere still runs it, so `is_closed` can never be true while the
          descriptor is open. `CancelledError` then continues to the caller: the
          resource is cleaned up, and the caller's cancellation is not eaten.

        `close_seconds` is not consumed here. It is the budget for gate 4C's
        graceful shutdown, where a TLS `close_notify` does involve waiting.
        """
        if self._closed:
            return
        self._closed = True
        try:
            with contextlib.suppress(OSError):
                self._socket.shutdown(socket.SHUT_RDWR)
        finally:
            with contextlib.suppress(OSError):
                self._socket.close()

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> AsyncioSMTPConnection:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()


@dataclass(frozen=True, slots=True)
class AsyncioSMTPTransport:
    """Opens connections to approved destinations, and nothing else."""

    limits: TransportLimits = field(default_factory=TransportLimits)
    timeouts: TransportTimeouts = field(default_factory=TransportTimeouts)

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        """Connect to `destination`, re-checking the policy first.

        On any failure after the socket exists the socket is closed here, so a
        caller never receives a half-open connection alongside a failure.

        The type is checked at run time before anything else happens, on the
        same reasoning `SMTPSession` checks its peer: mypy runs on `src` only,
        `Any` launders a wrong value, and an object that merely *has* `address`,
        `port`, and `version` would otherwise be connected to. That object has
        passed neither `approve_destination` nor the policy, so the entire chain
        would be bypassed by duck typing. A wrong type is a programmer error and
        raises rather than becoming a `ConnectionFailed`, so it cannot be
        mistaken for something the network did.
        """
        if not isinstance(destination, ApprovedDestination):
            raise SMTPContractError(
                "connect requires an ApprovedDestination, so the destination policy has run "
                "against the DNS candidate and again against the address"
            )

        decision = evaluate_destination(destination.address)
        if not decision.allowed or decision.address != destination.address:
            # Defence in depth: `ApprovedDestination` already checked this, and
            # it is checked again with the socket still unopened.
            return ConnectionFailed(failure=TransportFailure.DESTINATION_DENIED_BY_POLICY)

        family = _family_for(destination)
        open_socket = socket.socket(family, socket.SOCK_STREAM)
        open_socket.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(self.timeouts.connect_seconds):
                # The address is numeric and validated, so no name is resolved.
                await loop.sock_connect(open_socket, (destination.address, destination.port))
        except BaseException as error:
            open_socket.close()
            return ConnectionFailed(failure=_connect_failure_for(error))

        try:
            peer = _peer_from_sockaddr(open_socket.getpeername(), family)
        except OSError:
            open_socket.close()
            return ConnectionFailed(failure=TransportFailure.CONNECTION_RESET)
        if isinstance(peer, TransportFailure):
            open_socket.close()
            return ConnectionFailed(failure=peer)

        return ConnectionOpened(
            connection=AsyncioSMTPConnection._over_socket(
                open_socket, peer, limits=self.limits, timeouts=self.timeouts
            )
        )


def _connect_failure_for(error: BaseException) -> TransportFailure:
    """Name an OS failure in this project's vocabulary, keeping no text.

    Raises rather than naming for anything in `_NEVER_A_TRANSPORT_FAILURE`. The
    caller closes the socket before asking, so a re-raise still releases the
    descriptor; what it does not do is answer a cancelled or interrupted caller
    with a result about the network.
    """
    if isinstance(error, _NEVER_A_TRANSPORT_FAILURE):
        raise error
    for kind, failure in _CONNECT_FAILURES:
        if isinstance(error, kind):
            return failure
    if isinstance(error, OSError):
        return TransportFailure.NETWORK_UNREACHABLE
    return TransportFailure.INTERNAL_ERROR
