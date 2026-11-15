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
- **only an encoded command may be written.** `write_command` takes a
  `WireCommand` — one of six enum members plus bytes that were checked to begin
  with that verb — and writes its payload unchanged. There is no method taking
  `bytes`, a string, or a command name, so the reachable set of wire lines is
  the image of the six encoders. `_write_line` stays private underneath it.

Gate 4C adds TLS, and it is driven through `ssl.SSLObject` over a pair of
`MemoryBIO`s rather than a wrapped socket. That keeps every actual byte moving
through `loop.sock_recv` and `loop.sock_sendall`, which is what makes the test
suite's network guards and counters see TLS traffic exactly as they see
plaintext: the encryption is a transformation in memory, not a second I/O path.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final

from emailcheck.adapters.smtp.tls import SYSTEM_TRUST, TLSTrust, build_client_context
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
    TLSFailed,
    TLSNegotiated,
    TLSOutcome,
    TransportError,
    TransportFailure,
    TransportLimits,
    TransportTimeouts,
    WriteFailed,
    WriteOutcome,
    WriteSucceeded,
)
from emailcheck.domain.smtp_wire import WireCommand
from emailcheck.ports.smtp import (
    ConnectionFailed,
    ConnectionOpened,
    ConnectionOutcome,
    TLSUpgradeRequest,
)
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

#: OpenSSL's verification code for a certificate whose chain is fine and whose
#: name does not match. Distinguished from every other verification failure
#: because "the operator pointed at the wrong host" and "the certificate is not
#: trusted" are different problems, and both must stay non-fatal to the address.
_HOSTNAME_MISMATCH_VERIFY_CODE: Final = 62


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
class _TLSLayer:
    """An in-memory TLS session over the raw socket.

    `ssl.SSLObject` plus two `MemoryBIO`s rather than `wrap_socket`, so every
    byte still moves through `loop.sock_recv` and `loop.sock_sendall`. The
    encryption becomes a transformation in memory instead of a second I/O path,
    which means the suite's network guard and its outbound-call counter observe
    an encrypted session exactly as they observe a plaintext one.
    """

    ssl_object: ssl.SSLObject
    incoming: ssl.MemoryBIO
    outgoing: ssl.MemoryBIO


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
    _trust: TLSTrust = SYSTEM_TRUST
    _tls: _TLSLayer | None = None

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
        if not isinstance(self._trust, TLSTrust):
            raise SMTPContractError("a connection must carry a trust configuration")
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
        trust: TLSTrust = SYSTEM_TRUST,
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
            _trust=trust,
        )

    @property
    def peer(self) -> PeerEndpoint:
        return self._peer

    @property
    def tls_active(self) -> bool:
        return self._tls is not None

    # --- reading -----------------------------------------------------------

    async def read_line(self) -> ReadOutcome:
        """Read one line, bounded three ways: per line, per connection, in time."""
        if self._closed:
            return ReadFailed(failure=TransportFailure.CONNECTION_CLOSED)
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
                    chunk = await self._receive_bytes(READ_CHUNK_BYTES)
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

    # --- moving bytes, plaintext or encrypted ------------------------------

    async def _receive_bytes(self, size: int) -> bytes:
        """Read up to `size` application bytes. Empty means the peer is done.

        Plaintext is one socket read. Encrypted is a pump: ask the TLS session
        for plaintext, and when it needs more ciphertext, read the socket and
        feed it. Raises `OSError` on a TLS error so `read_line`'s existing
        handling names it without a second failure vocabulary.
        """
        loop = asyncio.get_running_loop()
        layer = self._tls
        if layer is None:
            return await loop.sock_recv(self._socket, size)

        while True:
            try:
                return layer.ssl_object.read(size)
            except ssl.SSLWantReadError:
                await self._flush_tls_output(layer)
                if not await self._feed_tls_input(layer):
                    return b""
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLError as error:
                raise OSError("the TLS session could not be read") from error

    async def _transmit_bytes(self, payload: bytes) -> None:
        """Put `payload` on the wire, encrypting it first when TLS is active."""
        loop = asyncio.get_running_loop()
        layer = self._tls
        if layer is None:
            await loop.sock_sendall(self._socket, payload)
            return

        view = memoryview(payload)
        while view:
            try:
                written = layer.ssl_object.write(view)
            except ssl.SSLWantReadError:
                await self._flush_tls_output(layer)
                if not await self._feed_tls_input(layer):
                    raise OSError("the peer closed during a TLS write") from None
                continue
            except ssl.SSLWantWriteError:
                await self._flush_tls_output(layer)
                continue
            except ssl.SSLError as error:
                raise OSError("the TLS session could not be written to") from error
            view = view[written:]
            await self._flush_tls_output(layer)
        await self._flush_tls_output(layer)

    async def _flush_tls_output(self, layer: _TLSLayer) -> None:
        """Move whatever the TLS session produced onto the socket."""
        payload = layer.outgoing.read()
        if payload:
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(self._socket, payload)

    async def _feed_tls_input(self, layer: _TLSLayer) -> bool:
        """Give the TLS session more ciphertext. False when the peer is done."""
        loop = asyncio.get_running_loop()
        chunk = await loop.sock_recv(self._socket, READ_CHUNK_BYTES)
        if not chunk:
            layer.incoming.write_eof()
            return False
        layer.incoming.write(chunk)
        return True

    # --- writing: only what an encoder produced ----------------------------

    async def write_command(self, command: WireCommand) -> WriteOutcome:
        """Write one encoded command line, and nothing else.

        The entire capability is the argument type. A `WireCommand` names one of
        six enum members and carries bytes that were checked to begin with that
        verb, so there is no reachable wire line that is not the output of one
        of the six encoders. The payload is written unchanged: the encoder
        already appended the one CRLF this project produces.
        """
        if not isinstance(command, WireCommand):
            # The same reasoning as `connect` and `SMTPSession.peer`: mypy runs
            # on `src` only, and an `Any` from a caller it never sees would
            # otherwise carry arbitrary bytes onto the wire.
            raise SMTPContractError("write_command requires a WireCommand from the encoders")
        try:
            await self._write_line(command.payload)
        except TransportError as error:
            return WriteFailed(failure=error.failure)
        return WriteSucceeded(payload_bytes=len(command.payload))

    async def _write_line(self, payload: bytes) -> None:
        """Write one already-encoded command line.

        Private on purpose, and it stays private now that `write_command`
        exists: the public capability takes a `WireCommand`, and this takes
        bytes. Everything that reaches it has come through the six encoders.
        """
        if self._closed:
            raise TransportError(TransportFailure.CONNECTION_CLOSED)
        try:
            async with asyncio.timeout(self._timeouts.write_seconds):
                await self._transmit_bytes(payload)
        except TimeoutError as error:
            raise TransportError(TransportFailure.WRITE_TIMEOUT) from error
        except OSError as error:
            raise TransportError(TransportFailure.CONNECTION_RESET) from error

    # --- upgrading to TLS ---------------------------------------------------

    async def start_tls(self, request: TLSUpgradeRequest) -> TLSOutcome:
        """Negotiate TLS in place over the socket that is already connected.

        Four things happen before a single handshake byte moves, and each of
        them is a refusal rather than a warning:

        - **the request must be a `TLSUpgradeRequest`**, which carries a
          `ConfirmedPeer`. The name verified against is `peer.host` — the MX
          host the destination chain validated — so the recipient's domain and
          any caller-supplied string are unrepresentable as an SNI value;
        - **the peer must still be the confirmed one.** `getpeername()` is read
          again and compared to both the endpoint this connection reported and
          the one the caller confirmed. Nothing is re-resolved: a name lookup
          here would reach somewhere the policy never saw;
        - **the read buffer must be empty.** Anything already received is
          plaintext an active attacker could have injected before the upgrade,
          and reading it afterwards would treat it as though it had arrived
          inside TLS. RFC 3207 says discard it; refusing the upgrade is
          stricter and leaves no path where injected bytes are used;
        - **verification is not negotiable.** `build_client_context` sets
          `check_hostname` and `CERT_REQUIRED` with no parameter that could turn
          either off.

        A failure is terminal. There is no fallback to plaintext, here or in the
        state machine, and none of these outcomes is evidence about the address.
        """
        if not isinstance(request, TLSUpgradeRequest):
            raise SMTPContractError("start_tls requires a TLSUpgradeRequest built from a peer")
        if (
            request.peer.peer_address != self._peer.address
            or request.peer.peer_port != self._peer.port
        ):
            # The confirmed peer and the endpoint this connection reached are
            # two records of one fact. If they disagree, one of them is about a
            # different connection.
            return TLSFailed(failure=TransportFailure.TLS_PEER_CHANGED)
        return await self._start_tls_over(request.server_hostname, request.timeout_seconds)

    async def _start_tls_over(self, server_hostname: str, timeout_seconds: float) -> TLSOutcome:
        """Negotiate TLS against `server_hostname`. Internal I/O primitive.

        `start_tls` is the only production caller and derives the name from a
        `ConfirmedPeer`, so nothing in `src/` can name a host of its own. The
        loopback integration tests call this directly for the same reason they
        call `_over_socket` directly: to exercise real socket behaviour without
        the authorization chain, which loopback cannot pass.

        It is not a verification bypass. `build_client_context` is used here as
        everywhere, so the certificate and the name are checked exactly as they
        are in production; the only thing this skips is the binding of the name
        to a `ConfirmedPeer`.
        """
        if self._closed:
            return TLSFailed(failure=TransportFailure.CONNECTION_CLOSED)
        if self._tls is not None:
            return TLSFailed(failure=TransportFailure.TLS_ALREADY_ACTIVE)
        if self._buffer:
            return TLSFailed(failure=TransportFailure.TLS_HANDSHAKE_FAILED)
        if not self._peer_is_unchanged():
            return TLSFailed(failure=TransportFailure.TLS_PEER_CHANGED)

        context = build_client_context(self._trust)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        layer = _TLSLayer(
            ssl_object=context.wrap_bio(
                incoming,
                outgoing,
                server_side=False,
                server_hostname=server_hostname,
            ),
            incoming=incoming,
            outgoing=outgoing,
        )

        try:
            async with asyncio.timeout(timeout_seconds):
                await self._perform_handshake(layer)
        except TimeoutError:
            return TLSFailed(failure=TransportFailure.TLS_TIMEOUT)
        except TransportError as error:
            return TLSFailed(failure=error.failure)
        except BaseException as error:
            if isinstance(error, _NEVER_A_TRANSPORT_FAILURE):
                raise
            return TLSFailed(failure=_tls_failure_for(error))

        self._tls = layer
        if not self._peer_is_unchanged():
            # Checked again on the other side of the upgrade, so a connection
            # cannot become a different peer's by being wrapped.
            return TLSFailed(failure=TransportFailure.TLS_PEER_CHANGED)
        return TLSNegotiated()

    async def _perform_handshake(self, layer: _TLSLayer) -> None:
        """Drive the handshake, translating what it raises into this vocabulary."""
        while True:
            try:
                layer.ssl_object.do_handshake()
            except ssl.SSLWantReadError:
                await self._flush_tls_output(layer)
                if not await self._feed_tls_input(layer):
                    raise TransportError(TransportFailure.TLS_HANDSHAKE_FAILED) from None
                continue
            except ssl.SSLWantWriteError:
                await self._flush_tls_output(layer)
                continue
            except ssl.SSLError as error:
                # The alert the failure produced is still in the outgoing BIO.
                # Flushing it is a courtesy to the peer and cannot fail the
                # handshake any further than it already has.
                with contextlib.suppress(OSError):
                    await self._flush_tls_output(layer)
                raise TransportError(_tls_failure_for(error)) from error
            except OSError as error:
                raise TransportError(TransportFailure.TLS_HANDSHAKE_FAILED) from error
            await self._flush_tls_output(layer)
            return

    def _peer_is_unchanged(self) -> bool:
        """Whether the socket is still on the endpoint this connection reported.

        Reads `getpeername()` and nothing else. No name is resolved, and the TLS
        session is never asked who it is talking to: a wrapper's opinion of the
        peer is not evidence about the socket underneath it.
        """
        try:
            current = _peer_from_sockaddr(self._socket.getpeername(), self._socket.family)
        except OSError:
            return False
        if isinstance(current, TransportFailure):
            return False
        return current == self._peer

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

        **No TLS `close_notify` is sent**, and that is a choice rather than an
        omission. Sending one means writing to the socket, which means awaiting,
        which would put back the cancellation point this close exists without.
        The peer sees a truncated session; the alternative is a close that can
        be interrupted with the descriptor still open, which is the defect the
        4B review found. The dialogue has already issued `QUIT`, so nothing is
        left to say.

        `close_seconds` is therefore consumed nowhere. It stays a validated
        field so a future graceful shutdown has a budget to use. It is currently
        unused; this close performs no awaited network operation.
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
    #: Extra certificate anchors, on top of the system trust store. Verification
    #: itself is not configurable; see `adapters/smtp/tls.py`.
    trust: TLSTrust = SYSTEM_TRUST

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
                open_socket,
                peer,
                limits=self.limits,
                timeouts=self.timeouts,
                trust=self.trust,
            )
        )


def _tls_failure_for(error: BaseException) -> TransportFailure:
    """Name a TLS failure without keeping a certificate, a chain, or a message.

    A hostname mismatch is separated from every other verification failure
    because the two mean different things to an operator — the wrong host was
    named, versus the chain does not verify — and neither means anything about
    the recipient. `docs/requirements.md` section 11 forbids library text in a
    result, so nothing beyond the enum member survives.
    """
    if isinstance(error, ssl.SSLCertVerificationError):
        if getattr(error, "verify_code", None) == _HOSTNAME_MISMATCH_VERIFY_CODE:
            return TransportFailure.TLS_HOSTNAME_MISMATCH
        return TransportFailure.TLS_CERTIFICATE_INVALID
    if isinstance(error, ssl.SSLError | OSError):
        return TransportFailure.TLS_HANDSHAKE_FAILED
    return TransportFailure.INTERNAL_ERROR


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
