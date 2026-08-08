"""A real TLS handshake, over loopback, with production verification on.

Everything else about TLS is tested against a fake, because a fake can script
outcomes a real server cannot be made to produce on demand. What a fake cannot
show is whether the handshake code works at all, and whether verification is
actually enforced rather than merely configured — so these run the real thing:

- a certificate the client trusts, for the right name, must succeed and the
  session must then carry bytes;
- a certificate signed by nobody the client trusts must fail;
- a certificate that verifies but names another host must fail.

The last two are the ones that matter. A client with verification quietly off
passes the first test and fails these, which is exactly why they exist.

`127.0.0.1` cannot pass the destination policy, so — as in
`test_loopback_transport.py` — these hand the connection an already-connected
socket and call the internal primitive. The authorization chain is not involved,
and the verification behaviour being exercised is the production one.
"""

from __future__ import annotations

import asyncio
import socket
import ssl

import pytest
from loopback_server import LoopbackServer
from tls_fixtures import (
    CERTIFICATE_HOST,
    SERVER_CERT,
    SERVER_KEY,
    TEST_TRUST,
    UNTRUSTED_CERT,
    UNTRUSTED_KEY,
    WRONG_NAME_CERT,
    WRONG_NAME_KEY,
    close_quietly,
    read_line_from,
    serve_handshake,
    server_context,
    write_from,
)

from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPConnection
from emailcheck.adapters.smtp.tls import SYSTEM_TRUST
from emailcheck.domain import smtp_wire as wire
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_identity import EhloIdentity
from emailcheck.domain.smtp_transport import (
    LineRead,
    TLSFailed,
    TLSNegotiated,
    TransportFailure,
    TransportTimeouts,
    WriteSucceeded,
)

pytestmark = pytest.mark.asyncio

FAST = TransportTimeouts(
    connect_seconds=2.0, read_seconds=2.0, write_seconds=2.0, close_seconds=1.0
)
HANDSHAKE_SECONDS = 5.0
EHLO_IDENTITY = EhloIdentity(host=HostName("probe.sender.test.example"))


async def connected(
    server: LoopbackServer, trust: object = TEST_TRUST
) -> tuple[AsyncioSMTPConnection, socket.socket]:
    """A connection whose reported peer is the endpoint the socket really reached.

    The peer has to be the real one: `start_tls` re-reads `getpeername()` and
    refuses an upgrade on an endpoint that is not the one the connection
    reported, which is the check that stops a wrapper changing who is on the
    other end.
    """
    client, peer_socket = await server.connected_pair()
    address, port = client.getpeername()[:2]
    connection = AsyncioSMTPConnection._over_socket(
        client,
        PeerEndpoint(address=address, port=port),
        timeouts=FAST,
        trust=trust,  # type: ignore[arg-type]
    )
    return connection, peer_socket


# --- the handshake that must succeed ---------------------------------------


async def test_a_trusted_certificate_for_the_right_name_negotiates(
    loopback_server: LoopbackServer,
) -> None:
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context()),
        )
        assert isinstance(client_side, TLSNegotiated)
        assert connection.tls_active is True
        assert secure is not None
    finally:
        close_quietly(secure)
        await connection.close()


async def test_the_encrypted_session_carries_commands_and_replies(
    loopback_server: LoopbackServer,
) -> None:
    """The upgrade is only useful if reading and writing still work through it."""
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context()),
        )
        assert isinstance(client_side, TLSNegotiated)
        assert secure is not None

        written, received = await asyncio.gather(
            connection.write_command(wire.ehlo(EHLO_IDENTITY)),
            read_line_from(secure),
        )
        assert isinstance(written, WriteSucceeded)
        assert received == b"EHLO probe.sender.test.example\r\n"

        await write_from(secure, b"250-mx.test.example at your service\r\n250 STARTTLS\r\n")
        first = await connection.read_line()
        second = await connection.read_line()
        assert isinstance(first, LineRead)
        assert isinstance(second, LineRead)
        assert first.line == b"250-mx.test.example at your service"
        assert second.line == b"250 STARTTLS"
    finally:
        close_quietly(secure)
        await connection.close()


async def test_the_bounds_still_apply_inside_tls(loopback_server: LoopbackServer) -> None:
    """Encryption is a transformation, not a second I/O path with its own rules."""
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context()),
        )
        assert isinstance(client_side, TLSNegotiated)
        assert secure is not None

        # The peer says nothing. The read deadline still fires.
        outcome = await connection.read_line()
        assert outcome.failure is TransportFailure.READ_TIMEOUT  # type: ignore[union-attr]
    finally:
        close_quietly(secure)
        await connection.close()


# --- the handshakes that must fail -----------------------------------------


async def test_an_untrusted_certificate_is_refused(loopback_server: LoopbackServer) -> None:
    """Signed by nobody the client trusts. Verification is what catches this."""
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context(UNTRUSTED_CERT, UNTRUSTED_KEY)),
        )
        assert isinstance(client_side, TLSFailed)
        assert client_side.failure is TransportFailure.TLS_CERTIFICATE_INVALID
        assert connection.tls_active is False
    finally:
        close_quietly(secure)
        await connection.close()


async def test_a_certificate_for_another_host_is_refused(
    loopback_server: LoopbackServer,
) -> None:
    """The chain verifies and the name does not.

    This is the test a client with `check_hostname = False` fails, and the
    reason the fixture set contains a second certificate from the same CA.
    """
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context(WRONG_NAME_CERT, WRONG_NAME_KEY)),
        )
        assert isinstance(client_side, TLSFailed)
        assert client_side.failure is TransportFailure.TLS_HOSTNAME_MISMATCH
        assert connection.tls_active is False
    finally:
        close_quietly(secure)
        await connection.close()


async def test_the_test_certificate_is_not_trusted_by_the_production_default(
    loopback_server: LoopbackServer,
) -> None:
    """The seam is real: without the extra anchor, the same certificate fails.

    This is what separates the test trust injection from production trust. If
    the fixture CA were reachable from `SYSTEM_TRUST`, the success cases above
    would prove nothing.
    """
    connection, peer_socket = await connected(loopback_server, trust=SYSTEM_TRUST)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context(SERVER_CERT, SERVER_KEY)),
        )
        assert isinstance(client_side, TLSFailed)
        assert client_side.failure is TransportFailure.TLS_CERTIFICATE_INVALID
    finally:
        close_quietly(secure)
        await connection.close()


async def test_a_handshake_that_never_completes_hits_its_deadline(
    loopback_server: LoopbackServer,
) -> None:
    """The peer accepts the connection and says nothing at all."""
    connection, _peer_socket = await connected(loopback_server)
    try:
        outcome = await connection._start_tls_over(CERTIFICATE_HOST, 0.3)
        assert isinstance(outcome, TLSFailed)
        assert outcome.failure is TransportFailure.TLS_TIMEOUT
        assert connection.tls_active is False
    finally:
        await connection.close()


# --- what the upgrade refuses to do ----------------------------------------


async def test_a_second_upgrade_is_refused(loopback_server: LoopbackServer) -> None:
    connection, peer_socket = await connected(loopback_server)
    secure: ssl.SSLSocket | None = None
    try:
        client_side, secure = await asyncio.gather(
            connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS),
            serve_handshake(peer_socket, server_context()),
        )
        assert isinstance(client_side, TLSNegotiated)

        again = await connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS)
        assert isinstance(again, TLSFailed)
        assert again.failure is TransportFailure.TLS_ALREADY_ACTIVE
    finally:
        close_quietly(secure)
        await connection.close()


async def test_buffered_plaintext_prevents_the_upgrade(
    loopback_server: LoopbackServer,
) -> None:
    """The pipelining attack, refused rather than discarded.

    Bytes received before the handshake are plaintext an active attacker could
    have injected. Reading them afterwards would treat them as though they had
    arrived inside TLS, which is CVE-2011-0411. RFC 3207 says discard; refusing
    the upgrade leaves no path where injected bytes are used at all.
    """
    connection, peer_socket = await connected(loopback_server)
    try:
        peer_socket.sendall(b"220 ready to start TLS\r\n250 injected\r\n")
        first = await connection.read_line()
        assert isinstance(first, LineRead)

        outcome = await connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS)
        assert isinstance(outcome, TLSFailed)
        assert outcome.failure is TransportFailure.TLS_HANDSHAKE_FAILED
        assert connection.tls_active is False
    finally:
        await connection.close()


async def test_an_upgrade_on_a_closed_connection_is_refused(
    loopback_server: LoopbackServer,
) -> None:
    connection, _peer_socket = await connected(loopback_server)
    await connection.close()

    outcome = await connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS)
    assert isinstance(outcome, TLSFailed)
    assert outcome.failure is TransportFailure.CONNECTION_CLOSED


async def test_an_upgrade_is_refused_when_the_peer_is_not_the_reported_one(
    loopback_server: LoopbackServer,
) -> None:
    """`ApprovedDestination → ConfirmedPeer` must survive the upgrade.

    The connection is built claiming a different endpoint than the socket
    actually reached, and the re-read of `getpeername()` catches it before a
    handshake byte moves.
    """
    client, peer_socket = await loopback_server.connected_pair()
    address, port = client.getpeername()[:2]
    connection = AsyncioSMTPConnection._over_socket(
        client,
        PeerEndpoint(address=address, port=(port + 1) % 65535 or 1),
        timeouts=FAST,
        trust=TEST_TRUST,
    )
    try:
        outcome = await connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS)
        assert isinstance(outcome, TLSFailed)
        assert outcome.failure is TransportFailure.TLS_PEER_CHANGED
    finally:
        peer_socket.close()
        await connection.close()


async def test_a_cancelled_handshake_propagates_and_closes(
    loopback_server: LoopbackServer,
) -> None:
    """4B's cancellation rule holds through TLS: re-raised, and nothing leaks."""
    connection, _peer_socket = await connected(loopback_server)
    raw = connection._socket

    upgrading = asyncio.create_task(connection._start_tls_over(CERTIFICATE_HOST, HANDSHAKE_SECONDS))
    for _ in range(3):
        await asyncio.sleep(0)
    upgrading.cancel()
    with pytest.raises(asyncio.CancelledError):
        await upgrading

    await connection.close()
    assert connection.is_closed is True
    assert raw.fileno() == -1
