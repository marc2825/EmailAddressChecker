"""A TLS server side for the loopback suite, and the test trust anchor.

The client under test is production code with production verification. What is
injected here is one extra certificate authority and nothing else:
`build_client_context` always sets `check_hostname` and `CERT_REQUIRED`, and
there is no parameter through which either could be turned off. So these tests
exercise a real handshake against a real certificate, and the failure cases fail
for the real reason.

The server side runs its handshake on a worker thread with a blocking socket.
That is the simplest correct way to have both ends progress at once, and it
matters that it is the *server* doing it: the client is the thing being tested,
and it stays entirely on the event loop, driven by `loop.sock_recv` and
`loop.sock_sendall` exactly as it is in production.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from pathlib import Path
from typing import Final

from emailcheck.adapters.smtp.tls import TLSTrust

FIXTURES: Final = Path(__file__).resolve().parents[1] / "fixtures" / "tls"

#: The name the good certificate is issued for. The client verifies against it.
CERTIFICATE_HOST: Final = "mx.test.example"

CA_FILE: Final = str(FIXTURES / "ca.crt")

#: `mx.test.example`, signed by the test CA. The success path.
SERVER_CERT: Final = str(FIXTURES / "server.crt")
SERVER_KEY: Final = str(FIXTURES / "server.key")

#: `other.test.example`, signed by the same CA. The chain verifies and the name
#: does not, which is the only way to prove hostname checking is on.
WRONG_NAME_CERT: Final = str(FIXTURES / "wrong-name.crt")
WRONG_NAME_KEY: Final = str(FIXTURES / "wrong-name.key")

#: `mx.test.example`, signed by nobody the client trusts.
UNTRUSTED_CERT: Final = str(FIXTURES / "untrusted.crt")
UNTRUSTED_KEY: Final = str(FIXTURES / "untrusted.key")

#: What a test hands the connection so the throwaway CA is an anchor. This is
#: the entire seam, and it can only *add* trust.
TEST_TRUST: Final = TLSTrust(ca_file=CA_FILE)


def server_context(certificate: str = SERVER_CERT, key: str = SERVER_KEY) -> ssl.SSLContext:
    """A server context for the fixture end of the connection.

    This is the *peer*, not the code under test. Its settings say nothing about
    what this project does as a client.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certificate, keyfile=key)
    return context


async def serve_handshake(
    peer_socket: socket.socket, context: ssl.SSLContext
) -> ssl.SSLSocket | None:
    """Complete the server side of one handshake, or report that it failed.

    Runs on a worker thread so the client can make progress on the event loop at
    the same time. Returns `None` when the client rejected the certificate,
    which is what the failure tests expect to happen.
    """

    def handshake() -> ssl.SSLSocket | None:
        peer_socket.setblocking(True)
        peer_socket.settimeout(5.0)
        try:
            return context.wrap_socket(peer_socket, server_side=True)
        except (ssl.SSLError, OSError):
            return None

    return await asyncio.to_thread(handshake)


async def read_line_from(secure: ssl.SSLSocket) -> bytes:
    """Read one CRLF-terminated line from the fixture server's side."""

    def read() -> bytes:
        buffer = bytearray()
        while not buffer.endswith(b"\r\n"):
            chunk = secure.recv(1024)
            if not chunk:
                break
            buffer.extend(chunk)
        return bytes(buffer)

    return await asyncio.to_thread(read)


async def write_from(secure: ssl.SSLSocket, payload: bytes) -> None:
    """Write from the fixture server's side."""
    await asyncio.to_thread(secure.sendall, payload)


def close_quietly(secure: ssl.SSLSocket | None) -> None:
    if secure is None:
        return
    with contextlib.suppress(OSError, ssl.SSLError):
        secure.close()
