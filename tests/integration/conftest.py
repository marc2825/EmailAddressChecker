"""The only place in this repository where a socket may connect.

The suite-wide guard in `tests/conftest.py` refuses every outbound call. These
tests need real socket behaviour — a reset, a partial read, a close that must
happen — so this directory replaces that fixture with a narrower one: **loopback
only, and nothing else**.

The narrowing is deliberate and small:

- `127.0.0.1` and `::1` may be connected to;
- every other address is refused, including public addresses, RFC 1918,
  link-local, and the cloud metadata endpoint;
- name resolution stays refused entirely. A test that resolves a name is a test
  that could reach something outside this machine, so `getaddrinfo` and friends
  raise here exactly as they do everywhere else.

This lives under `tests/`. Production code cannot import it, and none of it is a
production capability: `evaluate_destination` is untouched, there is no
allowlist in `src/`, no environment variable, and no test-mode branch. The
tests here reach the transport's I/O primitives by handing them an
already-connected socket, so the destination-authorization chain is not
involved at all — which is why the policy never has to know that loopback
exists.
"""

from __future__ import annotations

import asyncio
import socket
from asyncio.selector_events import BaseSelectorEventLoop
from collections.abc import Iterator
from typing import Any, NoReturn

import pytest
from loopback_server import LoopbackRefused, LoopbackServer, is_loopback, mark_guard

#: Every function this fixture installs is marked, so a test can assert the
#: guard is in place by inspection. That matters: the alternative is to prove the
#: guard works by attempting the call it forbids, which is exactly what performs
#: a real outbound connection on the day the guard is broken.


def _mark(function: Any) -> Any:
    mark_guard(function)
    return function


def _refuse(name: str) -> Any:
    def deny(*args: object, **kwargs: object) -> NoReturn:
        raise LoopbackRefused(f"integration test attempted a real network call: {name}")

    return _mark(deny)


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Permit loopback connects. Refuse everything else, including DNS.

    This overrides the identically named fixture in `tests/conftest.py` for this
    directory only; pytest resolves a fixture from the nearest conftest.
    """
    # Name resolution stays refused: a resolved name could be anywhere.
    monkeypatch.setattr(socket, "getaddrinfo", _refuse("socket.getaddrinfo"))
    monkeypatch.setattr(socket, "gethostbyname", _refuse("socket.gethostbyname"))
    monkeypatch.setattr(socket, "gethostbyname_ex", _refuse("socket.gethostbyname_ex"))
    monkeypatch.setattr(socket, "create_connection", _refuse("socket.create_connection"))

    # Datagram sends have no business here at all.
    monkeypatch.setattr(socket.socket, "sendto", _refuse("socket.sendto"))
    monkeypatch.setattr(socket.socket, "sendmsg", _refuse("socket.sendmsg"))
    monkeypatch.setattr(
        asyncio.BaseEventLoop,
        "create_datagram_endpoint",
        _refuse("asyncio.create_datagram_endpoint"),
    )
    monkeypatch.setattr(
        asyncio.BaseEventLoop, "create_connection", _refuse("asyncio.create_connection")
    )

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sock_connect = BaseSelectorEventLoop.sock_connect

    @_mark
    def guarded_connect(self: socket.socket, address: object) -> object:
        if not is_loopback(address):
            raise LoopbackRefused(f"integration test tried to reach {address!r}")
        return real_connect(self, address)  # type: ignore[arg-type]

    @_mark
    def guarded_connect_ex(self: socket.socket, address: object) -> object:
        if not is_loopback(address):
            raise LoopbackRefused(f"integration test tried to reach {address!r}")
        return real_connect_ex(self, address)  # type: ignore[arg-type]

    @_mark
    async def guarded_sock_connect(
        self: asyncio.BaseEventLoop, sock: socket.socket, address: object
    ) -> object:
        if not is_loopback(address):
            raise LoopbackRefused(f"integration test tried to reach {address!r}")
        return await real_sock_connect(self, sock, address)  # type: ignore[arg-type]

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    # On `BaseSelectorEventLoop`, which is where the running loop's method
    # actually comes from: patching `BaseEventLoop` sets an attribute the MRO
    # never reaches, so that guard layer was inert. The socket-level guard above
    # was doing the work on its own.
    monkeypatch.setattr(BaseSelectorEventLoop, "sock_connect", guarded_sock_connect)
    yield


@pytest.fixture
def loopback_server() -> Iterator[LoopbackServer]:
    """A plain TCP fixture on an ephemeral loopback port.

    Not an SMTP server: gate 4B speaks no SMTP, and this exists only so the
    transport's reads, resets, and closes run against a real socket. It binds
    `127.0.0.1` and never `0.0.0.0`, and closes in a `finally` so a failing test
    still releases the port.
    """
    server = LoopbackServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()
