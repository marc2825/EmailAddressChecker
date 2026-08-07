"""A plain TCP fixture on loopback, and the guard that keeps it there.

Not an SMTP server. Gate 4B speaks no SMTP, so this exists only so the
transport's reads, resets, and closes run against a real socket rather than a
scripted one.

It lives in its own module rather than in `conftest.py` because `from conftest
import ...` resolves to the root `tests/conftest.py` from any test file, so a
second conftest cannot share helpers under that name.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket

#: The only addresses a socket may reach from `tests/integration/`.
LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})

#: Marks a function the guard fixture installed, so a test can assert the guard
#: is in place by inspection rather than by attempting the call it forbids.
GUARD_MARKER = "emailcheck_loopback_guard"


class LoopbackRefused(AssertionError):
    """An integration test tried to reach something that is not loopback."""


def mark_guard(function: object) -> object:
    """Record that `function` is a guard this directory installed."""
    setattr(function, GUARD_MARKER, True)
    return function


def is_guard_installed(function: object) -> bool:
    """Whether `function` is a guard this directory installed."""
    return getattr(function, GUARD_MARKER, False) is True


def is_loopback(address: object) -> bool:
    """Whether a sockaddr names loopback, judged by parsing rather than by text."""
    if not isinstance(address, tuple) or not address:
        return False
    host = address[0]
    if not isinstance(host, str):
        return False
    try:
        parsed = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return str(parsed) in LOOPBACK_ADDRESSES


def is_permitted_bind_host(host: object) -> bool:
    """Whether a fixture may bind `host`. Pure, so it is testable without binding.

    The dangerous value is `0.0.0.0`, which would expose the fixture to every
    interface on the machine — and `::` does the same on IPv6. Neither is
    loopback, so the same rule that governs connecting governs binding, and it
    is a function rather than a comment so a test can assert it directly instead
    of by attempting the bind it exists to prevent.
    """
    if not isinstance(host, str) or not host:
        return False
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        # A name, including `localhost`, could resolve anywhere.
        return False
    return str(parsed) in LOOPBACK_ADDRESSES


class LoopbackServer:
    """Accepts connections on an ephemeral loopback port."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        if not is_permitted_bind_host(host):
            raise LoopbackRefused(f"a fixture may bind loopback only, not {host!r}")
        self._listener: socket.socket | None = None
        self.host = host
        self.port = 0
        self.accepted: list[socket.socket] = []

    def start(self) -> None:
        # Re-checked here, not only in the constructor: `host` is a plain
        # attribute, and this is the last point before a descriptor exists.
        if not is_permitted_bind_host(self.host):
            raise LoopbackRefused(f"a fixture may bind loopback only, not {self.host!r}")
        family = socket.AF_INET if ipaddress.ip_address(self.host).version == 4 else socket.AF_INET6
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, 0))
        listener.listen(4)
        listener.setblocking(False)
        self._listener = listener
        self.port = listener.getsockname()[1]

    def stop(self) -> None:
        """Release every socket. Runs from a `finally`, so it never raises."""
        for accepted in self.accepted:
            with contextlib.suppress(OSError):
                accepted.close()
        self.accepted.clear()
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()
            self._listener = None

    async def accept(self) -> socket.socket:
        assert self._listener is not None, "the server was not started"
        loop = asyncio.get_running_loop()
        accepted, _ = await loop.sock_accept(self._listener)
        accepted.setblocking(False)
        self.accepted.append(accepted)
        return accepted

    async def connected_pair(self) -> tuple[socket.socket, socket.socket]:
        """Return a client socket and the server side of the same connection."""
        loop = asyncio.get_running_loop()
        family = socket.AF_INET if ipaddress.ip_address(self.host).version == 4 else socket.AF_INET6
        client = socket.socket(family, socket.SOCK_STREAM)
        client.setblocking(False)
        connecting = asyncio.ensure_future(loop.sock_connect(client, (self.host, self.port)))
        server_side = await self.accept()
        await connecting
        self.accepted.append(client)
        return client, server_side
