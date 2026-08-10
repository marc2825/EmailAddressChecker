"""Test-wide guarantees.

Every test in this repository runs with outbound network access removed. A test
that reaches a real resolver fails loudly instead of quietly depending on the
machine it runs on, on the contents of `/etc/resolv.conf`, or on a timeout.

The guard covers the datagram paths too, not only the stream ones: a DNS query
needs no `getaddrinfo` and no `connect`, because the nameserver address comes
from `resolv.conf` and the query is sent with `sendto`. Blocking only the
stream calls would let a UDP query leave the machine.

`NetworkAccessAttempted` derives from `AssertionError` on purpose. The DNS
adapter re-raises `AssertionError` rather than converting it into a failure
value, so a blocked call fails the test instead of being reported as a DNS
result.

**The send guard exempts `AF_UNIX`, and that is a precision fix rather than a
weakening.** A Unix socket reaches no network by construction — there is no
address family through which one could — and asyncio's own event loop uses an
`AF_UNIX` socketpair as its self-pipe: `call_soon_threadsafe` wakes the loop by
calling `send` on it. Refusing that does not stop a packet leaving the machine;
it deadlocks any test that uses a worker thread, because the loop is never woken
and the future never completes. Phase 6 found it with `asyncio.to_thread`.

The exemption is exactly the one the out-of-repo counting harness already draws,
and `tests/test_no_network.py` pins both halves: an `AF_INET` send is still
refused, and an `AF_UNIX` one is not.
"""

import asyncio
import socket
from collections.abc import Iterator
from typing import Any, NoReturn

import pytest


class NetworkAccessAttempted(AssertionError):
    """A test tried to use the network."""


def _refuse(name: str) -> Any:
    def deny(*args: object, **kwargs: object) -> NoReturn:
        raise NetworkAccessAttempted(f"test attempted a real network call: {name}")

    return deny


def _refuse_unless_local(name: str, original: Any) -> Any:
    """Refuse a send, unless the socket is one that cannot reach a network.

    `AF_UNIX` is the only exemption, and it is a property of the address family
    rather than of an address a caller supplied: a Unix socket has nowhere to
    send *to* except a path on this machine. Everything else — `AF_INET`,
    `AF_INET6`, and anything added later — is refused.
    """

    def deny(self: socket.socket, *args: object, **kwargs: object) -> Any:
        if getattr(self, "family", None) == socket.AF_UNIX:
            return original(self, *args, **kwargs)
        raise NetworkAccessAttempted(f"test attempted a real network call: {name}")

    return deny


async def _refuse_async(name: str) -> Any:
    def deny(*args: object, **kwargs: object) -> NoReturn:
        raise NetworkAccessAttempted(f"test attempted a real network call: {name}")

    return deny


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail any attempt to resolve a name, open a connection, or send a packet."""
    # Name resolution.
    monkeypatch.setattr(socket, "getaddrinfo", _refuse("socket.getaddrinfo"))
    monkeypatch.setattr(socket, "gethostbyname", _refuse("socket.gethostbyname"))
    monkeypatch.setattr(socket, "gethostbyname_ex", _refuse("socket.gethostbyname_ex"))

    # Stream connections.
    monkeypatch.setattr(socket, "create_connection", _refuse("socket.create_connection"))
    monkeypatch.setattr(socket.socket, "connect", _refuse("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse("socket.connect_ex"))

    # Datagram sends, which is how a DNS query actually leaves the machine.
    # Each keeps the original so an `AF_UNIX` send — asyncio's own self-pipe —
    # still works; see the module docstring.
    for _name in ("sendto", "sendmsg", "send", "sendall"):
        monkeypatch.setattr(
            socket.socket,
            _name,
            _refuse_unless_local(f"socket.{_name}", getattr(socket.socket, _name)),
        )

    # The asyncio transports dnspython uses for its async resolver.
    monkeypatch.setattr(
        asyncio.BaseEventLoop,
        "create_connection",
        _refuse("asyncio.create_connection"),
    )
    monkeypatch.setattr(
        asyncio.BaseEventLoop,
        "create_datagram_endpoint",
        _refuse("asyncio.create_datagram_endpoint"),
    )
    yield
