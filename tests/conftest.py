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
    monkeypatch.setattr(socket.socket, "sendto", _refuse("socket.sendto"))
    monkeypatch.setattr(socket.socket, "sendmsg", _refuse("socket.sendmsg"))
    monkeypatch.setattr(socket.socket, "send", _refuse("socket.send"))
    monkeypatch.setattr(socket.socket, "sendall", _refuse("socket.sendall"))

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
