"""Prove the suite really cannot reach the network.

`tests/conftest.py` removes outbound network access for every test. These tests
fail if that guard stops working, so a later Phase cannot quietly start
depending on a real resolver.

Nothing here constructs a resolver that would talk to the system's nameservers.
The adapter is exercised only through an injected stub; the one test that drives
the real adapter asserts that it fails *before* a packet is sent, and it fails
the test rather than reporting a DNS result.
"""

import asyncio
import socket
from typing import Any

import pytest
from tests import conftest

from emailcheck.adapters.dns.dnspython_resolver import DNSPythonResolver
from emailcheck.domain.dns import HostName

# The guard raises an AssertionError subclass. It is matched by message rather
# than by class, because pytest imports `conftest` as a top-level module and an
# import through the package path would be a different object.
BLOCKED = "real network call"


@pytest.mark.parametrize(
    ("name", "call"),
    [
        ("getaddrinfo", lambda: socket.getaddrinfo("example.com", 25)),
        ("gethostbyname", lambda: socket.gethostbyname("example.com")),
        ("gethostbyname_ex", lambda: socket.gethostbyname_ex("example.com")),
        ("create_connection", lambda: socket.create_connection(("example.com", 25))),
    ],
)
def test_name_resolution_and_stream_connections_are_blocked(name: str, call: Any) -> None:
    with pytest.raises(AssertionError, match=BLOCKED):
        call()


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_stream_socket_methods_are_blocked(method: str) -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as opened,
        pytest.raises(AssertionError, match=BLOCKED),
    ):
        getattr(opened, method)(("192.0.2.1", 25))


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("sendto", (b"query", ("192.0.2.1", 53))),
        ("sendmsg", ([b"query"], [], 0, ("192.0.2.1", 53))),
        ("send", (b"query",)),
        ("sendall", (b"query",)),
    ],
)
def test_datagram_and_stream_sends_are_blocked(method: str, args: tuple[Any, ...]) -> None:
    """The path a DNS query actually takes out of the machine."""
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as opened,
        pytest.raises(AssertionError, match=BLOCKED),
    ):
        getattr(opened, method)(*args)


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", ["create_connection", "create_datagram_endpoint"])
async def test_asyncio_transports_are_blocked(factory: str) -> None:
    loop = asyncio.get_running_loop()
    with pytest.raises(AssertionError, match=BLOCKED):
        await getattr(loop, factory)(asyncio.Protocol, "192.0.2.1", 53)


class GuardTrippedResolver:
    """Stands in for a resolver whose transport hit the network guard."""

    async def resolve(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("test attempted a real network call: socket.sendto")


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query_mx", "query_a", "query_aaaa"])
async def test_the_adapter_never_converts_a_guard_failure_into_a_dns_result(method: str) -> None:
    """A blocked call must surface, not become a `DNSFailure`.

    If the adapter turned the guard's `AssertionError` into a failure value, a
    test could send packets and still pass, which is exactly how the earlier
    version of this file hid a real UDP query. The resolver is injected: no
    test in this repository builds one that would use the system nameservers.
    """
    adapter = DNSPythonResolver(resolver=GuardTrippedResolver())  # type: ignore[arg-type]
    with pytest.raises(AssertionError, match=BLOCKED):
        await getattr(adapter, method)(HostName("example.invalid"))


# --- the send guard's one exemption, pinned from both sides -----------------


def test_a_send_on_an_ordinary_socket_is_still_refused() -> None:
    """The half that matters. `AF_INET` is what reaches a network.

    Asserted on the pure classifier rather than by dialling: no test in this
    repository performs the act it exists to prove impossible.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for name in ("send", "sendall", "sendto"):
            with pytest.raises(AssertionError, match=BLOCKED):
                getattr(sock, name)(b"x", ("198.51.100.1", 53))


def test_a_send_on_a_unix_socket_is_permitted() -> None:
    """The exemption, and why it is not a weakening.

    A Unix socket has nowhere to send to except a path on this machine, and
    asyncio's event loop uses one as its self-pipe — `call_soon_threadsafe`
    wakes the loop with `send`. Refusing it deadlocks every test that uses a
    worker thread rather than stopping a packet.
    """
    left, right = socket.socketpair()
    with left, right:
        assert left.family == socket.AF_UNIX
        assert left.send(b"x") == 1
        assert right.recv(1) == b"x"


@pytest.mark.asyncio
async def test_a_worker_thread_can_still_wake_the_event_loop() -> None:
    """The property the exemption exists for, end to end.

    Without it this hangs: the thread finishes, the loop is never woken, and the
    future never completes. Phase 6's SQLite store is the first code here to
    use `asyncio.to_thread`, and this is what it depends on.
    """
    async with asyncio.timeout(5.0):
        assert await asyncio.to_thread(lambda: "done") == "done"


# --- the exemption is by family, and it fails closed ------------------------
#
# The `AF_UNIX` exemption is a change to reviewed Phase 0-5 safety
# infrastructure, so it is pinned from every side rather than only from the two
# that motivated it. An independent review found the gap: the guard was correct,
# and a mutation widening it from "is AF_UNIX" to "is not AF_INET" - which
# permits IPv6 and every unknown family - left the whole suite passing.
#
# The classifier is exercised directly on stand-in objects, so a future or
# unknown address family can be tested without this file being the thing that
# creates one.


class _StandInSocket:
    """Something with a family and nothing else. Never bound, never connected."""

    def __init__(self, family: object) -> None:
        self.family = family


class _FamilylessSocket:
    """An object whose family cannot be read at all."""


def _guard() -> Any:
    original = lambda self, *args, **kwargs: "sent"  # noqa: E731 - a one-line stand-in
    return conftest._refuse_unless_local("socket.send", original)


@pytest.mark.parametrize(
    "family",
    [
        socket.AF_INET,
        socket.AF_INET6,
        getattr(socket, "AF_PACKET", socket.AF_INET),
        getattr(socket, "AF_NETLINK", socket.AF_INET),
        999_999,
        None,
        "AF_UNIX",
    ],
    ids=["IPv4", "IPv6", "packet", "netlink", "unknown number", "none", "the name as text"],
)
def test_the_send_guard_refuses_every_family_but_unix(family: object) -> None:
    """Fail closed. An allowlist of one family, so a family nobody thought of -
    including a future one and a wrongly typed one - is refused rather than
    treated as internet-safe."""
    with pytest.raises(AssertionError, match=BLOCKED):
        _guard()(_StandInSocket(family), b"x")


def test_the_send_guard_refuses_a_socket_whose_family_cannot_be_read() -> None:
    with pytest.raises(AssertionError, match=BLOCKED):
        _guard()(_FamilylessSocket(), b"x")


def test_the_send_guard_permits_only_the_unix_family() -> None:
    assert _guard()(_StandInSocket(socket.AF_UNIX), b"x") == "sent"


def test_an_ipv6_datagram_send_is_refused() -> None:
    """The case the guard's own docstring says matters most, over IPv6.

    A DNS query needs neither `getaddrinfo` nor `connect`: the nameserver
    address comes from `resolv.conf` and the query leaves on `sendto`. The
    stream half is blocked unconditionally, so this send is the half the family
    exemption could have widened.
    """
    with (
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock,
        pytest.raises(AssertionError, match=BLOCKED),
    ):
        sock.sendto(b"query", ("2001:4860:4860::8888", 53))


def test_an_ipv6_stream_connect_is_refused() -> None:
    with (
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock,
        pytest.raises(AssertionError, match=BLOCKED),
    ):
        sock.connect(("2001:4860:4860::8888", 25))
