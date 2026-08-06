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
