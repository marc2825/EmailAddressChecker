"""The guard that keeps this directory on loopback, tested without dialling.

This module contains no I/O at all, and that is the point of it.

The previous version of these tests proved the guard by attempting a connection
to a public address and asserting that it was refused. That reads well and is
wrong: on the day the guard breaks, the test that discovers it is the one that
opens the connection the guard exists to prevent. A review found exactly that —
mutating `is_loopback` to return `True` made the negative test reach a public
address for real.

So the guard is tested where the decision is made: a pure classifier, a pure
bind-host rule, and an inspection of what the fixture actually installed. Every
mutation of the guard now fails on an assertion rather than on a socket.
"""

from __future__ import annotations

import asyncio
import socket
from asyncio.selector_events import BaseSelectorEventLoop

import pytest
from loopback_server import (
    LOOPBACK_ADDRESSES,
    LoopbackRefused,
    LoopbackServer,
    is_guard_installed,
    is_loopback,
    is_permitted_bind_host,
)

# --- what may be connected to ----------------------------------------------


@pytest.mark.parametrize(
    ("address", "label"),
    [
        (("127.0.0.1", 25), "IPv4 loopback"),
        (("::1", 25), "IPv6 loopback"),
        (("::1", 25, 0, 0), "IPv6 loopback with a flow and scope"),
        (("0000:0000:0000:0000:0000:0000:0000:0001", 25, 0, 0), "IPv6 loopback, expanded"),
    ],
)
def test_the_classifier_permits_loopback(address: tuple[object, ...], label: str) -> None:
    assert is_loopback(address) is True, label


@pytest.mark.parametrize(
    ("address", "label"),
    [
        (("93.184.216.34", 25), "a public IPv4"),
        (("8.8.8.8", 53), "a public resolver"),
        (("2606:4700:4700::1111", 25, 0, 0), "a public IPv6"),
        (("10.0.0.1", 25), "RFC 1918"),
        (("192.168.1.1", 25), "RFC 1918"),
        (("172.16.0.1", 25), "RFC 1918"),
        (("100.64.0.1", 25), "carrier-grade NAT"),
        (("169.254.169.254", 80), "the cloud metadata endpoint"),
        (("fe80::1", 25, 0, 2), "link-local IPv6"),
        # An address being refused as a destination, not a bind.
        (("0.0.0.0", 25), "the unspecified IPv4 address"),  # noqa: S104
        (("::", 25, 0, 0), "the unspecified IPv6 address"),
        (("127.0.0.2", 25), "loopback-adjacent, and still not permitted"),
        (("localhost", 25), "a name, which could resolve anywhere"),
        (("0177.0.0.1", 25), "loopback written in octal"),
        (("2130706433", 25), "loopback written as an integer"),
        (("::ffff:127.0.0.1", 25, 0, 0), "loopback in a mapped IPv6 form"),
        ((), "an empty sockaddr"),
        ("127.0.0.1:25", "a string rather than a sockaddr"),
        ((None, 25), "a host that is not text"),
        (None, "nothing at all"),
    ],
)
def test_the_classifier_refuses_everything_else(address: object, label: str) -> None:
    """Including every form that looks like loopback and is not."""
    assert is_loopback(address) is False, label


def test_the_permitted_set_is_exactly_two_addresses() -> None:
    """A mutation that widens the guard has to change this line to pass.

    `127.0.0.2` is loopback by RFC 1122 and is refused here anyway. The fixture
    binds one address and nothing needs the rest of `127.0.0.0/8`, so the
    narrower rule costs nothing and removes a whole class of accident.
    """
    assert frozenset({"127.0.0.1", "::1"}) == LOOPBACK_ADDRESSES


# --- what is actually installed --------------------------------------------


def test_every_outbound_entry_point_is_guarded() -> None:
    assert is_guard_installed(socket.getaddrinfo), "name resolution"
    assert is_guard_installed(socket.gethostbyname), "name resolution"
    assert is_guard_installed(socket.gethostbyname_ex), "name resolution"
    assert is_guard_installed(socket.create_connection), "stream connections"
    assert is_guard_installed(socket.socket.connect), "stream connections"
    assert is_guard_installed(socket.socket.connect_ex), "stream connections"
    assert is_guard_installed(socket.socket.sendto), "datagram sends"
    assert is_guard_installed(socket.socket.sendmsg), "datagram sends"
    assert is_guard_installed(BaseSelectorEventLoop.sock_connect), "the asyncio path"
    assert is_guard_installed(asyncio.BaseEventLoop.create_connection), "the asyncio path"
    assert is_guard_installed(asyncio.BaseEventLoop.create_datagram_endpoint), "the asyncio path"


def test_the_guard_sits_where_the_running_loop_looks_it_up() -> None:
    """`BaseEventLoop` is not where `sock_connect` comes from, so patching it is inert.

    A concrete loop resolves `sock_connect` on `BaseSelectorEventLoop`. Setting
    the attribute on `BaseEventLoop` succeeds and is never reached, which is a
    guard layer that looks present and does nothing — the socket-level guard was
    carrying it alone. This asserts the patch lands where the lookup goes.
    """
    loop = asyncio.new_event_loop()
    try:
        assert is_guard_installed(type(loop).sock_connect)
    finally:
        loop.close()


# --- what may be bound ------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_the_fixture_may_bind_loopback(host: str) -> None:
    assert is_permitted_bind_host(host) is True


@pytest.mark.parametrize(
    ("host", "label"),
    [
        ("0.0.0.0", "every interface on the machine"),  # noqa: S104
        ("::", "every interface, IPv6"),
        ("93.184.216.34", "a public address"),
        ("10.0.0.1", "a private address"),
        ("127.0.0.2", "loopback-adjacent"),
        ("localhost", "a name"),
        ("", "nothing"),
    ],
)
def test_the_fixture_refuses_to_bind_anything_else(host: str, label: str) -> None:
    """Refused by a pure rule, so the mutation fails before a descriptor exists."""
    assert is_permitted_bind_host(host) is False, label
    with pytest.raises(LoopbackRefused):
        LoopbackServer(host=host)


def test_a_tampered_bind_host_is_caught_before_the_socket_is_bound() -> None:
    """`host` is a plain attribute, so `start` checks it again rather than trusting it."""
    server = LoopbackServer()
    server.host = "0.0.0.0"  # noqa: S104 - tampering, which `start` must catch
    with pytest.raises(LoopbackRefused):
        server.start()
    assert server.port == 0, "no port was ever bound"
