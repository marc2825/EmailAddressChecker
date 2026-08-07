"""What the transport does when it is interrupted rather than answered.

None of this was covered before. A mutation that deleted the `CancelledError`
re-raise in `_connect_failure_for` passed the entire suite, which means the
property "a cancelled connect does not come back as a network result" was not
being kept by anything — it happened to be true.

Two rules are tested here, and they pull in opposite directions on purpose:

- **process and task control never becomes a transport failure.** A cancelled,
  interrupted, or exiting caller must not be handed a `ConnectionFailed` that
  reads like something the remote end did;
- **the descriptor is released anyway.** Re-raising is not an excuse to leak,
  so every path that creates a socket closes it before the exception continues.

No socket connects here. The connect is made to hang by replacing the running
loop's own `sock_connect`, so what is measured is this project's behaviour and
not the network's.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from emailcheck.adapters.smtp.asyncio_transport import (
    _NEVER_A_TRANSPORT_FAILURE,
    AsyncioSMTPTransport,
    _connect_failure_for,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_destination import ApprovedDestination
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.ports.smtp import ConnectionFailed

pytestmark = pytest.mark.asyncio

PUBLIC_V4 = "93.184.216.34"


def destination() -> ApprovedDestination:
    return ApprovedDestination(host=HostName("mx.example.com"), address=PUBLIC_V4)


def recording_sockets(monkeypatch: pytest.MonkeyPatch) -> list[socket.socket]:
    """Hand back every socket the adapter creates, so its fate can be asserted."""
    created: list[socket.socket] = []
    real = socket.socket

    def recording(*args: object, **kwargs: object) -> socket.socket:
        made = real(*args, **kwargs)  # type: ignore[arg-type]
        created.append(made)
        return made

    monkeypatch.setattr(socket, "socket", recording)
    return created


def hang_the_connect(monkeypatch: pytest.MonkeyPatch) -> asyncio.Event:
    """Make `sock_connect` wait forever, and report when it has been entered."""
    loop = asyncio.get_running_loop()
    reached = asyncio.Event()

    async def never_completes(sock: socket.socket, address: object) -> None:
        reached.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(loop, "sock_connect", never_completes)
    return reached


# --- cancellation while connecting -----------------------------------------


async def test_a_cancelled_connect_reaches_the_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    """It must not come back as a `ConnectionFailed` describing the network."""
    recording_sockets(monkeypatch)
    reached = hang_the_connect(monkeypatch)

    connecting = asyncio.create_task(AsyncioSMTPTransport().connect(destination()))
    await reached.wait()
    connecting.cancel()

    with pytest.raises(asyncio.CancelledError):
        await connecting


async def test_a_cancelled_connect_closes_the_socket_it_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-raising is not a licence to leak the descriptor."""
    created = recording_sockets(monkeypatch)
    reached = hang_the_connect(monkeypatch)

    connecting = asyncio.create_task(AsyncioSMTPTransport().connect(destination()))
    await reached.wait()
    connecting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await connecting

    assert len(created) == 1
    assert created[0].fileno() == -1, "the socket leaked when the connect was cancelled"


# --- which exceptions are never a transport failure ------------------------


@pytest.mark.parametrize(
    ("error", "label"),
    [
        (asyncio.CancelledError(), "a cancelled task"),
        (KeyboardInterrupt(), "Ctrl-C"),
        (SystemExit(1), "an interpreter shutdown"),
        (GeneratorExit(), "a closing generator"),
        (AssertionError("the network guard"), "this project's own invariant"),
    ],
)
async def test_process_control_is_re_raised_not_named(error: BaseException, label: str) -> None:
    """Anything here is about the process, not about a destination.

    `AssertionError` is included on the Phase 2 precedent: the DNS adapter
    re-raises it so the test suite's network guard fails a test rather than
    being reported as a DNS answer. The same reasoning applies to a socket.
    """
    with pytest.raises(type(error)):
        _connect_failure_for(error)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ConnectionRefusedError(), TransportFailure.CONNECTION_REFUSED),
        (TimeoutError(), TransportFailure.CONNECT_TIMEOUT),
        (OSError("unreachable"), TransportFailure.NETWORK_UNREACHABLE),
        (RuntimeError("a bug in this project"), TransportFailure.INTERNAL_ERROR),
    ],
)
async def test_ordinary_failures_are_still_named(
    error: BaseException, expected: TransportFailure
) -> None:
    """The typed classification of real network conditions is unchanged."""
    assert _connect_failure_for(error) is expected


async def test_the_re_raised_set_is_stated_rather_than_implied() -> None:
    """A mutation that drops one member has to change this line."""
    assert set(_NEVER_A_TRANSPORT_FAILURE) == {
        asyncio.CancelledError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
        AssertionError,
    }


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(1), asyncio.CancelledError()])
async def test_an_interrupted_connect_closes_its_socket_and_propagates(
    error: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole path, not only the classifier: interrupted mid-connect."""
    created = recording_sockets(monkeypatch)
    loop = asyncio.get_running_loop()

    async def interrupted(sock: socket.socket, address: object) -> None:
        raise error

    monkeypatch.setattr(loop, "sock_connect", interrupted)

    with pytest.raises(type(error)):
        await AsyncioSMTPTransport().connect(destination())

    assert len(created) == 1
    assert created[0].fileno() == -1, "the socket leaked on an interrupted connect"


async def test_a_bug_in_this_project_is_still_reported_rather_than_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`INTERNAL_ERROR` stays a typed outcome, so the two policies stay distinct."""
    recording_sockets(monkeypatch)
    loop = asyncio.get_running_loop()

    async def broken(sock: socket.socket, address: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(loop, "sock_connect", broken)

    outcome = await AsyncioSMTPTransport().connect(destination())
    assert isinstance(outcome, ConnectionFailed)
    assert outcome.failure is TransportFailure.INTERNAL_ERROR
