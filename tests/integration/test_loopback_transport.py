"""Real socket behaviour, over loopback, with the policy chain kept out of it.

`127.0.0.1` is denied by `evaluate_destination`, and `ApprovedDestination`
re-runs that check, so a loopback fixture cannot reach the production path.
That is the policy working. These tests therefore hand the transport's
connection an **already-connected socket** and exercise its I/O directly: no
`ApprovedDestination`, no `approve_destination`, no `confirm_peer`, and nothing
in `src/` that knows loopback exists.

What is being tested here is only what a fake cannot show: that a real reset, a
real EOF, a real partial read, and a real close behave the way the typed
outcomes say they do.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct

import pytest
from loopback_server import LoopbackServer

from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPConnection
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_transport import (
    LineRead,
    ReadFailed,
    TransportError,
    TransportFailure,
    TransportLimits,
    TransportTimeouts,
)

pytestmark = pytest.mark.asyncio

#: The peer value these tests hand the connection. It is never judged by the
#: policy here, because no authorization step is involved: this is the I/O
#: component on its own.
FIXTURE_PEER = PeerEndpoint(address="127.0.0.1", port=25)

FAST = TransportTimeouts(
    connect_seconds=2.0, read_seconds=0.5, write_seconds=0.5, close_seconds=0.5
)


async def connection_over(
    server: LoopbackServer, **kwargs: object
) -> tuple[AsyncioSMTPConnection, socket.socket]:
    client, peer_socket = await server.connected_pair()
    connection = AsyncioSMTPConnection._over_socket(
        client,
        FIXTURE_PEER,
        timeouts=FAST,
        **kwargs,  # type: ignore[arg-type]
    )
    return connection, peer_socket


# --- reading a real socket -------------------------------------------------


async def test_a_complete_line_is_framed(loopback_server: LoopbackServer) -> None:
    connection, peer_socket = await connection_over(loopback_server)
    async with connection:
        peer_socket.sendall(b"220 mx.example.com ESMTP\r\n")
        outcome = await connection.read_line()

    assert isinstance(outcome, LineRead)
    assert outcome.line == b"220 mx.example.com ESMTP"


async def test_several_lines_arrive_one_at_a_time(loopback_server: LoopbackServer) -> None:
    connection, peer_socket = await connection_over(loopback_server)
    async with connection:
        peer_socket.sendall(b"250-first\r\n250-second\r\n250 third\r\n")
        framed = [await connection.read_line() for _ in range(3)]

    assert [outcome.line for outcome in framed if isinstance(outcome, LineRead)] == [
        b"250-first",
        b"250-second",
        b"250 third",
    ]


async def test_a_partial_read_waits_for_the_rest(loopback_server: LoopbackServer) -> None:
    """A line split across two packets is one line, not two failures."""
    connection, peer_socket = await connection_over(loopback_server)
    async with connection:
        peer_socket.sendall(b"220 mx.exa")
        await asyncio.sleep(0)
        peer_socket.sendall(b"mple.com ready\r\n")
        outcome = await connection.read_line()

    assert isinstance(outcome, LineRead)
    assert outcome.line == b"220 mx.example.com ready"


async def test_an_eof_is_a_typed_outcome(loopback_server: LoopbackServer) -> None:
    connection, peer_socket = await connection_over(loopback_server)
    async with connection:
        peer_socket.shutdown(socket.SHUT_WR)
        outcome = await connection.read_line()

    assert isinstance(outcome, ReadFailed)
    assert outcome.failure is TransportFailure.CONNECTION_CLOSED


async def test_a_reset_is_a_typed_outcome(loopback_server: LoopbackServer) -> None:
    """The peer aborts rather than closing politely."""
    connection, peer_socket = await connection_over(loopback_server)
    async with connection:
        peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        peer_socket.close()
        outcome = await connection.read_line()

    assert isinstance(outcome, ReadFailed)
    assert outcome.failure in {
        TransportFailure.CONNECTION_RESET,
        TransportFailure.CONNECTION_CLOSED,
    }


async def test_a_slow_peer_hits_the_read_deadline(loopback_server: LoopbackServer) -> None:
    """A tarpit that says nothing must not hold the worker.

    The deadline is half a second and the peer sends nothing at all, so this
    measures the timeout firing rather than a race against a sleeping writer.
    """
    connection, _peer_socket = await connection_over(loopback_server)
    async with connection:
        outcome = await connection.read_line()

    assert isinstance(outcome, ReadFailed)
    assert outcome.failure is TransportFailure.READ_TIMEOUT


# --- the bounds hold against a real peer -----------------------------------


async def test_an_over_long_line_is_refused(loopback_server: LoopbackServer) -> None:
    connection, peer_socket = await connection_over(
        loopback_server, limits=TransportLimits(max_line_bytes=64, max_total_bytes=4096)
    )
    async with connection:
        peer_socket.sendall(b"250 " + b"x" * 500 + b"\r\n")
        outcome = await connection.read_line()

    assert isinstance(outcome, ReadFailed)
    assert outcome.failure is TransportFailure.LINE_TOO_LONG


async def test_a_flood_hits_the_total_limit(loopback_server: LoopbackServer) -> None:
    """A peer that never sends a terminator cannot make this read forever."""
    connection, peer_socket = await connection_over(
        loopback_server, limits=TransportLimits(max_line_bytes=1024, max_total_bytes=2048)
    )
    async with connection:
        with contextlib.suppress(OSError, BlockingIOError):
            for _ in range(8):
                peer_socket.sendall(b"250-" + b"y" * 900 + b"\r\n")
        outcomes = [await connection.read_line() for _ in range(4)]

    assert any(
        isinstance(outcome, ReadFailed)
        and outcome.failure
        in {TransportFailure.TOTAL_LIMIT_EXCEEDED, TransportFailure.LINE_TOO_LONG}
        for outcome in outcomes
    )


# --- closing ---------------------------------------------------------------


async def test_the_context_manager_closes_on_the_way_out(
    loopback_server: LoopbackServer,
) -> None:
    connection, _peer_socket = await connection_over(loopback_server)
    async with connection:
        assert connection.is_closed is False
    assert connection.is_closed is True


async def test_an_exception_inside_the_block_still_closes(
    loopback_server: LoopbackServer,
) -> None:
    """Gate 4C raises here when a banner is unusable. The socket must not survive."""
    connection, _peer_socket = await connection_over(loopback_server)
    with pytest.raises(RuntimeError, match="banner unusable"):
        async with connection:
            raise RuntimeError("banner unusable")
    assert connection.is_closed is True


async def test_close_is_idempotent(loopback_server: LoopbackServer) -> None:
    connection, _peer_socket = await connection_over(loopback_server)
    await connection.close()
    await connection.close()
    assert connection.is_closed is True


async def test_reading_after_close_is_a_typed_outcome(
    loopback_server: LoopbackServer,
) -> None:
    connection, _peer_socket = await connection_over(loopback_server)
    await connection.close()
    outcome = await connection.read_line()

    assert isinstance(outcome, ReadFailed)
    assert outcome.failure is TransportFailure.CONNECTION_CLOSED


async def test_the_private_write_primitive_refuses_a_closed_connection(
    loopback_server: LoopbackServer,
) -> None:
    """The primitive exists for gate 4C; nothing in gate 4B calls it.

    Exercised here only to prove it fails closed rather than writing to a dead
    socket. This is a test reaching a private member deliberately: production
    code cannot, because `SMTPConnection` does not declare it.
    """
    connection, _peer_socket = await connection_over(loopback_server)
    await connection.close()
    with pytest.raises(TransportError) as caught:
        await connection._write_line(b"NOOP\r\n")
    assert caught.value.failure is TransportFailure.CONNECTION_CLOSED


async def test_read_line_never_raises_whatever_the_peer_does(
    loopback_server: LoopbackServer,
) -> None:
    """Every read path is a typed outcome. An over-long complete line included.

    This is the shape the first implementation got wrong: a line that arrived
    complete and over-long raised, while the same line arriving in pieces
    returned `ReadFailed`. Both are failures; neither is an exception.
    """
    connection, peer_socket = await connection_over(
        loopback_server, limits=TransportLimits(max_line_bytes=32, max_total_bytes=4096)
    )
    async with connection:
        peer_socket.sendall(b"x" * 200 + b"\r\n")
        outcome = await connection.read_line()
        assert isinstance(outcome, ReadFailed)
        assert outcome.failure is TransportFailure.LINE_TOO_LONG


# --- the bounds interact, and the guarantee is stated as it actually is -----


async def test_both_shapes_of_an_over_long_line_end_in_a_typed_failure(
    loopback_server: LoopbackServer,
) -> None:
    """The guarantee is a typed bounded-read failure, not one particular reason.

    Which bound fires first depends on how the limits are configured. With the
    shipped defaults the line cap always wins, because a line cannot exceed
    4096 bytes before the connection has read 64 KB. With a small total cap the
    same complete line is refused as `total_limit_exceeded` instead. Both
    abandon the connection with a typed failure and neither raises, which is the
    property; pinning one reason would document a coincidence of the defaults.
    """
    tight = TransportLimits(max_line_bytes=32, max_total_bytes=128)
    connection, peer_socket = await connection_over(loopback_server, limits=tight)
    async with connection:
        peer_socket.sendall(b"x" * 200 + b"\r\n")
        complete = await connection.read_line()

    connection, peer_socket = await connection_over(loopback_server, limits=tight)
    async with connection:
        for _ in range(6):
            peer_socket.sendall(b"y" * 10)
            await asyncio.sleep(0)
        fragmented = await connection.read_line()

    bounded = {TransportFailure.LINE_TOO_LONG, TransportFailure.TOTAL_LIMIT_EXCEEDED}
    assert isinstance(complete, ReadFailed) and complete.failure in bounded
    assert isinstance(fragmented, ReadFailed) and fragmented.failure in bounded


async def test_a_read_after_the_total_cap_fails_without_touching_the_socket(
    loopback_server: LoopbackServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the budget is spent, a further read must not cost a whole deadline.

    Before this, `_total_read` stayed above the limit but was only re-checked
    after a successful `recv`, so every subsequent call sat on the socket until
    the read timeout expired. The failure was already correct; the cost was not.
    """
    connection, peer_socket = await connection_over(
        loopback_server, limits=TransportLimits(max_line_bytes=32, max_total_bytes=128)
    )
    async with connection:
        peer_socket.sendall(b"z" * 400)
        first = await connection.read_line()
        assert isinstance(first, ReadFailed)
        assert first.failure is TransportFailure.TOTAL_LIMIT_EXCEEDED

        loop = asyncio.get_running_loop()
        reads: list[object] = []

        async def recording_recv(sock: socket.socket, size: int) -> bytes:
            reads.append(size)
            return b""

        monkeypatch.setattr(loop, "sock_recv", recording_recv)
        elapsed = loop.time()
        again = await connection.read_line()
        cost = loop.time() - elapsed

    assert isinstance(again, ReadFailed)
    assert again.failure is TransportFailure.TOTAL_LIMIT_EXCEEDED
    assert reads == [], "the socket was read after the total limit was already exceeded"
    assert cost < FAST.read_seconds, "the read waited for its deadline instead of failing"


# --- cancellation -----------------------------------------------------------
#
# Every one of these was uncaught before. A mutation removing the `CancelledError`
# re-raise in `_connect_failure_for` passed the whole suite, and a cancellation
# arriving during `close()` leaked the descriptor while reporting `is_closed`.


async def test_a_cancellation_during_a_read_reaches_the_caller(
    loopback_server: LoopbackServer,
) -> None:
    """And leaves a connection that can still be closed."""
    connection, _peer_socket = await connection_over(loopback_server)
    raw = connection._socket

    reading = asyncio.create_task(connection.read_line())
    for _ in range(3):
        await asyncio.sleep(0)
    reading.cancel()
    with pytest.raises(asyncio.CancelledError):
        await reading

    await connection.close()
    assert connection.is_closed is True
    assert raw.fileno() == -1


async def test_a_cancellation_during_close_still_releases_the_descriptor(
    loopback_server: LoopbackServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression test for the leak this follow-up exists to fix.

    Cancellation is injected at the one operation `close` performs before
    releasing the descriptor. Before the fix the error escaped from there with
    `_closed` already true and the socket still open, so nothing would ever
    close it: the object reported itself closed and no retry would act.
    """
    connection, _peer_socket = await connection_over(loopback_server)
    raw = connection._socket

    def cancel_instead_of_shutting_down(self: socket.socket, how: int) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(socket.socket, "shutdown", cancel_instead_of_shutting_down)

    with pytest.raises(asyncio.CancelledError):
        await connection.close()

    assert raw.fileno() == -1, "the descriptor leaked when close was cancelled"
    assert connection.is_closed is True
    assert connection.is_closed == (raw.fileno() == -1), "the flag and the resource disagree"

    monkeypatch.undo()
    await connection.close()
    assert connection.is_closed is True


async def test_close_offers_no_point_at_which_it_can_be_cancelled(
    loopback_server: LoopbackServer,
) -> None:
    """`close` never suspends, which is why it cannot be interrupted part way.

    Driving the coroutine by hand: a single `send` that raises `StopIteration`
    means it ran to completion without yielding. Re-introducing an `await` —
    such as the decorative `asyncio.timeout` block this replaced — makes it
    yield instead, and that is the shape that created the leak above.
    """
    connection, _peer_socket = await connection_over(loopback_server)
    closing = connection.close()
    with pytest.raises(StopIteration):
        closing.send(None)
    assert connection.is_closed is True


async def test_a_cancellation_inside_the_block_closes_and_propagates(
    loopback_server: LoopbackServer,
) -> None:
    """The shape gate 4C uses: a long dialogue inside `async with`."""
    connection, _peer_socket = await connection_over(loopback_server)
    raw = connection._socket
    inside = asyncio.Event()

    async def body() -> None:
        async with connection:
            inside.set()
            await asyncio.sleep(3600)

    task = asyncio.create_task(body())
    await inside.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert connection.is_closed is True
    assert raw.fileno() == -1
