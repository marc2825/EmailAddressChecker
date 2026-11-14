"""A bounded loopback connection workload, over the local fixture only.

`docs/beta-report-template.md`: *add load testing against only the
scripted local server*. The emphasis is on **only**, so this file is written to
make the restriction checkable rather than promised — every socket it opens
reaches `tests/integration/loopback_server.py`, and each test asserts that from
the addresses actually connected to rather than trusting the fixture.

**What this file exercises, exactly.** `AsyncioSMTPConnection` over an
already-connected loopback socket: its reads, its failure paths, and its close.
That is the transport, and **nothing above it**. No
`AddressVerificationService`, no admission gate, no quota, no rate limiter, and
no destination policy is in the path, because the loopback fixture cannot reach
the production chain — `evaluate_destination` denies `127.0.0.1` and
`ApprovedDestination` re-runs that check, which is the policy working.

**So this file measures none of `docs/beta-report-template.md`'s beta metrics.**
An independent review found an earlier version claiming to pin *connections per
job*: it counted the connection pairs the test itself had created, which no
production change could ever alter. What is measured here is narrower and true:

- the fixture's own connection accounting stays exact under concurrency;
- concurrency stays inside the bound the caller set;
- every connection is released, whether its work succeeded or was reset;
- every socket reached loopback.

**Structure, not speed.** There is no assertion about throughput, latency, or
elapsed wall-clock time, and there must not be: a duration assertion on a shared
machine fails for reasons that have nothing to do with this project, and a green
one proves nothing. Each test carries its own outer bound, so a wait that should
have stopped fails rather than hangs.

The load test that *does* exercise production behaviour is
`tests/unit/application/test_load_scripted_server.py`: it drives
`SMTPVerificationService` over the scripted transport and counts `RCPT TO` on
the wire across concurrent verifications. `connections per job` becomes a real
beta metric only when it is measured over an authorized run of the production
path, which has not happened and is not what either file claims.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from loopback_server import LoopbackServer, is_guard_installed, is_loopback

from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPConnection
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_transport import LineRead, TransportTimeouts

pytestmark = pytest.mark.asyncio

#: Enough concurrency for a scheduling mistake to show, small enough that the
#: file stays fast. A load test that takes a minute is one people skip.
UNITS_OF_WORK = 64

#: The ceiling the caller sets. The assertion is that observed concurrency never
#: exceeds it — not that it reaches it, which would be a timing assertion.
CONCURRENCY = 8

#: Every test's outer bound. Generous, because it exists to convert a hang into
#: a failure rather than to measure anything.
OUTER_BOUND_SECONDS = 30.0

FIXTURE_PEER = PeerEndpoint(address="127.0.0.1", port=25)

FAST = TransportTimeouts(
    connect_seconds=2.0, read_seconds=2.0, write_seconds=2.0, close_seconds=2.0
)

GREETING = b"220 mx.test.example ESMTP\r\n"


class Load:
    """One server, the accepts serialized, and every address that was reached.

    The addresses are recorded **at connect time**, not read back at the end: a
    unit of work closes its socket, and `getpeername` on a closed descriptor
    raises rather than answering. Recording as it happens means the assertion
    covers the failing units too, which are exactly the ones a leak would hide
    in.
    """

    def __init__(self, server: LoopbackServer) -> None:
        self.server = server
        self.reached: list[object] = []
        # The accept is serialized, and that is a property of the fixture rather
        # than a concession about the code under test. `LoopbackServer` accepts
        # through `loop.sock_accept` on one listening socket, and asyncio
        # permits a single reader per descriptor: two concurrent accepts on one
        # listener install two readers on one fd, the second displaces the
        # first, and both wait forever. Everything after the accept — the reads,
        # the failures, the closes — runs concurrently, which is where the
        # properties this file measures actually live.
        self._accepting = asyncio.Lock()

    async def pair(self) -> tuple[socket.socket, socket.socket]:
        async with self._accepting:
            client, peer_socket = await self.server.connected_pair()
        self.reached.append(client.getpeername())
        return client, peer_socket


def assert_every_peer_was_loopback(load: Load) -> None:
    """The restriction, asserted rather than assumed.

    A test that only trusts the conftest guard is a test that passes on the day
    the guard stops being installed, which is the day it matters.
    """
    assert load.reached, "the load test opened no connections at all"
    for peer in load.reached:
        assert is_loopback(peer), f"a load-test socket reached {peer!r}"


async def one_unit(load: Load, *, fail: bool = False) -> bytes:
    """Open a connection, read one line, close. The unit of work under load."""
    client, peer_socket = await load.pair()
    connection = AsyncioSMTPConnection._over_socket(client, FIXTURE_PEER, timeouts=FAST)
    async with connection:
        if fail:
            # A reset mid-unit: the failure path has to release its socket too.
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\0\0\0\0\0\0\0")
            peer_socket.close()
            await connection.read_line()
            return b"failed"
        peer_socket.sendall(GREETING)
        outcome = await connection.read_line()
        assert isinstance(outcome, LineRead)
    assert connection.is_closed
    return outcome.line


# --- the restriction itself -------------------------------------------------


async def test_the_guard_is_installed_before_any_load_runs() -> None:
    """Asserted by inspection, never by attempting the call it forbids.

    Proving the guard works by reaching for a public address is what performs a
    real outbound connection on the day the guard is broken. So this reads the
    marker the fixture leaves behind.
    """
    assert is_guard_installed(socket.socket.connect)
    assert is_guard_installed(socket.getaddrinfo)


async def test_every_connection_under_load_reached_loopback(
    loopback_server: LoopbackServer,
) -> None:
    load = Load(loopback_server)

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        await asyncio.gather(*(one_unit(load) for _ in range(UNITS_OF_WORK)))

    assert_every_peer_was_loopback(load)
    assert len(load.reached) == UNITS_OF_WORK


# --- what has to hold when many of them run at once -------------------------


async def test_the_fixtures_connection_accounting_is_exact_under_concurrency(
    loopback_server: LoopbackServer,
) -> None:
    """Every unit of work reads its line, and the fixture's books balance.

    **This is fixture accounting, not a production metric.** The units of work
    are created by this test, so the connection count is bounded by the test
    rather than by anything in `src/`. What it would catch is a fixture that
    dropped, duplicated, or mispaired a connection under concurrency — which
    would silently weaken every other test in this file.
    """
    load = Load(loopback_server)

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        lines = await asyncio.gather(*(one_unit(load) for _ in range(UNITS_OF_WORK)))

    assert lines == [GREETING.rstrip(b"\r\n")] * UNITS_OF_WORK
    # `connected_pair` appends both ends, so each unit contributes exactly two.
    # A count taken from the fixture, about the fixture.
    assert len(loopback_server.accepted) == UNITS_OF_WORK * 2


async def test_concurrency_stays_inside_the_bound_it_was_given(
    loopback_server: LoopbackServer,
) -> None:
    """The ceiling holds, and the observation is of the peak rather than of time.

    The bound under test is this test's own semaphore, over real sockets — the
    property being checked is that a bounded workload against a real listener
    stays bounded, not that any production component paces anything.
    `docs/operations.md` section 5's per-domain pacing is Phase 4's, and
    `tests/unit/application/` measures it.
    """
    gate = asyncio.Semaphore(CONCURRENCY)
    load = Load(loopback_server)
    in_flight = 0
    peak = 0

    async def bounded() -> None:
        nonlocal in_flight, peak
        async with gate:
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await one_unit(load)
            finally:
                in_flight -= 1

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        await asyncio.gather(*(bounded() for _ in range(UNITS_OF_WORK)))

    assert peak <= CONCURRENCY
    assert in_flight == 0
    assert_every_peer_was_loopback(load)


async def test_a_failing_unit_releases_its_socket_like_a_succeeding_one(
    loopback_server: LoopbackServer,
) -> None:
    """Half the load fails mid-connection. The bounds are unchanged.

    A load test in which everything succeeds measures the happy path at volume.
    The property worth having is that a reset under load leaks nothing, because
    a descriptor leak only becomes an outage once there is load.
    """
    load = Load(loopback_server)
    work = [one_unit(load, fail=index % 2 == 1) for index in range(UNITS_OF_WORK)]

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        results = await asyncio.gather(*work, return_exceptions=True)

    assert not [result for result in results if isinstance(result, BaseException)]
    assert len(loopback_server.accepted) == UNITS_OF_WORK * 2
    assert_every_peer_was_loopback(load)


async def test_the_server_releases_every_socket_when_it_stops() -> None:
    """`stop()` runs from a `finally`, so a failing load test still frees the port."""
    server = LoopbackServer()
    server.start()
    load = Load(server)
    try:
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await asyncio.gather(*(one_unit(load) for _ in range(CONCURRENCY)))
        opened = list(server.accepted)
        assert len(opened) == CONCURRENCY * 2
    finally:
        server.stop()

    assert server.accepted == []
    for released in opened:
        assert released.fileno() == -1
