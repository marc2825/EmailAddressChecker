"""Many verifications at once, over the scripted server, counted on the wire.

The companion to `tests/integration/test_load_loopback.py`. That file runs real
sockets and can measure connection and descriptor behaviour; this one runs the
scripted transport, which is the only thing that can count **what was written**
— and the invariants worth protecting under load are protocol invariants:

- one verification is at most one `RCPT TO`, however many run concurrently;
- no `DATA`, `VRFY`, `EXPN`, or `AUTH` appears in any transcript, ever;
- concurrency does not cause a verification to reach an exchanger a serial run
  would have left alone.

`RoutedSMTPTransport` counts recipient commands across every connection it
made, so the assertions are on the transcript rather than on the report the code
under test produced.

**No wall-clock assertion appears here**, for the same reason as in the
integration file: a duration is a property of the machine. Each test still
carries an outer bound so a stall fails rather than hangs.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Final

import pytest

from dialogue_fixtures import (
    FakeMonotonicClock,
    RecordingRateLimiter,
    address,
    candidate,
    identity_provider,
    route,
)
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.application.smtp_probe import SMTPProbeService
from emailcheck.application.smtp_verification import (
    SMTPVerificationService,
    VerificationSettings,
)
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_tls import TLSPolicy
from fake_smtp_server import (
    RCPT_ACCEPTED,
    RCPT_NO_SUCH_USER,
    RCPT_TEMPORARY,
    RoutedSMTPTransport,
    tls_session_peer,
)

pytestmark = pytest.mark.asyncio

#: Enough concurrent verifications for an interleaving mistake to show.
VERIFICATIONS: Final = 32

OUTER_BOUND_SECONDS: Final = 10.0

FIRST: Final = "93.184.216.34"
SECOND: Final = "93.184.216.35"

TLS_SETTINGS: Final = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)

#: Commands that must never appear in a transcript, at any concurrency.
#: `CONTRIBUTING.md` forbids all four unconditionally.
FORBIDDEN: Final = ("DATA", "VRFY", "EXPN", "AUTH")


class _WallClock:
    def now(self) -> object:
        return datetime(2026, 8, 12, 12, 0, tzinfo=UTC)


def peer_at(address_value: str, *, rcpt: object = RCPT_ACCEPTED):  # type: ignore[no-untyped-def]
    return tls_session_peer(
        PeerEndpoint(address=address_value, port=25),
        rcpt=rcpt,  # type: ignore[arg-type]
    )


def verifier_over(transport: RoutedSMTPTransport) -> SMTPVerificationService:
    return SMTPVerificationService(
        probe=SMTPProbeService(
            transport=transport,  # type: ignore[arg-type]
            identity_provider=identity_provider(),
            rate_limiter=RecordingRateLimiter(),  # type: ignore[arg-type]
            clock=FakeMonotonicClock(),
            settings=TLS_SETTINGS,
        ),
        clock=_WallClock(),  # type: ignore[arg-type]
        settings=VerificationSettings(max_attempts=3),
    )


def two_hosts():  # type: ignore[no-untyped-def]
    return route(
        candidate(FIRST, host="mx1.test.example", preference=10),
        candidate(SECOND, host="mx2.test.example", preference=20),
    )


async def run_load(transport: RoutedSMTPTransport, *, count: int = VERIFICATIONS):  # type: ignore[no-untyped-def]
    verifier = verifier_over(transport)

    async def one(index: int):  # type: ignore[no-untyped-def]
        return await verifier.verify(address(), two_hosts(), account=f"acct-{index}")

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        return await asyncio.gather(*(one(index) for index in range(count)))


def assert_no_forbidden_command(transport: RoutedSMTPTransport) -> None:
    """Read the transcripts of the connections that actually ran.

    `transport.peers` holds the templates; `transport.connections` holds the
    clones the load drove, and only those were written to.
    """
    assert transport.connections, "the load opened no connection at all"
    for connection in transport.connections:
        transcript = connection.wire_text().upper()
        for command in FORBIDDEN:
            assert command not in transcript, f"{command} appeared in a transcript"


# --- the invariant that concurrency is most likely to break ------------------


async def test_one_rcpt_per_verification_however_many_run_at_once() -> None:
    """The count is `verifications`, exactly. Not fewer, and not one more.

    Measured across every connection the transport made. A shared piece of
    per-verification state — a cached session, a reused dialogue, a retry
    counter that is not per-attempt — would show here as a count that is not the
    number of verifications, and in no other test in this repository.
    """
    transport = RoutedSMTPTransport(peers={FIRST: peer_at(FIRST), SECOND: peer_at(SECOND)})

    reports = await run_load(transport)

    assert len(reports) == VERIFICATIONS
    assert transport.recipient_commands == VERIFICATIONS
    assert_no_forbidden_command(transport)


async def test_a_rejecting_destination_is_still_one_rcpt_each() -> None:
    """A `550` under load does not become a second attempt.

    `docs/status-model.md` is explicit that a bare `550` is not
    mailbox-not-found, and the thing that would quietly turn one into a second
    probe is a retry path that treats a rejection as worth another look.
    """
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_at(FIRST, rcpt=RCPT_NO_SUCH_USER),
            SECOND: peer_at(SECOND, rcpt=RCPT_NO_SUCH_USER),
        }
    )

    await run_load(transport)

    assert transport.recipient_commands == VERIFICATIONS
    assert transport.addresses_reached.count(SECOND) == 0
    assert_no_forbidden_command(transport)


async def test_a_temporary_answer_under_load_does_not_walk_the_candidates() -> None:
    """A `450` is not a reason to ask the next exchanger, at any concurrency.

    Asking the next host after a temporary answer looks like a retry and is a
    second probe of the same recipient. Serial tests already pin this; the load
    is what would expose a shared candidate iterator.
    """
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_at(FIRST, rcpt=RCPT_TEMPORARY),
            SECOND: peer_at(SECOND, rcpt=RCPT_TEMPORARY),
        }
    )

    await run_load(transport)

    assert transport.recipient_commands == VERIFICATIONS
    assert set(transport.addresses_reached) == {FIRST}
    assert_no_forbidden_command(transport)


async def test_every_connection_is_closed_after_the_load() -> None:
    """A leak only becomes an outage once there is load, so it is measured here."""
    transport = RoutedSMTPTransport(peers={FIRST: peer_at(FIRST), SECOND: peer_at(SECOND)})

    await run_load(transport)

    assert transport.all_closed


async def test_the_scripted_server_is_the_only_destination() -> None:
    """The restriction in work item 8, asserted rather than assumed.

    Every address the load reached came from the route this test built, and the
    suite-wide guard in `tests/conftest.py` is still installed underneath: this
    file opens no socket at all.
    """
    transport = RoutedSMTPTransport(peers={FIRST: peer_at(FIRST), SECOND: peer_at(SECOND)})

    await run_load(transport)

    assert set(transport.addresses_reached) <= {FIRST, SECOND}
