"""Shared pieces for the gate 4C dialogue tests.

A fake clock, a configured identity, and the confirmed peer a session needs.
None of it touches the network, and the clock is driven by hand so a deadline
test measures the deadline rather than the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from emailcheck.adapters.smtp.sender_identity import (
    ConfiguredSenderIdentityProvider,
    load_sender_identity,
)
from emailcheck.domain.address import (
    AddressAccepted,
    NormalizedAddress,
    RawAddressInput,
    parse_address,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.mail_route import CandidateStatus, RouteCandidate, RouteSource
from emailcheck.domain.smtp_destination import (
    ApprovedDestination,
    ConfirmedPeer,
    PeerEndpoint,
)
from emailcheck.domain.smtp_session import SMTPSession, begin_session
from emailcheck.ports.rate_limit import RateLimitLease
from emailcheck.ports.smtp_sender_identity import SenderIdentity
from emailcheck.security.destination import DestinationDecision

#: The MX host the test certificate is issued for, so the TLS integration tests
#: and the dialogue tests name the same peer.
MX_HOST = "mx.test.example"
PUBLIC_V4 = "93.184.216.34"
TARGET_TEXT = "probe.target@recipient.test.example"


@dataclass(slots=True)
class FakeMonotonicClock:
    """A clock a test moves by hand.

    Deadline behaviour has to be deterministic: a test that reaches a deadline
    by sleeping measures the machine's load, and one that reaches it by
    advancing a counter measures the deadline.
    """

    value: float = 1000.0

    def monotonic(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass(slots=True)
class AdvancingClock:
    """A clock that moves a fixed amount every time it is read.

    Useful for "the budget ran out part way through", where the step that
    exhausts it is whichever one happens to be running.
    """

    value: float = 1000.0
    step: float = 0.0

    def monotonic(self) -> float:
        current = self.value
        self.value += self.step
        return current


@dataclass(slots=True)
class RecordingRateLimiter:
    """A limiter that records when it was asked, and what for.

    It grants everything. What is being tested is the *ordering* contract —
    authorization before a socket — not a budget algorithm, which is gate 4E's.
    """

    acquisitions: list[tuple[str, str, str]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    released: int = 0

    def acquire(self, *, account: str, domain: str, mx_host: str) -> RateLimitLease:
        self.acquisitions.append((account, domain, mx_host))
        self.events.append("acquire")
        return _RecordingLease(limiter=self)


@dataclass(slots=True)
class _RecordingLease:
    limiter: RecordingRateLimiter

    async def __aenter__(self) -> None:
        self.limiter.events.append("enter")

    async def __aexit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.limiter.events.append("exit")
        self.limiter.released += 1


def address(text: str = TARGET_TEXT) -> NormalizedAddress:
    """Parse a target through the Phase 1 boundary, as production does."""
    accepted = parse_address(RawAddressInput(value=text))
    assert isinstance(accepted, AddressAccepted), text
    return accepted.address


def identity(
    ehlo_hostname: str = "probe.sender.test.example",
    envelope_sender: str = "verify@sender.test.example",
) -> SenderIdentity:
    return load_sender_identity(
        {"ehlo_hostname": ehlo_hostname, "envelope_sender": envelope_sender}
    )


def identity_provider(**overrides: str) -> ConfiguredSenderIdentityProvider:
    return ConfiguredSenderIdentityProvider(identity=identity(**overrides))


def approved(host: str = MX_HOST, host_address: str = PUBLIC_V4) -> ApprovedDestination:
    return ApprovedDestination(host=HostName(host), address=host_address)


def confirmed_peer(host: str = MX_HOST, host_address: str = PUBLIC_V4) -> ConfirmedPeer:
    return ConfirmedPeer(
        approved=approved(host, host_address), peer_address=host_address, peer_port=25
    )


def session(host: str = MX_HOST, host_address: str = PUBLIC_V4) -> SMTPSession:
    """A session in `CONNECTING`, exactly as the connector hands one over."""
    return begin_session(confirmed_peer(host, host_address))


def peer_endpoint(host_address: str = PUBLIC_V4) -> PeerEndpoint:
    return PeerEndpoint(address=host_address, port=25)


def candidate(*addresses: str, host: str = MX_HOST) -> RouteCandidate:
    return RouteCandidate(
        host=HostName(host),
        preference=10,
        source=RouteSource.MX,
        status=CandidateStatus.USABLE,
        decisions=tuple(
            DestinationDecision(
                allowed=True,
                address=value,
                version=6 if ":" in value else 4,
                deny_reason=None,
            )
            for value in (addresses or (PUBLIC_V4,))
        ),
    )
