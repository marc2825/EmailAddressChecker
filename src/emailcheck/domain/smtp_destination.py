"""Three checks of the same policy, at the three moments it can be evaded.

`docs/threat-model.md` requires that the destination policy run against the DNS
answer, again immediately before connecting, and again against the address the
socket actually reached. The gap between the second and the third is real: a
resolver can answer differently on a second lookup, and a connection can land
somewhere other than the address that was approved.

Making those checks types rather than steps is what stops one from being
skipped:

```text
RouteCandidate          Phase 2 judged the DNS answer
  → approve_destination()   the only way in: the address must be one the
                            candidate actually offered, and the policy runs again
  → ApprovedDestination
  → confirm_peer()          the address and port the socket actually reached
  → ConfirmedPeer
  → SMTPSession             requires one, and checks it at run time
```

Two things a review found are fixed here. `ApprovedDestination` used to be
constructible from any public IP with any host name, with no link to DNS at all,
so the policy protected against internal pivoting but not against connecting to
an address the domain never published. And the peer check compared an address
only, so a connection that landed on the right host at the wrong port passed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.dns import HostName
from emailcheck.domain.mail_route import CandidateStatus, RouteCandidate
from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.security.destination import DestinationDenyReason, evaluate_destination

#: The only port this project connects to. Submission on 587 requires
#: authentication, which is forbidden, so allowing it would widen the reachable
#: surface for no capability.
ALLOWED_SMTP_PORTS: Final[frozenset[int]] = frozenset({25})

DEFAULT_SMTP_PORT: Final = 25


class DestinationRejection(StrEnum):
    """Why an address may not be approved as a destination."""

    #: Phase 2 did not mark the candidate usable, so it offers no destination.
    CANDIDATE_NOT_USABLE = "candidate_not_usable"
    #: The candidate carries no address the policy allowed.
    NO_ALLOWED_ADDRESSES = "no_allowed_addresses"
    #: The address is not one this candidate resolved to.
    ADDRESS_NOT_IN_CANDIDATE = "address_not_in_candidate"
    #: The policy refuses the address now, whatever it said when DNS answered.
    DENIED_BY_POLICY = "denied_by_policy"
    #: The port is not one this project connects to.
    PORT_NOT_ALLOWED = "port_not_allowed"


class PeerRejection(StrEnum):
    """Why the endpoint a socket reached may not be spoken to."""

    #: The peer is inside a range the destination policy forbids.
    DENIED_BY_POLICY = "denied_by_policy"
    #: The peer is permitted but is not the address that was approved.
    ADDRESS_MISMATCH = "address_mismatch"
    #: The peer is the right address on a port this project did not approve.
    PORT_MISMATCH = "port_mismatch"


@dataclass(frozen=True, slots=True)
class PeerEndpoint:
    """The address and port a socket actually reached.

    This is what `getpeername()` reports, and it is untrusted. It is a value
    rather than two loose arguments so the transport cannot pass the address and
    forget the port.

    **The transport normalizes the family before building one of these.** An
    `AF_INET6` dual-stack socket reports an IPv4 peer as `::ffff:93.184.216.34`,
    and the destination policy refuses that form on purpose: a mapped address is
    how a NAT64 or translated prefix reaches somewhere it should not. Rather
    than teach the policy to unwrap it — which is exactly the fallback that
    would trust a mapped address as a public IPv4 — gate 4B connects with
    `AF_INET` for an IPv4 candidate and `AF_INET6` for an IPv6 one, never relies
    on `AI_V4MAPPED`, and reports the peer in the family it connected with.
    """

    address: str
    port: int


@dataclass(frozen=True, slots=True)
class ApprovedDestination:
    """One address, checked against the policy at the moment of connecting.

    Prefer `approve_destination`, which is the only path that ties the address
    to a Phase 2 candidate. The constructor stays validating rather than
    private: it is the second barrier, and Python has no honest private
    constructor. An inspection test fixes that production code uses the factory.
    """

    host: HostName
    address: str
    port: int = DEFAULT_SMTP_PORT

    def __post_init__(self) -> None:
        if self.port not in ALLOWED_SMTP_PORTS:
            raise SMTPContractError(f"port {self.port} is not an allowed SMTP destination port")
        decision = evaluate_destination(self.address)
        if not decision.allowed:
            reason = decision.deny_reason
            raise SMTPContractError(
                f"destination refused by policy: {reason.value if reason else 'unknown'}"
            )
        if decision.address != self.address:
            raise SMTPContractError("a destination must be stored in its canonical form")

    @property
    def version(self) -> int:
        decision = evaluate_destination(self.address)
        return decision.version if decision.version is not None else 0


@dataclass(frozen=True, slots=True)
class DestinationApproved:
    """The address came from the candidate and passed the policy again."""

    destination: ApprovedDestination


@dataclass(frozen=True, slots=True)
class DestinationRefused:
    """The address may not be connected to, and why."""

    reason: DestinationRejection
    deny_reason: DestinationDenyReason | None = None


DestinationVerdict = DestinationApproved | DestinationRefused


def approve_destination(
    candidate: RouteCandidate, address: str, *, port: int = DEFAULT_SMTP_PORT
) -> DestinationVerdict:
    """Approve one address that `candidate` actually resolved to.

    This is the only path from DNS to a connectable destination. Without it an
    `ApprovedDestination` could be built from any public IP: the policy would
    allow it, because the policy answers "is this address safe to reach", not
    "did the domain publish it". Both questions have to be asked, and only this
    function asks the second.

    The host is taken from the candidate rather than from a parameter, so a
    destination cannot name one exchanger while pointing at another's address.
    """
    if candidate.status is not CandidateStatus.USABLE:
        return DestinationRefused(reason=DestinationRejection.CANDIDATE_NOT_USABLE)
    allowed = candidate.allowed_addresses
    if not allowed:
        return DestinationRefused(reason=DestinationRejection.NO_ALLOWED_ADDRESSES)
    if port not in ALLOWED_SMTP_PORTS:
        return DestinationRefused(reason=DestinationRejection.PORT_NOT_ALLOWED)

    decision = evaluate_destination(address)
    if not decision.allowed:
        # The candidate offered it when DNS answered; the policy refuses it now.
        return DestinationRefused(
            reason=DestinationRejection.DENIED_BY_POLICY, deny_reason=decision.deny_reason
        )
    if decision.address not in allowed:
        return DestinationRefused(reason=DestinationRejection.ADDRESS_NOT_IN_CANDIDATE)

    return DestinationApproved(
        destination=ApprovedDestination(host=candidate.host, address=decision.address, port=port)
    )


@dataclass(frozen=True, slots=True)
class ConfirmedPeer:
    """The endpoint a socket actually reached, re-judged and matched.

    Holding one of these is the proof that all three checks happened. It is the
    only way to open a session, and `SMTPSession` verifies the type at run time
    rather than trusting the annotation.
    """

    approved: ApprovedDestination
    peer_address: str
    peer_port: int = DEFAULT_SMTP_PORT

    def __post_init__(self) -> None:
        decision = evaluate_destination(self.peer_address)
        if not decision.allowed:
            reason = decision.deny_reason
            raise SMTPContractError(
                f"peer refused by policy: {reason.value if reason else 'unknown'}"
            )
        if decision.address != self.approved.address:
            raise SMTPContractError("the peer address is not the approved destination")
        if self.peer_port != self.approved.port:
            raise SMTPContractError("the peer port is not the approved port")

    @property
    def host(self) -> HostName:
        return self.approved.host

    @property
    def port(self) -> int:
        return self.peer_port


@dataclass(frozen=True, slots=True)
class PeerAccepted:
    """The peer matched the approved destination and passed the policy."""

    peer: ConfirmedPeer


@dataclass(frozen=True, slots=True)
class PeerRefused:
    """The peer may not be spoken to. The connection is closed, not used."""

    reason: PeerRejection
    deny_reason: DestinationDenyReason | None = None


PeerVerdict = PeerAccepted | PeerRefused


def confirm_peer(approved: ApprovedDestination, peer: PeerEndpoint) -> PeerVerdict:
    """Judge the endpoint a socket reached against the one that was approved.

    A result rather than an exception: a peer that does not match is an
    observation about the connection, and the caller must close it and record
    why. The `SMTPContractError` path in `ConfirmedPeer` stays for the
    programmer error of constructing one directly with mismatched values.

    An IPv4-mapped IPv6 peer is refused by the policy, not unwrapped. See
    `PeerEndpoint` for why that belongs to the transport.
    """
    decision = evaluate_destination(peer.address)
    if not decision.allowed:
        return PeerRefused(reason=PeerRejection.DENIED_BY_POLICY, deny_reason=decision.deny_reason)
    if decision.address != approved.address:
        return PeerRefused(reason=PeerRejection.ADDRESS_MISMATCH)
    if peer.port != approved.port:
        return PeerRefused(reason=PeerRejection.PORT_MISMATCH)
    return PeerAccepted(
        peer=ConfirmedPeer(approved=approved, peer_address=decision.address, peer_port=peer.port)
    )
