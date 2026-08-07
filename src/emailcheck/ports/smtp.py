"""The SMTP boundary, shaped so the destination policy cannot be bypassed.

The important part of this file is what the transport port does *not* accept. It
takes an `ApprovedDestination` and nothing else: there is no overload taking a
host name, an address string, or a port, so no caller can reach a destination
the policy has not judged. What comes back is a `PeerEndpoint`, which the caller
must put through `confirm_peer` before a session can exist at all.

There is also no method that writes arbitrary bytes. A transport connects,
reads, and closes; the six encoders in `domain/smtp_command.py` are the only
things that produce a command line, and gate 4C wires them to a writer whose
argument is the encoder's output.

No implementation exists in Phase 4A. Adding one is gate 4B, and
`plans/phase-04-smtp.md` records that a 4A review comes first.
"""

from __future__ import annotations

from typing import Protocol

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.smtp_destination import ApprovedDestination, PeerEndpoint
from emailcheck.domain.smtp_result import RecipientObservation


class SMTPTransport(Protocol):
    """Opens and closes one bounded connection to an approved destination."""

    async def connect(
        self, destination: ApprovedDestination, *, timeout_seconds: float
    ) -> PeerEndpoint:
        """Connect and report the endpoint the socket actually reached.

        The return value is untrusted: it is where the connection landed, which
        may differ from what was approved. The caller passes it to
        `confirm_peer` and closes the connection unless that succeeds.

        **Family rule for the implementation.** Connect with `AF_INET` for an
        IPv4 destination and `AF_INET6` for an IPv6 one, and do not use
        `AI_V4MAPPED`. A dual-stack socket reports an IPv4 peer as
        `::ffff:93.184.216.34`, which the destination policy refuses on purpose,
        so a mapped peer would turn a healthy IPv4 connection into an unsafe
        destination. Report the address in the family the connection used; never
        unwrap a mapped form and treat it as a public IPv4.
        """
        ...

    async def close(self) -> None:
        """Release the connection. Safe to call after a cancellation."""
        ...


class SMTPProber(Protocol):
    """Observes the recipient stage for one address.

    The result is structured protocol evidence. It carries no status: the
    aggregator in Phase 5 decides what a code means, with the DNS and passive
    evidence in front of it.
    """

    async def probe_recipient(
        self, address: NormalizedAddress, route: MailRoute
    ) -> RecipientObservation:
        """Observe the recipient stage without transmitting message content."""
        ...
