"""One probe, in the one order it may happen in.

```text
rate-limit authorization
  → start the session deadline
  → approve destination     (the DNS candidate must have offered the address)
  → connect                 (the policy runs again; no socket if it refuses)
  → confirm peer            (the address and port actually reached)
  → session                 (requires a ConfirmedPeer, checked at run time)
  → dialogue                (banner, EHLO, optional STARTTLS, MAIL FROM, one RCPT)
  → close                   (always, from a finally)
```

**Budget before socket.** `docs/test-strategy.md` section 4 lists "rate budget
acquired before connect" as an invariant, and this is where it becomes one: the
lease is acquired first, the connection is opened inside it, and `RateLimiter`
has no default. A caller that has not supplied one cannot construct this
service, so there is no path from a future API to an unmetered probe.

The limiter itself is deliberately not implemented here. Gate 4E and Phase 6 own
the real budgets, the kill switch, and the per-destination pacing; what 4C owes
is the *ordering contract*, so that adding them is wiring rather than
restructuring.

**The session deadline covers the connect.** `docs/smtp-state-machine.md`
section 6 says the total deadline dominates every other bound, so it starts here
rather than inside the dialogue: from the first TCP SYN to the final close is one
budget. The connect is run inside whatever is left of it, so the bound that
applies is

```text
min(TransportTimeouts.connect_seconds, remaining session budget)
```

and the per-operation timeout is kept rather than replaced — the smaller of the
two wins, which is the same rule every step of the dialogue follows.

**Waiting for a rate-limit lease is deliberately outside that budget.** The
deadline starts after the lease is entered. A budget spanning the wait would turn
queue depth into `deadline_exhausted`, and Phase 4D reads that flag as *this
project's own bound on a remote conversation*; attributing our own scheduling to
the network is exactly the confusion the flag exists to prevent. Bounding how
long a caller may wait for a budget is gate 4E's, and it belongs to the limiter.

**One candidate, one attempt.** No retry, no backoff, no second MX, no second
recipient, and no second session for the same address. Gate 4E adds bounded MX
attempts; a `probe` call here is exactly one dialogue.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field

from emailcheck.application.smtp_connect import (
    ConnectOutcome,
    ConnectRefused,
    ConnectStage,
    SessionOpened,
    SMTPConnector,
)
from emailcheck.application.smtp_dialogue import DialogueSettings, SMTPDialogue
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.mail_route import RouteCandidate
from emailcheck.domain.smtp_deadline import SessionDeadline, start_deadline
from emailcheck.domain.smtp_protocol import SessionReport
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.ports.clock import MonotonicClock
from emailcheck.ports.rate_limit import RateLimiter
from emailcheck.ports.smtp import SMTPTransport
from emailcheck.ports.smtp_sender_identity import SenderIdentityProvider


@dataclass(frozen=True, slots=True)
class ProbeRefused:
    """No dialogue happened, and the reason has nothing to do with the address.

    Carried separately from a `SessionReport` because there is nothing to
    report: no command was written, no reply was read, and the connection either
    never opened or was closed before a byte went out.

    `deadline_exhausted` distinguishes the two ways a connect can run out of
    time. A `CONNECT_TIMEOUT` with the flag false is the transport's own
    per-operation bound; with it true, the whole session budget was spent before
    a connection existed. Phase 4D needs the difference for the same reason
    `SessionReport` carries the same flag.
    """

    refusal: ConnectRefused
    elapsed_milliseconds: int | None = None
    deadline_exhausted: bool = False

    @property
    def is_about_the_target(self) -> bool:
        """Always false."""
        return False


ProbeOutcome = SessionReport | ProbeRefused


@dataclass(frozen=True, slots=True)
class SMTPProbeService:
    """Observes the recipient stage for one address on one MX candidate.

    Every collaborator is required. There is no default transport, no default
    identity, and — the one that matters — no default rate limiter, because a
    default would be the unmetered path this service exists to make impossible.
    """

    transport: SMTPTransport
    identity_provider: SenderIdentityProvider
    rate_limiter: RateLimiter
    clock: MonotonicClock
    settings: DialogueSettings = field(default_factory=DialogueSettings)
    on_temporary_reply: Callable[[str, str], None] | None = None

    async def probe(
        self,
        candidate: RouteCandidate,
        address: str,
        target: NormalizedAddress,
        *,
        account: str,
    ) -> ProbeOutcome:
        """Run one bounded probe, holding a rate-limit lease throughout.

        `address` must be one `candidate` resolved to; `approve_destination`
        enforces that inside the connector, and there is no parameter here for a
        host name or a port.

        The lease is acquired before anything else happens and released on the
        way out, whatever happened in between. `account`, the recipient's
        domain, and the MX host are what the budgets are keyed by; the target's
        local part is not passed to the limiter, so a budget key can never carry
        one.

        The session deadline starts once the lease is held, and the connect runs
        inside it, so the whole span from the first SYN to the final close is
        bounded by one budget.
        """
        lease = self.rate_limiter.acquire(
            account=account,
            domain=target.domain.ascii_form,
            mx_host=candidate.host.value,
        )
        async with lease:
            deadline = start_deadline(self.settings.budget, self.clock.monotonic())
            connector = SMTPConnector(transport=self.transport)
            opened = await self._reach(connector, candidate, address, deadline)
            if isinstance(opened, ProbeRefused):
                return opened
            if isinstance(opened, ConnectRefused):
                # The connector already closed anything it opened.
                return ProbeRefused(
                    refusal=opened,
                    elapsed_milliseconds=self._elapsed(deadline),
                )

            report = await self._speak(opened, target, deadline)
            code = report.observation.basic_code
            if code is not None and 400 <= code < 500 and self.on_temporary_reply is not None:
                self.on_temporary_reply(target.domain.ascii_form, candidate.host.value)
            return report

    async def _reach(
        self,
        connector: SMTPConnector,
        candidate: RouteCandidate,
        address: str,
        deadline: SessionDeadline,
    ) -> ConnectOutcome | ProbeRefused:
        """Open a session inside whatever is left of the session budget.

        The transport applies `TransportTimeouts.connect_seconds` of its own, so
        the effective bound is the smaller of the two. Nothing is connected to at
        all when the budget is already spent: a socket opened with no time left
        to speak on it is a socket opened for nothing, and the remote host still
        sees the connection.

        A cancellation is not caught. The transport closes its socket before it
        re-raises, and `ConnectRefused`'s own `finally` closes a connection that
        was opened and not confirmed, so nothing leaks on the way past.
        """
        remaining = deadline.remaining(self.clock.monotonic())
        if remaining <= 0:
            return self._out_of_time(deadline)

        opened: ConnectOutcome | None = None
        try:
            async with asyncio.timeout(remaining):
                opened = await connector.open_session(candidate, address)
        except TimeoutError:
            if isinstance(opened, SessionOpened):
                # The deadline can land between the connect returning and the
                # block being left. Rare, and a leaked socket either way.
                await opened.connection.close()
            return self._out_of_time(deadline)
        return opened

    def _out_of_time(self, deadline: SessionDeadline) -> ProbeRefused:
        """The session budget ran out before a dialogue could begin.

        Reported as a connect timeout, because that is what happened, with
        `deadline_exhausted` naming whose bound it was. Nothing here is evidence
        about the address.
        """
        return ProbeRefused(
            refusal=ConnectRefused(
                stage=ConnectStage.CONNECT,
                transport_failure=TransportFailure.CONNECT_TIMEOUT,
            ),
            elapsed_milliseconds=self._elapsed(deadline),
            deadline_exhausted=True,
        )

    def _elapsed(self, deadline: SessionDeadline) -> int:
        """How long this probe has taken, measured on the same deadline."""
        return deadline.elapsed_milliseconds(self.clock.monotonic())

    async def _speak(
        self, opened: SessionOpened, target: NormalizedAddress, deadline: SessionDeadline
    ) -> SessionReport:
        """Run the dialogue and close, in that order, always.

        The close is in a `finally` and the connection's close is idempotent and
        never raises, so a cancellation, a bug, or a report all leave the same
        thing behind: nothing.

        The dialogue is handed the deadline that has been running since before
        the connect, so what it has left is what the connect did not spend.
        """
        dialogue = SMTPDialogue(
            identity_provider=self.identity_provider,
            clock=self.clock,
            settings=self.settings,
        )
        try:
            return await dialogue.run(opened.connection, opened.session, target, deadline=deadline)
        finally:
            await opened.connection.close()
