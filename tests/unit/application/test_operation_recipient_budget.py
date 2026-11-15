"""One high-level operation, at most one `RCPT TO`, counted on the wire.

The final system audit's second critical finding. Gate 4E bounds one
*verification* at one recipient command and proves it here; nothing bounded one
**job**, and `docs/requirements.md` section 14's automatic retry ran a second
whole verification. The two reason codes that retry was eligible for —
`smtp_temporary_failure` and `mailbox_full` — are produced by
`application/smtp_evidence.py` from the reply to `RCPT TO` and from nowhere
else, so every retry it authorized was a second recipient contact for one
submitted address, twenty minutes later. Two `RCPT TO` commands on the wire, for
one thing the caller asked once.

So the measurement is the wire and not the report.
`RoutedSMTPTransport.recipient_commands` counts what was actually written across
every connection of every attempt of every retry, and the report, the verdict,
and the job state are all derived from the code under test.

The stack is real from `JobService` down: the real verification service, the
real Phase 4E loop, the real probe, the real dialogue, and a scripted peer.
Nothing here opens a socket and nothing sleeps.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Final

import pytest
from tests.batch_fixtures import CORRELATION_KEY, PRINCIPAL, approved, csv_for
from tests.phase6_fixtures import (
    FakeClock,
    FakeRandomSource,
    FakeResolver,
    InMemoryVerdictStore,
    RecordingExecutor,
    build_service,
)

from dialogue_fixtures import (
    MX_HOST,
    PUBLIC_V4,
    TARGET_TEXT,
    FakeMonotonicClock,
    RecordingRateLimiter,
    identity_provider,
)
from emailcheck.application.batch import BatchService
from emailcheck.application.jobs import JobService
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.application.smtp_probe import SMTPProbeService
from emailcheck.application.smtp_verification import SMTPVerificationService
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.domain.dns import AddressLookup, DNSFailure, MXLookup, MXRecord, apply_ttl_policy
from emailcheck.domain.job import JobState
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.smtp_contract import SMTPCommand
from emailcheck.domain.smtp_tls import TLSPolicy
from emailcheck.domain.smtp_transport import TransportFailure
from fake_smtp_server import (
    BANNER_OK,
    CLEANUP_OK,
    EHLO_WITH_STARTTLS,
    EHLO_WITHOUT_STARTTLS,
    MAIL_FROM_OK,
    QUIT_OK,
    RCPT_ACCEPTED,
    RCPT_GREYLISTED,
    RCPT_STORAGE_PERMANENT,
    RCPT_STORAGE_TEMPORARY,
    RCPT_TEMPORARY,
    STARTTLS_READY,
    RoutedSMTPTransport,
    ScriptedSMTPPeer,
    failure,
)

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 10.0
DOMAIN: Final = "recipient.test.example"
#: Fake TLS negotiates before any recipient command, as production requires.
TLS_SETTINGS: Final = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)


def peer(rcpt: object = RCPT_ACCEPTED, *, write_fails: bool = False) -> ScriptedSMTPPeer:
    """A fake TLS server that answers everything and one scripted `RCPT TO`.

    `write_fails` makes the *write* of `RCPT TO` fail, which is a different
    scenario from a scripted failure reply: the command never enters the
    transcript, so the wire counter cannot see it, and the recipient may still
    have been contacted.
    """
    from emailcheck.domain.smtp_destination import PeerEndpoint

    return ScriptedSMTPPeer(
        peer=PeerEndpoint(address=PUBLIC_V4, port=25),
        banner=BANNER_OK,
        responses={
            SMTPCommand.EHLO: [EHLO_WITH_STARTTLS, EHLO_WITHOUT_STARTTLS],
            SMTPCommand.STARTTLS: STARTTLS_READY,
            SMTPCommand.MAIL_FROM: MAIL_FROM_OK,
            SMTPCommand.RCPT_TO: rcpt,
            SMTPCommand.RSET: CLEANUP_OK,
            SMTPCommand.QUIT: QUIT_OK,
        },  # type: ignore[arg-type]
        write_failure_on=SMTPCommand.RCPT_TO if write_fails else None,
    )


def routed_resolver(*, servfail: bool = False) -> FakeResolver:
    ttl = apply_ttl_policy(3600, positive=True)
    if servfail:
        return FakeResolver(mx={DOMAIN: MXLookup(failure=DNSFailure.SERVFAIL)})
    return FakeResolver(
        mx={DOMAIN: MXLookup(records=(MXRecord(preference=10, exchange=MX_HOST),), ttl=ttl)},
        a={MX_HOST: AddressLookup(addresses=(PUBLIC_V4,), ttl=ttl)},
    )


@dataclass(slots=True)
class Wire:
    """`JobService` over the real Phase 4 stack and one scripted peer.

    Every collaborator between the job and the socket is the production class.
    The only doubles are the resolver, the clock, the randomness, and the
    transport — which is the boundary `docs/test-strategy.md` puts them at.
    """

    rcpt: object = RCPT_TEMPORARY
    servfail: bool = False
    write_fails: bool = False
    transport: RoutedSMTPTransport = field(init=False)
    executor: RecordingExecutor = field(default_factory=RecordingExecutor)
    jobs: JobService = field(init=False)

    def __post_init__(self) -> None:
        self.transport = RoutedSMTPTransport(
            peers={PUBLIC_V4: peer(self.rcpt, write_fails=self.write_fails)}  # type: ignore[dict-item]
        )
        smtp = SMTPVerificationService(
            probe=SMTPProbeService(
                transport=self.transport,  # type: ignore[arg-type]
                identity_provider=identity_provider(),
                rate_limiter=RecordingRateLimiter(),  # type: ignore[arg-type]
                clock=FakeMonotonicClock(),
                settings=TLS_SETTINGS,
            ),
            clock=FakeClock(),
        )
        service, _, sink = build_service(
            resolver=routed_resolver(servfail=self.servfail),
            smtp=smtp,  # type: ignore[arg-type]
        )
        self.jobs = JobService(
            verification=service,
            executor=self.executor,
            clock=FakeClock(),
            random=FakeRandomSource(),
            operator=sink,
            correlation_key=CORRELATION_KEY,
            cache=VerdictCache(
                store=InMemoryVerdictStore(),  # type: ignore[arg-type]
                clock=FakeClock(),
                random=FakeRandomSource(prefix="rec"),
                correlation_key=CORRELATION_KEY,
            ),
        )

    @property
    def recipient_commands(self) -> int:
        """`RCPT TO` written across every connection of every attempt."""
        return self.transport.recipient_commands

    async def run_one_operation(self) -> object:
        """Submit, then drain the executor until nothing more is scheduled.

        The drain is what makes this an *operation* test rather than an attempt
        test: if a retry is scheduled it runs here, and its recipient commands
        land in the same counter.
        """
        submitted = await self.jobs.submit(TARGET_TEXT, principal=PRINCIPAL)
        async with asyncio.timeout(OUTER_BOUND):
            for _ in range(4):
                if not self.executor.pending:
                    break
                await self.executor.run_pending()
        return self.jobs.get(submitted.job.id, principal=PRINCIPAL)


# --- the finding, counted on the wire ----------------------------------------


@asyncio_test
@pytest.mark.parametrize(
    "rcpt",
    [RCPT_TEMPORARY, RCPT_GREYLISTED, RCPT_STORAGE_TEMPORARY, RCPT_STORAGE_PERMANENT],
    ids=["450", "451", "452", "552 5.2.2"],
)
async def test_a_temporary_recipient_reply_costs_exactly_one_recipient_command(
    rcpt: object,
) -> None:
    """One job, one `RCPT TO`, for every reply the old rule retried.

    Two before Remediation A. The four scripts are `docs/requirements.md`
    section 14's "explicit temporary SMTP response" as
    `application/smtp_evidence.py` classifies it, which is precisely the set
    that used to schedule a second verification.
    """
    wire = Wire(rcpt=rcpt)

    job = await wire.run_one_operation()

    assert wire.recipient_commands == 1, "one operation contacted the recipient twice"
    assert job is not None
    assert job.state is JobState.COMPLETED
    assert job.retries_used == 0
    assert job.recipient_touch is RecipientTouch.MAYBE_TOUCHED
    assert wire.executor.scheduled == []


@asyncio_test
async def test_a_lost_reply_to_the_recipient_command_is_never_replayed() -> None:
    """`RCPT TO` goes out and the connection dies before an answer arrives.

    The most tempting case to retry — nothing was learned, so it *looks* like
    nothing happened — and the one where a retry is most certainly a second
    contact: the command was written, and this project has no way to know
    whether the peer processed it before closing.
    """
    wire = Wire(rcpt=failure(TransportFailure.CONNECTION_RESET))

    job = await wire.run_one_operation()

    assert wire.recipient_commands == 1
    assert job is not None
    assert job.recipient_touch is RecipientTouch.MAYBE_TOUCHED
    assert wire.executor.scheduled == [], "a lost reply was replayed"


@asyncio_test
async def test_a_failed_write_of_the_recipient_command_is_never_replayed() -> None:
    """The write itself fails, so the command is not even in the transcript.

    `touched_the_recipient` counts the *stage* as well as the transcript for
    exactly this: some of the bytes may have reached the peer, and "an exception
    before a response" is not proof that nothing was delivered. Fail closed.
    """
    wire = Wire(write_fails=True)

    job = await wire.run_one_operation()

    assert wire.recipient_commands == 0, "the transcript should not name a command that failed"
    assert job is not None
    assert job.recipient_touch is RecipientTouch.MAYBE_TOUCHED, "an uncertain write was cleared"
    assert wire.executor.scheduled == [], "an uncertain write was replayed"


@asyncio_test
async def test_an_accepted_recipient_is_one_command_too() -> None:
    """The control that says the counter measures something."""
    wire = Wire(rcpt=RCPT_ACCEPTED)

    job = await wire.run_one_operation()

    assert wire.recipient_commands == 1
    assert job is not None and job.state is JobState.COMPLETED


# --- the retry that is still allowed, and still touches nobody ---------------


@asyncio_test
async def test_a_failure_before_any_socket_still_earns_its_one_retry() -> None:
    """The positive control. Removing the retry entirely fails here.

    A DNS SERVFAIL is `docs/requirements.md` section 14's second condition and
    happens before a socket exists, so the first attempt provably contacted
    nobody and replay is safe. One retry is scheduled, a second verification
    runs, and the wire counter stays at zero throughout — which is the shape the
    recipient-touch rule is meant to preserve rather than to forbid.
    """
    wire = Wire(servfail=True)

    job = await wire.run_one_operation()

    assert len(wire.executor.scheduled) == 1, "the one safe automatic retry was lost"
    assert wire.recipient_commands == 0
    assert job is not None
    assert job.state is JobState.COMPLETED
    assert job.retries_used == 1, "the retry budget was not spent exactly once"
    assert job.recipient_touch is RecipientTouch.NOT_TOUCHED


@asyncio_test
async def test_the_retry_budget_is_still_one_and_not_unlimited() -> None:
    """A safe condition does not become an unbounded loop.

    The drain runs the work four times; the second attempt is the last, because
    the budget lives on the record rather than in the scheduler.
    """
    wire = Wire(servfail=True)

    job = await wire.run_one_operation()

    assert len(wire.executor.scheduled) == 1
    assert job is not None and job.retries_used == 1


# --- a batch row is an ordinary operation ------------------------------------


@asyncio_test
async def test_a_batch_row_gets_no_second_recipient_command_either() -> None:
    """Phase 10 adds no retry layer of its own.

    A row is submitted through `JobService` like any other check, so it inherits
    this bound rather than restating it — and this is what fails if a batch ever
    grows its own resubmission.
    """
    wire = Wire(rcpt=RCPT_TEMPORARY)
    batch = BatchService(
        jobs=wire.jobs,
        store=_batch_store(),
        clock=FakeClock(),  # type: ignore[arg-type]
        random_source=FakeRandomSource(prefix="batch"),
        settings=approved(),
        correlation_key=CORRELATION_KEY,
    )

    async with asyncio.timeout(OUTER_BOUND):
        await batch.submit(csv_for(TARGET_TEXT), principal=PRINCIPAL)
        for _ in range(4):
            if not wire.executor.pending:
                break
            await wire.executor.run_pending()

    assert wire.recipient_commands == 1, "a batch row contacted one recipient twice"
    assert wire.executor.scheduled == []


def _batch_store() -> object:
    from tests.batch_fixtures import InMemoryBatchStore

    return InMemoryBatchStore()
