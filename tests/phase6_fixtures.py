"""Fakes for the Phase 6 pipeline, so a composition test opens no socket.

Every collaborator below answers from a table. The suite-wide guard in
`tests/conftest.py` already fails any real socket use; these exist so that a
whole verification can be driven deterministically, including the SMTP step.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from emailcheck.application.admission import AdmissionControl, AdmissionSettings
from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.mail_route import MailRouteService
from emailcheck.application.passive import PassiveClassifier
from emailcheck.application.public_job import PublicJob, public_job
from emailcheck.application.public_result import PublicResult, public_result
from emailcheck.application.smtp_evidence import map_session_evidence
from emailcheck.application.smtp_verification import (
    AttemptOutcome,
    AttemptRecord,
    VerificationReport,
    VerificationStop,
)
from emailcheck.application.syntax_evidence import SyntaxEvidenceProducer
from emailcheck.application.verification import AddressVerificationService, VerificationLimits
from emailcheck.classification.repository import PassiveDatasets
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.dns import (
    AddressLookup,
    DNSFailure,
    HostName,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)
from emailcheck.domain.evidence import Evidence
from emailcheck.domain.job import JobFailure, JobId, JobState
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.principal import Principal
from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPState
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_reply import ReplyParsed, parse_reply
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSOutcomeDetail
from emailcheck.ports.job_executor import ExecutorFull
from emailcheck.ports.observability import OperatorEvent
from emailcheck.ports.verdict_store import StoredVerdict

OBSERVED_AT = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
PRINCIPAL = Principal(account_id="acct-test")

#: The transcript a completed recipient exchange carries. `SessionReport`
#: refuses a report claiming a recipient was attempted with an empty
#: transcript — a reviewed 4C invariant — so a fixture has to be a shape a real
#: session could produce.
RECIPIENT_TRANSCRIPT = (
    SMTPCommand.EHLO,
    SMTPCommand.MAIL_FROM,
    SMTPCommand.RCPT_TO,
    SMTPCommand.RSET,
    SMTPCommand.QUIT,
)

MX_HOST = "mx.example.test"
#: A routable-looking address the destination policy allows. The documentation
#: ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are *denied* by
#: `security/destination.py`, so an MX resolving to one produces
#: `unsafe_destination` and no candidate — which is the policy working, and is
#: not the scenario these fixtures are for. Nothing connects to it: the SMTP
#: layer is a fake in every test that uses this.
MX_ADDRESS = "93.184.216.34"


@dataclass
class FakeClock:
    current: datetime = OBSERVED_AT

    def now(self) -> datetime:
        return self.current


@dataclass
class FakeResolver:
    """Answers from fixed tables, and counts what it was asked.

    The counter is what makes "an invalid address costs no DNS" a measurement
    rather than an assumption.
    """

    mx: dict[str, MXLookup] = field(default_factory=dict)
    a: dict[str, AddressLookup] = field(default_factory=dict)
    aaaa: dict[str, AddressLookup] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    #: Real seconds this resolver stalls for. Used only to drive the
    #: verification-total deadline against the event loop's own clock.
    delay_seconds: float = 0.0

    async def query_mx(self, domain: HostName) -> MXLookup:
        self.calls.append(("mx", domain.value))
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        return self.mx.get(domain.value, MXLookup(failure=DNSFailure.NO_RECORDS))

    async def query_a(self, host: HostName) -> AddressLookup:
        self.calls.append(("a", host.value))
        return self.a.get(host.value, AddressLookup(failure=DNSFailure.NO_RECORDS))

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        self.calls.append(("aaaa", host.value))
        return self.aaaa.get(host.value, AddressLookup(failure=DNSFailure.NO_RECORDS))


@dataclass
class RecordingOperatorSink:
    events: list[OperatorEvent] = field(default_factory=list)

    def record(self, event: OperatorEvent) -> None:
        self.events.append(event)

    def kinds(self) -> list[str]:
        return [event.kind.value for event in self.events]


@dataclass
class ScriptedSMTPVerification:
    """Stands in for `SMTPVerificationService`, answering with fixed evidence.

    It is not an `SMTPVerificationService` subclass on purpose: the point of a
    composition test is what the *high-level* service does with the evidence,
    and Phase 4 already has 700 tests about how that evidence is produced.
    """

    reply_lines: tuple[str, ...] | None = None
    evidence: tuple[Evidence, ...] | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)
    delay_seconds: float = 0.0
    raises: BaseException | None = None
    #: A whole `VerificationReport`, when a test needs the attempt records
    #: rather than only the evidence — the operational half Phase 6 reads.
    report: VerificationReport | None = None
    #: Whether the scripted outcome reached the recipient stage.
    #:
    #: **This fixture has to be honest about it**, because it is what
    #: `VerificationReport.recipient_touch` is derived from and therefore what
    #: gates the automatic retry. An earlier version returned `attempts=()` for
    #: every script, which made every scripted `450` look like a verification
    #: that never contacted anybody — so a test of "one job, one recipient
    #: touch" would have passed against a build that touched twice.
    #:
    #: `None` derives it from the script, and the derivation is the real rule: a
    #: scripted *reply* is a reply to `RCPT TO`, and there is no other way to
    #: obtain one. A script that produces evidence some other way — a refused
    #: connection, an internal error — reached no recipient.
    recipient_touched: bool | None = None

    async def verify(
        self, target: NormalizedAddress, route: MailRoute, *, account: str
    ) -> VerificationReport:
        self.calls.append((target.domain.ascii_form, account))
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.raises is not None:
            raise self.raises
        if self.report is not None:
            return self.report
        produced = self.evidence
        if produced is None:
            produced = () if self.reply_lines is None else recipient_evidence(self.reply_lines)
        touched = self.recipient_touched
        if touched is None:
            touched = self.reply_lines is not None
        return VerificationReport(
            attempts=(
                AttemptRecord(
                    index=0,
                    mx_host=MX_HOST,
                    outcome=(
                        AttemptOutcome.RECIPIENT_ATTEMPTED
                        if touched
                        else AttemptOutcome.PRE_RECIPIENT_FAILURE
                    ),
                    stage_reached=None,
                    recipient_attempted=touched,
                    reached_the_network=True,
                    evidence=produced,
                ),
            ),
            evidence=produced,
            stopped_because=(
                VerificationStop.RECIPIENT_ATTEMPTED
                if touched
                else VerificationStop.CANDIDATES_EXHAUSTED
            ),
        )


def recipient_evidence(lines: tuple[str, ...]) -> tuple[Evidence, ...]:
    """SMTP evidence built through the real Phase 4D mapper from a real reply."""
    parsed = parse_reply(list(lines))
    assert isinstance(parsed, ReplyParsed), lines
    reply = parsed.reply
    outcome = {
        2: RecipientStageOutcome.ACCEPTED,
        4: RecipientStageOutcome.TEMPORARY_FAILURE,
    }.get(reply.code // 100, RecipientStageOutcome.REJECTED)
    report = SessionReport(
        observation=RecipientObservation(
            outcome=outcome,
            final_state=SMTPState.CLOSED,
            reply=reply,
            tls_used=True,
            recipients_attempted=1,
            elapsed_milliseconds=42,
        ),
        stage_reached=DialogueStage.CLEANUP,
        tls=TLSOutcomeDetail(negotiated=True),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.COMPLETED,
        commands_issued=RECIPIENT_TRANSCRIPT,
        deadline_exhausted=False,
    )
    return map_session_evidence(report, observed_at=OBSERVED_AT)


def internal_error_evidence() -> tuple[Evidence, ...]:
    """What gate 4D produces when this project's own code failed."""
    report = SessionReport(
        observation=RecipientObservation(
            outcome=RecipientStageOutcome.INTERNAL_ERROR,
            final_state=SMTPState.CLOSED,
            reply=None,
            tls_used=False,
            recipients_attempted=0,
            elapsed_milliseconds=5,
        ),
        stage_reached=DialogueStage.EHLO,
        tls=TLSOutcomeDetail(),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=(),
        deadline_exhausted=False,
    )
    return map_session_evidence(report, observed_at=OBSERVED_AT)


def resolver_with_route(domain: str = "example.test") -> FakeResolver:
    """A resolver that publishes one usable exchanger."""
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={domain: MXLookup(records=(MXRecord(preference=10, exchange=MX_HOST),), ttl=ttl)},
        a={MX_HOST: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl)},
    )


def resolver_with_null_mx(domain: str = "example.test") -> FakeResolver:
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={domain: MXLookup(records=(MXRecord(preference=0, exchange="."),), ttl=ttl)}
    )


def resolver_with_temporary_failure(domain: str = "example.test") -> FakeResolver:
    """SERVFAIL: the resolver could not answer, which proves nothing."""
    return FakeResolver(mx={domain: MXLookup(failure=DNSFailure.SERVFAIL)})


def build_service(
    *,
    resolver: FakeResolver | None = None,
    smtp: ScriptedSMTPVerification | None = None,
    operator: RecordingOperatorSink | None = None,
    admission: AdmissionControl | None = None,
    limits: VerificationLimits | None = None,
    guard: object | None = None,
) -> tuple[AddressVerificationService, FakeResolver, RecordingOperatorSink]:
    """A service wired from fakes, shaped exactly like the production graph."""
    clock = FakeClock()
    used_resolver = resolver if resolver is not None else resolver_with_route()
    sink = operator if operator is not None else RecordingOperatorSink()
    service = AddressVerificationService(
        syntax=SyntaxEvidenceProducer(clock=clock),
        routes=MailRouteService(resolver=used_resolver, clock=clock),
        passive=PassiveClassifier(datasets=PassiveDatasets(), clock=clock),
        admission=admission if admission is not None else AdmissionControl(AdmissionSettings()),
        operator=sink,
        smtp=smtp,
        limits=limits if limits is not None else VerificationLimits(),
        guard=guard,  # type: ignore[arg-type]
    )
    return service, used_resolver, sink


def one_hour() -> timedelta:
    return timedelta(hours=1)


# --- Phase 6 follow-up: jobs, the cache, and the remote client ---------------


@dataclass
class FakeMonotonicClock:
    """Elapsed seconds, moved by the test rather than by the machine."""

    current: float = 0.0

    def monotonic(self) -> float:
        return self.current


@dataclass
class AdvancingSleeper:
    """Returns immediately and advances a fake clock by what it was asked for.

    This is what makes "wait twenty minutes for a retry" a measurement rather
    than twenty minutes of CI. The Phase 4E pacing tests use the same shape.
    """

    clock: FakeMonotonicClock
    slept: list[float] = field(default_factory=list)

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.clock.current += seconds
        await asyncio.sleep(0)


@dataclass
class HoldingSleeper:
    """Never returns. Parks the scheduler so a delayed job stays delayed.

    `AdvancingSleeper` is what makes a delay *measurable*, and it is exactly
    wrong for asserting that something is still waiting — the wait is over
    before the test can look. The Phase 4E review needed the same second fake
    for the same reason.
    """

    requested: list[float] = field(default_factory=list)

    async def sleep(self, seconds: float) -> None:
        self.requested.append(seconds)
        await asyncio.Event().wait()


@dataclass
class FakeRandomSource:
    """Deterministic tokens and no jitter, so an identifier is assertable."""

    prefix: str = "job"
    issued: int = 0
    jitter_value: float = 0.0

    def token(self, byte_count: int) -> str:
        self.issued += 1
        # Padded to satisfy `JobId`'s minimum length without depending on the
        # counter's width.
        return f"{self.prefix}-{self.issued:04d}".ljust(24, "x")

    def jitter(self, span_seconds: float) -> float:
        return min(self.jitter_value, span_seconds)


@dataclass
class InMemoryVerdictStore:
    """A `VerdictStore` that keeps rows in a list. Counts what it was asked.

    The whole key is compared here exactly as the SQL compares it, so a test of
    the *service* can assert cache behaviour without a database — and
    `tests/unit/adapters/` still exercises the real SQL against a real file.
    """

    rows: list[StoredVerdict] = field(default_factory=list)
    finds: int = 0
    saves: int = 0

    async def save(self, record: StoredVerdict) -> None:
        self.saves += 1
        self.rows.append(record)

    async def find(
        self,
        *,
        account_digest: str,
        target_digest: str,
        sender_identity_digest: str,
        aggregation_ruleset: str,
        now: datetime,
    ) -> StoredVerdict | None:
        self.finds += 1
        matching = [
            row
            for row in self.rows
            if row.account_digest == account_digest
            and row.target_digest == target_digest
            and row.sender_identity_digest == sender_identity_digest
            and row.aggregation_ruleset == aggregation_ruleset
            and row.expires_at > now
        ]
        return max(matching, key=lambda row: row.created_at, default=None)


@dataclass
class RecordingExecutor:
    """A `JobExecutor` that records instead of running, and runs on demand.

    Keeping "was this enqueued" and "did it run" separate is what makes
    `prompts/06-api-cli.md`'s "cache hit skips enqueue" measurable: the count is
    zero, rather than the work being cheap.
    """

    submitted: list[str] = field(default_factory=list)
    scheduled: list[tuple[str, float]] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)
    pending: dict[str, object] = field(default_factory=dict)
    isolated: bool = False
    full: bool = False
    #: Refuse only `schedule`. A separate switch from `full`, because the state
    #: that used to be left orphaned — `retry_scheduled` with nothing scheduled —
    #: is only reachable when the first submission *succeeded* and the retry is
    #: what gets refused.
    full_on_schedule: bool = False

    @property
    def is_isolated(self) -> bool:
        return self.isolated

    async def submit(self, job_id, work) -> None:  # type: ignore[no-untyped-def]
        if self.full:
            raise ExecutorFull("full")
        self.submitted.append(job_id.value)
        self.pending[job_id.value] = work

    async def schedule(self, job_id, work, *, delay_seconds: float) -> None:  # type: ignore[no-untyped-def]
        if self.full or self.full_on_schedule:
            raise ExecutorFull("full")
        self.scheduled.append((job_id.value, delay_seconds))
        self.pending[job_id.value] = work

    async def cancel(self, job_id) -> bool:  # type: ignore[no-untyped-def]
        self.cancelled.append(job_id.value)
        return self.pending.pop(job_id.value, None) is not None

    async def run_pending(self) -> None:
        """Run one pass over what is pending right now, in submission order.

        One pass rather than a drain, deliberately: a retry re-enters this map,
        and a loop that kept going would run the whole retry chain in a single
        call — which is exactly the step a test of "at most one retry" needs to
        take one at a time.
        """
        batch = list(self.pending.items())
        self.pending.clear()
        for _, work in batch:
            await work()  # type: ignore[operator]


@dataclass
class FakeRemoteClient:
    """A `RemoteCheckClient` answering from a scripted sequence of jobs."""

    submit_result: PublicJob | None = None
    sequence: list[PublicJob] = field(default_factory=list)
    submits: list[str] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)
    raises: Exception | None = None

    async def submit(self, address: str) -> PublicJob:
        self.submits.append(address)
        if self.raises is not None:
            raise self.raises
        assert self.submit_result is not None
        return self.submit_result

    async def fetch(self, job_id: str) -> PublicJob:
        self.fetches.append(job_id)
        if self.raises is not None:
            raise self.raises
        if len(self.sequence) > 1:
            return self.sequence.pop(0)
        return self.sequence[0]


def rate_limited_report() -> VerificationReport:
    """A report shaped like the one the Phase 4E loop produces when paced out.

    Built from `AttemptRecord` rather than by raising `RateLimitTimeout`,
    because the real loop converts that exception into exactly this — which is
    what makes the Phase 6 observability path production-reachable.
    """
    return VerificationReport(
        attempts=(
            AttemptRecord(
                index=0,
                mx_host=MX_HOST,
                outcome=AttemptOutcome.RATE_LIMITED,
                stage_reached=None,
                recipient_attempted=False,
                reached_the_network=False,
            ),
        ),
        evidence=(),
        stopped_because=VerificationStop.RATE_LIMIT_WAIT_EXCEEDED,
    )


def job_view(
    state: JobState,
    *,
    job_id: str = "remote-job-0001xxxxxxxx",
    result: PublicResult | None = None,
    failure: JobFailure | None = None,
) -> PublicJob:
    """One `PublicJob`, as a remote instance would have serialized it."""
    return public_job(
        job_id=JobId(job_id),
        state=state,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
        result=result,
        failure=failure,
    )


def empty_result() -> PublicResult:
    """The projection of the no-evidence verdict. A real aggregation."""
    return public_result(aggregate_evidence(()))


@dataclass
class BrokenSyntaxProducer:
    """A Phase 5 producer that raises. Stands in for a bug of this project's own.

    Used to reach the `except Exception` path of an entry point without
    pretending any real component behaves this way.
    """

    message: str = "a secret internal detail"

    def evidence(self, rejection: object) -> tuple[Evidence, ...]:
        raise RuntimeError(self.message)


@dataclass
class BlockingSMTPVerification:
    """An SMTP step that never finishes on its own, and counts what happened.

    Entry and completion are counted separately. A fake that only recorded
    "called" cannot tell a cancelled probe from a completed one, which is
    exactly the difference `asyncio.shield` erases.
    """

    entered: asyncio.Event = field(default_factory=asyncio.Event)
    started: int = 0
    completed: int = 0
    cancelled: int = 0

    async def verify(
        self, target: NormalizedAddress, route: MailRoute, *, account: str
    ) -> VerificationReport:
        self.started += 1
        self.entered.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        self.completed += 1  # pragma: no cover - only reached if nothing cancels
        return VerificationReport(
            attempts=(), evidence=(), stopped_because=VerificationStop.RECIPIENT_ATTEMPTED
        )


@dataclass
class GatedSMTPVerification(ScriptedSMTPVerification):
    """A scripted SMTP step that waits for the test to let it finish.

    Lets a test place a cancellation *inside* a running verification, which is
    the only way to reach the settling code with a job that is already terminal.
    """

    gate: asyncio.Event = field(default_factory=asyncio.Event)
    entered: asyncio.Event = field(default_factory=asyncio.Event)

    async def verify(
        self, target: NormalizedAddress, route: MailRoute, *, account: str
    ) -> VerificationReport:
        self.entered.set()
        await self.gate.wait()
        return await super().verify(target, route, account=account)


def connection_timeout_evidence() -> tuple[Evidence, ...]:
    """What gate 4D produces when the connection timed out.

    Built through the real `map_connect_failure`, so the reason and the
    temporary flag are the mapper's rather than this fixture's.
    """
    from emailcheck.application.smtp_evidence import map_connect_failure
    from emailcheck.domain.smtp_transport import TransportFailure

    return map_connect_failure(
        TransportFailure.CONNECT_TIMEOUT,
        elapsed_milliseconds=5000,
        deadline_exhausted=False,
        observed_at=OBSERVED_AT,
    )


@dataclass
class BarrierVerdictStore(InMemoryVerdictStore):
    """A store whose `find` parks every caller until `parties` have arrived.

    The cache lookup is the **last `await` before `JobService._claim`**, so
    holding two submissions here puts them at the claim boundary together.

    That seam is what makes a concurrency test mean something. Two plain
    `asyncio.gather`-ed submissions run one after the other in practice: the
    final review measured a lock-removal mutation staying inert against exactly
    that shape, because the scheduler never interleaved the two coroutines
    inside `_claim`. A barrier makes the interleaving a property of the test
    rather than of the scheduler, so the race the lock exists for is actually
    attempted every run.
    """

    parties: int = 2
    _arrived: int = 0
    _released: asyncio.Event = field(default_factory=asyncio.Event)

    async def find(self, **key: object) -> StoredVerdict | None:
        self._arrived += 1
        if self._arrived >= self.parties:
            self._released.set()
        await self._released.wait()
        return await super().find(**key)  # type: ignore[arg-type]
