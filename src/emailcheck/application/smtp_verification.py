"""One verification: bounded MX fallback, and at most one `RCPT TO` in total.

Gate 4C made a probe exactly one dialogue against one candidate. Real mail
routes publish several exchangers, and a domain whose first MX is unreachable is
not a domain this project can say anything about — so something has to try the
second. This is that something, and it is the last gate of Phase 4.

Everything here is orchestration. No status, no confidence, no verdict:
`docs/status-model.md` section 4 is still Phase 5's, and the output is attempt
records plus the `Evidence` the gate 4D mapper produced.

Four properties are what a review should check.

**One verification issues at most one `RCPT TO`, in total.** Not one per
session — gate 4A and 4C already guarantee that — but one across every candidate
this loop tries. The moment a dialogue reaches the recipient stage, the
verification stops, whatever the answer was and whether or not an answer
arrived. Asking a second exchanger about the same recipient is the shape a
receiving site fingerprints as harvesting, and it is what `docs/threat-model.md`
lists first under address enumeration.

**Fallback is for failures that happened before the recipient stage.** A refused
connection, a bad banner, a refused `EHLO`, a TLS failure, a rejected
`MAIL FROM`: none of those is an answer about the address, so trying the next
exchanger asks the question for the first time rather than asking it again. A
`450` at `RCPT TO` is an answer, and it stops the verification even though it is
temporary — "the recipient was touched" outranks what the reply said.

**Nothing is retried.** The only thing this loop does is move to a *different*,
already-approved candidate. There is no second attempt at one endpoint, no
backoff, no sleep, and no greylisting retry; `docs/requirements.md` section 14
puts one bounded retry much later in the pipeline, on a schedule rather than
inside a probe.

**The number of connections is bounded before the loop starts.** Candidates come
from a Phase 2 `MailRoute`, which an attacker's DNS controls the length of, so
the plan is capped and de-duplicated before anything connects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from emailcheck.application.smtp_evidence import map_connect_failure, map_session_evidence
from emailcheck.application.smtp_probe import ProbeRefused, SMTPProbeService
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.evidence import Evidence
from emailcheck.domain.mail_route import MailRoute, RouteCandidate
from emailcheck.domain.rate_limit import RateLimitTimeout
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError
from emailcheck.domain.smtp_destination import DEFAULT_SMTP_PORT
from emailcheck.domain.smtp_protocol import STAGE_ORDER, DialogueStage, SessionReport
from emailcheck.domain.smtp_result import RecipientStageOutcome
from emailcheck.ports.clock import Clock

#: How many endpoints one verification may connect to. `docs/requirements.md`
#: section 9 asks for one bounded attempt per MX candidate and forbids racing
#: every exchanger; it fixes no number, so this is the conservative one.
#:
#: Three covers the ordinary shape of a mail route — a primary, a secondary, and
#: one more — while keeping the worst case at three connections and three
#: session budgets. The value matters less than the fact that it exists: without
#: it, the number of outbound connections one verification makes is whatever a
#: hostile DNS answer says it is.
DEFAULT_MAX_ATTEMPTS: Final = 3

#: A cap above this is not a cap. A route with more usable exchangers than this
#: is a configuration nobody has, and trying them all would be a connection
#: burst from one request.
MAX_ATTEMPTS_CEILING: Final = 8

#: The stage from which a dialogue has touched the recipient. Derived from
#: `STAGE_ORDER` rather than listed, for the reason gate 4D's mapper derives its
#: own: a stage added after `RCPT_TO` must count as past it, not before it.
_AT_OR_PAST_RECIPIENT: Final[frozenset[DialogueStage]] = frozenset(
    STAGE_ORDER[STAGE_ORDER.index(DialogueStage.RCPT_TO) :]
)


class VerificationStop(StrEnum):
    """Why the loop ended. Operational vocabulary, and never a status.

    None of these says anything about the address. `candidates_exhausted` in
    particular is not "the mailbox does not exist": it means every exchanger
    this project was willing to try failed *before* the recipient stage, so
    nothing was learned. `docs/status-model.md` section 4 resolves the evidence,
    and evidence that says nothing resolves to `unknown`.
    """

    #: A dialogue reached the recipient stage. The verification is over,
    #: whatever the reply was and whether or not one arrived.
    RECIPIENT_ATTEMPTED = "recipient_attempted"
    #: Every planned candidate failed before the recipient stage.
    CANDIDATES_EXHAUSTED = "candidates_exhausted"
    #: The attempt cap was reached with candidates still unplanned.
    ATTEMPT_CAP_REACHED = "attempt_cap_reached"
    #: This project's own scheduling ran out of patience. No socket was opened
    #: for the attempt that was refused, and no mail server was involved.
    RATE_LIMIT_WAIT_EXCEEDED = "rate_limit_wait_exceeded"
    #: Phase 2 offered nowhere to connect. No SMTP happened at all.
    NO_USABLE_ROUTE = "no_usable_route"
    #: A failure of this project's own. Never attributed to an exchanger, and
    #: never a reason to try a different one.
    INTERNAL_ERROR = "internal_error"


class AttemptOutcome(StrEnum):
    """What one attempt did, in the coarse terms the loop branches on."""

    #: The dialogue reached the recipient stage. At most one attempt may be this.
    RECIPIENT_ATTEMPTED = "recipient_attempted"
    #: The dialogue ended before the recipient stage. Another candidate may run.
    PRE_RECIPIENT_FAILURE = "pre_recipient_failure"
    #: No connection was made. The destination was refused, or the transport was.
    NOT_CONNECTED = "not_connected"
    #: A failure of this project's own during the attempt.
    INTERNAL_ERROR = "internal_error"
    #: The wait budget expired. Nothing was connected to.
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class VerificationSettings:
    """What bounds one verification, validated the way every other bound is."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    def __post_init__(self) -> None:
        value = self.max_attempts
        if isinstance(value, bool) or not isinstance(value, int):
            raise SMTPContractError("an attempt cap must be a whole number, not a boolean")
        if value <= 0:
            raise SMTPContractError("an attempt cap must be positive")
        if value > MAX_ATTEMPTS_CEILING:
            raise SMTPContractError(f"an attempt cap above {MAX_ATTEMPTS_CEILING} is not a cap")


@dataclass(frozen=True, slots=True)
class PlannedAttempt:
    """One endpoint this verification is willing to reach.

    A candidate and one of the addresses it resolved to. The pair is what gets
    de-duplicated, because the same address behind two exchanger names is two
    different TLS identities: the certificate is verified against the MX host,
    so collapsing them on the address alone would silently accept one host's
    certificate for the other.
    """

    candidate: RouteCandidate
    address: str
    port: int = DEFAULT_SMTP_PORT

    @property
    def identity(self) -> tuple[str, str, int]:
        """What makes two attempts the same attempt."""
        return (self.candidate.host.value, self.address, self.port)


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """What one attempt did, with no remote text and no address in it.

    `mx_host` is the exchanger this project chose to connect to, which is
    operational metadata rather than user data. The recipient, the local part,
    the reply, and the transcript are all absent: what a server said is in the
    `Evidence` the 4D mapper built, bounded and sanitized.
    """

    index: int
    mx_host: str
    outcome: AttemptOutcome
    stage_reached: str | None
    recipient_attempted: bool
    reached_the_network: bool
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Everything one verification observed, and nothing it concluded.

    There is no status field, no confidence, and no verdict, and there will not
    be one here: Phase 5 aggregates `evidence` against the syntax, DNS, and
    passive evidence. `stopped_because` is operational — it says why the loop
    ended, not what the answer is.
    """

    attempts: tuple[AttemptRecord, ...]
    evidence: tuple[Evidence, ...]
    stopped_because: VerificationStop

    def __post_init__(self) -> None:
        attempted = sum(1 for attempt in self.attempts if attempt.recipient_attempted)
        if attempted > 1:
            # The invariant this whole gate exists for, refused in the type as
            # well as in the loop. Two barriers, and each has its own test.
            raise SMTPContractError(
                "a verification may attempt the recipient at most once in total"
            )

    @property
    def recipients_attempted(self) -> int:
        """How many times `RCPT TO` was reached. Never more than one."""
        return sum(1 for attempt in self.attempts if attempt.recipient_attempted)

    @property
    def recipient_touch(self) -> RecipientTouch:
        """Whether this verification may already have contacted the recipient.

        The fact everything above this layer needs in order to decide whether an
        automatic second attempt is a second recipient contact. Derived from the
        attempt records — which `touched_the_recipient` filled from the
        transcript and the stage reached — rather than from `stopped_because`,
        because a `VerificationStop` says why the *loop* ended and an
        `INTERNAL_ERROR` at the recipient stage ends it under a different name
        while having touched the recipient exactly as much.

        `NOT_TOUCHED` therefore requires every attempt to have said so. There is
        no branch here that produces it by default.
        """
        if any(attempt.recipient_attempted for attempt in self.attempts):
            return RecipientTouch.MAYBE_TOUCHED
        return RecipientTouch.NOT_TOUCHED

    @property
    def connections_made(self) -> int:
        """How many attempts reached the network, for a pacing metric."""
        return sum(1 for attempt in self.attempts if attempt.reached_the_network)


def plan_attempts(
    route: MailRoute, *, settings: VerificationSettings | None = None
) -> tuple[PlannedAttempt, ...]:
    """Which endpoints this verification may reach, in order, bounded.

    **Phase 2's ordering is kept exactly.** `connectable_candidates` is already
    in MX preference order, with hosts at an equal preference in the order the
    resolver served them, and this expands each candidate's allowed addresses in
    the order Phase 2 recorded them. Nothing is sorted again and nothing is
    randomized: a randomized scan would make one verification's behaviour
    unreproducible, and choosing a different endpoint to get a different answer
    is the identity-rotation shape `AGENTS.md` forbids.

    **The result is de-duplicated and capped.** Two candidates can resolve to
    one address, and a route can carry more exchangers than anyone should
    connect to. Without both of those the number of outbound connections from
    one request is whatever a DNS answer says it is.

    A routeless outcome yields nothing at all, because `connectable_candidates`
    is empty for every outcome except the two route outcomes — so a Null MX or
    an NXDOMAIN cannot produce an attempt, and Phase 2's hard-invalid evidence
    is not re-derived here.
    """
    settings = settings or VerificationSettings()
    planned: list[PlannedAttempt] = []
    seen: set[tuple[str, str, int]] = set()
    for candidate in route.connectable_candidates:
        for address in candidate.allowed_addresses:
            attempt = PlannedAttempt(candidate=candidate, address=address)
            if attempt.identity in seen:
                continue
            seen.add(attempt.identity)
            planned.append(attempt)
            if len(planned) == settings.max_attempts:
                return tuple(planned)
    return tuple(planned)


def touched_the_recipient(report: SessionReport) -> bool:
    """Whether this session put the recipient in front of the server.

    **Two independent barriers, and each answers a case the other misses.**

    The transcript names `RCPT TO` once the write has succeeded, which is the
    case where an answer arrived or the connection died waiting for one. But a
    write that *failed* is not in the transcript, and this project cannot know
    whether some of its bytes reached the peer — so reaching the stage counts
    too, and the stage is set before the command is written.

    Neither is redundant. `SessionReport` permits a transcript naming `RCPT TO`
    at a stage before the recipient's, which is the shape gate 4D's barrier
    tests are built from, and it permits reaching the stage with an empty
    transcript. Each barrier alone refuses one of those, and each has a test
    that fails when only it is removed.

    Conservative on purpose: the cost of a false positive is one verification
    that stops early and reports `unknown`, and the cost of a false negative is
    a second `RCPT TO` for the same recipient on a different server.
    """
    if SMTPCommand.RCPT_TO in report.commands_issued:
        return True
    return report.stage_reached in _AT_OR_PAST_RECIPIENT


@dataclass(frozen=True, slots=True)
class SMTPVerificationService:
    """Runs one verification: bounded fallback over a route's candidates.

    `probe` is required and carries the rate limiter, which is what keeps the
    authorization contract structural rather than repeated. `SMTPProbeService`
    cannot be constructed without a `RateLimiter`, so this service cannot be
    constructed without one either, and there is no parameter here through which
    to supply a permissive one.

    `clock` is the wall clock, used for one thing: the `observed_at` on the
    evidence this produces. The mapper takes a timestamp rather than a clock so
    that it stays a pure function (ADR 0010), which makes supplying one this
    layer's job.
    """

    probe: SMTPProbeService
    clock: Clock
    settings: VerificationSettings = field(default_factory=VerificationSettings)

    async def verify(
        self, target: NormalizedAddress, route: MailRoute, *, account: str
    ) -> VerificationReport:
        """Observe the recipient stage for `target`, over at most one `RCPT TO`.

        Returns what was observed. It decides nothing: a caller that wants a
        status calls Phase 5 with this evidence and everything else.
        """
        planned = plan_attempts(route, settings=self.settings)
        if not planned:
            # Phase 2 said there is nowhere to connect, and it already reported
            # why — a Null MX, an NXDOMAIN, a configuration anomaly. Producing a
            # second, weaker SMTP copy of that would double-count it, so this
            # returns no evidence rather than inventing some.
            return VerificationReport(
                attempts=(), evidence=(), stopped_because=VerificationStop.NO_USABLE_ROUTE
            )

        attempts: list[AttemptRecord] = []
        for index, attempt in enumerate(planned):
            record = await self._attempt(index, attempt, target, account=account)
            attempts.append(record)
            stop = _stop_for(record.outcome)
            if stop is not None:
                return _report(attempts, stop)

        return _report(attempts, _exhausted(planned, route, self.settings))

    async def _attempt(
        self,
        index: int,
        planned: PlannedAttempt,
        target: NormalizedAddress,
        *,
        account: str,
    ) -> AttemptRecord:
        """One candidate, one probe, one record.

        A cancellation is not caught here, and neither is anything else in
        `NEVER_A_SESSION_FAILURE`: the probe service and the transport already
        re-raise those, and a worker told to stop must not be handed a fallback
        to the next exchanger instead.
        """
        try:
            outcome = await self.probe.probe(
                planned.candidate, planned.address, target, account=account
            )
        except RateLimitTimeout:
            # This project's own queueing, not a remote condition. No socket was
            # opened and no evidence is produced, because nothing was observed.
            return AttemptRecord(
                index=index,
                mx_host=planned.candidate.host.value,
                outcome=AttemptOutcome.RATE_LIMITED,
                stage_reached=None,
                recipient_attempted=False,
                reached_the_network=False,
            )

        observed_at = self.clock.now()
        if isinstance(outcome, ProbeRefused):
            return _refusal_record(index, planned, outcome, observed_at)
        return _session_record(index, planned, outcome, observed_at)


def _refusal_record(
    index: int,
    planned: PlannedAttempt,
    refused: ProbeRefused,
    observed_at: datetime,
) -> AttemptRecord:
    """A probe that never produced a dialogue.

    A transport failure becomes evidence through the gate 4D mapper. A refusal
    at `approve_destination` does **not**: ADR 0010 settled that Phase 2 already
    reported it as `unsafe_destination`, and a second weaker copy of existing
    evidence is double-counting rather than completeness. The attempt is still
    recorded, so the fact that a candidate was skipped is visible.
    """
    failure = refused.refusal.transport_failure
    evidence: tuple[Evidence, ...] = ()
    if failure is not None:
        evidence = map_connect_failure(
            failure,
            observed_at=observed_at,
            deadline_exhausted=refused.deadline_exhausted,
            elapsed_milliseconds=refused.elapsed_milliseconds,
        )
    return AttemptRecord(
        index=index,
        mx_host=planned.candidate.host.value,
        outcome=AttemptOutcome.NOT_CONNECTED,
        stage_reached=DialogueStage.CONNECTED.value,
        recipient_attempted=False,
        reached_the_network=refused.refusal.reached_the_network,
        evidence=evidence,
    )


def _session_record(
    index: int,
    planned: PlannedAttempt,
    report: SessionReport,
    observed_at: datetime,
) -> AttemptRecord:
    """A dialogue that ran, mapped through gate 4D and classified for the loop.

    **The recipient-touch decision is taken first, before the mapper runs.** It
    is a protocol fact — the transcript and the stage the dialogue reached — and
    it must not depend on anything the evidence mapping does or fails to do. The
    Phase 4 final review found the reverse order here and showed what it costs:
    wrapping the mapper in `try/except` and returning a pre-recipient outcome —
    the "robustness" edit someone eventually makes — turned a mapper bug into a
    **second `RCPT TO` on the next exchanger**, and no test failed. Computing
    `attempted` above the mapper means a later `except` has nothing left to
    decide, and an ordering test pins the two lines in this order.

    The order of the two *classification* checks is deliberate too. A failure of
    this project's own is named as one even if it happened at the recipient
    stage, because calling it a recipient attempt would attribute our bug to the
    exchanger — and both stop the loop anyway, so only the label differs.
    """
    attempted = touched_the_recipient(report)
    evidence = map_session_evidence(report, observed_at=observed_at)
    if report.observation.outcome is RecipientStageOutcome.INTERNAL_ERROR:
        outcome = AttemptOutcome.INTERNAL_ERROR
    elif attempted:
        outcome = AttemptOutcome.RECIPIENT_ATTEMPTED
    else:
        outcome = AttemptOutcome.PRE_RECIPIENT_FAILURE
    return AttemptRecord(
        index=index,
        mx_host=planned.candidate.host.value,
        outcome=outcome,
        stage_reached=report.stage_reached.value,
        recipient_attempted=attempted,
        reached_the_network=True,
        evidence=evidence,
    )


#: Which attempt outcomes end the verification, and what they end it as. An
#: outcome absent from this table is one the loop may continue past, and there
#: is exactly one: a failure before the recipient stage.
_STOPS: Final[dict[AttemptOutcome, VerificationStop]] = {
    AttemptOutcome.RECIPIENT_ATTEMPTED: VerificationStop.RECIPIENT_ATTEMPTED,
    AttemptOutcome.INTERNAL_ERROR: VerificationStop.INTERNAL_ERROR,
    AttemptOutcome.RATE_LIMITED: VerificationStop.RATE_LIMIT_WAIT_EXCEEDED,
}


def _stop_for(outcome: AttemptOutcome) -> VerificationStop | None:
    """Whether this attempt ends the verification.

    Written as a table rather than as a chain of `if`s so that adding an
    `AttemptOutcome` member without deciding this question is visible: a new
    member falls through to "keep going", which is the permissive answer, so a
    test asserts every member appears here or in the one documented exception.
    """
    return _STOPS.get(outcome)


def _exhausted(
    planned: tuple[PlannedAttempt, ...], route: MailRoute, settings: VerificationSettings
) -> VerificationStop:
    """Why the loop ran out, when every attempt failed before the recipient.

    The two are worth separating for an operator: a route whose exchangers are
    all unreachable is a different situation from one this project declined to
    finish walking.
    """
    connectable = sum(
        len(candidate.allowed_addresses) for candidate in route.connectable_candidates
    )
    if len(planned) == settings.max_attempts and connectable > len(planned):
        return VerificationStop.ATTEMPT_CAP_REACHED
    return VerificationStop.CANDIDATES_EXHAUSTED


def _report(attempts: list[AttemptRecord], stop: VerificationStop) -> VerificationReport:
    """Assemble the report, with evidence in attempt order.

    Ordering is the attempts' own and nothing is sorted, grouped, or de-duplicated
    on the way out: the same inputs and the same clock produce the same tuple.
    Provenance comes from the attempt records rather than from a field added to
    `Evidence`, which keeps the 4D value type — and its privacy bound — untouched.
    """
    records = tuple(attempts)
    return VerificationReport(
        attempts=records,
        evidence=tuple(item for record in records for item in record.evidence),
        stopped_because=stop,
    )
