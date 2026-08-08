"""The dialogue: banner, EHLO, optional STARTTLS, MAIL FROM, one RCPT TO, out.

This is the first code in the project that speaks SMTP. Everything it is allowed
to say already existed before it did — the closed enum, the six encoders, the
state machine, the reply parser — and this module only decides *when*.

Four properties are worth reading the code for, because they are the ones a
review should check rather than take on trust.

**Nothing chooses a command by name.** Each step asks the session type for
permission, builds a `WireCommand` from one of six factories, and hands it to a
connection that accepts nothing else. A step that wanted a seventh command would
have nowhere to get one.

**The total deadline dominates.** Every awaited step runs inside the remaining
session budget, so a peer that answers each stage just inside its per-operation
timeout still cannot hold a worker for the sum of them.
`docs/smtp-state-machine.md` section 6 requires exactly this, and gate 4B
recorded it as the thing 4C owed.

**A failure ends the dialogue.** Any `ReadFailed`, any framing defect, any
rejected reply before the recipient stage: the run returns, and no further
command is written. `docs/test-strategy.md` states the `ReadFailed`-is-terminal
rule; here it is structural, and a second barrier refuses a write after a
terminal failure even if a future edit forgot to return.

**No reply becomes a status.** `250` produces `ACCEPTED` and `550` produces
`REJECTED`, which are observations. What either means for deliverability is
`docs/status-model.md` section 4's question, and Phase 5's to answer.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Final, NoReturn

from emailcheck.domain import smtp_wire as wire
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.smtp_capabilities import Capabilities, parse_capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError, SMTPState
from emailcheck.domain.smtp_deadline import (
    MAX_SESSION_SECONDS,
    SessionBudget,
    SessionDeadline,
    start_deadline,
)
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_reply import (
    MAX_REPLY_LINES,
    ReplyDefect,
    ReplyMalformed,
    ReplyParsed,
    SMTPReply,
)
from emailcheck.domain.smtp_reply import parse_reply as parse_smtp_reply
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_session import CommandPermitted, SMTPSession
from emailcheck.domain.smtp_tls import (
    DEFAULT_TLS_POLICY,
    TLSFailureReason,
    TLSOutcomeDetail,
    TLSPolicy,
)
from emailcheck.domain.smtp_transport import (
    LineRead,
    TLSNegotiated,
    TransportFailure,
    WriteSucceeded,
)
from emailcheck.domain.smtp_wire import WireCommand
from emailcheck.ports.clock import MonotonicClock
from emailcheck.ports.smtp import SMTPConnection, TLSUpgradeRequest
from emailcheck.ports.smtp_sender_identity import SenderIdentity, SenderIdentityProvider

#: Exceptions that are never a session failure. The same set the transport
#: re-raises, for the same reason: a worker told to stop must not be handed a
#: result about a mail server, and this project's own invariant failures must
#: fail loudly rather than be attributed to a remote host.
#:
#: A test asserts this equals the transport's set, so the two cannot drift.
NEVER_A_SESSION_FAILURE: Final[tuple[type[BaseException], ...]] = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    AssertionError,
)

#: How long a TLS handshake may take on its own. The session budget bounds it
#: again from outside, and the smaller of the two applies.
DEFAULT_TLS_HANDSHAKE_SECONDS: Final = 10.0

#: The only greeting a session may continue from. Anything else is recorded and
#: the dialogue stops; none of it is evidence about the recipient.
BANNER_CODE: Final = 220

#: What `STARTTLS` answers when it is ready to negotiate.
STARTTLS_READY_CODE: Final = 220


@dataclass(frozen=True, slots=True)
class DialogueSettings:
    """The bounds and the policy one probe runs under."""

    tls_policy: TLSPolicy = DEFAULT_TLS_POLICY
    budget: SessionBudget = field(default_factory=SessionBudget)
    tls_handshake_seconds: float = DEFAULT_TLS_HANDSHAKE_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.tls_policy, TLSPolicy):
            raise SMTPContractError("a TLS policy must be a TLSPolicy member")
        if not isinstance(self.budget, SessionBudget):
            raise SMTPContractError("a session budget must be a validated SessionBudget")
        seconds = self.tls_handshake_seconds
        if isinstance(seconds, bool) or not isinstance(seconds, int | float):
            raise SMTPContractError("a handshake timeout must be a number of seconds")
        if not math.isfinite(seconds):
            raise SMTPContractError("a handshake timeout must be finite")
        if seconds <= 0 or seconds > MAX_SESSION_SECONDS:
            raise SMTPContractError("a handshake timeout must be positive and within the maximum")
        # Deliberately not required to be smaller than the budget. The budget
        # dominates it anyway — every step runs inside `remaining` — so making
        # the two agree by hand would be a configuration chore that buys nothing
        # and that a small budget would fail on.


@dataclass(frozen=True, slots=True)
class SMTPDialogue:
    """Runs one recipient-stage dialogue on a connection that is already open.

    It does not connect, does not close, and does not choose a destination. The
    connector opened the session and the probe service owns the connection's
    lifetime; this speaks the protocol and reports what happened.
    """

    identity_provider: SenderIdentityProvider
    clock: MonotonicClock
    settings: DialogueSettings = field(default_factory=DialogueSettings)

    async def run(
        self,
        connection: SMTPConnection,
        session: SMTPSession,
        target: NormalizedAddress,
        *,
        deadline: SessionDeadline | None = None,
    ) -> SessionReport:
        """Observe the recipient stage for `target`, and report what happened.

        `deadline` is the probe's own, already running. `SMTPProbeService` starts
        it before it connects, so the TCP connect, the dialogue, and the close
        share one budget — `docs/smtp-state-machine.md` section 6 says the total
        dominates every other bound, and a budget that started after the connect
        would leave `connect_seconds` outside it.

        Omitting it starts a fresh one, which is what a dialogue test that has no
        connect to account for wants. Production always passes one.
        """
        run = _Run(
            connection=connection,
            session=session,
            target=target,
            identity=self.identity_provider.current_identity(),
            clock=self.clock,
            settings=self.settings,
            deadline=deadline
            if deadline is not None
            else start_deadline(self.settings.budget, self.clock.monotonic()),
        )
        try:
            return await run.execute()
        except _DialogueEnded as ended:
            return ended.report
        except _SessionExpired:
            # This project's own bound, not the peer's behaviour. Recorded as a
            # non-target outcome with the flag set, so Phase 4D can tell a
            # deadline apart from a reset at the same stage.
            run.deadline_exhausted = True
            run.session = run.session.fail()
            return run.report(outcome=RecipientStageOutcome.CONNECTION_ERROR, stage=run.stage)
        except BaseException as error:
            if isinstance(error, NEVER_A_SESSION_FAILURE):
                raise
            # A bug in this project during a probe is a fact about the probe, so
            # it is a typed outcome — but never one about the address.
            return run.report(outcome=RecipientStageOutcome.INTERNAL_ERROR, stage=run.stage)


@dataclass(slots=True)
class _Run:
    """One dialogue in progress. Mutable, and never shared."""

    connection: SMTPConnection
    session: SMTPSession
    target: NormalizedAddress
    identity: SenderIdentity
    clock: MonotonicClock
    settings: DialogueSettings
    deadline: SessionDeadline
    stage: DialogueStage = DialogueStage.CONNECTED
    capabilities: Capabilities = field(default_factory=Capabilities)
    tls: TLSOutcomeDetail = field(default_factory=TLSOutcomeDetail)
    cleanup: CleanupStatus = CleanupStatus.NOT_ATTEMPTED
    transcript: list[SMTPCommand] = field(default_factory=list)
    terminal: bool = False
    deadline_exhausted: bool = False

    # --- the dialogue -------------------------------------------------------

    async def execute(self) -> SessionReport:
        await self._read_banner()
        await self._introduce()
        await self._negotiate_tls()
        await self._declare_sender()
        reply = await self._offer_recipient()
        await self._clean_up()
        return self.report(
            outcome=_recipient_outcome(reply), stage=DialogueStage.CLEANUP, reply=reply
        )

    async def _read_banner(self) -> None:
        """Read the greeting. Nothing may be written before it arrives."""
        self.stage = DialogueStage.BANNER
        received = await self._read_reply()
        if received.reply.code != BANNER_CODE:
            # A `421` here is a server declining the session and a `554` is one
            # refusing it. Both are facts about this connection, and the
            # dialogue stops without a command ever being written.
            self._end(RecipientStageOutcome.CONNECTION_ERROR, reply=received.reply)
        self.session = self.session.observe_banner()

    async def _introduce(self) -> None:
        """`EHLO`, and read what the server says it supports.

        There is no `HELO` fallback and there will not be one: `HELO` is not a
        member of the closed command set, so no encoder produces it and no state
        permits it. A server too old for `EHLO` is one this project does not
        probe, which is a narrower capability than adding a second greeting.
        """
        self.stage = DialogueStage.EHLO
        received = await self._exchange(SMTPCommand.EHLO, wire.ehlo(self.identity.ehlo))
        self.capabilities = parse_capabilities(received.texts)

    async def _negotiate_tls(self) -> None:
        """Upgrade when the server offers it, and decide when it does not."""
        if not self.capabilities.supports_starttls:
            if self.settings.tls_policy is TLSPolicy.REQUIRED:
                self.stage = DialogueStage.STARTTLS
                self._fail_tls(TLSFailureReason.NOT_OFFERED)
            return

        self.stage = DialogueStage.STARTTLS
        permitted = self._permit(SMTPCommand.STARTTLS)
        await self._write(wire.starttls(), SMTPCommand.STARTTLS)
        # Not advanced until the handshake actually succeeds: `TLS_NEGOTIATED`
        # means encrypted. The attempt is counted either way, so a retry is
        # refused by the session even on this path.
        self.session = permitted.session.fail()
        received = await self._read_reply()
        if received.reply.code != STARTTLS_READY_CODE:
            self._fail_tls(TLSFailureReason.COMMAND_REJECTED, reply=received.reply)

        self.stage = DialogueStage.TLS_HANDSHAKE
        outcome = await self._bounded(
            self.connection.start_tls(
                TLSUpgradeRequest(
                    peer=self.session.peer,
                    timeout_seconds=self.settings.tls_handshake_seconds,
                )
            )
        )
        if not isinstance(outcome, TLSNegotiated):
            self.terminal = True
            self._fail_tls(_tls_reason_for(outcome.failure))
        self.session = permitted.session
        self.tls = TLSOutcomeDetail(negotiated=True)

        # The state machine permits only `EHLO` from `TLS_NEGOTIATED`, so this
        # is not a convention: removing it would make `MAIL FROM` a refusal.
        self.stage = DialogueStage.EHLO_AFTER_TLS
        received = await self._exchange(SMTPCommand.EHLO, wire.ehlo(self.identity.ehlo))
        self.capabilities = parse_capabilities(received.texts)

    async def _declare_sender(self) -> None:
        """`MAIL FROM`, with the operator-configured reverse path.

        A rejection here is about the sender, the connection, or the server's
        policy. `docs/requirements.md` section 9 is explicit that none of those
        is target-address invalidity, so it ends the probe without producing a
        recipient observation at all.
        """
        self.stage = DialogueStage.MAIL_FROM
        await self._exchange(SMTPCommand.MAIL_FROM, wire.mail_from(self.identity.envelope_sender))

    async def _offer_recipient(self) -> SMTPReply:
        """The one `RCPT TO`. Its reply is the observation this probe exists for."""
        self.stage = DialogueStage.RCPT_TO
        permitted = self._permit(SMTPCommand.RCPT_TO)
        await self._write(wire.rcpt_to(self.target), SMTPCommand.RCPT_TO)
        # The attempt counts from here whatever the answer is, so the transcript
        # and the observation cannot disagree about how many recipients were
        # offered. A `550` is a *result*, so the state advances for it too.
        self.session = permitted.session
        return (await self._read_reply()).reply

    async def _clean_up(self) -> None:
        """`RSET` then `QUIT`, best effort, and never at the cost of the answer.

        The recipient result is already in hand. A server that drops the
        connection before `QUIT` has answered the only question this project
        asked, so a cleanup failure is recorded as its own metadata and changes
        nothing about the observation.
        """
        self.stage = DialogueStage.CLEANUP
        if self.terminal:
            self.cleanup = CleanupStatus.NOT_ATTEMPTED
            return
        if self.deadline.is_expired(self.clock.monotonic()):
            # The budget is what stopped the cleanup, so the flag Phase 4D reads
            # has to say so. `SessionReport` refuses the pair where it does not.
            self.deadline_exhausted = True
            self.cleanup = CleanupStatus.SKIPPED_DEADLINE
            return

        self.cleanup = CleanupStatus.COMPLETED
        for command, encoded in (
            (SMTPCommand.RSET, wire.rset()),
            (SMTPCommand.QUIT, wire.quit_session()),
        ):
            if not await self._try_cleanup_command(command, encoded):
                self.cleanup = CleanupStatus.INCOMPLETE
                return

    async def _try_cleanup_command(self, command: SMTPCommand, encoded: WireCommand) -> bool:
        """Issue one courtesy command. False on anything short of a good reply.

        Never raises and never ends the dialogue: by this point the observation
        exists, and cleanup must not be able to change it.
        """
        outcome = self.session.issue(command)
        if not isinstance(outcome, CommandPermitted):
            return False
        try:
            written = await self._bounded(self.connection.write_command(encoded))
            if not isinstance(written, WriteSucceeded):
                self.terminal = True
                return False
            self.transcript.append(command)
            self.session = outcome.session
            lines = await self._collect_reply_lines()
        except _SessionExpired:
            self.deadline_exhausted = True
            return False
        if lines is None:
            self.terminal = True
            return False
        parsed = parse_smtp_reply(lines)
        return isinstance(parsed, ReplyParsed) and not parsed.reply.is_permanent

    # --- one command, one reply --------------------------------------------

    async def _exchange(self, command: SMTPCommand, encoded: WireCommand) -> _ReplyLines:
        """Issue `command`, require a positive reply, and return what came back.

        Anything other than a `2xx` ends the dialogue. Which stage it was is in
        `stage_reached` and the reply is carried whole, so Phase 4D can tell a
        rejected sender from a refused greeting without this layer deciding what
        either means.
        """
        permitted = self._permit(command)
        await self._write(encoded, command)
        # The session does not advance until the server has accepted. A `550`
        # to `EHLO` must not leave the session looking introduced.
        self.session = permitted.session.fail()
        received = await self._read_reply()
        if received.reply.code // 100 != 2:
            self._end(RecipientStageOutcome.CONNECTION_ERROR, reply=received.reply)
        self.session = permitted.session
        return received

    def _permit(self, command: SMTPCommand) -> CommandPermitted:
        """Ask the state machine. A refusal here is this project's bug, not the peer's.

        This is the second barrier behind every ordering rule in the dialogue.
        Removing the re-EHLO after TLS, issuing `MAIL FROM` before `EHLO`, and
        asking for a second `RCPT TO` all arrive here, and none of them gets a
        command written.
        """
        outcome = self.session.issue(command)
        if not isinstance(outcome, CommandPermitted):
            raise SMTPContractError(
                f"the session refused {command.value} in state {self.session.state.value}: "
                f"{outcome.reason.value}"
            )
        return outcome

    async def _write(self, encoded: WireCommand, command: SMTPCommand) -> None:
        """Put one encoded command on the wire, or end the dialogue."""
        if self.terminal:
            # A second barrier behind "a failure ends the dialogue". Every
            # failure path returns, so this should be unreachable; it is here
            # because "should be unreachable" is how a command gets written
            # after a connection has already failed.
            raise SMTPContractError("no command may be written after a terminal failure")
        outcome = await self._bounded(self.connection.write_command(encoded))
        if not isinstance(outcome, WriteSucceeded):
            self.terminal = True
            self._end(RecipientStageOutcome.CONNECTION_ERROR)
        self.transcript.append(command)

    async def _read_reply(self) -> _ReplyLines:
        """Read one complete reply, or end the dialogue with why it could not."""
        lines = await self._collect_reply_lines()
        if lines is None:
            self.terminal = True
            self._end(RecipientStageOutcome.CONNECTION_ERROR)
        parsed = parse_smtp_reply(lines)
        if isinstance(parsed, ReplyMalformed):
            self.terminal = True
            self._end(RecipientStageOutcome.PROTOCOL_ERROR, defect=parsed.defect)
        return _ReplyLines(reply=parsed.reply, texts=lines)

    async def _collect_reply_lines(self) -> list[str] | None:
        """Gather the lines of one reply. None means the connection failed.

        A line ending the reply is `NNN<space>` and a continuation is `NNN-`.
        The count is capped here as well as in the parser, so a server that
        never terminates a multiline reply cannot make this loop forever — the
        per-read deadline, the per-connection byte cap, and the session budget
        each bound it too, and any one of them alone would be enough.
        """
        lines: list[str] = []
        while True:
            outcome = await self._bounded(self.connection.read_line())
            if not isinstance(outcome, LineRead):
                return None
            lines.append(outcome.line.decode("utf-8", errors="replace"))
            if len(lines) > MAX_REPLY_LINES:
                # Handed to the parser, which names it `too_many_lines` rather
                # than this module inventing a second vocabulary for it.
                return lines
            if not _is_continuation(lines[-1]):
                return lines

    # --- bounds -------------------------------------------------------------

    async def _bounded[T](self, awaitable: Awaitable[T]) -> T:
        """Run one step inside whatever is left of the session budget.

        Two independent bounds, and the smaller wins. The per-operation timeouts
        the transport already applies bound one read or one write; this bounds
        the whole probe, which is what a peer answering slowly at every stage
        would otherwise defeat.
        """
        remaining = self.deadline.remaining(self.clock.monotonic())
        if remaining <= 0:
            # The call was built but must not run. Closing it keeps a coroutine
            # from being garbage-collected un-awaited, which is a warning in
            # tests and a leak in a worker.
            close = getattr(awaitable, "close", None)
            if callable(close):
                close()
            raise _SessionExpired
        try:
            async with asyncio.timeout(remaining):
                return await awaitable
        except TimeoutError:
            raise _SessionExpired from None

    # --- reporting ----------------------------------------------------------

    def report(
        self,
        *,
        outcome: RecipientStageOutcome,
        stage: DialogueStage,
        reply: SMTPReply | None = None,
        defect: ReplyDefect | None = None,
    ) -> SessionReport:
        """Assemble the report. Never decides what a code means."""
        observation = RecipientObservation(
            outcome=outcome,
            final_state=self.session.state,
            reply=reply,
            defect=defect,
            tls_used=self.tls.negotiated,
            recipients_attempted=self.session.recipients_attempted,
            elapsed_milliseconds=self.deadline.elapsed_milliseconds(self.clock.monotonic()),
        )
        return SessionReport(
            observation=observation,
            stage_reached=stage,
            tls=self.tls,
            capabilities=self.capabilities,
            cleanup=self.cleanup,
            commands_issued=tuple(self.transcript),
            deadline_exhausted=self.deadline_exhausted,
        )

    def _end(
        self,
        outcome: RecipientStageOutcome,
        *,
        reply: SMTPReply | None = None,
        defect: ReplyDefect | None = None,
    ) -> NoReturn:
        """Stop the dialogue here. Always raises."""
        if self.session.state is not SMTPState.CLOSED:
            self.session = self.session.fail()
        raise _DialogueEnded(
            self.report(outcome=outcome, stage=self.stage, reply=reply, defect=defect)
        )

    def _fail_tls(self, reason: TLSFailureReason, *, reply: SMTPReply | None = None) -> NoReturn:
        """End the dialogue on a TLS problem. Never mailbox evidence.

        `TLS_ERROR` is in `NON_TARGET_OUTCOMES`, so "this server offers no
        STARTTLS" can never contribute to a statement about the address.
        """
        self.tls = TLSOutcomeDetail(negotiated=False, reason=reason)
        self._end(RecipientStageOutcome.TLS_ERROR, reply=reply)


class _DialogueEnded(Exception):
    """Internal: a step decided the session is over. Never leaves this module."""

    def __init__(self, report: SessionReport) -> None:
        super().__init__("dialogue ended")
        self.report = report


class _SessionExpired(Exception):
    """Internal: the session budget ran out. Converted at the boundary."""


@dataclass(frozen=True, slots=True)
class _ReplyLines:
    """A parsed reply together with the raw lines its keywords come from."""

    reply: SMTPReply
    texts: list[str]


def _is_continuation(line: str) -> bool:
    """Whether this reply line is followed by another, per RFC 5321 section 4.2."""
    return len(line) >= 4 and line[:3].isdigit() and line[3] == "-"


def _recipient_outcome(reply: SMTPReply) -> RecipientStageOutcome:
    """Classify the RCPT reply, and stop well short of a verdict.

    `ACCEPTED` is not `likely_deliverable` and `REJECTED` is not `invalid`. An
    accept-all server says `250` to everyone and policy rejections share `550`,
    so what these mean is decided in Phase 5 with the syntax, DNS, and passive
    evidence in front of it. This maps a digit to an observation and does
    nothing else — in particular, `550 5.1.1` gets no special treatment here.
    """
    first_digit = reply.code // 100
    if first_digit == 2:
        return RecipientStageOutcome.ACCEPTED
    if first_digit == 4:
        return RecipientStageOutcome.TEMPORARY_FAILURE
    return RecipientStageOutcome.REJECTED


def _tls_reason_for(failure: TransportFailure) -> TLSFailureReason:
    """Name a transport-level TLS failure in the dialogue's vocabulary."""
    return {
        TransportFailure.TLS_CERTIFICATE_INVALID: TLSFailureReason.CERTIFICATE_INVALID,
        TransportFailure.TLS_HOSTNAME_MISMATCH: TLSFailureReason.HOSTNAME_MISMATCH,
        TransportFailure.TLS_TIMEOUT: TLSFailureReason.TIMEOUT,
        TransportFailure.TLS_PEER_CHANGED: TLSFailureReason.PEER_CHANGED,
    }.get(failure, TLSFailureReason.HANDSHAKE_FAILED)
