"""A scripted SMTP peer that opens no socket.

`docs/test-strategy.md` fixes a fake as the default for every protocol test, and
this is the one gate 4C needs: a peer that answers commands from a script and
records exactly what was said to it.

It behaves like a server rather than like a tape. Replies are queued when a
command arrives, so the transcript is the real sequence of commands and a reply
that was never triggered is never read. That is what makes the transcript
assertions in `docs/smtp-state-machine.md` section 7 meaningful: the dialogue
drives it, not the other way round.

Everything a real peer can do that matters is expressible: a multiline greeting,
a missing `STARTTLS`, a rejected command, every RCPT class, a malformed frame, an
unterminated reply, too many lines, an over-long line, an EOF, a reset, a
timeout, and a write that fails.

It is deliberately **not** more permissive than the real connection:
`write_command` refuses anything that is not a `WireCommand`, and `start_tls`
refuses anything that is not a `TLSUpgradeRequest`. A double that accepts what
the original rejects lets a test pass on a path production would refuse.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from types import TracebackType

from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError
from emailcheck.domain.smtp_destination import ApprovedDestination, PeerEndpoint
from emailcheck.domain.smtp_transport import (
    LineRead,
    ReadFailed,
    ReadOutcome,
    TLSFailed,
    TLSNegotiated,
    TLSOutcome,
    TransportFailure,
    WriteFailed,
    WriteOutcome,
    WriteSucceeded,
)
from emailcheck.domain.smtp_wire import WireCommand
from emailcheck.ports.smtp import (
    ConnectionFailed,
    ConnectionOpened,
    ConnectionOutcome,
    TLSUpgradeRequest,
)


@dataclass(frozen=True, slots=True)
class Lines:
    """Reply lines exactly as a server would frame them, without terminators."""

    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Failure:
    """The connection misbehaves instead of replying."""

    failure: TransportFailure


Response = Lines | Failure


@dataclass(frozen=True, slots=True)
class StageHang:
    """Where this peer stops answering and never answers again.

    A silent peer is the only way to measure that one awaited step is *enclosed*
    by the session deadline. A slow peer that eventually answers proves nothing:
    the step could be bounded by any other timeout, or by nothing at all, and the
    test would still pass. A peer that never answers finishes only if something
    interrupts the await, and inside the dialogue the only thing that can is
    `_Run._bounded`.

    Exactly one of the three is set. `occurrence` picks which `EHLO`, since the
    TLS path issues two.
    """

    #: Never return from the write of this command.
    write: SMTPCommand | None = None
    #: Never return from the first read of the reply to this command. `None`
    #: with `banner=True` means the greeting, which no command precedes.
    read_after: SMTPCommand | None = None
    #: Never return from the banner read.
    banner: bool = False
    #: Never return from the TLS handshake.
    handshake: bool = False
    occurrence: int = 1


async def _never_answers() -> object:
    """Wait for something that will not happen, and stay cancellable."""
    await asyncio.get_running_loop().create_future()
    raise AssertionError("unreachable: the future is never resolved")


def reply(*lines: str) -> Lines:
    """A reply written the way a server frames it: `250-first`, then `250 last`."""
    return Lines(values=tuple(lines))


def failure(kind: TransportFailure) -> Failure:
    return Failure(failure=kind)


#: The shapes `docs/test-strategy.md` section 3 asks for, named once so a test
#: reads as the scenario rather than as a string of digits.
BANNER_OK = reply("220 mx.test.example ESMTP ready")
BANNER_MULTILINE = reply("220-mx.test.example ESMTP ready", "220 be gentle")
BANNER_TEMPORARY = reply("421 service not available, closing channel")
BANNER_PERMANENT = reply("554 no SMTP service here")
BANNER_MALFORMED = reply("hello there")

EHLO_WITH_STARTTLS = reply(
    "250-mx.test.example at your service",
    "250-SIZE 35882577",
    "250-8BITMIME",
    "250-STARTTLS",
    "250 ENHANCEDSTATUSCODES",
)
EHLO_WITHOUT_STARTTLS = reply(
    "250-mx.test.example at your service",
    "250-SIZE 35882577",
    "250 ENHANCEDSTATUSCODES",
)
EHLO_TEMPORARY = reply("450 try again later")
EHLO_PERMANENT = reply("502 command not implemented")
#: A terminal line that is not a reply at all: the parser names it malformed.
EHLO_MALFORMED = reply("2x0 not a reply code")
#: A continuation with nothing after it. The server starts a multiline reply and
#: then says nothing, so this is a connection failure rather than a framing one.
EHLO_UNTERMINATED = reply("250-still talking")

STARTTLS_READY = reply("220 ready to start TLS")
STARTTLS_REFUSED = reply("454 TLS not available due to temporary reason")

MAIL_FROM_OK = reply("250 2.1.0 sender ok")
MAIL_FROM_TEMPORARY = reply("451 4.3.0 try later")
MAIL_FROM_REJECTED = reply("550 5.7.1 sender denied")

RCPT_ACCEPTED = reply("250 2.1.5 recipient ok")
RCPT_FORWARDED = reply("251 2.1.5 user not local; will forward")
RCPT_UNVERIFIABLE = reply("252 2.1.5 cannot verify user")
RCPT_TEMPORARY = reply("450 4.2.1 mailbox busy")
RCPT_GREYLISTED = reply("451 4.7.1 greylisted, try again")
RCPT_STORAGE_TEMPORARY = reply("452 4.2.2 insufficient storage")
RCPT_NO_SUCH_USER = reply("550 5.1.1 no such user")
RCPT_BARE_PERMANENT = reply("550 mailbox unavailable")
RCPT_POLICY = reply("550 5.7.1 policy rejection")
RCPT_USER_NOT_LOCAL = reply("551 5.1.6 user not local")
RCPT_STORAGE_PERMANENT = reply("552 5.2.2 mailbox full")
RCPT_BAD_MAILBOX = reply("553 5.1.3 bad recipient address syntax")
RCPT_TRANSACTION_FAILED = reply("554 5.0.0 transaction failed")
RCPT_MALFORMED = reply("2x0 not a reply code")
RCPT_ECHOES_THE_ADDRESS = reply("550 5.1.1 <probe.target@recipient.test.example> unknown")

CLEANUP_OK = reply("250 2.0.0 ok")
QUIT_OK = reply("221 2.0.0 bye")

#: One more line than the parser accepts.
TOO_MANY_LINES = reply(*[f"250-line {index}" for index in range(41)], "250 done")


@dataclass(slots=True)
class ScriptedSMTPPeer:
    """One connection to a server that answers from a script.

    `responses` maps a command to what the server says when it arrives. A list
    is consumed in order — `EHLO` is issued twice on the TLS path — and a single
    response is reused.
    """

    peer: PeerEndpoint
    banner: Response = BANNER_OK
    responses: dict[SMTPCommand, Response | list[Response]] = field(default_factory=dict)
    tls_outcome: TLSOutcome = field(default_factory=TLSNegotiated)
    write_failure_on: SMTPCommand | None = None
    write_failure: TransportFailure = TransportFailure.CONNECTION_RESET
    #: What a read gets once the script has nothing queued.
    exhausted: TransportFailure = TransportFailure.CONNECTION_CLOSED
    #: Where this peer goes silent, for the per-stage deadline matrix.
    hang: StageHang | None = None

    transcript: list[SMTPCommand] = field(default_factory=list)
    written: list[bytes] = field(default_factory=list)
    tls_requests: list[TLSUpgradeRequest] = field(default_factory=list)
    close_calls: int = 0
    _pending: deque[ReadOutcome] = field(default_factory=deque)
    _queues: dict[SMTPCommand, deque[Response]] = field(default_factory=dict)
    _tls_active: bool = False
    _started: bool = False
    #: How many times each command has been written, so `occurrence` can name
    #: the second `EHLO` of the TLS path.
    _issued: dict[SMTPCommand, int] = field(default_factory=dict)
    #: The command whose reply is currently being read, and how much of it has
    #: been read, so a hang lands on the first read of the group rather than on
    #: whichever line happens to be next.
    _group: SMTPCommand | None = None
    _group_reads: int = 0
    _group_occurrence: int = 0

    # --- the connection port ------------------------------------------------

    @property
    def tls_active(self) -> bool:
        return self._tls_active

    async def read_line(self) -> ReadOutcome:
        if self._hangs_on_read():
            await _never_answers()
        self._group_reads += 1
        if not self._started:
            self._started = True
            self._enqueue(self.banner)
        if not self._pending:
            return ReadFailed(failure=self.exhausted)
        return self._pending.popleft()

    async def write_command(self, command: WireCommand) -> WriteOutcome:
        if not isinstance(command, WireCommand):
            # The real connection refuses this. A double that accepts it lets a
            # test pass on a path production would refuse.
            raise SMTPContractError("write_command requires a WireCommand from the encoders")
        issued = self._issued.get(command.command, 0) + 1
        if self._hangs_on_write(command.command, issued):
            await _never_answers()
        if command.command is self.write_failure_on:
            return WriteFailed(failure=self.write_failure)
        self._issued[command.command] = issued
        self._group = command.command
        self._group_occurrence = issued
        self._group_reads = 0
        self.transcript.append(command.command)
        self.written.append(command.payload)
        self._enqueue(self._response_for(command.command))
        return WriteSucceeded(payload_bytes=len(command.payload))

    async def start_tls(self, request: TLSUpgradeRequest) -> TLSOutcome:
        if not isinstance(request, TLSUpgradeRequest):
            raise SMTPContractError("start_tls requires a TLSUpgradeRequest built from a peer")
        if self.hang is not None and self.hang.handshake:
            await _never_answers()
        self.tls_requests.append(request)
        if isinstance(self.tls_outcome, TLSNegotiated):
            self._tls_active = True
        return self.tls_outcome

    async def close(self) -> None:
        self.close_calls += 1

    @property
    def is_closed(self) -> bool:
        return self.close_calls > 0

    async def __aenter__(self) -> ScriptedSMTPPeer:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    # --- where it goes silent -----------------------------------------------

    def _hangs_on_read(self) -> bool:
        if self.hang is None:
            return False
        if self.hang.banner:
            return not self._started
        if self.hang.read_after is None:
            return False
        return (
            self._group is self.hang.read_after
            and self._group_reads == 0
            and self._group_occurrence == self.hang.occurrence
        )

    def _hangs_on_write(self, command: SMTPCommand, issued: int) -> bool:
        if self.hang is None or self.hang.write is None:
            return False
        return command is self.hang.write and issued == self.hang.occurrence

    # --- the script ---------------------------------------------------------

    def _response_for(self, command: SMTPCommand) -> Response | None:
        scripted = self.responses.get(command)
        if scripted is None:
            return None
        if isinstance(scripted, list):
            queue = self._queues.setdefault(command, deque(scripted))
            return queue.popleft() if queue else None
        return scripted

    def _enqueue(self, response: Response | None) -> None:
        if response is None:
            return
        if isinstance(response, Failure):
            self._pending.append(ReadFailed(failure=response.failure))
            return
        for line in response.values:
            self._pending.append(LineRead(line=line.encode("utf-8")))

    # --- what a test asserts afterwards ------------------------------------

    @property
    def recipient_commands(self) -> int:
        return sum(1 for command in self.transcript if command is SMTPCommand.RCPT_TO)

    def wire_text(self) -> str:
        """Every byte this peer was sent, for a transcript assertion."""
        return b"".join(self.written).decode("ascii", errors="replace")


@dataclass(slots=True)
class ScriptedSMTPTransport:
    """Hands out scripted peers. Records every destination it was asked for."""

    template: ScriptedSMTPPeer
    connect_calls: list[ApprovedDestination] = field(default_factory=list)
    connections: list[ScriptedSMTPPeer] = field(default_factory=list)
    connect_failure: TransportFailure | None = None

    async def connect(self, destination: ApprovedDestination) -> ConnectionOutcome:
        if not isinstance(destination, ApprovedDestination):
            raise SMTPContractError("connect requires an ApprovedDestination")
        self.connect_calls.append(destination)
        if self.connect_failure is not None:
            return ConnectionFailed(failure=self.connect_failure)
        connection = ScriptedSMTPPeer(
            peer=PeerEndpoint(address=destination.address, port=destination.port),
            banner=self.template.banner,
            responses=dict(self.template.responses),
            tls_outcome=self.template.tls_outcome,
            write_failure_on=self.template.write_failure_on,
            write_failure=self.template.write_failure,
            exhausted=self.template.exhausted,
            hang=self.template.hang,
        )
        self.connections.append(connection)
        return ConnectionOpened(connection=connection)

    @property
    def all_closed(self) -> bool:
        return all(connection.is_closed for connection in self.connections)


def plain_session_peer(peer: PeerEndpoint, rcpt: Response = RCPT_ACCEPTED) -> ScriptedSMTPPeer:
    """A server with no STARTTLS that accepts everything else."""
    return ScriptedSMTPPeer(
        peer=peer,
        banner=BANNER_OK,
        responses={
            SMTPCommand.EHLO: EHLO_WITHOUT_STARTTLS,
            SMTPCommand.MAIL_FROM: MAIL_FROM_OK,
            SMTPCommand.RCPT_TO: rcpt,
            SMTPCommand.RSET: CLEANUP_OK,
            SMTPCommand.QUIT: QUIT_OK,
        },
    )


def tls_session_peer(
    peer: PeerEndpoint,
    rcpt: Response = RCPT_ACCEPTED,
    tls_outcome: TLSOutcome | None = None,
    hang: StageHang | None = None,
) -> ScriptedSMTPPeer:
    """A server that advertises STARTTLS and re-greets after the upgrade."""
    return ScriptedSMTPPeer(
        peer=peer,
        banner=BANNER_OK,
        responses={
            SMTPCommand.EHLO: [EHLO_WITH_STARTTLS, EHLO_WITHOUT_STARTTLS],
            SMTPCommand.STARTTLS: STARTTLS_READY,
            SMTPCommand.MAIL_FROM: MAIL_FROM_OK,
            SMTPCommand.RCPT_TO: rcpt,
            SMTPCommand.RSET: CLEANUP_OK,
            SMTPCommand.QUIT: QUIT_OK,
        },
        tls_outcome=tls_outcome or TLSNegotiated(),
        hang=hang,
    )


def tls_failure(kind: TransportFailure) -> TLSFailed:
    return TLSFailed(failure=kind)
