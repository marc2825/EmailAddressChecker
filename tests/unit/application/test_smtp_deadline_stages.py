"""Every awaited step of the dialogue is *enclosed* by the session deadline.

The 4C review found the gap this file closes. Removing `_bounded` from the read
step, from the write step, or from the TLS handshake each left the whole suite
passing: the deadline tests drove a clock that advanced on every reading, so
whichever step ran next tripped the budget and the report looked identical. The
property held and nothing pinned it.

Two mechanisms, because neither alone is enough.

**A peer that goes silent.** For each stage a test hands the dialogue a peer that
never answers at that one point. A step that is bounded finishes; a step that is
not hangs forever. The clock is fake and never advances, so `remaining` is the
whole budget every time and the only thing that can end the await is the
`asyncio.timeout` inside `_bounded`. The outer bound in each test is what turns
a mutation into a failure rather than into a hung CI job.

**An inspection of the call sites.** Behaviour cannot see a step that no scenario
reaches, and a stage added later would arrive unbounded and untested. So the four
`await self.connection.…` sites are read out of the source and each one is
required to sit inside `self._bounded(...)`.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from dialogue_fixtures import (
    FakeMonotonicClock,
    address,
    identity_provider,
    peer_endpoint,
    session,
)
from emailcheck.application.smtp_dialogue import DialogueSettings, SMTPDialogue
from emailcheck.domain.smtp_contract import SMTPCommand
from emailcheck.domain.smtp_deadline import SessionBudget
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_result import RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSPolicy
from fake_smtp_server import ScriptedSMTPPeer, StageHang, tls_session_peer

pytestmark = pytest.mark.asyncio

#: Short enough that a bounded step ends promptly, long enough that it is a
#: deadline rather than a race. The clock is fake, so this is only ever handed to
#: `asyncio.timeout`; no test measures it against wall-clock work.
BUDGET_SECONDS = 0.05

#: What an unbounded step would exceed. A mutation that removes `_bounded` makes
#: the peer's silence permanent, and this is what converts that into a failing
#: test instead of a hung run.
OUTER_BOUND_SECONDS = 5.0

TLS_REQUIRED = DialogueSettings(
    tls_policy=TLSPolicy.REQUIRED,
    budget=SessionBudget(total_seconds=BUDGET_SECONDS),
)


async def run_until_the_budget_stops_it(peer: ScriptedSMTPPeer) -> SessionReport:
    """Run one dialogue against a peer that goes silent, and require it to end."""
    dialogue = SMTPDialogue(
        identity_provider=identity_provider(),
        clock=FakeMonotonicClock(),
        settings=TLS_REQUIRED,
    )
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        return await dialogue.run(peer, session(), address())  # type: ignore[arg-type]


def peer_silent_at(hang: StageHang) -> ScriptedSMTPPeer:
    return tls_session_peer(peer_endpoint(), hang=hang)


# --- the stages before the recipient result is in hand ---------------------

#: Every awaited step from the greeting to the recipient reply, with the stage
#: the report must name and how much of the transcript may exist by then. The
#: TLS path is used throughout because it is the longer one and contains the
#: plain path's steps as a prefix.
BEFORE_THE_ANSWER: list[tuple[str, StageHang, DialogueStage, tuple[SMTPCommand, ...]]] = [
    (
        "banner read",
        StageHang(banner=True),
        DialogueStage.BANNER,
        (),
    ),
    (
        "EHLO write",
        StageHang(write=SMTPCommand.EHLO),
        DialogueStage.EHLO,
        (),
    ),
    (
        "EHLO read",
        StageHang(read_after=SMTPCommand.EHLO),
        DialogueStage.EHLO,
        (SMTPCommand.EHLO,),
    ),
    (
        "STARTTLS write",
        StageHang(write=SMTPCommand.STARTTLS),
        DialogueStage.STARTTLS,
        (SMTPCommand.EHLO,),
    ),
    (
        "STARTTLS reply read",
        StageHang(read_after=SMTPCommand.STARTTLS),
        DialogueStage.STARTTLS,
        (SMTPCommand.EHLO, SMTPCommand.STARTTLS),
    ),
    (
        "TLS handshake",
        StageHang(handshake=True),
        DialogueStage.TLS_HANDSHAKE,
        (SMTPCommand.EHLO, SMTPCommand.STARTTLS),
    ),
    (
        "post-TLS EHLO write",
        StageHang(write=SMTPCommand.EHLO, occurrence=2),
        DialogueStage.EHLO_AFTER_TLS,
        (SMTPCommand.EHLO, SMTPCommand.STARTTLS),
    ),
    (
        "post-TLS EHLO read",
        StageHang(read_after=SMTPCommand.EHLO, occurrence=2),
        DialogueStage.EHLO_AFTER_TLS,
        (SMTPCommand.EHLO, SMTPCommand.STARTTLS, SMTPCommand.EHLO),
    ),
    (
        "MAIL FROM write",
        StageHang(write=SMTPCommand.MAIL_FROM),
        DialogueStage.MAIL_FROM,
        (SMTPCommand.EHLO, SMTPCommand.STARTTLS, SMTPCommand.EHLO),
    ),
    (
        "MAIL FROM read",
        StageHang(read_after=SMTPCommand.MAIL_FROM),
        DialogueStage.MAIL_FROM,
        (
            SMTPCommand.EHLO,
            SMTPCommand.STARTTLS,
            SMTPCommand.EHLO,
            SMTPCommand.MAIL_FROM,
        ),
    ),
    (
        "RCPT TO write",
        StageHang(write=SMTPCommand.RCPT_TO),
        DialogueStage.RCPT_TO,
        (
            SMTPCommand.EHLO,
            SMTPCommand.STARTTLS,
            SMTPCommand.EHLO,
            SMTPCommand.MAIL_FROM,
        ),
    ),
    (
        "RCPT TO read",
        StageHang(read_after=SMTPCommand.RCPT_TO),
        DialogueStage.RCPT_TO,
        (
            SMTPCommand.EHLO,
            SMTPCommand.STARTTLS,
            SMTPCommand.EHLO,
            SMTPCommand.MAIL_FROM,
            SMTPCommand.RCPT_TO,
        ),
    ),
]


@pytest.mark.parametrize(
    ("hang", "stage", "transcript"),
    [(hang, stage, transcript) for _label, hang, stage, transcript in BEFORE_THE_ANSWER],
    ids=[label for label, _hang, _stage, _transcript in BEFORE_THE_ANSWER],
)
async def test_a_silent_peer_at_one_stage_is_stopped_by_the_session_budget(
    hang: StageHang, stage: DialogueStage, transcript: tuple[SMTPCommand, ...]
) -> None:
    """The one awaited step of this stage runs inside the remaining budget.

    Nothing else can end it. The peer never answers, the fake clock never moves
    so no later step can notice the budget on this one's behalf, and the scripted
    connection has no timeout of its own.
    """
    peer = peer_silent_at(hang)

    report = await run_until_the_budget_stops_it(peer)

    assert report.deadline_exhausted is True
    assert report.stage_reached is stage
    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR
    assert report.observation.is_about_the_target is False
    assert report.commands_issued == transcript
    assert tuple(peer.transcript) == transcript


# --- the cleanup, where the answer is already in hand ----------------------

AFTER_THE_ANSWER: list[tuple[str, StageHang, tuple[SMTPCommand, ...]]] = [
    (
        "RSET write",
        StageHang(write=SMTPCommand.RSET),
        (),
    ),
    (
        "RSET reply read",
        StageHang(read_after=SMTPCommand.RSET),
        (SMTPCommand.RSET,),
    ),
    (
        "QUIT write",
        StageHang(write=SMTPCommand.QUIT),
        (SMTPCommand.RSET,),
    ),
    (
        "QUIT reply read",
        StageHang(read_after=SMTPCommand.QUIT),
        (SMTPCommand.RSET, SMTPCommand.QUIT),
    ),
]

RECIPIENT_STAGE_TRANSCRIPT = (
    SMTPCommand.EHLO,
    SMTPCommand.STARTTLS,
    SMTPCommand.EHLO,
    SMTPCommand.MAIL_FROM,
    SMTPCommand.RCPT_TO,
)


@pytest.mark.parametrize(
    ("hang", "cleanup_commands"),
    [(hang, commands) for _label, hang, commands in AFTER_THE_ANSWER],
    ids=[label for label, _hang, _commands in AFTER_THE_ANSWER],
)
async def test_a_silent_peer_during_cleanup_is_stopped_without_losing_the_answer(
    hang: StageHang, cleanup_commands: tuple[SMTPCommand, ...]
) -> None:
    """Cleanup is bounded too, and being cut short changes no observation.

    `docs/smtp-state-machine.md` section 7: by the time `RSET` is issued the
    recipient result is in hand, so a courtesy command that never completes must
    cost the budget and nothing else.
    """
    peer = peer_silent_at(hang)

    report = await run_until_the_budget_stops_it(peer)

    assert report.deadline_exhausted is True
    assert report.stage_reached is DialogueStage.CLEANUP
    assert report.cleanup is CleanupStatus.INCOMPLETE
    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert report.observation.basic_code == 250
    assert report.commands_issued == RECIPIENT_STAGE_TRANSCRIPT + cleanup_commands


async def test_every_named_stage_is_covered_exactly_once() -> None:
    """The matrix is the specification, so it may not quietly lose an entry."""
    labels = [label for label, *_ in BEFORE_THE_ANSWER] + [label for label, *_ in AFTER_THE_ANSWER]
    assert len(labels) == len(set(labels))
    assert labels == [
        "banner read",
        "EHLO write",
        "EHLO read",
        "STARTTLS write",
        "STARTTLS reply read",
        "TLS handshake",
        "post-TLS EHLO write",
        "post-TLS EHLO read",
        "MAIL FROM write",
        "MAIL FROM read",
        "RCPT TO write",
        "RCPT TO read",
        "RSET write",
        "RSET reply read",
        "QUIT write",
        "QUIT reply read",
    ]


# --- the call sites, read out of the source --------------------------------

DIALOGUE_SOURCE = (
    Path(__file__).resolve().parents[3] / "src" / "emailcheck" / "application" / "smtp_dialogue.py"
)


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    found: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            found[id(child)] = node
    return found


def _is_bounded_call(node: ast.AST) -> bool:
    """Whether `node` is the `self._bounded(...)` call that encloses a step."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_bounded"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )


def _connection_calls(tree: ast.AST) -> list[tuple[str, int, ast.Call]]:
    """Every `self.connection.<method>(...)` in the dialogue."""
    found: list[tuple[str, int, ast.Call]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = node.func
        if (
            isinstance(called, ast.Attribute)
            and isinstance(called.value, ast.Attribute)
            and called.value.attr == "connection"
            and isinstance(called.value.value, ast.Name)
            and called.value.value.id == "self"
        ):
            found.append((called.attr, node.lineno, node))
    return found


async def test_every_connection_call_sits_inside_the_deadline_wrapper() -> None:
    """A step the matrix above has not thought of still cannot be unbounded.

    The behavioural tests can only bound the steps a scenario reaches. This reads
    the source instead, so a step added in a later gate arrives bounded or fails
    here.
    """
    tree = ast.parse(DIALOGUE_SOURCE.read_text(encoding="utf-8"))
    parents = _parents(tree)
    calls = _connection_calls(tree)

    assert {method for method, _line, _node in calls} == {
        "read_line",
        "write_command",
        "start_tls",
    }
    assert len(calls) >= 4, "the four awaited I/O sites of the dialogue"

    unbounded = [
        f"{method} at line {line}"
        for method, line, node in calls
        if not _is_bounded_call(parents[id(node)])
    ]
    assert unbounded == [], f"connection calls outside the session deadline: {unbounded}"


async def test_the_wrapper_itself_still_bounds_what_it_is_given() -> None:
    """`_bounded` has to contain the timeout, or wrapping a call means nothing."""
    tree = ast.parse(DIALOGUE_SOURCE.read_text(encoding="utf-8"))
    bounded = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_bounded"
    ]
    assert len(bounded) == 1

    timeouts = [
        item
        for node in ast.walk(bounded[0])
        if isinstance(node, ast.AsyncWith)
        for item in node.items
        if isinstance(item.context_expr, ast.Call)
        and isinstance(item.context_expr.func, ast.Attribute)
        and item.context_expr.func.attr == "timeout"
    ]
    assert len(timeouts) == 1, "the awaited step runs inside asyncio.timeout"

    awaits_inside = [
        node
        for outer in ast.walk(bounded[0])
        if isinstance(outer, ast.AsyncWith)
        for node in ast.walk(outer)
        if isinstance(node, ast.Await)
    ]
    assert awaits_inside, "the await is inside the timeout, not beside it"
