"""The dialogue, against a scripted peer that opens no socket.

Two things are being checked throughout, and they pull in opposite directions.

**What is said.** The transcript must be exactly the six-command vocabulary, in
the right order, with one `RCPT TO` and no forbidden verb anywhere. Those are
the product promises in `docs/requirements.md` section 2.

**What is concluded.** Nothing. A `250` produces `ACCEPTED`, a `550` produces
`REJECTED`, and neither is a status. `550 5.1.1` gets no special treatment here
either: `docs/status-model.md` section 4 gives Phase 5 that job, with the DNS
and passive evidence in front of it.
"""

from __future__ import annotations

import asyncio

import pytest

from dialogue_fixtures import (
    AdvancingClock,
    FakeMonotonicClock,
    address,
    identity_provider,
    peer_endpoint,
    session,
)
from emailcheck.application.smtp_dialogue import (
    NEVER_A_SESSION_FAILURE,
    DialogueSettings,
    SMTPDialogue,
)
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError, SMTPState
from emailcheck.domain.smtp_deadline import SessionBudget
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage
from emailcheck.domain.smtp_reply import ReplyDefect
from emailcheck.domain.smtp_result import RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSFailureReason, TLSPolicy
from emailcheck.domain.smtp_transport import TLSFailed, TransportFailure
from fake_smtp_server import (
    BANNER_MALFORMED,
    BANNER_MULTILINE,
    BANNER_OK,
    BANNER_PERMANENT,
    BANNER_TEMPORARY,
    CLEANUP_OK,
    EHLO_MALFORMED,
    EHLO_PERMANENT,
    EHLO_TEMPORARY,
    EHLO_UNTERMINATED,
    EHLO_WITH_STARTTLS,
    EHLO_WITHOUT_STARTTLS,
    MAIL_FROM_OK,
    MAIL_FROM_REJECTED,
    MAIL_FROM_TEMPORARY,
    QUIT_OK,
    RCPT_ACCEPTED,
    RCPT_BARE_PERMANENT,
    RCPT_ECHOES_THE_ADDRESS,
    RCPT_FORWARDED,
    RCPT_GREYLISTED,
    RCPT_MALFORMED,
    RCPT_NO_SUCH_USER,
    RCPT_POLICY,
    RCPT_STORAGE_PERMANENT,
    RCPT_STORAGE_TEMPORARY,
    RCPT_TEMPORARY,
    RCPT_UNVERIFIABLE,
    STARTTLS_READY,
    STARTTLS_REFUSED,
    TOO_MANY_LINES,
    Response,
    ScriptedSMTPPeer,
    failure,
    plain_session_peer,
    reply,
    tls_session_peer,
)

pytestmark = pytest.mark.asyncio

TLS_SETTINGS = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)
REQUIRE_TLS = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)


def dialogue(
    settings: DialogueSettings = TLS_SETTINGS, clock: object | None = None
) -> SMTPDialogue:
    return SMTPDialogue(
        identity_provider=identity_provider(),
        clock=clock or FakeMonotonicClock(),  # type: ignore[arg-type]
        settings=settings,
    )


async def run(
    peer: ScriptedSMTPPeer, settings: DialogueSettings = TLS_SETTINGS, clock: object = None
):  # type: ignore[no-untyped-def]
    return await dialogue(settings, clock).run(peer, session(), address())  # type: ignore[arg-type]


# --- the default TLS path --------------------------------------------------


async def test_a_verified_tls_session_reaches_the_recipient_stage() -> None:
    peer = tls_session_peer(peer_endpoint())
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert report.observation.basic_code == 250
    assert report.stage_reached is DialogueStage.CLEANUP
    assert report.tls.negotiated is True
    assert report.cleanup is CleanupStatus.COMPLETED
    assert report.observation.no_message_data_sent is True


async def test_the_default_transcript_includes_verified_tls() -> None:
    """`docs/smtp-state-machine.md` section 7: the sequence is asserted, not reviewed."""
    peer = tls_session_peer(peer_endpoint())
    report = await run(peer)

    assert peer.transcript == [
        SMTPCommand.EHLO,
        SMTPCommand.STARTTLS,
        SMTPCommand.EHLO,
        SMTPCommand.MAIL_FROM,
        SMTPCommand.RCPT_TO,
        SMTPCommand.RSET,
        SMTPCommand.QUIT,
    ]
    assert report.commands_issued == tuple(peer.transcript)


async def test_a_multiline_banner_is_one_greeting() -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.banner = BANNER_MULTILINE
    report = await run(peer)
    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED


# --- the TLS path ----------------------------------------------------------


async def test_a_tls_session_upgrades_and_re_introduces_itself() -> None:
    peer = tls_session_peer(peer_endpoint())
    report = await run(peer, REQUIRE_TLS)

    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert report.tls.negotiated is True
    assert report.observation.tls_used is True
    assert report.cleanup is CleanupStatus.COMPLETED


async def test_the_tls_transcript_re_issues_ehlo_after_the_handshake() -> None:
    peer = tls_session_peer(peer_endpoint())
    await run(peer, REQUIRE_TLS)

    assert peer.transcript == [
        SMTPCommand.EHLO,
        SMTPCommand.STARTTLS,
        SMTPCommand.EHLO,
        SMTPCommand.MAIL_FROM,
        SMTPCommand.RCPT_TO,
        SMTPCommand.RSET,
        SMTPCommand.QUIT,
    ]


async def test_the_handshake_is_asked_for_on_the_confirmed_peer() -> None:
    """The SNI name is the MX host from the destination chain, never the target."""
    peer = tls_session_peer(peer_endpoint())
    await run(peer, REQUIRE_TLS)

    (request,) = peer.tls_requests
    assert request.server_hostname == "mx.test.example"
    assert request.server_hostname != address().domain.ascii_form
    assert request.peer.peer_address == peer.peer.address


async def test_nothing_is_written_before_the_banner_arrives() -> None:
    """A greeting that never comes must not be answered."""
    peer = ScriptedSMTPPeer(peer=peer_endpoint(), banner=failure(TransportFailure.READ_TIMEOUT))
    report = await run(peer)

    assert peer.transcript == []
    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR


# --- TLS policy ------------------------------------------------------------


async def test_a_server_without_starttls_ends_a_required_tls_probe() -> None:
    peer = plain_session_peer(peer_endpoint())
    report = await run(peer, REQUIRE_TLS)

    assert report.observation.outcome is RecipientStageOutcome.TLS_ERROR
    assert report.tls.reason is TLSFailureReason.NOT_OFFERED
    assert report.stage_reached is DialogueStage.STARTTLS
    assert peer.transcript == [SMTPCommand.EHLO]


async def test_a_server_without_starttls_is_never_an_invalid_mailbox() -> None:
    """The property that matters most about the conservative default.

    Requiring TLS produces `unknown` for a server that offers none. It must
    never produce anything about the address, and the taxonomy is what enforces
    that rather than this module's care.
    """
    report = await run(plain_session_peer(peer_endpoint()), REQUIRE_TLS)

    assert report.observation.is_about_the_target is False
    assert report.tls.is_about_the_target is False
    assert report.observation.outcome is not RecipientStageOutcome.REJECTED


async def test_an_opportunistic_policy_cannot_be_configured() -> None:
    with pytest.raises(SMTPContractError):
        DialogueSettings(tls_policy="opportunistic")  # type: ignore[arg-type]


async def test_the_default_policy_requires_tls() -> None:
    """Stated as a test because the default is the decision."""
    assert DialogueSettings().tls_policy is TLSPolicy.REQUIRED


@pytest.mark.parametrize("policy", list(TLSPolicy))
async def test_a_failed_handshake_never_falls_back_to_plaintext(policy: TLSPolicy) -> None:
    """Every supported policy stops before the sender on handshake failure."""
    peer = tls_session_peer(
        peer_endpoint(), tls_outcome=TLSFailed(failure=TransportFailure.TLS_HANDSHAKE_FAILED)
    )
    report = await run(peer, DialogueSettings(tls_policy=policy))

    assert report.observation.outcome is RecipientStageOutcome.TLS_ERROR
    assert SMTPCommand.MAIL_FROM not in peer.transcript
    assert SMTPCommand.RCPT_TO not in peer.transcript
    assert report.observation.final_state is SMTPState.FAILED


async def test_a_rejected_starttls_command_ends_the_probe() -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.STARTTLS] = STARTTLS_REFUSED
    report = await run(peer, REQUIRE_TLS)

    assert report.observation.outcome is RecipientStageOutcome.TLS_ERROR
    assert report.tls.reason is TLSFailureReason.COMMAND_REJECTED
    assert peer.transcript == [SMTPCommand.EHLO, SMTPCommand.STARTTLS]


@pytest.mark.parametrize(
    ("transport_failure", "expected"),
    [
        (TransportFailure.TLS_CERTIFICATE_INVALID, TLSFailureReason.CERTIFICATE_INVALID),
        (TransportFailure.TLS_HOSTNAME_MISMATCH, TLSFailureReason.HOSTNAME_MISMATCH),
        (TransportFailure.TLS_TIMEOUT, TLSFailureReason.TIMEOUT),
        (TransportFailure.TLS_PEER_CHANGED, TLSFailureReason.PEER_CHANGED),
        (TransportFailure.TLS_HANDSHAKE_FAILED, TLSFailureReason.HANDSHAKE_FAILED),
        (TransportFailure.CONNECTION_RESET, TLSFailureReason.HANDSHAKE_FAILED),
    ],
)
async def test_every_handshake_failure_is_named_and_none_is_about_the_target(
    transport_failure: TransportFailure, expected: TLSFailureReason
) -> None:
    peer = tls_session_peer(peer_endpoint(), tls_outcome=TLSFailed(failure=transport_failure))
    report = await run(peer, REQUIRE_TLS)

    assert report.tls.reason is expected
    assert report.observation.is_about_the_target is False


async def test_a_post_tls_ehlo_failure_ends_the_probe() -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.EHLO] = [EHLO_WITH_STARTTLS, EHLO_PERMANENT]
    report = await run(peer, REQUIRE_TLS)

    assert report.stage_reached is DialogueStage.EHLO_AFTER_TLS
    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR
    assert SMTPCommand.MAIL_FROM not in peer.transcript


# --- failures before the recipient stage -----------------------------------


@pytest.mark.parametrize(
    ("banner", "expected_outcome", "label"),
    [
        (BANNER_TEMPORARY, RecipientStageOutcome.CONNECTION_ERROR, "a 421 greeting"),
        (BANNER_PERMANENT, RecipientStageOutcome.CONNECTION_ERROR, "a 554 greeting"),
        (BANNER_MALFORMED, RecipientStageOutcome.PROTOCOL_ERROR, "not a reply at all"),
        (failure(TransportFailure.READ_TIMEOUT), RecipientStageOutcome.CONNECTION_ERROR, "silence"),
        (
            failure(TransportFailure.CONNECTION_CLOSED),
            RecipientStageOutcome.CONNECTION_ERROR,
            "EOF",
        ),
        (
            failure(TransportFailure.CONNECTION_RESET),
            RecipientStageOutcome.CONNECTION_ERROR,
            "reset",
        ),
        (
            failure(TransportFailure.LINE_TOO_LONG),
            RecipientStageOutcome.CONNECTION_ERROR,
            "an oversized greeting",
        ),
        (TOO_MANY_LINES, RecipientStageOutcome.PROTOCOL_ERROR, "too many lines"),
    ],
)
async def test_an_unusable_banner_stops_the_dialogue(
    banner: Response, expected_outcome: RecipientStageOutcome, label: str
) -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.banner = banner
    report = await run(peer)

    assert report.observation.outcome is expected_outcome, label
    assert report.observation.is_about_the_target is False
    assert peer.transcript == [], "a command was written after the banner failed"
    assert report.stage_reached is DialogueStage.BANNER


@pytest.mark.parametrize(
    ("response", "expected", "label"),
    [
        (EHLO_TEMPORARY, RecipientStageOutcome.CONNECTION_ERROR, "a 450"),
        (EHLO_PERMANENT, RecipientStageOutcome.CONNECTION_ERROR, "a 502"),
        (EHLO_MALFORMED, RecipientStageOutcome.PROTOCOL_ERROR, "not a reply code"),
        (
            EHLO_UNTERMINATED,
            RecipientStageOutcome.CONNECTION_ERROR,
            "a multiline reply the server never finished",
        ),
        (
            failure(TransportFailure.CONNECTION_CLOSED),
            RecipientStageOutcome.CONNECTION_ERROR,
            "EOF",
        ),
        (
            failure(TransportFailure.CONNECTION_RESET),
            RecipientStageOutcome.CONNECTION_ERROR,
            "reset",
        ),
    ],
)
async def test_an_ehlo_failure_stops_before_mail_from(
    response: Response, expected: RecipientStageOutcome, label: str
) -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.EHLO] = response
    report = await run(peer)

    assert report.observation.outcome is expected, label
    assert report.stage_reached is DialogueStage.EHLO
    assert peer.transcript == [SMTPCommand.EHLO]
    assert report.observation.recipients_attempted == 0


async def test_there_is_no_helo_fallback() -> None:
    """`HELO` is not in the closed set, so a refused `EHLO` ends the session.

    A fallback would be a seventh command, and there is no encoder, no enum
    member, and no state that permits one.
    """
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.EHLO] = EHLO_PERMANENT
    await run(peer)

    assert peer.wire_text().count("EHLO") == 1
    assert "HELO " not in peer.wire_text().replace("EHLO ", "")


@pytest.mark.parametrize(
    ("response", "label"),
    [
        (MAIL_FROM_TEMPORARY, "a 451"),
        (MAIL_FROM_REJECTED, "a 550 policy rejection of the sender"),
        (failure(TransportFailure.CONNECTION_CLOSED), "a disconnect after MAIL FROM"),
    ],
)
async def test_a_mail_from_failure_produces_no_recipient_observation(
    response: Response, label: str
) -> None:
    """`docs/requirements.md` section 9: a sender rejection is not the target's."""
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.MAIL_FROM] = response
    report = await run(peer)

    assert report.stage_reached is DialogueStage.MAIL_FROM, label
    assert report.observation.is_about_the_target is False
    assert report.observation.recipients_attempted == 0
    assert SMTPCommand.RCPT_TO not in peer.transcript


# --- the recipient stage ---------------------------------------------------


@pytest.mark.parametrize(
    ("response", "expected", "code"),
    [
        (RCPT_ACCEPTED, RecipientStageOutcome.ACCEPTED, 250),
        (RCPT_FORWARDED, RecipientStageOutcome.ACCEPTED, 251),
        (RCPT_UNVERIFIABLE, RecipientStageOutcome.ACCEPTED, 252),
        (RCPT_TEMPORARY, RecipientStageOutcome.TEMPORARY_FAILURE, 450),
        (RCPT_GREYLISTED, RecipientStageOutcome.TEMPORARY_FAILURE, 451),
        (RCPT_STORAGE_TEMPORARY, RecipientStageOutcome.TEMPORARY_FAILURE, 452),
        (RCPT_NO_SUCH_USER, RecipientStageOutcome.REJECTED, 550),
        (RCPT_BARE_PERMANENT, RecipientStageOutcome.REJECTED, 550),
        (RCPT_POLICY, RecipientStageOutcome.REJECTED, 550),
        (RCPT_STORAGE_PERMANENT, RecipientStageOutcome.REJECTED, 552),
    ],
)
async def test_every_recipient_reply_becomes_an_observation(
    response: Response, expected: RecipientStageOutcome, code: int
) -> None:
    peer = tls_session_peer(peer_endpoint(), rcpt=response)
    report = await run(peer)

    assert report.observation.outcome is expected
    assert report.observation.basic_code == code
    assert report.observation.recipients_attempted == 1


async def test_no_reply_code_becomes_a_status() -> None:
    """The invariant this Phase exists under, asserted rather than assumed."""
    accepted = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_ACCEPTED))
    rejected = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_NO_SUCH_USER))

    for report in (accepted, rejected):
        rendered = repr(report) + repr(report.summary)
        for status in ("likely_deliverable", "temporary_unknown", "invalid", "verdict"):
            assert status not in rendered


async def test_a_bare_550_and_an_explicit_5_1_1_are_recorded_the_same_way_here() -> None:
    """Distinguishing them is Phase 4D's job; both are `REJECTED` observations.

    What differs is the enhanced code, which is carried so 4D can use it. What
    must not differ is any conclusion drawn here.
    """
    bare = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_BARE_PERMANENT))
    explicit = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_NO_SUCH_USER))

    assert bare.observation.outcome is explicit.observation.outcome
    assert bare.observation.enhanced_code is None
    assert explicit.observation.enhanced_code == "5.1.1"


async def test_a_252_keeps_everything_phase_4d_needs_to_refuse_it() -> None:
    """`252` shares an observation with `250`, and must not share a conclusion.

    `docs/status-model.md` puts `252` under `unknown` — the server said it will
    not verify the recipient — while this layer records it as `ACCEPTED`, which
    means only "the command was answered in the 2xx class". The whole reason that
    is safe is that the basic code survives, so 4D can separate them; the whole
    reason it is dangerous is that `outcome` and `is_about_the_target` alone
    cannot. Both halves are pinned here.
    """
    unverifiable = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_UNVERIFIABLE))
    accepted = await run(tls_session_peer(peer_endpoint(), rcpt=RCPT_ACCEPTED))

    assert unverifiable.observation.basic_code == 252
    assert unverifiable.observation.enhanced_code == "2.1.5"
    assert unverifiable.summary["basic_code"] == 252

    # Indistinguishable on the derived fields alone. A Phase 4D mapping written
    # against `outcome` or `is_about_the_target` would call a refusal to verify
    # an acceptance, which is why `docs/status-model.md` requires the basic code
    # to be branched on first.
    assert unverifiable.observation.outcome is accepted.observation.outcome
    assert unverifiable.observation.is_about_the_target is True

    # And still no verdict anywhere: 4D has not happened yet.
    rendered = repr(unverifiable) + repr(unverifiable.summary)
    for vocabulary in ("unknown", "rcpt_unverifiable", "likely_deliverable", "confidence"):
        assert vocabulary not in rendered


async def test_a_malformed_recipient_reply_is_a_protocol_error() -> None:
    peer = tls_session_peer(peer_endpoint(), rcpt=RCPT_MALFORMED)
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.PROTOCOL_ERROR
    assert report.observation.defect is ReplyDefect.MALFORMED_LINE
    assert report.observation.is_about_the_target is False


async def test_exactly_one_recipient_is_ever_offered() -> None:
    peer = tls_session_peer(peer_endpoint(), rcpt=RCPT_NO_SUCH_USER)
    report = await run(peer)

    assert peer.recipient_commands == 1
    assert report.observation.recipients_attempted == 1
    assert peer.wire_text().count("RCPT TO:") == 1


async def test_the_submitted_address_is_probed_unchanged() -> None:
    """No plus-tag removal, no case normalisation, no alternate spelling."""
    submitted = address("Mixed.Case+tag@recipient.test.example")
    peer = tls_session_peer(peer_endpoint())
    await dialogue().run(peer, session(), submitted)

    assert "RCPT TO:<Mixed.Case+tag@recipient.test.example>" in peer.wire_text()


# --- privacy ---------------------------------------------------------------


async def test_a_reply_that_echoes_the_recipient_does_not_keep_it() -> None:
    """`docs/requirements.md` section 16: no complete address in what is kept."""
    peer = tls_session_peer(peer_endpoint(), rcpt=RCPT_ECHOES_THE_ADDRESS)
    report = await run(peer)

    rendered = repr(report) + repr(report.summary) + str(report.observation.reply)
    assert "probe.target@recipient.test.example" not in rendered
    assert "@" not in (report.observation.reply.diagnostic if report.observation.reply else "")


async def test_no_raw_reply_or_raw_command_survives_into_the_report() -> None:
    peer = tls_session_peer(peer_endpoint())
    report = await run(peer)

    rendered = repr(report) + repr(report.summary)
    # What may be kept is a *bounded, sanitized* diagnostic — `docs/status-model.md`
    # section 6 publishes exactly that. What may not be kept is a raw reply line
    # with its code, a wire command, or a terminator.
    assert "220 mx.test.example ESMTP ready" not in rendered, "the raw banner"
    assert "250-mx.test.example at your service" not in rendered, "a raw EHLO line"
    assert "RCPT TO:<" not in rendered, "a wire command line"
    assert "EHLO probe.sender" not in rendered, "a wire command line"
    assert "\\r\\n" not in rendered, "a wire terminator"

    diagnostic = report.observation.reply.diagnostic if report.observation.reply else ""
    assert "@" not in diagnostic
    assert len(diagnostic) <= 120


# --- cleanup ---------------------------------------------------------------


async def test_a_cleanup_failure_does_not_change_the_observation() -> None:
    peer = tls_session_peer(peer_endpoint(), rcpt=RCPT_ACCEPTED)
    peer.responses[SMTPCommand.RSET] = failure(TransportFailure.CONNECTION_RESET)
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert report.observation.basic_code == 250
    assert report.cleanup is CleanupStatus.INCOMPLETE


async def test_a_rejected_quit_is_recorded_and_nothing_else() -> None:
    peer = tls_session_peer(peer_endpoint(), rcpt=RCPT_NO_SUCH_USER)
    peer.responses[SMTPCommand.QUIT] = reply("554 5.0.0 no")
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.REJECTED
    assert report.cleanup is CleanupStatus.INCOMPLETE


async def test_cleanup_is_not_attempted_after_a_terminal_failure() -> None:
    """No command may be written once the connection has failed."""
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.MAIL_FROM] = failure(TransportFailure.CONNECTION_RESET)
    report = await run(peer)

    assert report.cleanup is CleanupStatus.NOT_ATTEMPTED
    assert SMTPCommand.RSET not in peer.transcript
    assert SMTPCommand.QUIT not in peer.transcript


async def test_rset_does_not_buy_a_second_recipient() -> None:
    peer = tls_session_peer(peer_endpoint())
    await run(peer)
    assert peer.recipient_commands == 1
    assert peer.transcript.index(SMTPCommand.RSET) > peer.transcript.index(SMTPCommand.RCPT_TO)


# --- the total session deadline --------------------------------------------


async def test_a_deadline_that_is_already_spent_writes_nothing() -> None:
    # The clock jumps a whole budget between starting the deadline and the first
    # step, so the budget is spent before anything could be written.
    clock = AdvancingClock(step=10.0)
    settings = DialogueSettings(
        tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
    )
    peer = tls_session_peer(peer_endpoint())
    report = await SMTPDialogue(
        identity_provider=identity_provider(), clock=clock, settings=settings
    ).run(peer, session(), address())

    assert peer.transcript == []
    assert report.deadline_exhausted is True
    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR
    assert report.observation.is_about_the_target is False


async def test_the_deadline_stops_a_session_part_way_through() -> None:
    """A peer answering every stage slowly still cannot hold a worker.

    The clock advances two seconds on every read, so a five-second budget runs
    out mid-dialogue no matter how fast the peer actually is.
    """
    clock = AdvancingClock(step=2.0)
    settings = DialogueSettings(
        tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
    )
    peer = tls_session_peer(peer_endpoint())
    report = await SMTPDialogue(
        identity_provider=identity_provider(), clock=clock, settings=settings
    ).run(peer, session(), address())

    assert report.deadline_exhausted is True
    assert report.observation.recipients_attempted <= 1
    assert peer.recipient_commands <= 1


async def test_a_budget_spent_at_the_cleanup_boundary_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`SKIPPED_DEADLINE` and `deadline_exhausted` describe one fact.

    The 4C review found them disagreeing: the budget ran out, the cleanup was
    skipped for exactly that reason, and the flag Phase 4D reads still said the
    deadline was fine. The clock here is tuned so the budget survives every step
    up to the recipient reply and is gone by the time cleanup is considered.
    """
    clock = FakeMonotonicClock()
    settings = DialogueSettings(
        tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
    )
    peer = tls_session_peer(peer_endpoint())
    original_read = ScriptedSMTPPeer.read_line

    async def expire_after_recipient(self: ScriptedSMTPPeer):  # type: ignore[no-untyped-def]
        result = await original_read(self)
        if self.transcript and self.transcript[-1] is SMTPCommand.RCPT_TO:
            clock.advance(settings.budget.total_seconds)
        return result

    monkeypatch.setattr(ScriptedSMTPPeer, "read_line", expire_after_recipient)
    report = await SMTPDialogue(
        identity_provider=identity_provider(), clock=clock, settings=settings
    ).run(peer, session(), address())

    assert report.cleanup is CleanupStatus.SKIPPED_DEADLINE
    assert report.deadline_exhausted is True
    # The answer was already in hand, so the cleanup being skipped changes it not
    # at all.
    assert report.observation.outcome is RecipientStageOutcome.ACCEPTED
    assert peer.transcript == [
        SMTPCommand.EHLO,
        SMTPCommand.STARTTLS,
        SMTPCommand.EHLO,
        SMTPCommand.MAIL_FROM,
        SMTPCommand.RCPT_TO,
    ]


async def test_an_externally_started_deadline_is_the_one_that_applies() -> None:
    """The probe service starts the budget before it connects, and hands it over.

    Without this the dialogue would start a fresh full budget of its own, which
    is how `connect_seconds` ended up outside the total.
    """
    from emailcheck.domain.smtp_deadline import start_deadline

    clock = FakeMonotonicClock()
    settings = DialogueSettings(
        tls_policy=TLSPolicy.REQUIRED, budget=SessionBudget(total_seconds=5.0)
    )
    # Started five seconds ago: nothing is left, and no fresh budget appears.
    spent = start_deadline(settings.budget, clock.monotonic() - 5.0)
    peer = tls_session_peer(peer_endpoint())

    report = await SMTPDialogue(
        identity_provider=identity_provider(), clock=clock, settings=settings
    ).run(peer, session(), address(), deadline=spent)

    assert peer.transcript == []
    assert report.deadline_exhausted is True
    assert report.observation.elapsed_milliseconds == 5000


async def test_the_deadline_is_a_validated_value() -> None:
    with pytest.raises(SMTPContractError):
        DialogueSettings(budget=SessionBudget(total_seconds=0))  # type: ignore[arg-type]
    with pytest.raises(SMTPContractError):
        DialogueSettings(tls_handshake_seconds=0)
    with pytest.raises(SMTPContractError):
        DialogueSettings(tls_handshake_seconds=float("inf"))
    with pytest.raises(SMTPContractError):
        DialogueSettings(tls_handshake_seconds=True)
    with pytest.raises(SMTPContractError):
        DialogueSettings(tls_policy="required")  # type: ignore[arg-type]

    # A handshake timeout larger than the budget is *not* an error: the budget
    # dominates it at run time, so requiring the two to agree by hand would be a
    # configuration chore that a small budget would fail on.
    settings = DialogueSettings(budget=SessionBudget(total_seconds=5.0), tls_handshake_seconds=10.0)
    assert settings.tls_handshake_seconds == 10.0


# --- cancellation ----------------------------------------------------------


async def test_the_re_raised_set_matches_the_transport() -> None:
    """One rule, defined twice, and asserted to be the same rule."""
    from emailcheck.adapters.smtp.asyncio_transport import _NEVER_A_TRANSPORT_FAILURE

    assert set(NEVER_A_SESSION_FAILURE) == set(_NEVER_A_TRANSPORT_FAILURE)
    assert set(NEVER_A_SESSION_FAILURE) == {
        asyncio.CancelledError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
        AssertionError,
    }


@pytest.mark.parametrize(
    "control", [asyncio.CancelledError(), KeyboardInterrupt(), SystemExit(1), AssertionError("x")]
)
async def test_process_control_is_never_converted_into_an_smtp_result(
    control: BaseException,
) -> None:
    """A cancelled worker must not be handed a fact about a mail server."""
    peer = _RaisingPeer(peer=peer_endpoint(), error=control)
    with pytest.raises(type(control)):
        await run(peer)  # type: ignore[arg-type]


async def test_a_bug_in_this_project_is_a_typed_internal_error() -> None:
    """Distinct from the above: a `RuntimeError` is a fact about the probe."""
    peer = _RaisingPeer(peer=peer_endpoint(), error=RuntimeError("boom"))
    report = await run(peer)  # type: ignore[arg-type]

    assert report.observation.outcome is RecipientStageOutcome.INTERNAL_ERROR
    assert report.observation.is_about_the_target is False


class _RaisingPeer(ScriptedSMTPPeer):
    """A peer whose first read raises, so the boundary can be exercised."""

    def __init__(self, peer, error: BaseException) -> None:  # type: ignore[no-untyped-def]
        super().__init__(peer=peer)
        self._error = error

    async def read_line(self):  # type: ignore[no-untyped-def]
        raise self._error


# --- what the session type refuses even if this module asks ----------------


async def test_a_session_handed_over_in_the_wrong_state_writes_nothing() -> None:
    """The second barrier behind the dialogue's ordering, exercised end to end.

    The dialogue is handed a session that has already reached the recipient
    stage, so its first `EHLO` is refused by the state machine. A `_permit`
    refusal is this project's bug, so the result is `INTERNAL_ERROR` — never
    something about the address — and no command reaches the wire.
    """
    from dialogue_fixtures import confirmed_peer
    from emailcheck.domain.smtp_session import SMTPSession

    peer = tls_session_peer(peer_endpoint())
    # `MAIL_FROM_ACCEPTED` permits `RCPT TO`, `RSET`, and `QUIT` — not `EHLO`,
    # which is the first thing the dialogue tries to issue.
    misplaced = SMTPSession(peer=confirmed_peer(), state=SMTPState.MAIL_FROM_ACCEPTED)
    report = await dialogue().run(peer, misplaced, address())

    assert report.observation.outcome is RecipientStageOutcome.INTERNAL_ERROR
    assert report.observation.is_about_the_target is False
    assert peer.transcript == []


async def test_the_state_machine_alone_refuses_a_second_recipient() -> None:
    """Pinned directly, because the dialogue offering one is a separate barrier.

    Two barriers are only two barriers while each is asserted on its own: the
    dialogue calls `RCPT TO` exactly once, *and* the session refuses a second
    from any state.
    """
    used = _session_that_already_probed()
    assert used.refusal(SMTPCommand.RCPT_TO) is not None
    assert SMTPCommand.RCPT_TO not in used.permitted_commands


def _session_that_already_probed():  # type: ignore[no-untyped-def]
    from dialogue_fixtures import confirmed_peer
    from emailcheck.domain.smtp_session import CommandPermitted, SMTPSession

    started = SMTPSession(peer=confirmed_peer(), state=SMTPState.MAIL_FROM_ACCEPTED)
    issued = started.issue(SMTPCommand.RCPT_TO)
    assert isinstance(issued, CommandPermitted)
    return issued.session


@pytest.mark.parametrize(
    "command",
    [SMTPCommand.EHLO, SMTPCommand.MAIL_FROM, SMTPCommand.RCPT_TO],
)
async def test_a_write_that_fails_ends_the_dialogue_at_that_stage(
    command: SMTPCommand,
) -> None:
    """A command that never reached the wire is not in the transcript either."""
    peer = tls_session_peer(peer_endpoint())
    peer.write_failure_on = command
    report = await run(peer, REQUIRE_TLS)

    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR
    assert command not in peer.transcript
    assert report.observation.is_about_the_target is False


@pytest.mark.parametrize(
    "stage_response",
    [SMTPCommand.EHLO, SMTPCommand.STARTTLS, SMTPCommand.MAIL_FROM, SMTPCommand.RCPT_TO],
)
@pytest.mark.parametrize(
    "kind",
    [
        TransportFailure.CONNECTION_CLOSED,
        TransportFailure.CONNECTION_RESET,
        TransportFailure.READ_TIMEOUT,
        TransportFailure.LINE_TOO_LONG,
        TransportFailure.TOTAL_LIMIT_EXCEEDED,
    ],
)
async def test_a_connection_failure_at_any_stage_is_never_about_the_target(
    stage_response: SMTPCommand, kind: TransportFailure
) -> None:
    """EOF, reset, silence, and both read caps, at every stage that reads."""
    peer = tls_session_peer(peer_endpoint())
    peer.responses[stage_response] = failure(kind)
    report = await run(peer, REQUIRE_TLS)

    assert report.observation.is_about_the_target is False
    assert report.observation.outcome in {
        RecipientStageOutcome.CONNECTION_ERROR,
        RecipientStageOutcome.TLS_ERROR,
    }
    assert peer.recipient_commands <= 1


async def test_an_oversized_recipient_reply_is_not_a_rejection() -> None:
    """A read cap firing says nothing about the mailbox."""
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.RCPT_TO] = failure(TransportFailure.LINE_TOO_LONG)
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.CONNECTION_ERROR
    assert report.observation.outcome is not RecipientStageOutcome.REJECTED
    assert report.observation.is_about_the_target is False


async def test_a_reply_with_too_many_lines_is_a_protocol_error() -> None:
    peer = tls_session_peer(peer_endpoint())
    peer.responses[SMTPCommand.RCPT_TO] = TOO_MANY_LINES
    report = await run(peer)

    assert report.observation.outcome is RecipientStageOutcome.PROTOCOL_ERROR
    assert report.observation.defect is ReplyDefect.TOO_MANY_LINES


async def test_the_scripted_peer_refuses_anything_but_a_wire_command() -> None:
    """The double is not more permissive than the connection it stands in for."""
    peer = tls_session_peer(peer_endpoint())
    for value in (b"EHLO x\r\n", "EHLO x\r\n", None):
        with pytest.raises(SMTPContractError):
            await peer.write_command(value)  # type: ignore[arg-type]


# --- the fixtures themselves -----------------------------------------------


async def test_the_scripted_server_answers_only_what_it_was_asked() -> None:
    """The transcript is driven by the dialogue, not replayed from a tape."""
    peer = ScriptedSMTPPeer(
        peer=peer_endpoint(),
        banner=BANNER_OK,
        responses={
            SMTPCommand.EHLO: EHLO_WITHOUT_STARTTLS,
            SMTPCommand.MAIL_FROM: MAIL_FROM_OK,
            SMTPCommand.RCPT_TO: RCPT_ACCEPTED,
            SMTPCommand.RSET: CLEANUP_OK,
            SMTPCommand.QUIT: QUIT_OK,
            SMTPCommand.STARTTLS: STARTTLS_READY,
        },
    )
    report = await run(peer)
    assert SMTPCommand.STARTTLS not in peer.transcript
    assert peer.transcript == [SMTPCommand.EHLO]
    assert report.observation.outcome is RecipientStageOutcome.TLS_ERROR


# --- the sender is the operator's, and the target is only ever the recipient -


async def test_the_envelope_sender_is_the_configured_one() -> None:
    """`docs/threat-model.md`, "sender identity misuse", asserted on the wire.

    A mutation that built `MAIL FROM` from the probe target passed every other
    test in this file: nothing else looks at what the command actually carried.
    This does.
    """
    peer = tls_session_peer(peer_endpoint())
    await run(peer)
    text = peer.wire_text()

    assert "MAIL FROM:<verify@sender.test.example>" in text
    assert "MAIL FROM:<probe.target@recipient.test.example>" not in text
    assert "MAIL FROM:<>" not in text, "the null reverse path is not configurable"


async def test_the_target_appears_once_and_only_as_the_recipient() -> None:
    """It is the thing being asked about, not the thing this project claims to be."""
    peer = tls_session_peer(peer_endpoint())
    await run(peer)
    text = peer.wire_text()

    assert text.count("probe.target@recipient.test.example") == 1
    assert "RCPT TO:<probe.target@recipient.test.example>" in text


async def test_the_ehlo_name_is_the_configured_one() -> None:
    """Never the recipient's domain, and never the MX host being connected to."""
    peer = tls_session_peer(peer_endpoint())
    await run(peer)
    text = peer.wire_text()

    assert "EHLO probe.sender.test.example\r\n" in text
    assert "EHLO recipient.test.example" not in text
    assert "EHLO mx.test.example" not in text


async def test_a_different_target_does_not_change_the_sender() -> None:
    """The sender is a function of configuration alone."""
    senders = []
    for text in ("a@one.test.example", "b@two.test.example", "c@three.test.example"):
        peer = tls_session_peer(peer_endpoint())
        await dialogue().run(peer, session(), address(text))
        senders.append(
            [line for line in peer.wire_text().split("\r\n") if line.startswith("MAIL FROM")]
        )
    assert senders == [["MAIL FROM:<verify@sender.test.example>"]] * 3


async def test_the_tls_path_uses_the_same_sender_and_ehlo_name() -> None:
    peer = tls_session_peer(peer_endpoint())
    await run(peer, REQUIRE_TLS)
    text = peer.wire_text()

    assert text.count("EHLO probe.sender.test.example\r\n") == 2
    assert text.count("MAIL FROM:<verify@sender.test.example>") == 1


# --- provider neutrality ---------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        "google.com",
        "gmail.com",
        "outlook.com",
        "yahoo.co.jp",
        "protonmail.com",
        "some-small-host.test.example",
    ],
)
async def test_the_dialogue_is_the_same_whoever_hosts_the_domain(domain: str) -> None:
    """`docs/architecture.md`: provider family is metadata and decides nothing.

    An MX name is a weak signal and a keyword is a better fingerprint than one,
    so neither may change what is said. The transcript and the outcome are
    compared against a domain nobody has heard of.
    """
    transcripts = []
    for target_domain in (domain, "some-small-host.test.example"):
        peer = tls_session_peer(peer_endpoint())
        report = await dialogue().run(peer, session(), address(f"person@{target_domain}"))
        transcripts.append((peer.transcript, report.observation.outcome, report.tls.negotiated))

    assert transcripts[0] == transcripts[1]


@pytest.mark.inspection
async def test_no_smtp_module_names_a_mail_provider() -> None:
    """A behavioural branch has to be written down somewhere, so this looks.

    A mutation that skipped STARTTLS for one provider passed every behavioural
    test in this file, because a test cannot enumerate the providers it does not
    know about. The inspection can.
    """
    named = _provider_names_in_the_smtp_tree()
    assert named == [], f"a provider is named in a production SMTP path: {named}"


def _provider_names_in_the_smtp_tree() -> list[str]:
    import ast
    from pathlib import Path

    providers = {
        "google",
        "gmail",
        "googlemail",
        "microsoft",
        "outlook",
        "hotmail",
        "office365",
        "yahoo",
        "proton",
        "zoho",
        "fastmail",
        "mimecast",
        "barracuda",
        "qq.com",
        "yandex",
    }
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    found: list[str] = []
    for module in sorted(root.rglob("*.py")):
        if "smtp" not in module.name and module.parent.name != "smtp":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.lower()
                found.extend(
                    f"{module.name}:{node.lineno} {provider}"
                    for provider in providers
                    if provider in lowered
                )
            if isinstance(node, ast.Name | ast.Attribute):
                name = (node.id if isinstance(node, ast.Name) else node.attr).lower()
                found.extend(
                    f"{module.name}:{node.lineno} {provider}"
                    for provider in providers
                    if provider in name
                )
    return found


async def test_the_dialogue_reads_the_targets_domain_only_for_the_recipient() -> None:
    """The one place the target may influence the wire is `RCPT TO`."""
    peer = tls_session_peer(peer_endpoint())
    await dialogue().run(peer, session(), address("person@some-provider.test.example"))
    text = peer.wire_text()

    lines_naming_the_domain = [
        line for line in text.split("\r\n") if "some-provider.test.example" in line
    ]
    assert lines_naming_the_domain == ["RCPT TO:<person@some-provider.test.example>"]


# --- Phase 5's vocabulary is absent from the dialogue layer too -------------


def _application_smtp_modules() -> list[object]:
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck" / "application"
    return sorted(root.glob("*smtp*.py"))


@pytest.mark.inspection
async def test_no_application_smtp_module_names_a_status() -> None:
    """The 4A inspection covers `domain/smtp*`; this covers the layer above it.

    A reply code becoming a status is most tempting here, because this is where
    the code is read. `docs/status-model.md` section 4 gives that to Phase 5,
    with the syntax, DNS, and passive evidence in front of it.

    Docstrings are exempt: this module's own prose says `250` does not become
    `likely_deliverable`, and a text search would find its own explanation.
    """
    import ast

    offences: list[str] = []
    for module in _application_smtp_modules():
        source = module.read_text(encoding="utf-8")  # type: ignore[attr-defined]
        tree = ast.parse(source)
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and node.value in {"likely_deliverable", "temporary_unknown", "invalid"}
            ):
                offences.append(f"{module.name}:{node.lineno} {node.value!r}")  # type: ignore[attr-defined]
            for attribute in ("id", "attr", "name"):
                value = getattr(node, attribute, None)
                if isinstance(value, str) and value in {
                    "Status",
                    "Verdict",
                    "Confidence",
                    "RiskFlag",
                    "likely_deliverable",
                    "temporary_unknown",
                }:
                    offences.append(f"{module.name}:{node.lineno} {value}")  # type: ignore[attr-defined]
    assert offences == [], f"Phase 5 vocabulary in a Phase 4 module: {offences}"


@pytest.mark.inspection
async def test_no_application_smtp_module_imports_verdict_vocabulary() -> None:
    import ast

    for module in _application_smtp_modules():
        tree = ast.parse(module.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom | ast.Import):
                imported.update(alias.name for alias in node.names)
        for name in ("Status", "Verdict", "Confidence", "RiskFlag"):
            assert name not in imported, f"{module.name} imports {name}"  # type: ignore[attr-defined]
