"""What a dialogue reports, kept separate from what a reply means.

`RecipientObservation` in `smtp_result.py` is the Phase 4 → Phase 5 boundary and
says what happened at the recipient stage. A session has more to report than
that — which stage it reached, whether TLS was negotiated, whether the courtesy
cleanup worked — and none of it is recipient evidence.

Keeping the two apart is the point. A `SessionReport` can say "the banner timed
out" without that being a fact about a mailbox, and the observation it carries
uses the same taxonomy whether the session got as far as `RCPT TO` or not.

Nothing here maps a code to a status. `250` and `550` are numbers at this layer,
and `docs/status-model.md` section 4 gives Phase 5 the job of weighing them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError, SMTPState
from emailcheck.domain.smtp_result import RecipientObservation
from emailcheck.domain.smtp_tls import TLSOutcomeDetail


class DialogueStage(StrEnum):
    """How far a session got. Ordered as the dialogue runs."""

    CONNECTED = "connected"
    BANNER = "banner"
    EHLO = "ehlo"
    STARTTLS = "starttls"
    TLS_HANDSHAKE = "tls_handshake"
    EHLO_AFTER_TLS = "ehlo_after_tls"
    MAIL_FROM = "mail_from"
    RCPT_TO = "rcpt_to"
    CLEANUP = "cleanup"


#: The stage order, so "how far did it get" is comparable rather than a guess.
STAGE_ORDER: Final[tuple[DialogueStage, ...]] = (
    DialogueStage.CONNECTED,
    DialogueStage.BANNER,
    DialogueStage.EHLO,
    DialogueStage.STARTTLS,
    DialogueStage.TLS_HANDSHAKE,
    DialogueStage.EHLO_AFTER_TLS,
    DialogueStage.MAIL_FROM,
    DialogueStage.RCPT_TO,
    DialogueStage.CLEANUP,
)


class CleanupStatus(StrEnum):
    """What happened to the courtesy `RSET` and `QUIT`.

    Recorded separately because it must never change the observation. A server
    that accepts `RCPT TO` and then drops the connection before `QUIT` has
    already answered the only question this project asked.
    """

    #: Both were issued and accepted.
    COMPLETED = "completed"
    #: One or both failed or could not be issued. The observation is unchanged.
    INCOMPLETE = "incomplete"
    #: The budget ran out first, so nothing further was attempted.
    SKIPPED_DEADLINE = "skipped_deadline"
    #: The session never reached a state where cleanup applies.
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True, slots=True)
class SessionReport:
    """One session, completely described, and still not a verdict.

    `observation` is what Phase 5 will read. Everything else is context for
    operators and for Phase 4D's evidence mapping.
    """

    observation: RecipientObservation
    stage_reached: DialogueStage
    tls: TLSOutcomeDetail
    capabilities: Capabilities
    cleanup: CleanupStatus
    commands_issued: tuple[SMTPCommand, ...] = ()
    #: Whether the total session budget ran out. Kept separate from the outcome
    #: because a deadline and a reset produce the same non-target outcome at the
    #: same stage, and Phase 4D needs to tell them apart: one is this project's
    #: own bound and the other is the network's.
    #:
    #: `cleanup is SKIPPED_DEADLINE` implies this is true, and `__post_init__`
    #: refuses the contradiction. The converse does not hold: a budget that ran
    #: out mid-dialogue sets this while cleanup is `NOT_ATTEMPTED`, and one that
    #: ran out during `RSET` sets it while cleanup is `INCOMPLETE`.
    deadline_exhausted: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.observation, RecipientObservation):
            raise SMTPContractError("a session report must carry a recipient observation")
        if self.observation.tls_used != self.tls.negotiated:
            # Two fields describing one fact must agree, or a reader picks the
            # one that suits them.
            raise SMTPContractError("the observation and the TLS detail disagree about TLS")
        recipient_commands = sum(
            1 for command in self.commands_issued if command is SMTPCommand.RCPT_TO
        )
        if recipient_commands > 1:
            raise SMTPContractError("a session may issue at most one RCPT TO")
        if sum(1 for command in self.commands_issued if command is SMTPCommand.STARTTLS) > 1:
            raise SMTPContractError("a session may issue STARTTLS at most once")
        if sum(1 for command in self.commands_issued if command is SMTPCommand.MAIL_FROM) > 1:
            raise SMTPContractError("a session may issue MAIL FROM at most once")
        if recipient_commands != self.observation.recipients_attempted:
            raise SMTPContractError(
                "the transcript and the observation disagree about the recipient"
            )
        if self.cleanup is CleanupStatus.SKIPPED_DEADLINE and not self.deadline_exhausted:
            # `SKIPPED_DEADLINE` says the session budget is what stopped the
            # cleanup, and `deadline_exhausted` is the field Phase 4D reads to
            # tell this project's own bound apart from the network's. Two fields
            # describing one fact must agree, so the contradiction is
            # unconstructible rather than merely unlikely.
            raise SMTPContractError(
                "cleanup skipped for the deadline requires deadline_exhausted to be true"
            )

    @property
    def final_state(self) -> SMTPState:
        return self.observation.final_state

    @property
    def no_message_data_sent(self) -> bool:
        """Always true, and published so a test can assert the promise."""
        return self.observation.no_message_data_sent

    @property
    def summary(self) -> dict[str, str | int | bool | None]:
        """The safe structured summary. No remote text, no address, no chain."""
        return {
            **self.observation.summary,
            "stage_reached": self.stage_reached.value,
            "tls_negotiated": self.tls.negotiated,
            "tls_reason": self.tls.reason.value if self.tls.reason else None,
            "cleanup": self.cleanup.value,
            "starttls_advertised": self.capabilities.supports_starttls,
            "deadline_exhausted": self.deadline_exhausted,
        }
