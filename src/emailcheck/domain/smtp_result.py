"""What was observed at the recipient stage, and nothing about what it means.

This is the boundary between Phase 4 and Phase 5. An observation records the
stage reached, the reply codes, whether TLS was used, and that no message data
was sent. It does not carry a status, a confidence, or a reason code, because
`docs/status-model.md` section 4 gives the aggregator the job of weighing this
against the syntax, DNS, and passive evidence.

That separation is not stylistic. `250` at RCPT does not mean the mailbox
exists — an accept-all server says it to everyone — and a bare `550` does not
mean it does not, because policy rejections share the code. Turning either into
a verdict here would put the decision in the layer with the least context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from emailcheck.domain.smtp_contract import SMTPState
from emailcheck.domain.smtp_reply import ReplyDefect, SMTPReply


class RecipientStageOutcome(StrEnum):
    """What happened, at the level of detail this layer can honestly report."""

    #: The server accepted the recipient at that stage. Not mailbox existence.
    ACCEPTED = "accepted"
    #: The server permanently refused it. Which kind of refusal is in the codes.
    REJECTED = "rejected"
    #: An explicit 4xx. Worth one bounded retry.
    TEMPORARY_FAILURE = "temporary_failure"
    #: The dialogue itself was unusable: a malformed or unterminated reply.
    PROTOCOL_ERROR = "protocol_error"
    #: STARTTLS or the handshake failed. Never mailbox invalidity.
    TLS_ERROR = "tls_error"
    #: The connection could not be made or was lost. Says nothing about the target.
    CONNECTION_ERROR = "connection_error"
    #: This project failed. Never evidence about the address.
    INTERNAL_ERROR = "internal_error"


#: Outcomes that describe this project or the transport rather than the
#: recipient. None of them may ever contribute to a target-specific verdict.
NON_TARGET_OUTCOMES: Final[frozenset[RecipientStageOutcome]] = frozenset(
    {
        RecipientStageOutcome.PROTOCOL_ERROR,
        RecipientStageOutcome.TLS_ERROR,
        RecipientStageOutcome.CONNECTION_ERROR,
        RecipientStageOutcome.INTERNAL_ERROR,
    }
)


@dataclass(frozen=True, slots=True)
class RecipientObservation:
    """One session's report. Structured evidence, never a verdict.

    `no_message_data_sent` is derived and always true. It is published rather
    than assumed because `docs/requirements.md` section 2 makes it a promise to
    the user, and a promise that appears in the output is one a test can check.
    """

    outcome: RecipientStageOutcome
    final_state: SMTPState
    reply: SMTPReply | None = None
    defect: ReplyDefect | None = None
    tls_used: bool = False
    recipients_attempted: int = 0
    elapsed_milliseconds: int | None = None

    def __post_init__(self) -> None:
        if self.recipients_attempted > 1:
            raise ValueError("a session may attempt at most one recipient")
        if self.recipients_attempted < 0:
            raise ValueError("a recipient count cannot be negative")
        if self.elapsed_milliseconds is not None and self.elapsed_milliseconds < 0:
            raise ValueError("elapsed time cannot be negative")
        if (
            self.outcome
            in {
                RecipientStageOutcome.ACCEPTED,
                RecipientStageOutcome.REJECTED,
            }
            and self.reply is None
        ):
            raise ValueError("an accepted or rejected recipient must carry the reply that said so")
        if self.outcome is RecipientStageOutcome.PROTOCOL_ERROR and self.defect is None:
            raise ValueError("a protocol error must name the defect")

    @property
    def no_message_data_sent(self) -> bool:
        """Always true. There is no code path that could make it false."""
        return True

    @property
    def is_about_the_target(self) -> bool:
        """Whether this observation says anything about the address at all."""
        return self.outcome not in NON_TARGET_OUTCOMES

    @property
    def basic_code(self) -> int | None:
        return self.reply.code if self.reply else None

    @property
    def enhanced_code(self) -> str | None:
        if self.reply is None or self.reply.enhanced is None:
            return None
        return self.reply.enhanced.value

    @property
    def summary(self) -> dict[str, str | int | bool | None]:
        """The safe structured summary `docs/status-model.md` section 6 shows."""
        return {
            "result": self.outcome.value,
            "final_state": self.final_state.value,
            "basic_code": self.basic_code,
            "enhanced_code": self.enhanced_code,
            "tls_used": self.tls_used,
            "recipients_attempted": self.recipients_attempted,
            "no_message_data_sent": self.no_message_data_sent,
        }
