"""Whether one active operation may already have contacted its recipient.

One value, and it exists because the question it answers has no correct answer
anywhere else. `docs/threat-model.md` bounds **one active verification operation
at one `RCPT TO` in total**, so every decision to run an operation a second time
— an automatic retry, a resumed batch row, a process that restarted — has to
know whether the first attempt reached the recipient stage. Nothing already in
the vocabulary carries that:

- a `Status` cannot. `temporary_unknown` is produced by a DNS SERVFAIL that
  opened no socket **and** by a `451` at `RCPT TO`, and an earlier build that
  retried on the status therefore retried both — which put one submitted address
  in front of a mail server twice, measured on the wire by the final system
  audit;
- a `ReasonCode` cannot, for the same reason one layer down;
- a reply class cannot, because the cases with no reply at all — a connection
  reset after the command was written, a write that failed with some bytes
  possibly delivered — are exactly the ones replay must refuse.

**It lives here rather than in `domain/smtp_result.py` on purpose.** This value
travels from the SMTP layer through `application/verification.py` into
`application/jobs.py` and onto disk in `ports/job_store.py`, and the Phase 6
inspection refuses an entry point that imports anything whose module name
contains `smtp` — a blunt rule, deliberately, because it is what stops a job
worker reaching `SMTPProbeService` and probing without the one-`RCPT TO` bound.
Putting a fact that a job worker legitimately needs inside an `smtp` module
would have meant weakening that inspection, so the fact moved instead.

No SMTP type is imported here and none may be: this is the *conclusion* drawn
from a transcript, not the transcript.
"""

from __future__ import annotations

from enum import StrEnum


class RecipientTouch(StrEnum):
    """Two members and no third.

    `MAYBE_TOUCHED` covers *touched* as well. A `450` that arrived, a `RCPT TO`
    whose reply never came, and a write that failed midway are the same fact for
    the only question asked of this value — may an automatic second attempt
    contact the recipient again? — and telling them apart would be inventing
    certainty out of a closed socket.

    `NOT_TOUCHED` is the value a producer must *prove*, never the one it falls
    back to. Every path that cannot answer is required to say `MAYBE_TOUCHED`,
    and the cost of that asymmetry is one retry that does not happen against one
    recipient contact that does.
    """

    #: No dialogue reached the recipient stage. Replay cannot be a second
    #: recipient contact, because there was no first one.
    NOT_TOUCHED = "not_touched"
    #: A dialogue reached the recipient stage, or this project cannot rule it
    #: out. Automatic replay of the operation is prohibited.
    MAYBE_TOUCHED = "maybe_touched"

    @property
    def replay_is_safe(self) -> bool:
        """Whether an automatic second attempt can avoid a second recipient touch.

        A property on the enum rather than a comparison at each call site, so a
        member added later has to answer the question here instead of falling
        through somebody's `!=`.
        """
        return self is RecipientTouch.NOT_TOUCHED
