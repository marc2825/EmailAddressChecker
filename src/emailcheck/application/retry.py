"""Whether one automatic retry is allowed, and how long to wait.

`docs/requirements.md` section 14 is the whole specification, and it is short:
at most one automatic retry, for three named conditions, with none for syntax,
NXDOMAIN, Null MX, or a permanent policy response. ADR 0014 records the mapping
onto published reason codes.

**The eligible set is closed.** A reason outside it is not retried — including
`rcpt_unverifiable` (a `252`), `smtp_ambiguous_permanent_failure` (a bare
`550`), `rcpt_rejected_policy`, and every non-target failure. There is no rule
here derived from a provider's name and none derived from a reply's text, and
**no `if temporary: retry` shortcut**: a reason added to the vocabulary later is
not retryable until somebody adds it here on purpose, with a test.

**The classification is semantic, not the reply's first digit.** `mailbox_full`
arises from both `452 4.2.2` and `552 5.2.2`, and Phase 4D marks both temporary
because `docs/requirements.md` section 9 says a `552` carrying an explicit
`X.2.2` is a temporary storage condition. Section 14's "explicit temporary SMTP
response" therefore covers it, and an earlier build retried `450`/`451` but not
`452` — a split section 14 does not draw. Branching on the basic code would have
made that permanent; branching on the reason code does not.

**`smtp_connection_timeout` is deliberately absent.** Section 14 permits that
retry "only if service health is otherwise normal", and this project does not
model service health. Retrying anyway would be implementing half a rule and
calling it the rule.

**A retry is a whole new verification, and only where the first one is known not
to have reached the recipient.** `application/jobs.py` calls
`AddressVerificationService.verify` again, so admission, the rate limiter, the
destination policy, and the verification-total deadline all apply exactly as
they did the first time.

That second condition is the one this module got wrong, and it was not a
detail. `docs/threat-model.md` bounds **one active operation at one `RCPT TO` in
total**, not one per verification, and the eligible set above is reachable only
*through* the recipient stage: `smtp_temporary_failure` and `mailbox_full` are
produced by `application/smtp_evidence.py` from the reply to the one `RCPT TO`
and from nothing else. So the earlier build — "a `450` is a temporary SMTP
response, section 14 retries those" — issued a second `RCPT TO` for one
submitted address twenty minutes later, which is the enumeration pattern
`docs/threat-model.md` lists first. The final system audit measured it: two
recipient commands on the wire for one job.

So the reason code is now a **necessary and not a sufficient** condition.
`recipient_touch` is required, it comes from the protocol facts
`application/smtp_verification.py` recorded rather than from the verdict, and
`MAYBE_TOUCHED` refuses whatever the reason says. `docs/requirements.md` section
14 keeps its delays; what it no longer does is authorize a replay of an attempt
that may already have named the recipient to a mail server.

**The delays stay keyed by reason anyway**, rather than being deleted along with
the recipient-stage retry they currently describe. A temporary SMTP failure
observed *before* the recipient stage would be eligible under both rules, the
20-minute figure is the one section 14 gives for it, and encoding "this reason
is retryable when nothing was touched" is a smaller and more honest statement
than deciding here that such a reason can never arise.

Pure. No clock, no sleeper, no randomness — the caller supplies the jitter, so
this stays a function of its input and a test can compare two calls.
"""

from __future__ import annotations

from typing import Final

from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.verdict import Verdict

_MINUTE: Final = 60

#: `docs/requirements.md` section 14, one row per named condition.
#:
#: "explicit temporary SMTP response: approximately 20 minutes plus jitter" and
#: "DNS SERVFAIL: one retry after a few minutes".
RETRY_AFTER_SECONDS: Final[dict[ReasonCode, int]] = {
    ReasonCode.SMTP_TEMPORARY_FAILURE: 20 * _MINUTE,
    ReasonCode.MAILBOX_FULL: 20 * _MINUTE,
    ReasonCode.DNS_TEMPORARY_FAILURE: 3 * _MINUTE,
}

#: How far past the base delay jitter may spread a retry. Section 14 says
#: "plus jitter" without a number; a tenth of the delay spreads a burst without
#: turning "approximately 20 minutes" into something else.
JITTER_FRACTION: Final = 0.1


def retry_delay_seconds(
    verdict: Verdict, *, recipient_touch: RecipientTouch, jitter_seconds: float = 0.0
) -> float | None:
    """Seconds to wait before one more attempt, or `None` for no retry.

    Keyed on the verdict's **primary reason** rather than on the whole reason
    set: the primary reason is the one the aggregation actually decided on, and
    a supporting observation is not what a retry would be re-testing.

    `recipient_touch` has no default. A keyword with a safe default would still
    be a keyword somebody forgets at a new call site, and the failure mode of
    forgetting it is a second `RCPT TO` — so the signature refuses to be called
    without an answer, and mypy is the thing that notices.
    """
    if not isinstance(recipient_touch, RecipientTouch):
        raise ValueError("a retry decision needs a recipient-touch fact")
    if not recipient_touch.replay_is_safe:
        # **Checked before the reason is even looked up.** Not because the order
        # is faster, but because an inspection reading this function has to see
        # that no reason code can reach a delay past this line.
        return None
    primary = verdict.primary_reason
    if primary is None:
        return None
    base = RETRY_AFTER_SECONDS.get(primary)
    if base is None:
        return None
    if isinstance(jitter_seconds, bool) or not isinstance(jitter_seconds, int | float):
        raise ValueError("jitter must be a real number")
    if jitter_seconds < 0:
        raise ValueError("jitter must not be negative")
    return float(base) + float(min(jitter_seconds, base * JITTER_FRACTION))


def jitter_span_seconds(verdict: Verdict, *, recipient_touch: RecipientTouch) -> float:
    """How wide a jitter span this verdict's retry may use, or zero.

    Gated on the same fact as the delay, so a caller cannot draw jitter for a
    retry that will not happen — which would spend randomness, and would make
    the two functions disagree about whether there is a retry at all.
    """
    if not isinstance(recipient_touch, RecipientTouch) or not recipient_touch.replay_is_safe:
        return 0.0
    primary = verdict.primary_reason
    if primary is None:
        return 0.0
    base = RETRY_AFTER_SECONDS.get(primary)
    return 0.0 if base is None else base * JITTER_FRACTION
