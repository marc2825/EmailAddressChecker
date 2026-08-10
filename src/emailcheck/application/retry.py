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

**A retry is a whole new verification.** `application/jobs.py` calls
`AddressVerificationService.verify` again, so admission, the rate limiter, the
destination policy, and the verification-total deadline all apply exactly as
they did the first time. Phase 4E's "at most one `RCPT TO` per verification" is
untouched: this is a second verification, twenty minutes later, which section 14
authorizes in the same sentence that caps it at one.

Pure. No clock, no sleeper, no randomness — the caller supplies the jitter, so
this stays a function of its input and a test can compare two calls.
"""

from __future__ import annotations

from typing import Final

from emailcheck.domain.reasons import ReasonCode
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


def retry_delay_seconds(verdict: Verdict, *, jitter_seconds: float = 0.0) -> float | None:
    """Seconds to wait before one more attempt, or `None` for no retry.

    Keyed on the verdict's **primary reason** rather than on the whole reason
    set: the primary reason is the one the aggregation actually decided on, and
    a supporting observation is not what a retry would be re-testing.
    """
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


def jitter_span_seconds(verdict: Verdict) -> float:
    """How wide a jitter span this verdict's retry may use, or zero."""
    primary = verdict.primary_reason
    if primary is None:
        return 0.0
    base = RETRY_AFTER_SECONDS.get(primary)
    return 0.0 if base is None else base * JITTER_FRACTION
