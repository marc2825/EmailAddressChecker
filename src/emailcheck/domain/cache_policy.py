"""How long a `Verdict` may be reused. Pure, table-driven, and conservative.

`docs/requirements.md` section 13 prices evidence **per class** and defines no
lifetime for an aggregated verdict, which is a composition of several classes at
once. ADR 0015 decides the composition:

```text
verdict lifetime = min(lifetime of each decision-relevant reason)
```

and a verdict whose decision-relevant evidence includes a class section 13 does
not price is **not cacheable at all**. Returning `None` rather than a default is
the whole point: a default would be a duration nobody wrote down, and a caching
rule that invents durations is a deliverability rule nobody reviewed.

**Decision-relevant** is every reason in `Verdict.reason_codes` minus the four
risk-only ones. That set is published vocabulary, so this module needs none of
the aggregation internals — the Phase 6 inspection refuses them, and correctness
of a cache is not worth a hole in the re-derivation barrier.

Risk-only reasons are excluded because section 13 governs passive datasets by
**data version** rather than by duration, and because they decide nothing: a
risk flag never changes a status, so letting one shorten a verdict's life would
be a timing rule derived from an observation with no bearing on the answer.

Nothing here reads a status, and nothing here produces one.
"""

from __future__ import annotations

from typing import Final

from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Verdict

_MINUTE: Final = 60
_HOUR: Final = 60 * _MINUTE
_DAY: Final = 24 * _HOUR

#: `docs/requirements.md` section 13, one row per named class.
#:
#: A reason absent from this mapping is **not priced**, which makes the verdict
#: uncacheable. That is deliberate and it is not free: `rcpt_unverifiable` (a
#: `252`) and `smtp_ambiguous_permanent_failure` (a bare `550`) are common
#: answers, and not caching them costs repeat probing. ADR 0015 records it as a
#: gap for a section 13 amendment rather than closing it by guessing.
SECTION_13_TTL_SECONDS: Final[dict[ReasonCode, int]] = {
    # "SMTP accepted: 6 hours"
    ReasonCode.RCPT_ACCEPTED: 6 * _HOUR,
    ReasonCode.RCPT_FORWARDED: 6 * _HOUR,
    # "explicit recipient-not-found: 1 hour"
    ReasonCode.RCPT_REJECTED_ADDRESS: 1 * _HOUR,
    # "temporary SMTP failure: 10 minutes"
    ReasonCode.SMTP_TEMPORARY_FAILURE: 10 * _MINUTE,
    ReasonCode.MAILBOX_FULL: 10 * _MINUTE,
    # "policy block: 30 minutes"
    ReasonCode.RCPT_REJECTED_POLICY: 30 * _MINUTE,
    ReasonCode.SMTP_POLICY_BLOCKED: 30 * _MINUTE,
    # "connection timeout: 5 minutes"
    ReasonCode.SMTP_CONNECTION_TIMEOUT: 5 * _MINUTE,
    # "accept-all suspected: 7 days". Phase 9 produces this; nothing does today.
    ReasonCode.ACCEPT_ALL_SUSPECTED: 7 * _DAY,
}

#: Reasons whose lifetime is the DNS record's own.
#:
#: Section 13 prices DNS by the served TTL under a cap, and `domain/dns.py`'s
#: `apply_ttl_policy` already implements exactly that — including honouring a
#: served TTL of zero as zero. So these read `MailRoute.ttl` rather than a
#: constant here, and re-deriving the cap in a second place is avoided.
DNS_GOVERNED_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.DOMAIN_NXDOMAIN,
        ReasonCode.NULL_MX,
        ReasonCode.NO_MAIL_ROUTE,
        ReasonCode.MX_AVAILABLE,
        ReasonCode.IMPLICIT_MX_AVAILABLE,
        ReasonCode.MX_CONFIGURATION_ANOMALY,
        ReasonCode.DNS_TEMPORARY_FAILURE,
    }
)

#: The four risk-only reasons, excluded from the composition above.
#:
#: `docs/architecture.md` states the property these have in common: passive
#: classification "has no status field, so this layer cannot express a
#: deliverability judgment".
RISK_ONLY_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.DISPOSABLE_DOMAIN,
        ReasonCode.ROLE_ACCOUNT,
        ReasonCode.FREE_MAIL,
        ReasonCode.PROVIDER_OPAQUE,
    }
)


def decision_relevant_reasons(verdict: Verdict) -> tuple[ReasonCode, ...]:
    """The reasons whose freshness bounds this verdict's, in the verdict's order."""
    return tuple(reason for reason in verdict.reason_codes if reason not in RISK_ONLY_REASONS)


def verdict_ttl_seconds(verdict: Verdict, *, route_ttl_seconds: int | None) -> int | None:
    """How long this verdict may be reused, or `None` if it may not be.

    `route_ttl_seconds` is `MailRoute.ttl.applied_seconds` when DNS was
    consulted and `None` when it was not — a syntax rejection never resolves
    anything, and a DNS-governed reason with no route TTL to read is
    uncacheable rather than assumed fresh.
    """
    if ReasonCode.INTERNAL_ERROR in verdict.reason_codes:
        # A failure of this project's own is not an observation about the
        # address, and storing one would serve our outage to the next caller.
        return None

    relevant = decision_relevant_reasons(verdict)
    if not relevant:
        # No verdict at all, or a verdict resting only on risk flags. Neither is
        # something to answer a later request with.
        return None

    lifetimes: list[int] = []
    for reason in relevant:
        if reason in DNS_GOVERNED_REASONS:
            if route_ttl_seconds is None:
                return None
            lifetimes.append(route_ttl_seconds)
            continue
        priced = SECTION_13_TTL_SECONDS.get(reason)
        if priced is None:
            # Unpriced by section 13. Not cached, rather than cached under a
            # duration this module chose.
            return None
        lifetimes.append(priced)

    shortest = min(lifetimes)
    if shortest <= 0:
        # A served DNS TTL of zero is a request not to cache, and it survives
        # aggregation rather than being rounded up to a floor.
        return None
    return shortest
