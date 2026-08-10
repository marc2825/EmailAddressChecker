"""Storing a result, and finding one the current rules and the clock still allow.

Phase 5 stop condition 4: a cached verdict served after the aggregation rules
changed is a result nothing produced. So the ruleset is not a column that
happens to be recorded — it is part of what a lookup matches on, and a row
carrying a different one is not a hit.

ADR 0015 adds the two components `docs/requirements.md` section 13 requires
beside it. **The sender identity is a key component**, because a verdict
obtained from one envelope sender is not evidence about another: reputation, SPF
alignment, and policy responses are all properties of the sender that asked.
**Expiry is a predicate**, for the same reason the ruleset is — a row filtered
after selection is a row an implementation can still answer with.

**What a stored record may hold is fixed by the record type, not by the
adapter.** `docs/requirements.md` section 16 keeps full addresses out of
ordinary storage and asks for an HMAC for correlation, so the record carries
digests rather than the address, the account, or the sender, and it carries no
evidence detail, no transcript, and no certificate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from emailcheck.domain.verdict import Status

#: Every field that must be a non-empty digest carrying no address.
DIGEST_FIELDS = ("record_id", "account_digest", "target_digest", "sender_identity_digest")


@dataclass(frozen=True, slots=True)
class StoredVerdict:
    """One persisted result. Digests and published vocabulary only."""

    #: An unguessable identifier, so a stored result cannot be enumerated.
    record_id: str
    #: HMAC of the authenticated principal. Never the account identifier.
    account_digest: str
    #: HMAC of the normalized target. Never the address.
    target_digest: str
    #: HMAC of the envelope sender and EHLO name this verdict was obtained
    #: through. `docs/requirements.md` section 13 requires it in the key.
    sender_identity_digest: str
    status: Status
    confidence: str
    primary_reason: str | None
    reasons: tuple[str, ...]
    risk_flags: tuple[str, ...]
    #: The per-layer summary, as `(layer, reason value)` pairs.
    #:
    #: Stored so that a cache hit is indistinguishable from a fresh answer —
    #: otherwise a caller could tell which of its requests were cached, which is
    #: information about this project's internals rather than about the address.
    #: Every value is a published reason code, the same kind already in
    #: `reasons`; the counts `Verdict.checks` also carries are internal and are
    #: dropped by `application/public_result.py` before they reach here.
    checks: tuple[tuple[str, str], ...]
    #: Which aggregation produced this. A lookup that ignores it is a lookup
    #: that can answer with a verdict the current rules would not reach.
    aggregation_ruleset: str
    #: Aware UTC, serialized with an explicit offset.
    created_at: datetime
    #: When this stops being answerable. ADR 0015 derives it from the shortest
    #: lifetime among the evidence that decided the verdict.
    expires_at: datetime

    def __post_init__(self) -> None:
        for name in DIGEST_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"a stored verdict needs a non-empty {name}")
            if "@" in value:
                raise ValueError(f"a stored verdict {name} may not carry an address")
        if not isinstance(self.aggregation_ruleset, str) or not self.aggregation_ruleset:
            raise ValueError("a stored verdict needs a non-empty aggregation_ruleset")
        if not isinstance(self.status, Status):
            raise ValueError("a stored verdict must name a published status")
        for name in ("created_at", "expires_at"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise ValueError(f"a stored verdict {name} must be timezone-aware")
        if self.expires_at <= self.created_at:
            # A row that is already expired when written is a row that cost a
            # write and can never be read.
            raise ValueError("a stored verdict must expire after it was created")


class VerdictStore(Protocol):
    async def save(self, record: StoredVerdict) -> None:
        """Persist one result."""
        ...

    async def find(
        self,
        *,
        account_digest: str,
        target_digest: str,
        sender_identity_digest: str,
        aggregation_ruleset: str,
        now: datetime,
    ) -> StoredVerdict | None:
        """The most recent live matching result, or `None`.

        Every parameter is part of the match rather than a field to compare
        afterwards, so an implementation cannot answer with a row the current
        rules did not produce, a row obtained through a different sender, or a
        row whose evidence has expired.
        """
        ...
