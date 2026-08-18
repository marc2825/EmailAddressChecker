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
    #: Which passive dataset snapshot produced it, for exactly the same reason.
    #:
    #: The key held every input that could change the answer except the lists the
    #: answer partly came from, so a verdict computed before an operator added a
    #: domain to the role-account dataset was still served afterwards. The final
    #: system audit found it. A bounded digest — never a path, never a version
    #: string a reader could mistake for one.
    passive_dataset_fingerprint: str
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
    async def save(self, record: StoredVerdict, *, expected_generation: int) -> bool:
        """Persist one result. `False` means the account fence refused it.

        `expected_generation` is the account deletion generation the work that
        produced this result was admitted under, and an implementation must
        compare it with its own fence **inside the same transaction** as the
        write. A cached verdict recreated after a deletion is the account's data
        exactly as a job row is, and the focused review reproduced both through
        a check that ended before the write began.
        """
        ...

    async def fence(self, *, account_digest: str, generation: int) -> int:
        """Raise this store's own deletion fence. Returns the value held.

        Keyed by digest rather than by account, because that is the only form of
        an account identifier this store is ever given.
        """
        ...

    async def find(
        self,
        *,
        account_digest: str,
        target_digest: str,
        sender_identity_digest: str,
        aggregation_ruleset: str,
        passive_dataset_fingerprint: str,
        now: datetime,
    ) -> StoredVerdict | None:
        """The most recent live matching result, or `None`.

        Every parameter is part of the match rather than a field to compare
        afterwards, so an implementation cannot answer with a row the current
        rules did not produce, a row obtained through a different sender, or a
        row whose evidence has expired.
        """
        ...

    async def delete_account(self, *, account_digest: str) -> int:
        """Remove every record this account owns. Returns how many went.

        `docs/privacy.md` section 7 promises account-requested deletion and
        `docs/runbooks/privacy-deletion.md` describes an operator performing it.
        No production operation did it: the runbook's steps were manual, and the
        final system audit found the promise had no implementation.
        `application/account_deletion.py` orchestrates the set; this is one
        store's half.

        **The account digest is the key, and it is the only key.** Every record
        here carries one precisely so that "everything belonging to A" is a
        `WHERE` clause rather than an inference. Deleting by target digest would
        remove whatever other account had checked the same mailbox.

        **Every fingerprint and every ruleset**, so a deletion is not scoped to
        the snapshot this process happens to be running: an entry written under
        an older passive dataset is still the account's data.

        Unbounded, unlike `purge_expired`. Routine housekeeping must not hold a
        write lock; an account deletion is a rare operator action whose whole
        value is that it finishes.
        """
        ...
