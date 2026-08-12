"""The seven-day domain cache, as a port.

`prompts/09-accept-all.md` lists "seven-day or longer domain cache" among the
preconditions, and `docs/requirements.md` section 13 prices accept-all suspicion
at seven days. A cache is storage, and `docs/architecture.md` section 2 puts
storage behind a port — so a test can exercise expiry against a fake clock
rather than against a week of waiting.

**What the key is, and what it is not.** Accept-all is a property of a
*domain's* configuration, so the key is a domain and never a mailbox: no local
part, no target address, and nothing derived from the caller's question. It also
carries the sender identity and the experiment version, because an answer
obtained through one identity by one version of the experiment is not evidence
about another — `docs/requirements.md` section 13's "cache keys include relevant
ruleset, sender identity, and normalized target HMAC" with the domain standing
where the target does.

**The store never decides what may be cached.** `CACHEABLE_OUTCOMES` in
`domain/accept_all.py` does, and `application/accept_all.py` applies it. An
implementation that cached something else would be one this project could not
review by reading the domain layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from emailcheck.domain.accept_all import AcceptAllOutcome

__all__ = ["AcceptAllCache", "AcceptAllCacheKey", "CachedAcceptAll"]

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AcceptAllCacheKey:
    """What an answer is filed under. Every part decides the answer's meaning."""

    #: An HMAC of the canonical recipient domain, under the operator's
    #: correlation key. A digest rather than the domain because this is a
    #: durable store and `docs/privacy.md` prefers correlation by HMAC — the
    #: domain itself is a permitted analytics dimension, but a cache row does
    #: not need it to work.
    domain_digest: str
    #: An HMAC of the sender identity the answer was obtained through. A
    #: destination may treat two identities differently, so an answer is only
    #: about the identity that asked.
    sender_digest: str
    #: `EXPERIMENT_VERSION`. What the experiment asked, and how the reply was
    #: read, are part of what the answer means.
    experiment_version: str


@dataclass(frozen=True, slots=True)
class CachedAcceptAll:
    """One stored answer and when it stops being one."""

    outcome: AcceptAllOutcome
    #: When the experiment ran. `prompts/09-accept-all.md`'s Result section
    #: requires "checked time and cache expiry" to be reportable.
    checked_at: datetime
    expires_at: datetime


class AcceptAllCache(Protocol):
    async def get(self, key: AcceptAllCacheKey, *, now: datetime) -> CachedAcceptAll | None:
        """The unexpired answer for this key, or `None`.

        Expiry is evaluated against `now` rather than against the
        implementation's own clock, so a caller's fake clock is the only clock.
        """
        ...

    async def put(self, key: AcceptAllCacheKey, entry: CachedAcceptAll) -> None:
        """Store an answer. The caller has already checked it may be cached."""
        ...
