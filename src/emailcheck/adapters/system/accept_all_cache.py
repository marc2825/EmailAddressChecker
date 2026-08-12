"""A bounded in-process accept-all cache.

The development implementation of `ports/accept_all_cache.py`, on the precedent
`adapters/system/quota.py` set: in-process, **finite in every dimension**, and
replaceable by a shared store behind the same port without anything above it
learning which one it has.

**Bounded, because the key is attacker-influenced.** A caller chooses which
domains this deployment is asked about, so an unbounded table is a memory leak
with a remote trigger — the same shape `docs/threat-model.md` records for the
rate limiter's per-domain state. Expired entries are swept first, and only when
that frees nothing does a live entry get evicted.

**Eviction is a cache miss, never a wrong answer.** An evicted domain is
re-experimented under the separate accept-all budget; it is never reported as
`not_suspected` because its row went away. Losing a cached answer costs one
probe against a budget of five; keeping a wrong one costs seven days of a claim
this project never made.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from emailcheck.ports.accept_all_cache import AcceptAllCacheKey, CachedAcceptAll

__all__ = ["DEFAULT_MAX_ENTRIES", "InProcessAcceptAllCache"]

#: How many domains one process remembers. A seven-day answer per domain means
#: this is a working set rather than a hot path, and ten thousand rows of three
#: short strings is a few megabytes.
DEFAULT_MAX_ENTRIES: Final = 10_000


@dataclass(slots=True)
class InProcessAcceptAllCache:
    """An LRU of decided answers, with expiry evaluated against the caller's clock."""

    max_entries: int = DEFAULT_MAX_ENTRIES
    _entries: OrderedDict[tuple[str, str, str], CachedAcceptAll] = field(
        default_factory=OrderedDict, repr=False
    )

    def __post_init__(self) -> None:
        if isinstance(self.max_entries, bool) or not isinstance(self.max_entries, int):
            raise ValueError("max_entries must be a whole number, not a boolean")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")

    async def get(self, key: AcceptAllCacheKey, *, now: datetime) -> CachedAcceptAll | None:
        slot = _slot(key)
        entry = self._entries.get(slot)
        if entry is None:
            return None
        if entry.expires_at <= now:
            # Expiry is `<=` rather than `<`: an answer whose lifetime has
            # exactly run out is spent. The boundary is pinned by a test in both
            # directions, on the precedent ADR 0015 set for the verdict cache.
            del self._entries[slot]
            return None
        self._entries.move_to_end(slot)
        return entry

    async def put(self, key: AcceptAllCacheKey, entry: CachedAcceptAll) -> None:
        slot = _slot(key)
        self._entries[slot] = entry
        self._entries.move_to_end(slot)
        self._evict(now=entry.checked_at)

    def _evict(self, *, now: datetime) -> None:
        if len(self._entries) <= self.max_entries:
            return
        for slot in [slot for slot, held in self._entries.items() if held.expires_at <= now]:
            del self._entries[slot]
        while len(self._entries) > self.max_entries:
            # Least recently used. Costs a probe, never an answer.
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


def _slot(key: AcceptAllCacheKey) -> tuple[str, str, str]:
    return (key.domain_digest, key.sender_digest, key.experiment_version)
