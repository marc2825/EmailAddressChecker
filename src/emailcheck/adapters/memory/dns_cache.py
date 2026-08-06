"""A deterministic in-memory DNS cache.

Entries expire against an injected `Clock`, never the wall clock, so a test can
prove expiry without sleeping. Redis belongs to a later Phase; the contract this
implements is what a shared cache would have to honor too.

TTL caps come from the domain, so a cache cannot keep an answer longer than
policy allows even when a server asks it to. Keys are `DNSCacheKey` values
rather than strings, so MX, A, and AAAA answers for one host cannot overwrite
each other and no key can carry a local part or a complete address.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from emailcheck.domain.dns import TTL, DNSCacheKey
from emailcheck.ports.clock import Clock


@dataclass(frozen=True, slots=True)
class CacheEntry[T]:
    """One stored answer and the moment it stops being usable."""

    value: T
    ttl: TTL
    stored_at: datetime
    expires_at: datetime

    def is_fresh(self, now: datetime) -> bool:
        return now < self.expires_at


@dataclass
class InMemoryDNSCache[T]:
    """A small keyed cache with TTL honoring, for one process.

    Storing an answer whose applied TTL is zero is a no-op: a server asking for
    no caching is obeyed rather than rounded up.
    """

    clock: Clock
    _entries: dict[DNSCacheKey, CacheEntry[T]] = field(default_factory=dict)

    @staticmethod
    def _checked(key: DNSCacheKey) -> DNSCacheKey:
        """Refuse a bare string at runtime, not only in the type checker.

        A string key is how MX, A, and AAAA answers for one host would start
        overwriting each other, and how an address could end up in a key.
        """
        if not isinstance(key, DNSCacheKey):
            raise TypeError("a DNS cache key must be a DNSCacheKey, not a bare string")
        return key

    def get(self, key: DNSCacheKey) -> T | None:
        entry = self._entries.get(self._checked(key))
        if entry is None:
            return None
        if not entry.is_fresh(self.clock.now()):
            del self._entries[key]
            return None
        return entry.value

    def set(self, key: DNSCacheKey, value: T, ttl: TTL) -> None:
        self._checked(key)
        if ttl.applied_seconds <= 0:
            self._entries.pop(key, None)
            return
        now = self.clock.now()
        self._entries[key] = CacheEntry(
            value=value,
            ttl=ttl,
            stored_at=now,
            expires_at=now + timedelta(seconds=ttl.applied_seconds),
        )

    def delete(self, key: DNSCacheKey) -> None:
        self._entries.pop(self._checked(key), None)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
