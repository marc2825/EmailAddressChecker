"""Bounded TTL DNS reuse with per-key single-flight lookup and task-local hit metadata.

**One lock per key, never shared between keys.** Concurrent callers asking the
same question wait for the first one's upstream query and are then answered
from the cache, so a burst of identical lookups reaches the resolver once. A
caller asking a *different* question never waits: issue #2 found that the
earlier fixed pool of 64 striped locks was held across the upstream query, so
one slow lookup (up to the resolver's timeout) delayed every unrelated key that
hashed to the same stripe.

The lock table holds an entry only while some caller is using or waiting for
that key, so it is bounded by in-flight callers, which admission control bounds,
not by how many distinct names were ever asked about. Cancellation stays local
to the cancelled caller: the next waiter finds no cache entry and queries for
itself.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace

from emailcheck.adapters.memory.dns_cache import InMemoryDNSCache
from emailcheck.domain.dns import AddressLookup, DNSCacheKey, DNSRecordType, HostName, MXLookup
from emailcheck.ports.clock import Clock
from emailcheck.ports.dns import DNSResolver

dns_cache_used: ContextVar[bool] = ContextVar("dns_cache_used", default=False)


@dataclass(slots=True)
class _KeyGate:
    """The lock for one key, and how many callers currently hold or await it."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@dataclass
class CachedDNSResolver:
    resolver: DNSResolver
    clock: Clock
    max_entries: int = 4096
    _mx: InMemoryDNSCache[MXLookup] = field(init=False)
    _addresses: InMemoryDNSCache[AddressLookup] = field(init=False)
    _gates: dict[DNSCacheKey, _KeyGate] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.max_entries) is not int or not 1 <= self.max_entries <= 100_000:
            raise ValueError("DNS cache size must be 1..100000")
        self._mx = InMemoryDNSCache(self.clock, max_entries=self.max_entries)
        self._addresses = InMemoryDNSCache(self.clock, max_entries=self.max_entries)

    @asynccontextmanager
    async def _exclusive(self, key: DNSCacheKey) -> AsyncIterator[None]:
        """Hold `key`'s lock, creating it on first use and dropping it on last.

        There is no `await` between looking the gate up and counting this
        caller, so on one event loop no other caller can remove it in between.
        The count is released in `finally`, so a caller cancelled while waiting
        does not leave an entry behind.
        """
        gate = self._gates.get(key)
        if gate is None:
            gate = self._gates[key] = _KeyGate()
        gate.users += 1
        try:
            async with gate.lock:
                yield
        finally:
            gate.users -= 1
            if gate.users == 0:
                del self._gates[key]

    async def _query[T: (MXLookup, AddressLookup)](
        self,
        host: HostName,
        kind: DNSRecordType,
        cache: InMemoryDNSCache[T],
        query: Callable[[HostName], Awaitable[T]],
    ) -> T:
        key = DNSCacheKey(host=host, record_type=kind)
        async with self._exclusive(key):
            cached = cache.get(key)
            remaining = cache.remaining_ttl(key)
            if cached is not None and remaining is not None:
                dns_cache_used.set(True)
                return replace(cached, ttl=remaining)
            result = await query(host)
            if result.ttl is not None:
                cache.set(key, result, result.ttl)
            return result

    async def query_mx(self, domain: HostName) -> MXLookup:
        return await self._query(domain, DNSRecordType.MX, self._mx, self.resolver.query_mx)

    async def query_a(self, host: HostName) -> AddressLookup:
        return await self._query(host, DNSRecordType.A, self._addresses, self.resolver.query_a)

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        return await self._query(
            host, DNSRecordType.AAAA, self._addresses, self.resolver.query_aaaa
        )
