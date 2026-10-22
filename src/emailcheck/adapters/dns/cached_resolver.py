"""Bounded TTL DNS reuse with single-flight lookup and task-local hit metadata."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field, replace

from emailcheck.adapters.memory.dns_cache import InMemoryDNSCache
from emailcheck.domain.dns import AddressLookup, DNSCacheKey, DNSRecordType, HostName, MXLookup
from emailcheck.ports.clock import Clock
from emailcheck.ports.dns import DNSResolver

dns_cache_used: ContextVar[bool] = ContextVar("dns_cache_used", default=False)


@dataclass
class CachedDNSResolver:
    resolver: DNSResolver
    clock: Clock
    max_entries: int = 4096
    _mx: InMemoryDNSCache[MXLookup] = field(init=False)
    _addresses: InMemoryDNSCache[AddressLookup] = field(init=False)
    _locks: tuple[asyncio.Lock, ...] = field(
        default_factory=lambda: tuple(asyncio.Lock() for _ in range(64)),
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.max_entries) is not int or not 1 <= self.max_entries <= 100_000:
            raise ValueError("DNS cache size must be 1..100000")
        self._mx = InMemoryDNSCache(self.clock, max_entries=self.max_entries)
        self._addresses = InMemoryDNSCache(self.clock, max_entries=self.max_entries)

    async def _query[T: (MXLookup, AddressLookup)](
        self,
        host: HostName,
        kind: DNSRecordType,
        cache: InMemoryDNSCache[T],
        query: Callable[[HostName], Awaitable[T]],
    ) -> T:
        key = DNSCacheKey(host=host, record_type=kind)
        async with self._locks[hash(key) % len(self._locks)]:
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
