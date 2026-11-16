"""The caching resolver's concurrency: coalesce one key, never block another.

Issue #2 found that the cache held one of 64 striped locks across the upstream
query, so a slow lookup (up to the resolver's timeout) delayed every unrelated
key that happened to hash to the same stripe. These tests pin the contract the
fix restores, against a resolver the test releases by hand: nothing sleeps,
and nothing reaches a real resolver (`tests/conftest.py` blocks sockets).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

import pytest

from emailcheck.adapters.dns.cached_resolver import CachedDNSResolver, dns_cache_used
from emailcheck.domain.dns import (
    AddressLookup,
    DNSFailure,
    HostName,
    MXLookup,
    apply_ttl_policy,
)

#: Generous, because nothing here waits on time: on a regression the slow
#: lookup is never released, and this bound turns a hang into a failure.
OUTER_BOUND: Final = 5.0

SLOW: Final = "slow.example"

#: Enough unrelated hosts that, under any fixed striping of a few dozen locks,
#: at least one shares the slow host's stripe. With the original 64 stripes the
#: chance that none does is (63/64)**1024, about 1e-7.
UNRELATED: Final = 1024


@dataclass
class FixedClock:
    current: datetime = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


@dataclass
class GatedResolver:
    """Answers at once, except that the MX lookup for `SLOW` waits for `release`."""

    release: asyncio.Event = field(default_factory=asyncio.Event)
    calls: list[tuple[str, str]] = field(default_factory=list)
    cacheable: bool = True

    async def _gate(self, kind: str, host: HostName) -> None:
        self.calls.append((kind, host.value))
        if (kind, host.value) == ("mx", SLOW):
            await self.release.wait()

    async def query_mx(self, domain: HostName) -> MXLookup:
        await self._gate("mx", domain)
        ttl = apply_ttl_policy(60, positive=False) if self.cacheable else None
        return MXLookup(failure=DNSFailure.NXDOMAIN, ttl=ttl)

    async def query_a(self, host: HostName) -> AddressLookup:
        await self._gate("a", host)
        return AddressLookup(addresses=("93.184.216.34",), ttl=apply_ttl_policy(300, positive=True))

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        await self._gate("aaaa", host)
        return AddressLookup(
            failure=DNSFailure.NO_RECORDS, ttl=apply_ttl_policy(300, positive=False)
        )


def build() -> tuple[CachedDNSResolver, GatedResolver]:
    upstream = GatedResolver()
    return CachedDNSResolver(upstream, FixedClock()), upstream


async def settle() -> None:
    """Let every runnable task reach its next suspension point."""
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_a_pending_lookup_never_delays_a_different_key() -> None:
    """The issue itself: unrelated domains must not serialize behind a slow one."""
    resolver, upstream = build()
    slow = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()

    async with asyncio.timeout(OUTER_BOUND):
        await asyncio.gather(
            *(resolver.query_mx(HostName(f"d{i}.example")) for i in range(UNRELATED)),
            # Same host, other record types: different keys, so not delayed either.
            resolver.query_a(HostName(SLOW)),
            resolver.query_aaaa(HostName(SLOW)),
        )

    assert not slow.done()
    upstream.release.set()
    async with asyncio.timeout(OUTER_BOUND):
        await slow
    assert resolver._gates == {}


@pytest.mark.asyncio
async def test_concurrent_lookups_for_one_key_reach_the_resolver_once() -> None:
    """Coalescing is kept: the second caller waits and is answered from cache."""
    resolver, upstream = build()

    async def lookup() -> tuple[MXLookup, bool]:
        answer = await resolver.query_mx(HostName(SLOW))
        return answer, dns_cache_used.get()

    first = asyncio.create_task(lookup())
    await settle()
    second = asyncio.create_task(lookup())
    await settle()
    assert upstream.calls == [("mx", SLOW)]

    upstream.release.set()
    async with asyncio.timeout(OUTER_BOUND):
        (first_answer, first_hit), (second_answer, second_hit) = await asyncio.gather(first, second)

    assert upstream.calls == [("mx", SLOW)]
    assert first_answer.failure is second_answer.failure is DNSFailure.NXDOMAIN
    # The flag is task-local: only the caller answered from cache reports a hit.
    assert (first_hit, second_hit) == (False, True)
    assert resolver._gates == {}


@pytest.mark.asyncio
async def test_an_uncacheable_answer_is_not_shared_with_a_waiting_caller() -> None:
    """Unchanged semantics: no TTL means no cache entry, so the waiter asks again."""
    resolver, upstream = build()
    upstream.cacheable = False
    first = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()
    second = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()

    upstream.release.set()
    async with asyncio.timeout(OUTER_BOUND):
        await asyncio.gather(first, second)

    assert upstream.calls == [("mx", SLOW), ("mx", SLOW)]


@pytest.mark.asyncio
async def test_a_cancelled_waiter_leaves_no_lock_behind() -> None:
    """The lock table holds only keys with live callers, so it stays bounded."""
    resolver, upstream = build()
    leader = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()
    waiter = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    upstream.release.set()
    async with asyncio.timeout(OUTER_BOUND):
        await leader

    assert upstream.calls == [("mx", SLOW)]
    assert resolver._gates == {}


@pytest.mark.asyncio
async def test_a_cancelled_lookup_does_not_cancel_the_caller_behind_it() -> None:
    """Cancelling one caller's query is not a failure for another caller."""
    resolver, upstream = build()
    leader = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()
    follower = asyncio.create_task(resolver.query_mx(HostName(SLOW)))
    await settle()

    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader
    upstream.release.set()
    async with asyncio.timeout(OUTER_BOUND):
        answer = await follower

    assert answer.failure is DNSFailure.NXDOMAIN
    # The follower found no cache entry and asked for itself.
    assert upstream.calls == [("mx", SLOW), ("mx", SLOW)]
    assert resolver._gates == {}
