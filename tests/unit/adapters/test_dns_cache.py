"""The in-memory DNS cache. Time comes from a manual clock, never the wall."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from emailcheck.adapters.memory.dns_cache import InMemoryDNSCache
from emailcheck.domain.dns import DNSCacheKey, DNSRecordType, HostName, apply_ttl_policy


@dataclass
class ManualClock:
    current: datetime = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


MX_KEY = DNSCacheKey(HostName("example.com"), DNSRecordType.MX)
MX_ABSENT = DNSCacheKey(HostName("absent.example"), DNSRecordType.MX)
A_KEY = DNSCacheKey(HostName("example.com"), DNSRecordType.A)


def cache(clock: ManualClock) -> InMemoryDNSCache[str]:
    return InMemoryDNSCache[str](clock=clock)


def test_a_stored_answer_is_returned_while_fresh() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_KEY, "answer", apply_ttl_policy(300, positive=True))

    clock.advance(299)
    assert store.get(MX_KEY) == "answer"


def test_an_answer_expires_exactly_at_its_applied_ttl() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_KEY, "answer", apply_ttl_policy(300, positive=True))

    clock.advance(300)
    assert store.get(MX_KEY) is None
    assert len(store) == 0


def test_a_positive_answer_cannot_outlive_the_twenty_four_hour_cap() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_KEY, "answer", apply_ttl_policy(60 * 60 * 72, positive=True))

    clock.advance(24 * 60 * 60 - 1)
    assert store.get(MX_KEY) == "answer"
    clock.advance(1)
    assert store.get(MX_KEY) is None


def test_a_negative_answer_cannot_outlive_the_three_hour_cap() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_ABSENT, "nxdomain", apply_ttl_policy(60 * 60 * 24, positive=False))

    clock.advance(3 * 60 * 60 - 1)
    assert store.get(MX_ABSENT) == "nxdomain"
    clock.advance(1)
    assert store.get(MX_ABSENT) is None


def test_a_zero_ttl_is_never_cached() -> None:
    """A server asking for no caching is obeyed rather than rounded up."""
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_KEY, "answer", apply_ttl_policy(0, positive=True))

    assert store.get(MX_KEY) is None
    assert len(store) == 0


def test_a_missing_ttl_is_cached_only_briefly() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(MX_KEY, "answer", apply_ttl_policy(None, positive=True))

    clock.advance(59)
    assert store.get(MX_KEY) == "answer"
    clock.advance(1)
    assert store.get(MX_KEY) is None


def test_storing_again_replaces_the_entry_and_its_deadline() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(A_KEY, "first", apply_ttl_policy(60, positive=True))
    clock.advance(30)
    store.set(A_KEY, "second", apply_ttl_policy(60, positive=True))

    clock.advance(31)
    assert store.get(A_KEY) == "second"


def test_entries_can_be_removed() -> None:
    clock = ManualClock()
    store = cache(clock)
    store.set(A_KEY, "value", apply_ttl_policy(300, positive=True))
    store.delete(A_KEY)
    assert store.get(A_KEY) is None

    store.set(A_KEY, "value", apply_ttl_policy(300, positive=True))
    store.clear()
    assert len(store) == 0


def test_a_missing_key_is_simply_absent() -> None:
    assert cache(ManualClock()).get(DNSCacheKey(HostName("never.example"), DNSRecordType.A)) is None


# --- key discipline -------------------------------------------------------


def test_record_types_for_one_host_never_collide() -> None:
    """A bare hostname key would have let an A answer overwrite an MX answer."""
    clock = ManualClock()
    store = cache(clock)
    host = HostName("example.com")
    ttl = apply_ttl_policy(300, positive=True)

    store.set(DNSCacheKey(host, DNSRecordType.MX), "mx-answer", ttl)
    store.set(DNSCacheKey(host, DNSRecordType.A), "a-answer", ttl)
    store.set(DNSCacheKey(host, DNSRecordType.AAAA), "aaaa-answer", ttl)

    assert store.get(DNSCacheKey(host, DNSRecordType.MX)) == "mx-answer"
    assert store.get(DNSCacheKey(host, DNSRecordType.A)) == "a-answer"
    assert store.get(DNSCacheKey(host, DNSRecordType.AAAA)) == "aaaa-answer"
    assert len(store) == 3


@pytest.mark.parametrize("spelling", ["example.com", "EXAMPLE.COM", "Example.Com.", "example.com."])
def test_host_spelling_differences_reach_the_same_entry(spelling: str) -> None:
    """`HostName` normalization is what makes the key canonical."""
    clock = ManualClock()
    store = cache(clock)
    store.set(
        DNSCacheKey(HostName("example.com"), DNSRecordType.MX),
        "answer",
        apply_ttl_policy(300, positive=True),
    )

    host = HostName.normalize(spelling)
    assert host is not None
    assert store.get(DNSCacheKey(host, DNSRecordType.MX)) == "answer"


@pytest.mark.parametrize("bad_key", ["mx:example.com", "example.com", 42, None])
def test_a_bare_key_is_refused(bad_key: object) -> None:
    store = cache(ManualClock())
    with pytest.raises(TypeError, match="DNSCacheKey"):
        store.get(bad_key)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="DNSCacheKey"):
        store.set(bad_key, "value", apply_ttl_policy(300, positive=True))  # type: ignore[arg-type]


def test_a_key_carries_no_local_part_or_complete_address() -> None:
    key = DNSCacheKey(HostName("example.com"), DNSRecordType.MX)
    assert "@" not in str(key)
    assert str(key) == "mx:example.com"
