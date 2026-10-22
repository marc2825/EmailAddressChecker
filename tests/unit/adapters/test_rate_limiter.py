"""The production limiter: what it refuses, and what it never leaks.

Not one of these tests sleeps. Every delay goes through the injected `Sleeper`,
which advances a fake `MonotonicClock` and yields, so "wait five seconds for a
token" is a measurement rather than five seconds of CI. That is the whole reason
suspension is a port: a pacing test that actually waited would be measuring the
machine, and the 4C review already established what a deadline test that
measures the wrong thing is worth.

The properties that matter most are the leaks. A slot taken and not returned
removes capacity from the process permanently, and no amount of retrying gets it
back — the same shape as the descriptor leak the 4B review found in `close`.
"""

from __future__ import annotations

import asyncio

import pytest

from dialogue_fixtures import BlockingSleeper, FakeMonotonicClock, FakeSleeper
from emailcheck.adapters.system.rate_limit import InProcessRateLimiter
from emailcheck.domain.rate_limit import RateLimitError, RateLimitSettings, RateLimitTimeout

pytestmark = pytest.mark.asyncio

#: Every test carries its own outer bound, so a limiter that waits when it
#: should refuse fails rather than hangs. A gate that hangs is not a gate.
OUTER_BOUND_SECONDS = 5.0


def limiter(**overrides: object) -> tuple[InProcessRateLimiter, FakeMonotonicClock, FakeSleeper]:
    """A limiter on a clock a test moves by hand.

    Lowering the global concurrency lowers the per-domain one with it unless the
    test says otherwise, because a domain may not be given more than the service
    has — a coherence rule the settings enforce and this helper respects rather
    than works around.
    """
    limits = dict(overrides)
    if "global_concurrency" in limits and "domain_concurrency" not in limits:
        limits["domain_concurrency"] = min(
            RateLimitSettings().domain_concurrency,
            int(limits["global_concurrency"]),  # type: ignore[call-overload]
        )
    clock = FakeMonotonicClock()
    sleeper = FakeSleeper(clock=clock)
    settings = RateLimitSettings(**limits)  # type: ignore[arg-type]
    return InProcessRateLimiter(clock=clock, sleeper=sleeper, settings=settings), clock, sleeper


async def acquire(
    limits: InProcessRateLimiter, domain: str = "example.com", account: str = "acct-1"
) -> object:
    return limits.acquire(account=account, domain=domain, mx_host=f"mx.{domain}")


# --- the ordinary path ------------------------------------------------------


async def test_a_first_probe_is_granted_without_waiting() -> None:
    """A full bucket is what a new domain starts with, so nothing is paced."""
    limits, _, sleeper = limiter()

    async with await acquire(limits):
        assert limits.active_leases == 1

    assert limits.active_leases == 0
    assert sleeper.slept == []


async def test_a_lease_releases_on_the_way_out_of_the_block() -> None:
    limits, _, _ = limiter()

    async with await acquire(limits):
        pass
    async with await acquire(limits):
        pass

    assert limits.active_leases == 0


async def test_a_lease_releases_when_the_body_raises() -> None:
    """A probe that fails must not cost a slot for the life of the process."""
    limits, _, _ = limiter()

    with pytest.raises(RuntimeError):
        async with await acquire(limits):
            raise RuntimeError("the probe failed")

    assert limits.active_leases == 0


# --- global concurrency -----------------------------------------------------


async def test_the_global_concurrency_cap_is_enforced() -> None:
    limits, _, _ = limiter(global_concurrency=2, domain_concurrency=2)

    first = await acquire(limits)
    second = await acquire(limits, domain="a.example")
    await first.__aenter__()  # type: ignore[attr-defined]
    await second.__aenter__()  # type: ignore[attr-defined]

    assert limits.active_leases == 2

    third = await acquire(limits, domain="b.example")
    with pytest.raises(RateLimitTimeout, match="the service"):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            await third.__aenter__()  # type: ignore[attr-defined]

    await first.__aexit__(None, None, None)  # type: ignore[attr-defined]
    await second.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


async def test_a_released_slot_lets_a_waiter_through() -> None:
    """The "wait, then permit" path, driven without a real delay.

    The fake sleeper yields, so the releasing task runs while the waiter is
    nominally asleep — which is exactly the interleaving a real wait produces.
    """
    limits, _, _ = limiter(global_concurrency=1, domain_concurrency=1)

    holder = await acquire(limits)
    await holder.__aenter__()  # type: ignore[attr-defined]

    async def release_soon() -> None:
        await asyncio.sleep(0)
        await holder.__aexit__(None, None, None)  # type: ignore[attr-defined]

    async def wait_for_it() -> bool:
        async with await acquire(limits, domain="b.example"):
            return True
        return False

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        released, granted = await asyncio.gather(release_soon(), wait_for_it())

    assert granted is True
    assert released is None
    assert limits.active_leases == 0


async def test_the_per_domain_concurrency_cap_is_enforced() -> None:
    """One busy domain may not consume the whole service."""
    limits, _, _ = limiter(global_concurrency=4, domain_concurrency=1)

    held = await acquire(limits, domain="busy.example")
    await held.__aenter__()  # type: ignore[attr-defined]

    with pytest.raises(RateLimitTimeout, match="the domain"):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            async with await acquire(limits, domain="busy.example"):
                pass

    # And another domain is unaffected, which is what makes it *per domain*.
    async with await acquire(limits, domain="quiet.example"):
        assert limits.active_leases == 2

    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


# --- pacing -----------------------------------------------------------------


async def test_a_domain_is_paced_once_its_burst_is_spent() -> None:
    """The burst is the capacity; after that it is one probe per refill."""
    limits, clock, sleeper = limiter(domain_capacity=2, domain_refill_seconds=5.0)

    for _ in range(2):
        async with await acquire(limits, domain="paced.example"):
            pass
    assert sleeper.slept == []

    started = clock.value
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        async with await acquire(limits, domain="paced.example"):
            pass

    assert sleeper.slept == [pytest.approx(5.0)]
    assert clock.value - started == pytest.approx(5.0)


async def test_pacing_refuses_rather_than_waiting_past_the_budget() -> None:
    """Waiting out a budget that cannot be met holds a slot for nothing."""
    limits, _, sleeper = limiter(
        domain_capacity=1, domain_refill_seconds=60.0, wait_budget_seconds=5.0
    )

    async with await acquire(limits, domain="slow.example"):
        pass

    with pytest.raises(RateLimitTimeout, match="pacing"):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            async with await acquire(limits, domain="slow.example"):
                pass

    assert sleeper.slept == [], "it slept before deciding it could not succeed"


async def test_pacing_is_per_domain_and_not_global() -> None:
    limits, _, sleeper = limiter(domain_capacity=1, domain_refill_seconds=5.0)

    async with await acquire(limits, domain="one.example"):
        pass
    async with await acquire(limits, domain="two.example"):
        pass

    assert sleeper.slept == []


async def test_a_domain_recovers_its_burst_while_idle() -> None:
    """And recovers exactly its burst, never more.

    The third acquisition after the refill is paced again, which is what shows
    the bucket refilled to two rather than to however many seconds went by.
    """
    limits, clock, sleeper = limiter(domain_capacity=2, domain_refill_seconds=5.0)

    for _ in range(2):
        async with await acquire(limits, domain="paced.example"):
            pass

    clock.advance(600.0)
    for _ in range(2):
        async with await acquire(limits, domain="paced.example"):
            pass
    assert sleeper.slept == [], "the idle time refilled the burst"

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        async with await acquire(limits, domain="paced.example"):
            pass
    assert sleeper.slept == [pytest.approx(5.0)], "ten minutes idle bought two, not more"


# --- the wait budget --------------------------------------------------------


async def test_the_wait_budget_bounds_the_whole_acquisition() -> None:
    """Three budgets share one deadline, so three steps cost one budget."""
    limits, clock, _ = limiter(global_concurrency=1, domain_concurrency=1, wait_budget_seconds=4.0)

    held = await acquire(limits, domain="a.example")
    await held.__aenter__()  # type: ignore[attr-defined]

    started = clock.value
    with pytest.raises(RateLimitTimeout):
        async with asyncio.timeout(OUTER_BOUND_SECONDS):
            async with await acquire(limits, domain="b.example"):
                pass

    assert clock.value - started == pytest.approx(4.0)
    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]


async def test_a_refused_acquisition_leaves_nothing_held() -> None:
    """The leak that would remove capacity from the process for good."""
    limits, _, _ = limiter(global_concurrency=2, domain_concurrency=1)

    held = await acquire(limits, domain="busy.example")
    await held.__aenter__()  # type: ignore[attr-defined]
    assert limits.active_leases == 1

    for _ in range(3):
        with pytest.raises(RateLimitTimeout):
            async with asyncio.timeout(OUTER_BOUND_SECONDS):
                async with await acquire(limits, domain="busy.example"):
                    pass
        # The global slot taken on the way to the domain check is given back
        # every time. Without that, three refusals would exhaust the service.
        assert limits.active_leases == 1

    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


# --- cancellation -----------------------------------------------------------


async def test_a_cancellation_while_waiting_leaks_no_slot() -> None:
    """A worker told to stop must not take capacity with it."""
    limits, _, _ = limiter(global_concurrency=1, domain_concurrency=1)

    held = await acquire(limits, domain="a.example")
    await held.__aenter__()  # type: ignore[attr-defined]

    async def waits() -> None:
        async with await acquire(limits, domain="b.example"):
            pass

    task = asyncio.create_task(waits())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert limits.active_leases == 1
    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


async def test_a_cancellation_holding_the_global_slot_gives_it_back() -> None:
    """The leak the test above cannot see, and the one that matters.

    Cancelling a caller that has not acquired anything yet proves nothing: the
    unwind has nothing to unwind. A caller waiting for the *domain* slot is
    already holding the *global* one, so a cancellation there removes capacity
    from the whole process permanently unless it is given back — and it is
    permanent, because nothing ever counts it again.

    A mutation from `except BaseException` to `except Exception` passed the
    entire suite before this existed. `CancelledError` does not derive from
    `Exception`, which is the whole reason the wider clause is there.
    """
    clock = FakeMonotonicClock()
    sleeper = BlockingSleeper()
    limits = InProcessRateLimiter(
        clock=clock,
        sleeper=sleeper,
        settings=RateLimitSettings(global_concurrency=2, domain_concurrency=1),
    )

    held = limits.acquire(account="a", domain="busy.example", mx_host="mx.busy.example")
    await held.__aenter__()
    assert limits.active_leases == 1

    async def waits_for_the_domain() -> None:
        async with limits.acquire(account="a", domain="busy.example", mx_host="mx.busy.example"):
            pass

    task = asyncio.create_task(waits_for_the_domain())
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        await sleeper.entered.wait()

    # It got past the global check and is parked on the domain one.
    assert limits.active_leases == 2

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert limits.active_leases == 1, "the global slot was not given back"
    await held.__aexit__(None, None, None)
    assert limits.active_leases == 0


async def test_a_cancellation_while_paced_gives_both_slots_back() -> None:
    """Cancelled waiting for a token, holding the global and domain slots."""
    clock = FakeMonotonicClock()
    sleeper = BlockingSleeper()
    limits = InProcessRateLimiter(
        clock=clock,
        sleeper=sleeper,
        # The budget has to be longer than the refill, or the limiter refuses
        # before it sleeps and there is no wait to cancel.
        settings=RateLimitSettings(
            domain_capacity=1, domain_refill_seconds=60.0, wait_budget_seconds=100.0
        ),
    )

    async with limits.acquire(account="a", domain="paced.example", mx_host="mx.paced.example"):
        pass
    assert limits.active_leases == 0

    async def waits_for_a_token() -> None:
        async with limits.acquire(account="a", domain="paced.example", mx_host="mx.paced.example"):
            pass

    task = asyncio.create_task(waits_for_a_token())
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        await sleeper.entered.wait()

    assert limits.active_leases == 1
    assert sleeper.calls == [pytest.approx(60.0)]

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert limits.active_leases == 0, "a slot was held by a cancelled caller"


async def test_a_cancellation_after_the_lease_is_held_still_releases() -> None:
    limits, _, _ = limiter()

    async def works() -> None:
        async with await acquire(limits):
            await asyncio.get_running_loop().create_future()

    task = asyncio.create_task(works())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert limits.active_leases == 0


async def test_a_cancellation_is_never_converted_into_a_refusal() -> None:
    """`CancelledError` is process control, not a budget decision.

    The same rule the transport and the dialogue follow: a worker told to stop
    must not be answered with a fact about a limit.
    """
    limits, _, _ = limiter(global_concurrency=1, domain_concurrency=1)

    held = await acquire(limits, domain="a.example")
    await held.__aenter__()  # type: ignore[attr-defined]

    async def waits() -> None:
        async with await acquire(limits, domain="b.example"):
            pass

    task = asyncio.create_task(waits())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]


# --- the lease itself -------------------------------------------------------


async def test_a_lease_cannot_be_entered_twice() -> None:
    """Two acquisitions and one release is a slot that never comes back."""
    limits, _, _ = limiter()
    lease = await acquire(limits)

    await lease.__aenter__()  # type: ignore[attr-defined]
    with pytest.raises(RateLimitError):
        await lease.__aenter__()  # type: ignore[attr-defined]
    await lease.__aexit__(None, None, None)  # type: ignore[attr-defined]

    assert limits.active_leases == 0


async def test_releasing_twice_does_not_return_a_slot_twice() -> None:
    """The leak in the other direction: one more probe than the limit allows."""
    limits, _, _ = limiter(global_concurrency=1)
    lease = await acquire(limits)

    await lease.__aenter__()  # type: ignore[attr-defined]
    await lease.__aexit__(None, None, None)  # type: ignore[attr-defined]
    await lease.__aexit__(None, None, None)  # type: ignore[attr-defined]

    assert limits.active_leases == 0


async def test_a_lease_that_was_never_entered_releases_nothing() -> None:
    limits, _, _ = limiter()
    lease = await acquire(limits)

    await lease.__aexit__(None, None, None)  # type: ignore[attr-defined]

    assert limits.active_leases == 0


# --- the state table is bounded --------------------------------------------


async def test_an_unbounded_stream_of_domains_produces_bounded_state() -> None:
    """The attack: a caller supplies a new domain every time, forever.

    Without a bound this is a memory leak with a remote trigger, and nothing
    else in the process would notice it happening.
    """
    limits, _, _ = limiter(max_tracked_domains=16)

    for index in range(500):
        try:
            async with await acquire(limits, domain=f"host-{index}.example"):
                pass
        except RateLimitTimeout:
            pass  # A full table refuses rather than resetting a spent bucket.

    assert limits.tracked_domains <= 16


async def test_an_idle_domain_is_evicted_after_its_ttl() -> None:
    limits, clock, _ = limiter(idle_ttl_seconds=60.0, max_tracked_domains=1000)

    async with await acquire(limits, domain="briefly.example"):
        pass
    assert limits.tracked_domains == 1

    clock.advance(120.0)
    async with await acquire(limits, domain="later.example"):
        pass

    assert limits.tracked_domains == 1


def tracked_state(limits: InProcessRateLimiter, domain: str) -> object:
    """The live state object for one domain, or `None` if it was evicted.

    Reaching into `_domains` is deliberate. "The entry survived" is the property
    under test, and every observable *consequence* of losing it — a balanced
    counter, a successful release — is also produced by an orphaned entry. Only
    identity distinguishes them.
    """
    return limits._domains.get(domain)


async def test_a_held_entry_survives_a_ttl_sweep_that_would_have_evicted_it() -> None:
    """The TTL guard, pinned on its own, with the consequence asserted.

    Losing this is a **pacing bypass**: the entry below has spent one of its two
    tokens, and an eviction would replace it with a fresh full bucket the moment
    the next caller arrives. The Phase 4 final review found that removing
    `state.is_idle` from the TTL sweep left the whole suite passing.

    The TTL here is one second while the lease is held for ten thousand — a
    configuration that is entirely legal, because the TTL applies to *idle*
    entries and this one is not idle.
    """
    limits, clock, _ = limiter(
        idle_ttl_seconds=1.0,
        max_tracked_domains=1000,
        domain_capacity=2,
        domain_refill_seconds=600.0,
        global_concurrency=4,
        domain_concurrency=2,
    )

    held = await acquire(limits, domain="held.example")
    await held.__aenter__()  # type: ignore[attr-defined]
    original = tracked_state(limits, "held.example")
    assert original is not None
    spent = original.bucket.tokens  # type: ignore[attr-defined]
    assert spent == 1.0, "one of the two tokens is gone"

    # Far beyond the TTL, and the lease is still held.
    clock.advance(10_000.0)
    async with await acquire(limits, domain="sweeps.example"):
        pass

    survivor = tracked_state(limits, "held.example")
    assert survivor is not None, "the held entry was evicted by the TTL sweep"
    assert survivor is original, "the entry was replaced rather than kept"
    assert survivor.bucket.tokens == spent, "the bucket was reset — a pacing bypass"  # type: ignore[attr-defined]

    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


async def test_a_held_entry_survives_lru_pressure_that_would_have_evicted_it() -> None:
    """The LRU guard, pinned separately so the TTL guard cannot cover for it.

    The clock never advances here, so the TTL sweep selects nothing at all and
    only the cap can evict. The held entry is the least recently used — it was
    claimed first and never re-claimed — so it is exactly what an unguarded LRU
    pass would drop first.
    """
    limits, _, _ = limiter(
        # The cap must be at least the global concurrency — an entry in use
        # cannot be evicted, so a smaller cap would be one that cannot be
        # honoured, and `RateLimitSettings` refuses it.
        max_tracked_domains=2,
        idle_ttl_seconds=86_400.0,
        global_concurrency=2,
        domain_concurrency=1,
        domain_capacity=2,
        domain_refill_seconds=600.0,
    )

    held = await acquire(limits, domain="held.example")
    await held.__aenter__()  # type: ignore[attr-defined]
    original = tracked_state(limits, "held.example")
    assert original is not None
    spent = original.bucket.tokens  # type: ignore[attr-defined]

    for index in range(20):
        try:
            async with await acquire(limits, domain=f"flood-{index}.example"):
                pass
        except RateLimitTimeout:
            pass

    survivor = tracked_state(limits, "held.example")
    assert survivor is not None, "the held entry was evicted under LRU pressure"
    assert survivor is original, "the entry was replaced rather than kept"
    assert survivor.bucket.tokens == spent, "the bucket was reset — a pacing bypass"  # type: ignore[attr-defined]

    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


async def test_a_waiting_entry_is_never_evicted_either() -> None:
    """A caller that has registered interest holds the entry it will spend from.

    `_claim` runs before global admission, so a waiter owns an entry before it
    owns a slot. Evicting it would hand that waiter a bucket the table no longer
    knows about.
    """
    clock = FakeMonotonicClock()
    sleeper = BlockingSleeper()
    limits = InProcessRateLimiter(
        clock=clock,
        sleeper=sleeper,
        # Three global slots: one for the holder, one the waiter takes on its way
        # to the domain check, and one left so the sweeping acquire below can
        # complete rather than parking on a sleeper that never returns.
        settings=RateLimitSettings(
            global_concurrency=3, domain_concurrency=1, max_tracked_domains=3, idle_ttl_seconds=1.0
        ),
    )

    held = limits.acquire(account="a", domain="busy.example", mx_host="mx.busy.example")
    await held.__aenter__()

    async def waits() -> None:
        async with limits.acquire(account="a", domain="busy.example", mx_host="mx.busy.example"):
            pass

    task = asyncio.create_task(waits())
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        await sleeper.entered.wait()

    waiting = tracked_state(limits, "busy.example")
    assert waiting is not None
    assert waiting.waiters >= 1  # type: ignore[attr-defined]

    clock.advance(10_000.0)
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        async with limits.acquire(account="a", domain="elsewhere.example", mx_host="mx.e.example"):
            pass

    assert tracked_state(limits, "busy.example") is waiting, "an entry with a waiter was evicted"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await held.__aexit__(None, None, None)
    assert limits.active_leases == 0


async def test_a_short_ttl_is_a_legal_configuration() -> None:
    """The TTL need not exceed the longest SMTP session, and does not have to.

    An active entry is protected by not being idle, not by arithmetic between
    two unrelated settings. This asserts the relationship the documentation
    claims rather than leaving it as prose.
    """
    from emailcheck.domain.smtp_deadline import MAX_SESSION_SECONDS

    limits, clock, _ = limiter(idle_ttl_seconds=1.0, max_tracked_domains=1000)
    assert limits.settings.idle_ttl_seconds < MAX_SESSION_SECONDS

    held = await acquire(limits, domain="slow.example")
    await held.__aenter__()  # type: ignore[attr-defined]
    original = tracked_state(limits, "slow.example")

    clock.advance(MAX_SESSION_SECONDS + 1.0)
    async with await acquire(limits, domain="other.example"):
        pass

    assert tracked_state(limits, "slow.example") is original
    await held.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


async def test_eviction_under_pressure_never_leaves_a_negative_count() -> None:
    """Two held entries survive a flood of others, and release cleanly.

    An entry evicted while held would be re-created empty on release, and the
    counter that came back would be a different counter — which shows up later
    as capacity that is either missing or duplicated, long after the eviction.
    """
    limits, clock, _ = limiter(
        global_concurrency=4, domain_concurrency=1, max_tracked_domains=4, idle_ttl_seconds=1.0
    )

    first = await acquire(limits, domain="one.example")
    second = await acquire(limits, domain="two.example")
    await first.__aenter__()  # type: ignore[attr-defined]
    await second.__aenter__()  # type: ignore[attr-defined]
    assert limits.active_leases == 2

    clock.advance(500.0)
    for index in range(30):
        try:
            async with await acquire(limits, domain=f"flood-{index}.example"):
                pass
        except RateLimitTimeout:
            pass

    assert limits.tracked_domains <= 4
    await first.__aexit__(None, None, None)  # type: ignore[attr-defined]
    await second.__aexit__(None, None, None)  # type: ignore[attr-defined]
    assert limits.active_leases == 0


# --- neutrality and privacy -------------------------------------------------


async def test_the_limiter_treats_every_domain_the_same() -> None:
    """A provider-specific quota would be a rule nobody looks for here.

    The wait budget is shorter than the refill, so the second acquisition for
    each domain is refused rather than paced — and it is refused identically for
    a household name and for a domain nobody has heard of.
    """
    limits, _, _ = limiter(domain_capacity=1, domain_refill_seconds=60.0, wait_budget_seconds=5.0)

    for domain in ("gmail.com", "outlook.com", "some-small-host.test.example"):
        async with await acquire(limits, domain=domain):
            pass
        with pytest.raises(RateLimitTimeout):
            async with asyncio.timeout(OUTER_BOUND_SECONDS):
                async with await acquire(limits, domain=domain):
                    pass


async def test_a_complete_address_never_reaches_the_limiter() -> None:
    """The caller is refused at the boundary rather than storing one."""
    limits, _, _ = limiter()

    with pytest.raises(RateLimitError):
        limits.acquire(account="acct-1", domain="person@example.com", mx_host="mx.example.com")


async def test_shared_mx_pacing_and_temporary_backoff() -> None:
    limits, clock, _ = limiter(domain_capacity=1, domain_refill_seconds=30, wait_budget_seconds=10)
    async with limits.acquire(account="a", domain="a.example", mx_host="mx.provider.example"):
        pass
    with pytest.raises(RateLimitTimeout):
        async with limits.acquire(account="b", domain="b.example", mx_host="MX.PROVIDER.EXAMPLE."):
            pass
    assert limits.active_leases == 0
    clock.advance(30)
    limits.defer("a.example", "mx.provider.example")
    with pytest.raises(RateLimitTimeout):
        async with limits.acquire(account="b", domain="c.example", mx_host="mx.provider.example"):
            pass
    clock.advance(60)
    async with limits.acquire(account="b", domain="c.example", mx_host="mx.provider.example"):
        pass
    assert limits.active_leases == 0


async def test_idle_ttl_and_capacity_never_reset_spent_tokens() -> None:
    limits, clock, _ = limiter(
        global_concurrency=1,
        max_tracked_domains=1,
        domain_capacity=1,
        domain_refill_seconds=60,
        idle_ttl_seconds=1,
        wait_budget_seconds=1,
    )
    async with await acquire(limits):
        pass
    clock.advance(2)
    with pytest.raises(RateLimitTimeout):
        async with await acquire(limits, domain="other.example"):
            pass
    with pytest.raises(RateLimitTimeout):
        async with await acquire(limits):
            pass
    assert limits.tracked_domains == 1
    assert limits.active_leases == 0
