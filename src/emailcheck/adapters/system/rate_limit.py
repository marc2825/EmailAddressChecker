"""The rate limiter gate 4C left as a contract, implemented.

`SMTPProbeService` has taken a `RateLimiter` with no default since 4C, so the
ordering — authorization before a socket — has been enforced by the type for two
gates. What did not exist was anything that said no. This does.

**Single process, and shaped so that is not permanent.** Everything below is an
in-memory counter, so it bounds one worker and not a fleet. That is the right
size for the MVP and it is why the port exists: a Redis or database limiter
implements the same `acquire`, and nothing above this module learns which one it
has. `docs/requirements.md` section 15 makes a shared limiter part of the
service-active profile, which is Phase 6 and later.

**Nothing here decides how long.** Every duration and every bound comes from
`domain/rate_limit.py`, computed against a `MonotonicClock`. This module holds
the counters, the waiting, and the eviction — the parts that need a loop.

**Waiting is bounded, and it is not the session budget.** ADR 0009 put the
rate-limit wait deliberately outside the SMTP session deadline, because a budget
spanning it would record this project's own queue depth as a remote timeout.
That leaves the wait itself needing a bound of its own, and
`RateLimitSettings.wait_budget_seconds` is it. Exceeding it raises
`RateLimitTimeout`, which is not an SMTP outcome and never becomes one.

**Budgets partition independently on recipient domain and MX host.** `acquire`
takes an account, a domain, and an MX host; all three are canonicalized and
validated, and `_enter` claims separate domain and MX state. Both budgets
are shared across accounts; one provider cannot gain extra capacity merely by
hosting more recipient domains. Account-specific volume is AbuseGuard's concern.

**No branch anywhere reads a host name.** Every key component is an opaque
canonical string. A limiter that gave one provider a different quota would be a
provider-specific rule in the one place nobody looks for one, and an inspection
test refuses it.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from types import TracebackType

from emailcheck.domain.rate_limit import (
    RateLimitError,
    RateLimitKey,
    RateLimitSettings,
    RateLimitTimeout,
    TokenBucket,
    new_bucket,
    rate_limit_key,
)
from emailcheck.ports.clock import MonotonicClock, Sleeper


@dataclass(slots=True)
class _DomainState:
    """One domain's pacing and occupancy.

    `waiters` exists so an entry cannot be evicted out from under a coroutine
    that is waiting to use it. A caller registers interest before it waits for
    anything, and eviction skips every entry with an interest or an active
    lease, so the bucket a caller is waiting on is still the bucket it spends
    from.
    """

    bucket: TokenBucket
    active: int = 0
    waiters: int = 0
    touched_at: float = 0.0
    blocked_until: float = 0.0

    @property
    def is_idle(self) -> bool:
        return self.active == 0 and self.waiters == 0


@dataclass(slots=True)
class InProcessRateLimiter:
    """Global concurrency, per-domain concurrency, and per-domain pacing.

    Three budgets, acquired in that order and released in reverse, all inside
    one wait budget. A caller either holds all three or holds none: a partial
    acquisition is unwound before the exception leaves, so a refusal or a
    cancellation cannot leave a slot counted against a probe that never ran.
    """

    clock: MonotonicClock
    sleeper: Sleeper
    settings: RateLimitSettings = field(default_factory=RateLimitSettings)
    _domains: OrderedDict[str, _DomainState] = field(default_factory=OrderedDict)
    _mx_domains: OrderedDict[str, _DomainState] = field(default_factory=OrderedDict)
    _active: int = 0
    #: Replaced rather than cleared on every release, so a waiter that has
    #: already taken a reference cannot miss the signal it is waiting for.
    _change: asyncio.Event = field(default_factory=asyncio.Event)

    def acquire(self, *, account: str, domain: str, mx_host: str) -> _Lease:
        """Name the budgets. Nothing is held until the lease is entered.

        The key is canonicalized and validated here, so a caller that passes a
        complete address fails at the boundary rather than storing one.
        """
        return _Lease(
            limiter=self,
            key=rate_limit_key(account=account, domain=domain, mx_host=mx_host),
        )

    @property
    def active_leases(self) -> int:
        """How many leases are held right now. Zero when nothing is in flight."""
        return self._active

    @property
    def tracked_domains(self) -> int:
        """How many domains hold state. Bounded; see `_evict`."""
        return len(self._domains)

    # --- acquiring ----------------------------------------------------------

    async def _enter(self, key: RateLimitKey) -> tuple[_DomainState, _DomainState]:
        deadline = self.clock.monotonic() + self.settings.wait_budget_seconds
        domain = self._claim(key.domain)
        try:
            mx = self._claim(key.mx_host, mx=True)
        except BaseException:
            domain.waiters -= 1
            raise
        states = (domain, mx)
        held: list[_DomainState] = []
        holds_global = False
        try:
            await self._wait_until(
                lambda: self._active < self.settings.global_concurrency, deadline, "the service"
            )
            self._active += 1
            holds_global = True
            for state in states:

                def available(state: _DomainState = state) -> bool:
                    return state.active < self.settings.domain_concurrency

                await self._wait_until(
                    available,
                    deadline,
                    "the domain" if state is domain else "the exchanger",
                )
                state.active += 1
                held.append(state)
                await self._wait_for_token(state, deadline)
        except BaseException:
            for state in held:
                state.active -= 1
            if holds_global:
                self._active -= 1
            self._signal()
            raise
        finally:
            for state in states:
                state.waiters -= 1
                state.touched_at = self.clock.monotonic()
        return states

    def _exit(self, states: tuple[_DomainState, _DomainState]) -> None:
        for state in states:
            state.active -= 1
            state.touched_at = self.clock.monotonic()
            if state.active < 0:
                raise RateLimitError("a destination slot was released more than once")
        self._active -= 1
        if self._active < 0:
            raise RateLimitError("a rate-limit slot was released more than once")
        self._signal()

    def defer(self, domain: str, mx_host: str) -> None:
        """Back off future operations for at least 60s after a temporary reply.

        This schedules no retry and never permits another recipient touch.
        Both keys are canonicalized and no mailbox is retained.
        """
        key = rate_limit_key(account="pacing", domain=domain, mx_host=mx_host)
        now = self.clock.monotonic()
        for name, is_mx in ((key.domain, False), (key.mx_host, True)):
            state = self._claim(name, mx=is_mx)
            state.waiters -= 1
            state.blocked_until = max(state.blocked_until, now + 60.0)
        self._signal()

    async def _wait_until(self, permitted: Callable[[], bool], deadline: float, scope: str) -> None:
        """Wait for a counter to allow one more, inside the shared deadline."""
        while not permitted():
            remaining = deadline - self.clock.monotonic()
            if remaining <= 0:
                raise RateLimitTimeout(scope)
            await self._wait_for_change(remaining)

    async def _wait_for_token(self, state: _DomainState, deadline: float) -> None:
        """Spend one of the domain's tokens, pacing until one exists.

        The delay is computed rather than polled: the bucket knows exactly when
        it will next hold a token, so this suspends once per token rather than
        waking repeatedly to look.
        """
        while True:
            now = self.clock.monotonic()
            state.bucket = state.bucket.refilled(now)
            if state.bucket.has_token and now >= state.blocked_until:
                state.bucket = state.bucket.take()
                return
            delay = max(state.bucket.seconds_until_token(), state.blocked_until - now)
            if now + delay > deadline:
                # Refusing before sleeping matters: waiting out a budget that
                # cannot possibly be met holds a global concurrency slot for
                # nothing.
                raise RateLimitTimeout("a destination-pacing token")
            await self.sleeper.sleep(delay)

    async def _wait_for_change(self, remaining: float) -> None:
        """Suspend until something is released, or until `remaining` runs out.

        Both halves are tasks and both are cancelled on the way out, so neither
        a release nor a cancellation leaves one pending.
        """
        change = self._change
        waiter = asyncio.ensure_future(change.wait())
        timer = asyncio.ensure_future(self.sleeper.sleep(remaining))
        try:
            await asyncio.wait({waiter, timer}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()
            timer.cancel()

    def _signal(self) -> None:
        """Wake every waiter, and hand the next one a fresh event.

        Replacing the event rather than clearing it removes the race where a
        waiter takes a reference, something is released, and the clear arrives
        before the wait: the waiter would then be waiting on an event that has
        already had its turn.
        """
        previous = self._change
        self._change = asyncio.Event()
        previous.set()

    # --- per-domain state, and its bound ------------------------------------

    def _claim(self, domain: str, *, mx: bool = False) -> _DomainState:
        """The state for one domain, registering interest in it immediately.

        Registering before waiting is what makes eviction safe: from here until
        the lease is released, this entry is not idle and cannot be removed.

        Eviction runs **after** the entry exists, not before. Running it first
        leaves the table one over its cap for the duration of the call, which is
        a cap that is never quite honoured; running it afterwards counts the new
        entry, and the new entry is protected by the interest registered above.
        """
        now = self.clock.monotonic()
        table = self._mx_domains if mx else self._domains
        state = table.get(domain)
        if state is None:
            state = _DomainState(bucket=new_bucket(self.settings, now), touched_at=now)
            table[domain] = state
        else:
            table.move_to_end(domain)
        state.waiters += 1
        state.touched_at = now
        self._evict(now, table)
        if len(table) > self.settings.max_tracked_domains:
            state.waiters -= 1
            if state.is_idle and state.bucket.refilled(now).tokens == state.bucket.capacity:
                table.pop(domain, None)
            raise RateLimitTimeout("destination state capacity")
        return state

    def _evict(self, now: float, table: OrderedDict[str, _DomainState] | None = None) -> None:
        """Keep the per-domain table bounded, and never drop one in use.

        Two rules, and the order matters. Anything idle for longer than the TTL
        goes, because a domain checked once an hour ago is holding a full bucket
        it does not need. Then, if the table is still over its cap, the
        least-recently-used idle entries go until it is not.

        **An entry with an active lease or a waiter is never evicted, and that
        is a security barrier rather than tidiness.** Evicting a held entry
        forgets its bucket, and the next caller for that domain gets a *fresh,
        full* one — which is a pacing bypass: a domain that had just spent its
        burst is immediately allowed another. It also orphans the counter the
        held lease will release, so per-domain concurrency stops being
        enforceable for as long as that lease lives.

        `state.is_idle` appears in both passes below and neither is redundant:
        the TTL sweep and the LRU sweep select entries by different rules, and
        removing the guard from either one alone is enough to evict something in
        use. The Phase 4 final review found both unpinned — the test named for
        this property asserted only that the counters balanced afterwards, which
        an orphaned entry also satisfies — so each now has a test that fails when
        its own guard is removed.

        The TTL is therefore **not** required to exceed the longest SMTP session.
        It applies to idle entries only, and an entry stops being idle the moment
        a caller registers interest in it, so a TTL shorter than a session is a
        legal configuration that changes nothing about a held entry.

        Each table is capped at max_tracked_domains. A full table refuses new
        destinations if it cannot safely reclaim an idle, fully refilled entry.
        Spent tokens and active cooldowns survive both TTL and LRU pressure.
        """
        if table is None:
            table = self._domains
        expired = [
            domain
            for domain, state in table.items()
            if state.is_idle
            and now >= state.blocked_until
            and state.bucket.refilled(now).tokens == state.bucket.capacity
            and now - state.touched_at > self.settings.idle_ttl_seconds
        ]
        for domain in expired:
            del table[domain]

        if len(table) <= self.settings.max_tracked_domains:
            return
        over = len(table) - self.settings.max_tracked_domains
        # `OrderedDict` keeps insertion and `move_to_end` order, so iterating
        # forward is least-recently-used first.
        removable = [
            domain
            for domain, state in table.items()
            if state.is_idle
            and now >= state.blocked_until
            and state.bucket.refilled(now).tokens == state.bucket.capacity
        ]
        for domain in removable[:over]:
            del table[domain]


@dataclass(slots=True)
class _Lease:
    """One acquisition, held for the body of an `async with`.

    Entering acquires; leaving releases exactly once. Releasing twice is a
    capacity leak in the direction that matters — a slot returned twice lets one
    more probe run than the limit allows — so the second release does nothing
    rather than being trusted not to happen.
    """

    limiter: InProcessRateLimiter
    key: RateLimitKey
    _state: tuple[_DomainState, _DomainState] | None = None
    _entered: bool = False

    async def __aenter__(self) -> None:
        if self._entered:
            # Re-entering would acquire a second set of budgets that only one
            # `__aexit__` would ever release.
            raise RateLimitError("a rate-limit lease may be entered only once")
        self._entered = True
        self._state = await self.limiter._enter(self.key)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        state = self._state
        if state is None:
            # `__aenter__` raised, so nothing is held. Python does not call
            # `__aexit__` in that case, and this is the second barrier.
            return
        self._state = None
        self.limiter._exit(state)
