"""What a rate limit *is*, kept apart from what waiting for one *does*.

Every number, every bound, and every arithmetic step lives here and is pure.
`adapters/system/rate_limit.py` holds the counters, the waiting, and the
eviction; this holds the decisions it makes, so the parts that are easy to get
subtly wrong — refill arithmetic, a burst that grows, a key that carries an
address — are testable without a clock, a loop, or a socket.

Three things are worth reading for.

**The key can never carry a local part.** `docs/requirements.md` section 16
forbids a complete address in metrics and keys, and a limiter's state is both.
`rate_limit_key` refuses an `@` in any component rather than trusting callers,
so the guarantee is a property of the value instead of a convention in the one
place that builds it today.

**A bucket cannot hold more than its capacity.** Refill is
`min(capacity, tokens + elapsed / refill_seconds)`, clamped, and the value type
refuses a token count outside `0..capacity` on construction. Float arithmetic
cannot round a burst upward past the cap, because the cap is applied after the
addition and checked again by the type.

**Time only moves forward here.** Every function takes `now` from a
`MonotonicClock`, never a wall clock: a bucket refilled from `datetime.now()`
would hand out a burst of tokens the moment NTP stepped the machine forward.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

#: Nothing this project runs may exceed these. A bound nobody would reach is not
#: a bound, and each of these is set where a plausible deployment stays well
#: underneath while an implausible configuration fails loudly.
MAX_GLOBAL_CONCURRENCY: Final = 64
MAX_DOMAIN_CONCURRENCY: Final = 16
MAX_DOMAIN_CAPACITY: Final = 64
MAX_REFILL_SECONDS: Final = 3600.0
MAX_WAIT_BUDGET_SECONDS: Final = 120.0
MAX_TRACKED_DOMAINS: Final = 100_000
MAX_IDLE_TTL_SECONDS: Final = 86_400.0

#: Conservative defaults. `docs/threat-model.md` wants low concurrency and
#: destination pacing, and this project would rather be slow than be reported as
#: a harvester: four probes at a time, two of them to any one domain, and a
#: domain may not be touched faster than once every five seconds on average.
DEFAULT_GLOBAL_CONCURRENCY: Final = 4
DEFAULT_DOMAIN_CONCURRENCY: Final = 2
DEFAULT_DOMAIN_CAPACITY: Final = 4
DEFAULT_REFILL_SECONDS: Final = 5.0
DEFAULT_WAIT_BUDGET_SECONDS: Final = 10.0
DEFAULT_TRACKED_DOMAINS: Final = 4096
DEFAULT_IDLE_TTL_SECONDS: Final = 900.0

#: A key component longer than this is a caller passing something that is not an
#: account, a domain, or a host name.
MAX_KEY_COMPONENT_LENGTH: Final = 253

#: Characters that must never reach a limiter key. Control characters because a
#: key becomes a metric label and a log line; `@` because a component carrying
#: one is a mailbox rather than a domain.
_FORBIDDEN_IN_KEY: Final = ("\r", "\n", "\x00", "\t", "@")


class RateLimitError(ValueError):
    """A rate-limit value was built from something it may not be built from.

    A configuration or programmer error, never a remote condition: a caller that
    is merely over budget is told so by `RateLimitTimeout`.
    """


class RateLimitTimeout(Exception):
    """The wait budget ran out before every budget could be acquired.

    **This is not a remote timeout and must never be reported as one.** Nothing
    was connected to, no SMTP command was written, and no mail server was
    involved: the probe waited for this project's own scheduling and gave up.
    `application/smtp_verification.py` records it as an operational stop reason
    and produces no SMTP evidence, because there is no observation to report.

    Raised from `RateLimitLease.__aenter__`, so a caller that holds a lease
    holds every budget it names.
    """

    def __init__(self, scope: str) -> None:
        # The scope names which budget was not available, and nothing else. No
        # account, no domain, no host: this text can reach a log.
        super().__init__(f"the rate-limit wait budget expired waiting for {scope}")
        self.scope = scope


def _check_count(name: str, value: object, maximum: int) -> int:
    """A whole positive number within a maximum, and not a boolean.

    `True` is `1` in Python, so a boolean concurrency limit would silently mean
    "one at a time" — the same trap `TransportTimeouts` and `SessionBudget`
    already refuse.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise RateLimitError(f"{name} must be a whole number, not a boolean")
    if value <= 0:
        raise RateLimitError(f"{name} must be positive")
    if value > maximum:
        raise RateLimitError(f"{name} exceeds the maximum of {maximum}")
    return value


def _check_seconds(name: str, value: object, maximum: float) -> float:
    """A positive, finite number of seconds within a maximum."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise RateLimitError(f"{name} must be a number of seconds, not a boolean")
    if not math.isfinite(value):
        raise RateLimitError(f"{name} must be finite")
    if value <= 0:
        raise RateLimitError(f"{name} must be positive")
    if value > maximum:
        raise RateLimitError(f"{name} exceeds the maximum of {maximum}")
    return float(value)


@dataclass(frozen=True, slots=True)
class RateLimitSettings:
    """Every bound a limiter enforces, validated the way a timeout is.

    The last field pair is the one worth explaining. A limiter keeps per-domain
    state, and a caller can supply domains without limit, so the state has to be
    bounded or it is a memory leak with a remote trigger. `max_tracked_domains`
    with `idle_ttl_seconds` is that bound, and the constructor requires it to be
    at least the global concurrency: an entry may only be evicted when nothing
    is using it, so a cap below the number of simultaneously *held* entries
    would be a cap that cannot be honoured.
    """

    global_concurrency: int = DEFAULT_GLOBAL_CONCURRENCY
    domain_concurrency: int = DEFAULT_DOMAIN_CONCURRENCY
    domain_capacity: int = DEFAULT_DOMAIN_CAPACITY
    domain_refill_seconds: float = DEFAULT_REFILL_SECONDS
    wait_budget_seconds: float = DEFAULT_WAIT_BUDGET_SECONDS
    max_tracked_domains: int = DEFAULT_TRACKED_DOMAINS
    idle_ttl_seconds: float = DEFAULT_IDLE_TTL_SECONDS

    def __post_init__(self) -> None:
        _check_count("global concurrency", self.global_concurrency, MAX_GLOBAL_CONCURRENCY)
        _check_count("domain concurrency", self.domain_concurrency, MAX_DOMAIN_CONCURRENCY)
        _check_count("domain capacity", self.domain_capacity, MAX_DOMAIN_CAPACITY)
        _check_seconds("a refill interval", self.domain_refill_seconds, MAX_REFILL_SECONDS)
        _check_seconds("a wait budget", self.wait_budget_seconds, MAX_WAIT_BUDGET_SECONDS)
        _check_count("the tracked-domain cap", self.max_tracked_domains, MAX_TRACKED_DOMAINS)
        _check_seconds("an idle TTL", self.idle_ttl_seconds, MAX_IDLE_TTL_SECONDS)
        if self.domain_concurrency > self.global_concurrency:
            raise RateLimitError(
                "a domain may not be given more concurrency than the whole service"
            )
        if self.max_tracked_domains < self.global_concurrency:
            raise RateLimitError(
                "the tracked-domain cap must be at least the global concurrency, "
                "because an entry in use cannot be evicted"
            )


@dataclass(frozen=True, slots=True)
class RateLimitKey:
    """What a budget is counted against. Never a mailbox.

    Built through `rate_limit_key`, which canonicalizes and refuses. The
    constructor validates as well, because Python has no honest private
    constructor and this is the value that carries the privacy guarantee.
    """

    account: str
    domain: str
    mx_host: str

    def __post_init__(self) -> None:
        for name, value in (
            ("an account", self.account),
            ("a domain", self.domain),
            ("an MX host", self.mx_host),
        ):
            _check_key_component(name, value)


def _check_key_component(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise RateLimitError(f"{name} in a rate-limit key must be text")
    if not value:
        raise RateLimitError(f"{name} in a rate-limit key cannot be empty")
    if len(value) > MAX_KEY_COMPONENT_LENGTH:
        raise RateLimitError(f"{name} in a rate-limit key is too long")
    for character in _FORBIDDEN_IN_KEY:
        if character in value:
            # The `@` case is the one that matters. A component carrying one is
            # a complete address, and `docs/requirements.md` section 16 forbids
            # one in a key. Refusing here rather than stripping is deliberate:
            # stripping would silently keep the local part in the caller's hand
            # and put the domain in the key under a name that lied about it.
            raise RateLimitError(f"{name} in a rate-limit key cannot carry {character!r}")
    if any(not character.isprintable() for character in value):
        raise RateLimitError(f"{name} in a rate-limit key cannot carry a control character")


def rate_limit_key(*, account: str, domain: str, mx_host: str) -> RateLimitKey:
    """Canonicalize the three things a budget is counted against.

    `example.com`, `EXAMPLE.com`, and `example.com.` are one domain and must
    share one budget, or an attacker varies the case of a name and gets a fresh
    quota for each spelling. The account is *not* case-folded: it is an opaque
    identifier this project did not issue, and folding it would merge two
    accounts a deployment considers distinct.
    """
    return RateLimitKey(
        account=_canonical(account, fold_case=False),
        domain=_canonical(domain, fold_case=True),
        mx_host=_canonical(mx_host, fold_case=True),
    )


def _canonical(value: str, *, fold_case: bool) -> str:
    if not isinstance(value, str):
        raise RateLimitError("a rate-limit key component must be text")
    canonical = value.strip()
    if fold_case:
        canonical = canonical.rstrip(".").lower()
    return canonical


@dataclass(frozen=True, slots=True)
class TokenBucket:
    """Pacing for one domain, as arithmetic rather than as a schedule.

    `capacity` is the burst a domain may be given at once and `refill_seconds`
    is how long one token takes to come back, so the steady rate is one probe
    per `refill_seconds` and the most that can ever arrive together is
    `capacity`.

    Immutable: every operation returns a new bucket, so a half-applied refill
    cannot be left behind by an exception between two mutations.
    """

    capacity: int
    refill_seconds: float
    tokens: float
    updated_at: float

    def __post_init__(self) -> None:
        _check_count("a bucket capacity", self.capacity, MAX_DOMAIN_CAPACITY)
        _check_seconds("a refill interval", self.refill_seconds, MAX_REFILL_SECONDS)
        if isinstance(self.tokens, bool) or not isinstance(self.tokens, int | float):
            raise RateLimitError("a token count must be a number")
        if not math.isfinite(self.tokens):
            raise RateLimitError("a token count must be finite")
        if self.tokens < 0:
            # The state a bug in the refill arithmetic would produce, refused
            # rather than carried: a negative bucket hands out a token the
            # moment the next refill rounds it above zero.
            raise RateLimitError("a token count cannot be negative")
        if self.tokens > self.capacity:
            raise RateLimitError("a token count cannot exceed the bucket's capacity")

    def refilled(self, now: float) -> TokenBucket:
        """The bucket as of `now`, never holding more than it may.

        A clock that appears to move backwards contributes nothing rather than
        removing tokens. `MonotonicClock` promises it will not, and a value that
        would be wrong if the promise broke is a value that trusts a promise.
        """
        elapsed = max(0.0, now - self.updated_at)
        gained = elapsed / self.refill_seconds
        # `min` after the addition, so no rounding can carry a burst past the
        # capacity: the result is bounded by an exact integer.
        tokens = min(float(self.capacity), self.tokens + gained)
        return TokenBucket(
            capacity=self.capacity,
            refill_seconds=self.refill_seconds,
            tokens=tokens,
            updated_at=max(self.updated_at, now),
        )

    @property
    def has_token(self) -> bool:
        return self.tokens >= 1.0

    def take(self) -> TokenBucket:
        """Spend one token. Refuses rather than going negative."""
        if not self.has_token:
            raise RateLimitError("a token was taken from an empty bucket")
        return TokenBucket(
            capacity=self.capacity,
            refill_seconds=self.refill_seconds,
            tokens=self.tokens - 1.0,
            updated_at=self.updated_at,
        )

    def seconds_until_token(self) -> float:
        """How long until this bucket holds a whole token. Zero when it does."""
        if self.has_token:
            return 0.0
        return (1.0 - self.tokens) * self.refill_seconds


def new_bucket(settings: RateLimitSettings, now: float) -> TokenBucket:
    """A domain's first bucket: full, so a first probe is not paced for nothing."""
    return TokenBucket(
        capacity=settings.domain_capacity,
        refill_seconds=settings.domain_refill_seconds,
        tokens=float(settings.domain_capacity),
        updated_at=now,
    )
