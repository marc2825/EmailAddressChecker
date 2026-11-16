"""The arithmetic and the bounds, with no clock, no loop, and no socket.

Everything a limiter decides lives in `domain/rate_limit.py`, which is what
makes it testable this way: a bucket is a value, a refill is a function of a
timestamp, and a key is a value that refuses what it may not carry.

The two properties worth stating are the ones a float would quietly break. A
bucket may never hold more than its capacity, so pacing cannot be widened by
letting a machine idle; and a key may never carry a local part, because a
limiter's state is exactly the metrics store `docs/requirements.md` section 16
forbids a complete address in.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.rate_limit import (
    MAX_GLOBAL_CONCURRENCY,
    MAX_KEY_COMPONENT_LENGTH,
    RateLimitError,
    RateLimitKey,
    RateLimitSettings,
    RateLimitTimeout,
    TokenBucket,
    new_bucket,
    rate_limit_key,
)

NOW = 1000.0


def bucket(
    capacity: int = 2, refill_seconds: float = 5.0, tokens: float | None = None
) -> TokenBucket:
    return TokenBucket(
        capacity=capacity,
        refill_seconds=refill_seconds,
        tokens=float(capacity) if tokens is None else tokens,
        updated_at=NOW,
    )


# --- settings validation ----------------------------------------------------


def test_the_defaults_are_valid_and_conservative() -> None:
    settings = RateLimitSettings()

    assert settings.global_concurrency <= MAX_GLOBAL_CONCURRENCY
    assert settings.domain_concurrency <= settings.global_concurrency
    assert settings.domain_refill_seconds > 0


@pytest.mark.parametrize(
    "field",
    [
        "global_concurrency",
        "domain_concurrency",
        "domain_capacity",
        "domain_refill_seconds",
        "wait_budget_seconds",
        "max_tracked_domains",
        "idle_ttl_seconds",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True, False, float("nan"), float("inf"), "5", None])
def test_every_limit_refuses_a_value_that_is_not_one(field: str, value: object) -> None:
    """One rule for all seven, so a new bound cannot be added with a weaker one.

    `True` is the case that needs saying: it is `1` in Python, so a boolean
    concurrency limit would silently mean "one at a time" rather than failing.
    """
    with pytest.raises(RateLimitError):
        RateLimitSettings(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("global_concurrency", 1_000),
        ("domain_concurrency", 1_000),
        ("domain_capacity", 1_000),
        ("domain_refill_seconds", 100_000.0),
        ("wait_budget_seconds", 10_000.0),
        ("max_tracked_domains", 10_000_000),
        ("idle_ttl_seconds", 10_000_000.0),
    ],
)
def test_an_unreasonably_large_limit_is_refused(field: str, value: object) -> None:
    """A bound nobody would reach is not a bound."""
    with pytest.raises(RateLimitError):
        RateLimitSettings(**{field: value})  # type: ignore[arg-type]


def test_a_domain_may_not_outrank_the_whole_service() -> None:
    with pytest.raises(RateLimitError):
        RateLimitSettings(global_concurrency=2, domain_concurrency=3)


def test_the_tracked_domain_cap_must_be_reachable() -> None:
    """An entry in use cannot be evicted, so the cap has to allow for them all.

    Without this the limiter has a cap it can be asked to honour and cannot,
    which is the kind of configuration that fails only under load.
    """
    with pytest.raises(RateLimitError):
        RateLimitSettings(global_concurrency=8, domain_concurrency=8, max_tracked_domains=4)


# --- the key never carries a mailbox ----------------------------------------


def test_a_key_is_canonicalized_so_one_domain_is_one_budget() -> None:
    """Otherwise varying the spelling of a name buys a fresh quota."""
    one = rate_limit_key(account="acct-1", domain="Example.COM.", mx_host="MX1.Example.com.")
    other = rate_limit_key(account="acct-1", domain=" example.com ", mx_host="mx1.example.com")

    assert one == other
    assert one.domain == "example.com"
    assert one.mx_host == "mx1.example.com"


def test_an_account_is_not_case_folded() -> None:
    """It is an opaque identifier this project did not issue.

    Folding it would merge two accounts a deployment considers distinct, which
    is a budget shared between two customers.
    """
    assert rate_limit_key(account="Acct-1", domain="a.example", mx_host="mx.a.example").account == (
        "Acct-1"
    )


@pytest.mark.parametrize("component", ["account", "domain", "mx_host"])
def test_no_key_component_may_carry_an_address(component: str) -> None:
    """The privacy invariant, refused in the value rather than at the call site."""
    parts = {"account": "acct-1", "domain": "example.com", "mx_host": "mx.example.com"}
    parts[component] = "person@example.com"

    with pytest.raises(RateLimitError, match="@"):
        rate_limit_key(**parts)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["", "   ", "a\rb", "a\nb", "a\x00b", "a\tb", "a\x1bb"])
def test_a_key_component_refuses_what_a_log_line_must_not_carry(bad: str) -> None:
    with pytest.raises(RateLimitError):
        rate_limit_key(account=bad, domain="example.com", mx_host="mx.example.com")


def test_a_key_component_is_bounded() -> None:
    with pytest.raises(RateLimitError):
        rate_limit_key(
            account="a" * (MAX_KEY_COMPONENT_LENGTH + 1),
            domain="example.com",
            mx_host="mx.example.com",
        )


def test_the_key_type_validates_on_its_own() -> None:
    """The factory canonicalizes; the type is the second barrier.

    Python has no honest private constructor, so a caller that builds one
    directly gets the same refusal rather than a key the factory would not have
    produced.
    """
    with pytest.raises(RateLimitError):
        RateLimitKey(account="person@example.com", domain="example.com", mx_host="mx.example.com")


# --- the bucket -------------------------------------------------------------


def test_a_new_bucket_is_full_so_a_first_probe_is_not_paced() -> None:
    settings = RateLimitSettings(domain_capacity=3)

    assert new_bucket(settings, NOW).tokens == 3.0


def test_taking_a_token_spends_exactly_one() -> None:
    spent = bucket(capacity=2).take()

    assert spent.tokens == 1.0
    assert spent.take().tokens == 0.0


def test_an_empty_bucket_refuses_rather_than_going_negative() -> None:
    """A negative bucket hands out a token as soon as a refill rounds it up."""
    empty = bucket(capacity=2, tokens=0.0)

    assert empty.has_token is False
    with pytest.raises(RateLimitError):
        empty.take()


def test_a_bucket_refills_at_the_configured_rate() -> None:
    empty = bucket(capacity=4, refill_seconds=5.0, tokens=0.0)

    assert empty.refilled(NOW + 2.5).tokens == pytest.approx(0.5)
    assert empty.refilled(NOW + 5.0).tokens == pytest.approx(1.0)
    assert empty.refilled(NOW + 5.0).has_token is True


def test_idling_never_widens_the_burst() -> None:
    """The property a float could break, asserted at absurd durations.

    `min` is applied after the addition, so the result is bounded by an exact
    integer whatever the elapsed time was.
    """
    empty = bucket(capacity=4, refill_seconds=5.0, tokens=0.0)

    for elapsed in (20.0, 1_000.0, 86_400.0, 1e9, 1e15):
        refilled = empty.refilled(NOW + elapsed)
        assert refilled.tokens == 4.0, elapsed
        assert refilled.capacity == 4


def test_a_clock_that_appears_to_move_backwards_adds_nothing() -> None:
    """`MonotonicClock` promises it will not, and this does not depend on it."""
    half = bucket(capacity=4, refill_seconds=5.0, tokens=2.0)

    assert half.refilled(NOW - 100.0).tokens == 2.0


def test_repeated_small_refills_cannot_drift_above_the_capacity() -> None:
    """A thousand partial refills, each a fraction of a token."""
    current = bucket(capacity=2, refill_seconds=1.0, tokens=0.0)
    for step in range(1, 1001):
        current = current.refilled(NOW + step * 0.001)
        assert 0.0 <= current.tokens <= 2.0, step


def test_a_bucket_refuses_an_impossible_token_count() -> None:
    with pytest.raises(RateLimitError):
        TokenBucket(capacity=2, refill_seconds=5.0, tokens=-0.5, updated_at=NOW)
    with pytest.raises(RateLimitError):
        TokenBucket(capacity=2, refill_seconds=5.0, tokens=2.5, updated_at=NOW)
    with pytest.raises(RateLimitError):
        TokenBucket(capacity=2, refill_seconds=5.0, tokens=float("nan"), updated_at=NOW)


def test_the_wait_until_a_token_is_exact() -> None:
    """Computed rather than polled, so pacing suspends once per token."""
    assert bucket(capacity=2).seconds_until_token() == 0.0
    assert bucket(capacity=2, refill_seconds=5.0, tokens=0.0).seconds_until_token() == 5.0
    assert bucket(capacity=2, refill_seconds=5.0, tokens=0.5).seconds_until_token() == 2.5


def test_the_bucket_is_immutable() -> None:
    """A half-applied refill cannot be left behind by an exception."""
    from dataclasses import FrozenInstanceError

    full = bucket()
    with pytest.raises(FrozenInstanceError):
        full.tokens = 0.0  # type: ignore[misc]


# --- the refusal is not a remote condition ----------------------------------


def test_a_rate_limit_timeout_names_the_scope_and_nothing_else() -> None:
    """It can reach a log, so it carries no account, domain, or host."""
    refusal = RateLimitTimeout("the domain")

    assert refusal.scope == "the domain"
    rendered = str(refusal)
    assert "@" not in rendered
    assert "example" not in rendered


def test_a_rate_limit_timeout_is_not_a_transport_or_smtp_error() -> None:
    """Nothing may catch it as though a mail server had done something.

    It is deliberately not an `OSError`, not a `TimeoutError`, and not an
    `SMTPContractError`: a handler written for a remote timeout must not catch
    this project's own queueing.
    """
    from emailcheck.domain.smtp_contract import SMTPContractError

    refusal = RateLimitTimeout("the service")

    assert not isinstance(refusal, TimeoutError)
    assert not isinstance(refusal, OSError)
    assert not isinstance(refusal, SMTPContractError)
    assert not isinstance(refusal, RateLimitError)


# --- inspection: the limiter is neutral and reads no wall clock ------------


@pytest.mark.inspection
def test_the_limiter_names_no_provider() -> None:
    """Behaviour cannot enumerate the providers a branch might name."""
    import ast
    from pathlib import Path

    providers = {
        "google",
        "gmail",
        "googlemail",
        "microsoft",
        "outlook",
        "hotmail",
        "office365",
        "yahoo",
        "proton",
        "zoho",
        "fastmail",
        "mimecast",
        "barracuda",
        "qq.com",
        "yandex",
    }
    found: list[str] = []
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    for module in (
        root / "domain" / "rate_limit.py",
        root / "adapters" / "system" / "rate_limit.py",
    ):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.extend(
                    f"{module.name}:{node.lineno} {name}"
                    for name in providers
                    if name in node.value.lower()
                )
            if isinstance(node, ast.Name | ast.Attribute):
                text = (node.id if isinstance(node, ast.Name) else node.attr).lower()
                found.extend(
                    f"{module.name}:{node.lineno} {name}" for name in providers if name in text
                )
    assert found == [], f"the limiter names a provider: {found}"


@pytest.mark.inspection
def test_the_limiter_reads_no_wall_clock() -> None:
    """Pacing from `datetime.now()` grants a burst the moment NTP steps.

    Asserted over the syntax rather than the text, because both modules explain
    in prose exactly why they do not do this and a text search finds its own
    explanation. That mistake has been made twice in this repository already.
    """
    import ast
    from pathlib import Path

    forbidden_modules = {"datetime", "time", "random", "os"}
    forbidden_names = {"now", "utcnow", "today", "time"}
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    offences: list[str] = []
    for module in (
        root / "domain" / "rate_limit.py",
        root / "adapters" / "system" / "rate_limit.py",
    ):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offences.extend(
                    f"{module.name}:{node.lineno} import {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in forbidden_modules
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in forbidden_modules:
                    offences.append(f"{module.name}:{node.lineno} from {node.module}")
            elif isinstance(node, ast.Attribute) and node.attr in forbidden_names:
                offences.append(f"{module.name}:{node.lineno} .{node.attr}")
    assert offences == [], f"the limiter reads a wall clock: {offences}"
