"""Each layered budget, enforced. `prompts/07-hardening.md`'s first test.

The guard is exercised against the **real** `InProcessQuotaStore` wherever the
question is arithmetic, and against `CountingQuotaStore` wherever the question is
which requests the guard built — because "the account budget refused" and "the
guard asked about the account layer at all" are different claims and a fake that
answers both proves neither.
"""

from __future__ import annotations

import pytest
from tests.phase7_fixtures import (
    ACCOUNT,
    CORRELATION_KEY,
    OTHER_PRINCIPAL,
    OTHER_SOURCE,
    PRINCIPAL,
    SAME_ACCOUNT_OTHER_KEY,
    SOURCE,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
    quota_settings,
    target,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.application.abuse import AbuseGuard, AbuseRefused
from emailcheck.domain.abuse import BudgetLayer
from emailcheck.domain.principal import Principal
from emailcheck.ports.metrics import MetricLabels, MetricName, Outcome

pytestmark = pytest.mark.asyncio


def build(store: object | None = None, **overrides: object) -> AbuseGuard:
    fields: dict[str, object] = {
        "quota": store if store is not None else InProcessQuotaStore(),
        "clock": SteppableClock(),
        "metrics": InMemoryMetrics(),
        "operator": RecordingOperator(),
        "correlation_key": CORRELATION_KEY,
        "settings": quota_settings(),
    }
    fields.update(overrides)
    return AbuseGuard(**fields)  # type: ignore[arg-type]


async def submit(
    guard: AbuseGuard,
    *,
    principal: Principal = PRINCIPAL,
    address: str | None = None,
    source: object = SOURCE,
    active: bool = True,
) -> None:
    await guard.authorize_submission(
        principal=principal,
        target=target() if address is None else target(address),
        source=source,  # type: ignore[arg-type]
        active=active,
    )


# --- every layer is enforced ------------------------------------------------


@pytest.mark.parametrize(
    ("layer", "limit_name", "limit"),
    [
        (BudgetLayer.API_KEY, "per_api_key", 3),
        (BudgetLayer.ACCOUNT, "per_account", 4),
        (BudgetLayer.SOURCE_IP, "per_source_ip", 5),
        (BudgetLayer.TARGET, "per_target", 2),
        (BudgetLayer.DAILY_TOTAL, "daily_total", 8),
    ],
    ids=lambda value: value if isinstance(value, str) else getattr(value, "value", str(value)),
)
async def test_a_caller_layer_refuses_at_its_own_limit(
    layer: BudgetLayer, limit_name: str, limit: int
) -> None:
    """Each layer alone, with every other layer set out of the way.

    Testing them together would only ever exercise whichever is narrowest, so
    each row raises the others far above it — which is what makes this a test of
    *this* layer rather than of the minimum.
    """
    generous = {
        name: 10_000
        for name in (
            "per_api_key",
            "per_account",
            "per_source_ip",
            "per_target",
            "daily_total",
        )
    }
    generous[limit_name] = limit
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(**generous),
    )

    for _ in range(limit):
        await submit(guard)

    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard)
    assert refusal.value.layer is layer


async def test_the_target_layer_counts_one_address_not_the_domain() -> None:
    """`BudgetLayer.TARGET` is keyed by the target HMAC, so a second address at
    the same domain has its own allowance."""
    guard = build()
    for _ in range(2):
        await submit(guard, address="user@example.test")
    with pytest.raises(AbuseRefused):
        await submit(guard, address="user@example.test")

    # A different mailbox at the same domain still has its own target budget.
    await submit(guard, address="other@example.test")


async def test_the_key_and_the_account_are_separate_layers() -> None:
    """One account, two credentials: the key budget binds each separately and
    the account budget binds both together.

    This is the property that makes "suspend a key" meaningful — if the two were
    one layer, containing a leaked credential would mean suspending the account
    that owns it.
    """
    # Distinct addresses throughout, so the *target* layer never binds and the
    # only thing under test is the key/account split.
    guard = build(settings=quota_settings(per_api_key=3, per_account=4, daily_total=100))
    for index in range(3):
        await submit(guard, principal=PRINCIPAL, address=f"a{index}@example.test")
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, principal=PRINCIPAL, address="b@example.test")
    assert refusal.value.layer is BudgetLayer.API_KEY

    # The account's fourth unit is still there, and the other key may spend it.
    await submit(guard, principal=SAME_ACCOUNT_OTHER_KEY, address="c@example.test")
    with pytest.raises(AbuseRefused) as second:
        await submit(guard, principal=SAME_ACCOUNT_OTHER_KEY, address="d@example.test")
    assert second.value.layer is BudgetLayer.ACCOUNT


async def test_one_accounts_budget_is_not_anothers() -> None:
    guard = build(settings=quota_settings(per_api_key=100, per_account=4, daily_total=100))
    for index in range(4):
        await submit(guard, principal=PRINCIPAL, address=f"a{index}@example.test")
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, principal=PRINCIPAL, address="z@example.test")
    assert refusal.value.layer is BudgetLayer.ACCOUNT
    await submit(guard, principal=OTHER_PRINCIPAL, address="z@example.test")


async def test_one_sources_budget_is_not_anothers() -> None:
    guard = build(settings=quota_settings(per_api_key=100, per_account=100, daily_total=100))
    for index in range(5):
        await submit(guard, address=f"a{index}@example.test", source=SOURCE)
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, address="z@example.test", source=SOURCE)
    assert refusal.value.layer is BudgetLayer.SOURCE_IP
    await submit(guard, address="z@example.test", source=OTHER_SOURCE)


# --- what the guard asks for ------------------------------------------------


async def test_a_submission_charges_the_caller_layers_and_no_destination_layer() -> None:
    store = CountingQuotaStore()
    guard = build(store)
    await submit(guard)
    assert store.layers_seen == (("api_key", "account", "source_ip", "target", "daily_total"),)


async def test_an_attempt_charges_the_destination_layers() -> None:
    store = CountingQuotaStore()
    guard = build(store)
    await guard.authorize_destination(
        domain="example.test", mx_host="mx.example.test", sender_identity="probe.example"
    )
    assert store.layers_seen == (("target_domain", "target_mx", "sender_identity"),)


async def test_an_absent_source_is_skipped_rather_than_defaulted() -> None:
    """Every caller without a known source would otherwise share one counter,
    which is a budget any two of them can exhaust for each other."""
    store = CountingQuotaStore()
    guard = build(store)
    await submit(guard, source=None)
    assert store.layers_seen == (("api_key", "account", "target", "daily_total"),)


async def test_an_unenforced_layer_is_skipped_rather_than_treated_as_unlimited() -> None:
    store = CountingQuotaStore()
    guard = build(store, settings=quota_settings(per_target=None, per_source_ip=None))
    await submit(guard)
    assert store.layers_seen == (("api_key", "account", "daily_total"),)


async def test_a_principal_without_a_key_identity_skips_the_key_layer() -> None:
    """`key_id` is `None` when the authenticator issues no per-credential
    identity. The key layer is not counted — deliberately not collapsed onto the
    account, which would make one account's keys share the key budget."""
    store = CountingQuotaStore()
    guard = build(store)
    await guard.authorize_submission(
        principal=Principal(account_id=ACCOUNT), target=target(), source=SOURCE, active=True
    )
    assert store.layers_seen == (("account", "source_ip", "target", "daily_total"),)


# --- all or nothing ---------------------------------------------------------


async def test_a_refusal_by_one_layer_spends_none_of_the_others() -> None:
    """Otherwise a caller near one limit is drained by requests that never ran."""
    store = InProcessQuotaStore()
    guard = build(
        store,
        settings=quota_settings(
            per_target=1, per_account=10, per_api_key=10, per_source_ip=10, daily_total=10
        ),
    )
    await submit(guard, address="user@example.test")

    spent_before = store.tracked
    for _ in range(5):
        with pytest.raises(AbuseRefused) as refusal:
            await submit(guard, address="user@example.test")
        assert refusal.value.layer is BudgetLayer.TARGET

    # No new counter was created by any of the five refusals...
    assert store.tracked == spent_before

    # ...and the account, key, source, and daily counters are all still at one,
    # so nine more distinct addresses fit inside budgets of ten. A build that
    # spent the earlier layers before reaching the target layer would have
    # burned six of each and this would refuse.
    for index in range(9):
        await submit(guard, address=f"fresh{index}@example.test")


# --- windows ----------------------------------------------------------------


async def test_a_budget_resets_at_the_window_boundary() -> None:
    clock = SteppableClock()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=clock,
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(),
    )
    for _ in range(2):
        await submit(guard, address="user@example.test")
    with pytest.raises(AbuseRefused):
        await submit(guard, address="user@example.test")

    clock.advance(60)
    await submit(guard, address="user@example.test")


async def test_the_daily_total_uses_a_day_whatever_the_window_is() -> None:
    """`prompts/07-hardening.md` calls it a daily total, so it is a day by
    definition rather than by configuration — advancing past the *configured*
    window must not refill it."""
    clock = SteppableClock()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=clock,
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(
            per_api_key=None, per_account=None, per_source_ip=None, per_target=None, daily_total=2
        ),
    )
    for _ in range(2):
        await submit(guard, address="user@example.test")
    clock.advance(60 * 60)
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, address="user@example.test")
    assert refusal.value.layer is BudgetLayer.DAILY_TOTAL


# --- failing closed ---------------------------------------------------------


async def test_a_quota_store_failure_refuses_an_active_check() -> None:
    """`prompts/07-hardening.md`: rate storage failure fails closed for active."""
    store = CountingQuotaStore(unavailable=True)
    guard = build(store)
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, active=True)
    assert refusal.value.unavailable is True
    assert refusal.value.category == "quota_unavailable"


async def test_a_quota_store_failure_still_serves_a_passive_check() -> None:
    """`docs/architecture.md` section 5: passive checks keep working when a
    dependency is down. A passive check opens no socket and spends no
    reputation, so failing it closed would take the service down to protect
    nothing."""
    store = CountingQuotaStore(unavailable=True)
    guard = build(store)
    await submit(guard, active=False)


async def test_a_quota_store_failure_is_reported_to_the_operator() -> None:
    operator = RecordingOperator()
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(unavailable=True),
        clock=SteppableClock(),
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(),
    )
    await submit(guard, active=False)
    assert "quota_unavailable" in operator.details
    assert (
        metrics.counter(MetricName.RATE_LIMIT_DECISION, labels=MetricLabels(outcome=Outcome.FAILED))
        == 1
    )


# --- what a refusal tells the caller ----------------------------------------


async def test_a_refusal_names_the_layer_to_the_operator_and_nothing_to_anyone_else() -> None:
    operator = RecordingOperator()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=operator,
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_target=1),
    )
    await submit(guard, address="alice@example.test")
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, address="alice@example.test")

    assert refusal.value.category == "target"
    rendered = f"{refusal.value} {operator.rendered()}"
    for secret in ("alice", "alice@example.test", ACCOUNT, PRINCIPAL.key_id or ""):
        assert secret not in rendered


async def test_an_abuse_refusal_is_not_a_timeout_or_an_os_error() -> None:
    """The treatment `AdmissionRefused` and `RateLimitTimeout` already get: a
    handler written for a remote condition must not catch this project's own."""
    assert not issubclass(AbuseRefused, TimeoutError)
    assert not issubclass(AbuseRefused, OSError)


# --- what the indicator window retains ---------------------------------------


async def test_the_indicator_window_retains_no_local_part() -> None:
    """Read from the guard's own state rather than from its `repr`.

    The window is `repr=False`, so the privacy corpus cannot see it — which
    means the corpus stopped being able to catch a build that stored the local
    part in the clear. A mutation storing the stem un-digested escaped the whole
    suite until this test read the field directly.
    """
    guard = build()
    local_part = "very.secret.localpart+tag"
    await guard.authorize_submission(
        principal=PRINCIPAL,
        target=target(f"{local_part}7@example.test"),
        source=SOURCE,
        active=True,
    )

    window = guard._windows[PRINCIPAL.account_id]
    shapes = list(window.attempts)
    assert len(shapes) == 1
    shape = shapes[0]

    assert local_part not in shape.stem_digest
    assert "very" not in shape.stem_digest
    assert len(shape.stem_digest) == 64
    # The ordinal survives, because that is what a numeric sequence is made of.
    assert shape.ordinal == 7
    assert repr(shape).count("very.secret") == 0


async def test_two_attempts_sharing_a_stem_still_compare_equal_after_digesting() -> None:
    """Digesting must not cost the rule anything: every indicator needs
    equality, and equality survives hashing."""
    guard = build(settings=quota_settings(per_api_key=100, per_account=100, daily_total=100))
    for index in (1, 2, 3, 4):
        await guard.authorize_submission(
            principal=PRINCIPAL,
            target=target(f"user{index}@example.test"),
            source=SOURCE,
            active=True,
        )
    digests = {shape.stem_digest for shape in guard._windows[PRINCIPAL.account_id].attempts}
    assert len(digests) == 1


async def test_the_caller_window_table_is_bounded() -> None:
    """A map keyed by an identity an attacker can vary is a memory leak with a
    remote trigger."""
    guard = build(
        settings=quota_settings(
            per_api_key=None,
            per_account=None,
            per_target=None,
            per_source_ip=None,
            daily_total=None,
        ),
        max_tracked_callers=4,
    )
    for index in range(20):
        await guard.authorize_submission(
            principal=Principal(account_id=f"acct-{index}"),
            target=target(),
            source=SOURCE,
            active=True,
        )
    assert guard.tracked_callers == 4
