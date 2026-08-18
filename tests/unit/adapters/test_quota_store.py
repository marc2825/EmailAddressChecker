"""The quota store's arithmetic, its bound, and what it refuses to evict."""

from __future__ import annotations

import asyncio

import pytest

from emailcheck.adapters.system.quota import (
    MAX_COUNTERS_CEILING,
    InProcessQuotaStore,
    QuotaSettingsError,
)
from emailcheck.domain.abuse import (
    AbuseSettingsError,
    BudgetKey,
    BudgetLayer,
    window_start,
)
from emailcheck.ports.quota import BudgetRequest, QuotaStoreUnavailable

asyncio_test = pytest.mark.asyncio

WINDOW = 60


def request(
    value: str, *, limit: int = 2, layer: BudgetLayer = BudgetLayer.ACCOUNT
) -> BudgetRequest:
    return BudgetRequest(
        key=BudgetKey(layer=layer, value=value), limit=limit, window_seconds=WINDOW
    )


# --- the arithmetic ----------------------------------------------------------


@asyncio_test
async def test_a_counter_refuses_at_its_limit_and_not_before() -> None:
    store = InProcessQuotaStore()
    for _ in range(2):
        assert (await store.consume([request("a")], now=0.0)).permitted
    decision = await store.consume([request("a")], now=0.0)
    assert not decision.permitted
    assert decision.refused_layer is BudgetLayer.ACCOUNT


@asyncio_test
async def test_counters_are_independent() -> None:
    store = InProcessQuotaStore()
    for _ in range(2):
        await store.consume([request("a")], now=0.0)
    assert (await store.consume([request("b")], now=0.0)).permitted


@asyncio_test
async def test_a_window_boundary_resets_a_counter() -> None:
    store = InProcessQuotaStore()
    for _ in range(2):
        await store.consume([request("a")], now=0.0)
    assert not (await store.consume([request("a")], now=59.0)).permitted
    assert (await store.consume([request("a")], now=60.0)).permitted


@asyncio_test
async def test_a_refusal_spends_nothing_at_all() -> None:
    """The property the port exists to make possible: a request refused by the
    last layer must not have spent the first."""
    store = InProcessQuotaStore()
    generous = request("generous", limit=100, layer=BudgetLayer.API_KEY)
    tight = request("tight", limit=1, layer=BudgetLayer.TARGET)

    await store.consume([generous, tight], now=0.0)
    for _ in range(10):
        decision = await store.consume([generous, tight], now=0.0)
        assert not decision.permitted
        assert decision.refused_layer is BudgetLayer.TARGET

    # The generous counter was spent exactly once, by the one permitted call.
    for _ in range(99):
        assert (await store.consume([generous], now=0.0)).permitted


@asyncio_test
async def test_an_empty_request_set_is_permitted() -> None:
    assert (await InProcessQuotaStore().consume([], now=0.0)).permitted


@asyncio_test
async def test_consume_takes_no_lock_because_it_awaits_nothing_in_the_middle() -> None:
    """The check and the commit are atomic on one event loop because there is no
    suspension point between them. A future `await` inserted there would open a
    window in which two callers both pass the check — so the property is stated
    and this is what measures it."""
    import ast
    import inspect

    source = inspect.getsource(InProcessQuotaStore.consume)
    tree = ast.parse(source.lstrip())
    awaits = [node for node in ast.walk(tree) if isinstance(node, ast.Await)]
    assert awaits == []


# --- the bound ---------------------------------------------------------------


@asyncio_test
async def test_the_table_is_bounded_and_expired_counters_make_room() -> None:
    store = InProcessQuotaStore(max_counters=4)
    for index in range(4):
        await store.consume([request(f"k{index}")], now=0.0)
    assert store.tracked == 4

    # A later window: the four are dead and are replaced rather than refused.
    for index in range(4):
        assert (await store.consume([request(f"n{index}")], now=120.0)).permitted
    assert store.tracked == 4


@asyncio_test
async def test_a_live_counter_is_never_evicted_to_make_room() -> None:
    """Evicting a live counter resets a budget, which is a bypass rather than
    tidiness — the rule the Phase 4 limiter's per-domain table already follows.
    Refusing is the fail-closed answer."""
    store = InProcessQuotaStore(max_counters=2)
    await store.consume([request("a", limit=1)], now=0.0)
    await store.consume([request("b", limit=1)], now=0.0)

    with pytest.raises(QuotaStoreUnavailable):
        await store.consume([request("c", limit=1)], now=0.0)

    # `a` is still spent: it was not evicted and its budget was not reset.
    assert not (await store.consume([request("a", limit=1)], now=0.0)).permitted


@asyncio_test
async def test_purging_removes_only_counters_whose_window_has_ended() -> None:
    store = InProcessQuotaStore()
    await store.consume([request("a")], now=0.0)
    assert await store.purge_expired(now=30.0) == 0
    assert store.tracked == 1
    assert await store.purge_expired(now=60.0) == 1
    assert store.tracked == 0


@asyncio_test
async def test_an_unavailable_store_raises_rather_than_permitting() -> None:
    store = InProcessQuotaStore()
    store.unavailable = True
    with pytest.raises(QuotaStoreUnavailable):
        await store.consume([request("a")], now=0.0)


def test_a_store_failure_is_not_a_timeout_or_an_os_error() -> None:
    assert not issubclass(QuotaStoreUnavailable, TimeoutError)
    assert not issubclass(QuotaStoreUnavailable, OSError)


# --- configuration -----------------------------------------------------------


@pytest.mark.parametrize(
    "value", [0, -1, True, MAX_COUNTERS_CEILING + 1], ids=["zero", "negative", "boolean", "huge"]
)
def test_an_unusable_capacity_is_refused(value: object) -> None:
    with pytest.raises(QuotaSettingsError):
        InProcessQuotaStore(max_counters=value)  # type: ignore[arg-type]


# --- the window function -----------------------------------------------------


@pytest.mark.parametrize(("now", "expected"), [(0.0, 0), (59.9, 0), (60.0, 60), (3661.0, 3660)])
def test_a_window_start_floors_to_the_window(now: float, expected: int) -> None:
    assert window_start(now, window_seconds=60) == expected


@pytest.mark.parametrize(
    "now",
    [-1.0, float("nan"), float("inf"), True, "now"],
    ids=["negative", "nan", "inf", "bool", "text"],
)
def test_an_unusable_timestamp_is_refused(now: object) -> None:
    """A timestamp before the epoch is a bug in the caller's clock, and
    bucketing it silently would hide that."""
    with pytest.raises(AbuseSettingsError):
        window_start(now, window_seconds=60)  # type: ignore[arg-type]


# --- the SQLite purge is bounded ---------------------------------------------


@asyncio_test
async def test_the_verdict_purge_deletes_at_most_one_batch(tmp_path: object) -> None:
    """An unbounded `DELETE` holds a write lock for as long as the backlog is.

    Driven against the **real** store rather than a fake, because the bound is
    in the SQL: a mutation widening the `LIMIT` left every retention test
    passing, since those use a scripted store that reports whatever it likes.
    """
    import pathlib
    from datetime import UTC, datetime, timedelta

    from emailcheck.adapters.storage.sqlite_store import SQLiteVerdictStore
    from emailcheck.domain.verdict import Status
    from emailcheck.ports.verdict_store import StoredVerdict

    path = pathlib.Path(str(tmp_path)) / "verdicts.sqlite"
    store = SQLiteVerdictStore(path=path)
    store.initialize()

    expired = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    for index in range(25):
        await store.save(
            StoredVerdict(
                record_id=f"rec-{index:04d}",
                account_digest="a" * 64,
                target_digest=f"{index:064d}",
                sender_identity_digest="s" * 64,
                status=Status.UNKNOWN,
                confidence="low",
                primary_reason=None,
                reasons=(),
                risk_flags=(),
                checks=(),
                aggregation_ruleset="r1",
                passive_dataset_fingerprint="f1",
                created_at=expired - timedelta(hours=2),
                expires_at=expired - timedelta(hours=1),
            ),
            expected_generation=0,
        )

    assert await store.purge_expired(now=expired, limit=10) == 10
    assert await store.purge_expired(now=expired, limit=10) == 10
    assert await store.purge_expired(now=expired, limit=10) == 5
    assert await store.purge_expired(now=expired, limit=10) == 0


@asyncio_test
async def test_a_purge_batch_must_be_a_positive_whole_number(tmp_path: object) -> None:
    import pathlib

    from emailcheck.adapters.storage.sqlite_store import SQLiteVerdictStore

    store = SQLiteVerdictStore(path=pathlib.Path(str(tmp_path)) / "v.sqlite")
    store.initialize()
    from datetime import UTC, datetime

    for bad in (0, -1, True):
        with pytest.raises(ValueError):
            await store.purge_expired(now=datetime(2026, 1, 1, tzinfo=UTC), limit=bad)


# --- F1: the table-full path is all-or-nothing too ---------------------------
#
# An independent review measured the earlier build checking limits, beginning to
# increment, and discovering on a later layer that the table was full — raising
# with the first layers already spent. A refused request had drained the
# caller's key, account, and daily budgets, which is exactly what the port
# promises cannot happen. These are the rows that fail if the reservation pass
# is removed.


def _slot_counts(store: InProcessQuotaStore) -> dict[str, int]:
    return {key[0]: counter.spent for key, counter in store._counters.items()}


@asyncio_test
async def test_a_full_table_spends_nothing_when_the_new_key_comes_last() -> None:
    store = InProcessQuotaStore(max_counters=2)
    existing = [request("k", layer=BudgetLayer.API_KEY), request("a", layer=BudgetLayer.ACCOUNT)]
    await store.consume(existing, now=0.0)
    before = _slot_counts(store)

    with pytest.raises(QuotaStoreUnavailable):
        await store.consume([*existing, request("t", layer=BudgetLayer.TARGET)], now=0.0)

    assert _slot_counts(store) == before
    assert store.tracked == 2


@asyncio_test
async def test_a_full_table_spends_nothing_when_the_new_key_comes_first() -> None:
    """The inverse ordering, because a build that reserved lazily would pass the
    first row by accident — the new key would be reached before anything else
    had been incremented."""
    store = InProcessQuotaStore(max_counters=2)
    existing = [request("k", layer=BudgetLayer.API_KEY), request("a", layer=BudgetLayer.ACCOUNT)]
    await store.consume(existing, now=0.0)
    before = _slot_counts(store)

    with pytest.raises(QuotaStoreUnavailable):
        await store.consume([request("t", layer=BudgetLayer.TARGET), *existing], now=0.0)

    assert _slot_counts(store) == before
    assert store.tracked == 2


@asyncio_test
async def test_two_missing_keys_need_two_free_slots() -> None:
    """`len(table) < max` asked once per insertion answers the wrong question.

    One free slot and two missing counters must refuse **before creating
    either**, or the first is written and the second raises — a partial spend
    wearing a different hat.
    """
    store = InProcessQuotaStore(max_counters=3)
    existing = [request("k", layer=BudgetLayer.API_KEY), request("a", layer=BudgetLayer.ACCOUNT)]
    await store.consume(existing, now=0.0)
    before = _slot_counts(store)

    with pytest.raises(QuotaStoreUnavailable):
        await store.consume(
            [
                request("k", layer=BudgetLayer.API_KEY),
                request("t", layer=BudgetLayer.TARGET),
                request("d", layer=BudgetLayer.TARGET_DOMAIN),
            ],
            now=0.0,
        )

    assert _slot_counts(store) == before
    assert store.tracked == 2


@asyncio_test
async def test_exactly_the_missing_number_of_slots_is_enough() -> None:
    """The bound is not off by one in the safe direction either: two missing
    counters and two free slots must succeed."""
    store = InProcessQuotaStore(max_counters=4)
    await store.consume([request("k", layer=BudgetLayer.API_KEY)], now=0.0)
    decision = await store.consume(
        [
            request("k", layer=BudgetLayer.API_KEY),
            request("t", layer=BudgetLayer.TARGET),
            request("d", layer=BudgetLayer.TARGET_DOMAIN),
        ],
        now=0.0,
    )
    assert decision.permitted
    assert store.tracked == 3


@asyncio_test
async def test_expired_counters_are_swept_once_before_the_table_is_called_full() -> None:
    store = InProcessQuotaStore(max_counters=2)
    await store.consume(
        [request("k", layer=BudgetLayer.API_KEY), request("a", layer=BudgetLayer.ACCOUNT)],
        now=0.0,
    )
    # A later window: both are dead, so three new counters do not fit a table of
    # two, but two do.
    decision = await store.consume(
        [request("x", layer=BudgetLayer.TARGET), request("y", layer=BudgetLayer.TARGET_DOMAIN)],
        now=600.0,
    )
    assert decision.permitted
    assert store.tracked == 2


@asyncio_test
async def test_two_racing_spends_for_one_free_slot_leave_no_partial_spend() -> None:
    """Capacity for exactly one new counter, two concurrent multi-layer spends
    that each need a different one."""
    # Generous limits throughout, so the **table** is the binding constraint
    # rather than a layer's own allowance — otherwise this measures the limit
    # check and says nothing about the reservation.
    store = InProcessQuotaStore(max_counters=3)
    shared = request("k", limit=100, layer=BudgetLayer.API_KEY)
    await store.consume([shared, request("a", limit=100, layer=BudgetLayer.ACCOUNT)], now=0.0)

    async def spend(value: str) -> str:
        try:
            decision = await store.consume(
                [shared, request(value, limit=100, layer=BudgetLayer.TARGET)], now=0.0
            )
        except QuotaStoreUnavailable:
            return "unavailable"
        return "permitted" if decision.permitted else "refused"

    outcomes = sorted(await asyncio.gather(spend("t1"), spend("t2")))

    assert outcomes == ["permitted", "unavailable"]
    assert store.tracked <= 3
    # The shared counter moved once, for the winner alone. A loser that had
    # incremented it before failing would leave this at three.
    assert _slot_counts(store)["api_key:k"] == 2
