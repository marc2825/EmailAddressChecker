"""The guard is actually *in* the verification path, and where.

Every other Phase 7 test calls `AbuseGuard` directly, which says what the guard
does and nothing about whether anything asks it. A mutation matrix made that
concrete: disconnecting the guard from `AddressVerificationService` entirely —
both the submission charge and the destination charge — left the whole suite
passing. This file is what fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from tests.phase6_fixtures import (
    AddressLookup,
    FakeResolver,
    MXLookup,
    MXRecord,
    ScriptedSMTPVerification,
    apply_ttl_policy,
    build_service,
    recipient_evidence,
    resolver_with_route,
)
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    PRINCIPAL,
    SOURCE,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
    quota_settings,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl
from emailcheck.application.smtp_verification import VerificationReport, VerificationStop
from emailcheck.application.verification import VerificationRefused
from emailcheck.domain.abuse import BudgetLayer

asyncio_test = pytest.mark.asyncio

CALLER_LAYERS = ("api_key", "account", "target", "daily_total")
DESTINATION_LAYERS = ("target_domain", "target_mx", "sender_identity")


def harness(**overrides: object):
    store = CountingQuotaStore()
    guard = AbuseGuard(
        quota=store,
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_api_key=1000, per_account=1000, daily_total=1000),
        **overrides,  # type: ignore[arg-type]
    )
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    resolver = resolver_with_route()
    service, _, _ = build_service(resolver=resolver, smtp=smtp, guard=guard)
    return service, guard, store, resolver, smtp


# --- the submission charge ---------------------------------------------------


@asyncio_test
async def test_a_passive_verification_charges_the_caller_layers() -> None:
    service, _, store, _, _ = harness()
    await service.verify("user@example.test", principal=PRINCIPAL, active=False)
    assert store.layers_seen == (CALLER_LAYERS,)


@asyncio_test
async def test_an_active_verification_charges_the_caller_then_the_destination() -> None:
    """Two charges, in that order: the caller's budget is spent before any DNS
    work, and the destination's only once there is somewhere to connect."""
    service, _, store, _, smtp = harness()
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)
    assert store.layers_seen == (CALLER_LAYERS, DESTINATION_LAYERS)
    assert len(smtp.calls) == 1


@asyncio_test
async def test_a_refused_caller_costs_no_dns_lookup_and_no_probe() -> None:
    """The guard runs after parsing — so the target layer is keyed by a
    normalized address — and before the resolver."""
    service, _, store, resolver, smtp = harness()
    store.refuse_layer = BudgetLayer.ACCOUNT

    with pytest.raises(VerificationRefused) as refusal:
        await service.verify("user@example.test", principal=PRINCIPAL, active=True)

    assert refusal.value.scope == "an abuse control"
    assert resolver.calls == []
    assert smtp.calls == []


@asyncio_test
async def test_a_rejected_address_is_never_charged() -> None:
    """There is no target to charge it against, and charging one caller's budget
    for another's typo would be a way to spend somebody else's allowance."""
    service, _, store, _, _ = harness()
    await service.verify("not-an-address", principal=PRINCIPAL, active=False)
    assert store.layers_seen == ()


# --- the destination charge --------------------------------------------------


@asyncio_test
async def test_a_route_with_nowhere_to_connect_charges_no_destination_layer() -> None:
    """Phase 2 decided there is nowhere to go, so no remote site is about to
    experience anything."""
    from tests.phase6_fixtures import resolver_with_temporary_failure

    store = CountingQuotaStore()
    guard = AbuseGuard(
        quota=store,
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_api_key=1000, per_account=1000, daily_total=1000),
    )
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(
        resolver=resolver_with_temporary_failure(), smtp=smtp, guard=guard
    )

    await service.verify("user@example.test", principal=PRINCIPAL, active=True)
    assert store.layers_seen == (CALLER_LAYERS,)
    assert smtp.calls == []


@asyncio_test
async def test_a_refused_destination_opens_no_socket() -> None:
    service, _, store, _, smtp = harness()
    store.refuse_layer = BudgetLayer.TARGET_DOMAIN

    with pytest.raises(VerificationRefused):
        await service.verify("user@example.test", principal=PRINCIPAL, active=True)
    assert smtp.calls == []


@asyncio_test
async def test_the_exchanger_charged_is_the_one_that_will_be_approached_first() -> None:
    """ADR 0016 states the accounting is approximate and says which way: the
    preferred candidate is charged, which is the one Phase 4E's plan approaches
    first and, unless it fails before the recipient stage, the only one."""
    service, _, store, _, _ = harness()
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)

    destination = store.seen[1]
    mx = next(request for request in destination if request.key.layer.value == "target_mx")
    assert mx.key.value.endswith("example.test")


# --- the retry is not free ---------------------------------------------------


@asyncio_test
async def test_a_retry_charges_the_destination_layers_again() -> None:
    """`docs/requirements.md` section 14's one retry is a whole new
    verification. The remote site experiences it as a second connection whatever
    this project calls it, so it costs what a first attempt costs."""
    service, _, store, _, _ = harness()
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)

    assert store.layers_seen == (
        CALLER_LAYERS,
        DESTINATION_LAYERS,
        CALLER_LAYERS,
        DESTINATION_LAYERS,
    )


# --- a cache hit is not free -------------------------------------------------


@asyncio_test
async def test_a_submission_served_from_cache_still_charges_the_caller() -> None:
    """Otherwise a caller enumerating a set of already-cached addresses is
    entirely unbudgeted — the enumeration `docs/threat-model.md` lists first,
    arriving through the one door nobody was counting."""
    from tests.phase6_fixtures import (
        FakeClock,
        FakeRandomSource,
        InMemoryVerdictStore,
        RecordingExecutor,
    )

    from emailcheck.application.jobs import JobService
    from emailcheck.application.verdict_cache import VerdictCache

    service, guard, store, _, _smtp = harness()
    executor = RecordingExecutor()
    jobs = JobService(
        verification=service,
        executor=executor,
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        guard=guard,
        cache=VerdictCache(
            store=InMemoryVerdictStore(),
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec"),
            correlation_key=CORRELATION_KEY,
        ),
    )

    await jobs.submit("user@example.test", principal=PRINCIPAL, source=SOURCE)
    await executor.run_pending()
    charges_before = len(store.seen)

    await jobs.submit("user@example.test", principal=PRINCIPAL, source=SOURCE)
    assert len(store.seen) > charges_before, "the cached repeat was free"
    assert store.layers_seen[-1][0] == "api_key"


# --- F2: the per-MX kill switch reaches every exchanger ----------------------
#
# An independent review measured the earlier build consulting the exchanger
# switch for `connectable_candidates[0]` alone. Phase 4E falls through to the
# next exchanger on any pre-recipient failure, so a blocked *second* exchanger
# was still connected to and the control `docs/threat-model.md` section 4 lists
# among the required ones did nothing.
#
# The semantics are the repository's, taken from `docs/operations.md` section 2,
# which lists "one target domain" and "one target MX" as **separate** switches:
# a blocked domain refuses the whole verification, a blocked exchanger is
# skipped and another may still be used.


@dataclass(slots=True)
class RouteRecordingSMTP:
    """Records which exchangers Phase 4E was actually handed.

    Measured on what reaches the orchestrator rather than on the guard's own
    bookkeeping, because "the guard refused" and "nothing could reach that host"
    are different claims and only the second one is the control.
    """

    seen: list[str] = field(default_factory=list)
    calls: int = 0

    async def verify(self, target: object, route: object, *, account: str) -> VerificationReport:
        self.calls += 1
        self.seen.extend(
            candidate.host.value
            for candidate in route.connectable_candidates  # type: ignore[attr-defined]
        )
        return VerificationReport(
            attempts=(),
            evidence=recipient_evidence(("250 2.1.5 ok",)),
            stopped_because=VerificationStop.RECIPIENT_ATTEMPTED,
        )


def two_exchanger_resolver() -> FakeResolver:
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={
            "example.test": MXLookup(
                records=(
                    MXRecord(preference=10, exchange="mx1.example.test"),
                    MXRecord(preference=20, exchange="mx2.example.test"),
                ),
                ttl=ttl,
            )
        },
        a={
            "mx1.example.test": AddressLookup(addresses=("93.184.216.34",), ttl=ttl),
            "mx2.example.test": AddressLookup(addresses=("93.184.216.35",), ttl=ttl),
        },
    )


def blocking_harness() -> tuple[object, AdminControl, RouteRecordingSMTP]:
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_api_key=999, per_account=999, daily_total=999, per_target=999),
    )
    admin = AdminControl(
        guard=guard,
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        correlation_key=CORRELATION_KEY,
    )
    smtp = RouteRecordingSMTP()
    service, _, _ = build_service(resolver=two_exchanger_resolver(), smtp=smtp, guard=guard)
    return service, admin, smtp


@asyncio_test
async def test_both_exchangers_are_reachable_when_nothing_is_blocked() -> None:
    service, _, smtp = blocking_harness()
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]
    assert smtp.seen == ["mx1.example.test", "mx2.example.test"]


@asyncio_test
async def test_a_blocked_fallback_exchanger_is_never_reachable() -> None:
    """**The defect.** `mx1` is permitted and answers first, so the earlier
    build never consulted the switch for `mx2` at all — and Phase 4E would have
    reached it the moment `mx1` failed before the recipient stage."""
    service, admin, smtp = blocking_harness()
    admin.block_exchanger("mx2.example.test")

    await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]

    assert "mx2.example.test" not in smtp.seen
    assert smtp.seen == ["mx1.example.test"]


@asyncio_test
async def test_a_blocked_preferred_exchanger_is_skipped_and_the_next_is_used() -> None:
    """`docs/operations.md` section 2 makes the exchanger switch a per-host one,
    so another exchanger for the same domain may still be used. Blocking the
    whole domain is the separate switch for the other intent."""
    service, admin, smtp = blocking_harness()
    admin.block_exchanger("mx1.example.test")

    await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]

    assert smtp.seen == ["mx2.example.test"]


@asyncio_test
async def test_every_exchanger_blocked_opens_no_socket_at_all() -> None:
    service, admin, smtp = blocking_harness()
    admin.block_exchanger("mx1.example.test")
    admin.block_exchanger("mx2.example.test")

    outcome = await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]

    assert smtp.calls == 0
    assert outcome.active is False


@asyncio_test
async def test_a_blocked_domain_refuses_the_whole_verification() -> None:
    service, admin, smtp = blocking_harness()
    admin.block_domain("example.test")

    with pytest.raises(VerificationRefused):
        await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]
    assert smtp.calls == 0


@asyncio_test
async def test_a_blocked_domain_still_refuses_when_every_exchanger_is_blocked_too() -> None:
    """The domain switch is checked **before** the candidates are filtered.

    Otherwise the two controls set together answer "nowhere to connect" and the
    caller sees a passive verdict where the domain switch promises a refusal —
    a public difference between one control and two.
    """
    service, admin, smtp = blocking_harness()
    admin.block_domain("example.test")
    admin.block_exchanger("mx1.example.test")
    admin.block_exchanger("mx2.example.test")

    with pytest.raises(VerificationRefused):
        await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]
    assert smtp.calls == 0


@asyncio_test
async def test_filtering_removes_candidates_and_never_adds_one() -> None:
    """Phase 4E's ordering, cap, de-duplication, and one-`RCPT TO` bound are
    untouched: the filter is a subset of what Phase 2 published, in Phase 2's
    order, so it cannot create a second recipient attempt."""
    service, admin, smtp = blocking_harness()
    admin.block_exchanger("mx2.example.test")
    await service.verify("user@example.test", principal=PRINCIPAL, active=True)  # type: ignore[attr-defined]

    published = ["mx1.example.test", "mx2.example.test"]
    assert smtp.seen == [host for host in published if host in smtp.seen]
    assert len(smtp.seen) <= len(published)
