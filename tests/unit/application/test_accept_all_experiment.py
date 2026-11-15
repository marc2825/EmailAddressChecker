"""The accept-all experiment, against the scripted server only.

`docs/adr/0017-accept-all-control-experiment.md`'s Tests section names seven scenarios and this file
covers each: all-recipient accept, only the real recipient accepted, a temporary
control response, a policy block, inconsistent replies, the domain budget and
the cache, and the feature disabled.

Nothing here opens a socket. The suite-wide guard in `tests/conftest.py` fails
any test that tries, so every count of zero below is a measurement rather than
an assumption.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from tests.phase7_fixtures import CORRELATION_KEY, PRINCIPAL, RecordingOperator, SteppableClock

from dialogue_fixtures import (
    FakeMonotonicClock,
    RecordingRateLimiter,
    candidate,
    identity_provider,
    route,
)
from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.system.accept_all_cache import InProcessAcceptAllCache
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.accept_all import (
    AcceptAllAuthorization,
    AcceptAllExperiment,
    AcceptAllRefused,
    generate_control_local_part,
)
from emailcheck.application.smtp_dialogue import DialogueSettings
from emailcheck.application.smtp_probe import SMTPProbeService
from emailcheck.application.smtp_verification import SMTPVerificationService, VerificationSettings
from emailcheck.domain.abuse import BudgetLayer, QuotaSettings
from emailcheck.domain.accept_all import (
    CONTROL_ALPHABET,
    CONTROL_LOCAL_PART_LENGTH,
    EXPERIMENT_VERSION,
    MAX_COLLISION_RETRIES,
    AcceptAllOutcome,
    AcceptAllSettings,
)
from emailcheck.domain.admin import AdminState
from emailcheck.domain.evidence import EvidenceLayer, EvidenceStrength
from emailcheck.domain.mail_route import MailRoute, MailRouteOutcome
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_tls import TLSPolicy
from emailcheck.domain.verdict import RiskFlag, Status
from fake_smtp_server import (
    RCPT_ACCEPTED,
    RCPT_GREYLISTED,
    RCPT_NO_SUCH_USER,
    RCPT_TEMPORARY,
    RCPT_UNVERIFIABLE,
    RoutedSMTPTransport,
    reply,
    tls_session_peer,
)

asyncio_test = pytest.mark.asyncio

DOMAIN: Final = "example.test"
FIRST: Final = "93.184.216.34"
SECOND: Final = "93.184.216.35"
OUTER_BOUND_SECONDS: Final = 5.0
TLS_SETTINGS: Final = DialogueSettings(tls_policy=TLSPolicy.REQUIRED)


#: The most draws any bounded generator may ask this fake for.
#:
#: **The fake carries the outer bound**, because the alternative is a test that
#: *hangs* when the retry cap is removed rather than failing. This repository
#: has hit that exact failure mode before — a mutation removing a polling cap
#: hung the suite instead of failing it — and a synchronous generator has no
#: `asyncio.timeout` to fall back on. Refusing the extra call converts an
#: unbounded search into a loud failure, with no wall clock involved.
MAX_DRAWS: Final = 8


class ExhaustedRandomSource(AssertionError):
    """A generator asked for more entropy than any bound permits."""


class FixedRandom:
    """A `RandomSource` a test can pin. Deterministic, per `docs/test-strategy.md`."""

    def __init__(self, *draws: str) -> None:
        self.draws = list(draws) or ["q7x2m9k4d1p8s5v3n6b0" * 2]
        self.calls = 0

    def token(self, byte_count: int) -> str:
        self.calls += 1
        if self.calls > MAX_DRAWS:
            raise ExhaustedRandomSource(
                f"the generator drew {self.calls} times; no bound permits that"
            )
        return self.draws[min(self.calls - 1, len(self.draws) - 1)]

    def jitter(self, span_seconds: float) -> float:
        return 0.0


class WallClock:
    def __init__(self) -> None:
        self.moment = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


def two_hosts() -> MailRoute:
    return route(
        candidate(FIRST, host="mx1.test.example", preference=10),
        candidate(SECOND, host="mx2.test.example", preference=20),
    )


def peer_at(address: str, *, rcpt: object = RCPT_ACCEPTED):  # type: ignore[no-untyped-def]
    return tls_session_peer(PeerEndpoint(address=address, port=25), rcpt=rcpt)  # type: ignore[arg-type]


def build(
    *,
    rcpt: object = RCPT_ACCEPTED,
    enabled: bool = True,
    authorized_domains: frozenset[str] = frozenset({DOMAIN}),
    external: bool = True,
    quota: QuotaSettings | None = None,
    state: AdminState | None = None,
    cache: InProcessAcceptAllCache | None = None,
    clock: WallClock | None = None,
    random_source: object | None = None,
    second_rcpt: object | None = None,
):  # type: ignore[no-untyped-def]
    """One experiment wired from fakes, shaped like the production graph."""
    peers = {
        FIRST: peer_at(FIRST, rcpt=rcpt),
        SECOND: peer_at(SECOND, rcpt=second_rcpt if second_rcpt is not None else rcpt),
    }
    transport = RoutedSMTPTransport(peers=peers)
    verification = SMTPVerificationService(
        probe=SMTPProbeService(
            transport=transport,  # type: ignore[arg-type]
            identity_provider=identity_provider(),
            rate_limiter=RecordingRateLimiter(),  # type: ignore[arg-type]
            clock=FakeMonotonicClock(),
            settings=TLS_SETTINGS,
        ),
        clock=clock if clock is not None else WallClock(),  # type: ignore[arg-type]
        settings=VerificationSettings(max_attempts=3),
    )
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota if quota is not None else QuotaSettings(),
        state=state if state is not None else AdminState(),
    )
    experiment = AcceptAllExperiment(
        verification=verification,
        guard=guard,
        # **`is not None`, never `or`.** `InProcessAcceptAllCache` defines
        # `__len__`, so a freshly injected *empty* cache is falsy and `or`
        # silently replaced it with a different object — which made every
        # `len(injected_cache)` assertion inspect a cache the experiment never
        # touched. An independent review found one such assertion passing
        # vacuously. The adapter's truthiness is left alone: it is not the
        # defect, and changing it would hide this rather than fix it.
        cache=cache if cache is not None else InProcessAcceptAllCache(),
        clock=clock if clock is not None else WallClock(),  # type: ignore[arg-type]
        random_source=random_source if random_source is not None else FixedRandom(),  # type: ignore[arg-type]
        settings=AcceptAllSettings(enabled=enabled),
        authorization=AcceptAllAuthorization(
            domains=authorized_domains, external_probing_authorized=external
        ),
        correlation_key=CORRELATION_KEY,
    )
    return experiment, transport


def experiment_over(
    transport,  # type: ignore[no-untyped-def]
    *,
    cache: InProcessAcceptAllCache | None = None,
    quota: QuotaSettings | None = None,
    authorized: set[str] | None = None,
    clock: WallClock | None = None,
):  # type: ignore[no-untyped-def]
    """An experiment over a transport the caller keeps a handle on.

    `build` hides the transport, which is right for most scenarios and wrong for
    the cross-domain ones: those need to change what the exchangers answer
    between two runs of the *same* experiment.
    """
    the_clock = clock if clock is not None else WallClock()
    verification = SMTPVerificationService(
        probe=SMTPProbeService(
            transport=transport,
            identity_provider=identity_provider(),
            rate_limiter=RecordingRateLimiter(),  # type: ignore[arg-type]
            clock=FakeMonotonicClock(),
            settings=TLS_SETTINGS,
        ),
        clock=the_clock,  # type: ignore[arg-type]
        settings=VerificationSettings(max_attempts=3),
    )
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=InMemoryMetrics(),
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota if quota is not None else QuotaSettings(),
    )
    return AcceptAllExperiment(
        verification=verification,
        guard=guard,
        cache=cache if cache is not None else InProcessAcceptAllCache(),
        clock=the_clock,  # type: ignore[arg-type]
        random_source=FixedRandom(),  # type: ignore[arg-type]
        settings=AcceptAllSettings(enabled=True),
        authorization=AcceptAllAuthorization(
            domains=frozenset(authorized if authorized is not None else {DOMAIN}),
            external_probing_authorized=True,
        ),
        correlation_key=CORRELATION_KEY,
    )


async def run(experiment, route_value: MailRoute | None = None):  # type: ignore[no-untyped-def]
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        return await experiment.run(route_value or two_hosts(), domain=DOMAIN, principal=PRINCIPAL)


# --- the seven scenarios the prompt names -----------------------------------


@asyncio_test
async def test_all_recipient_accept_yields_suspicion_and_never_certainty() -> None:
    """A control nobody created was accepted. Suspicion, and one risk flag."""
    experiment, transport = build(rcpt=RCPT_ACCEPTED)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.SUSPECTED
    assert transport.recipient_commands == 1
    assert [item.reason for item in result.evidence] == [ReasonCode.ACCEPT_ALL_SUSPECTED]
    assert all(not item.temporary for item in result.evidence)


@asyncio_test
async def test_only_the_real_recipient_accepted_publishes_nothing() -> None:
    """The control was rejected as an address. That is the absence of suspicion.

    **No evidence at all**, because this project has no reason code meaning
    "not accept-all" and inventing one would be inventing a claim. In
    particular it is not evidence that the caller's target exists.
    """
    experiment, transport = build(rcpt=RCPT_NO_SUCH_USER)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.NOT_SUSPECTED
    assert result.evidence == ()
    assert transport.recipient_commands == 1


@asyncio_test
async def test_a_temporary_control_response_is_never_definitive() -> None:
    experiment, _ = build(rcpt=RCPT_TEMPORARY)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.TEMPORARY
    assert result.evidence == ()


@asyncio_test
async def test_a_policy_block_is_inconclusive_rather_than_a_conclusion() -> None:
    """`5.7.1` is the destination's policy speaking, not its recipient table."""
    experiment, _ = build(rcpt=reply("550 5.7.1 policy"))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.INCONCLUSIVE
    assert result.evidence == ()


@asyncio_test
async def test_an_ambiguous_reply_does_not_declare_a_catch_all() -> None:
    """`docs/requirements.md` section 10, as a row.

    A bare `550` reaches the mapper as `smtp_ambiguous_permanent_failure`, and
    an experiment that read the basic code alone would have called this
    "rejected, therefore not accept-all".
    """
    experiment, _ = build(rcpt=reply("550 nope"))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.INCONCLUSIVE
    assert result.evidence == ()


@asyncio_test
async def test_a_server_that_will_not_verify_is_inconclusive() -> None:
    experiment, _ = build(rcpt=RCPT_UNVERIFIABLE)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.INCONCLUSIVE


@asyncio_test
async def test_greylisting_is_temporary_and_uncached() -> None:
    cache = InProcessAcceptAllCache()
    experiment, _ = build(rcpt=RCPT_GREYLISTED, cache=cache)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.TEMPORARY
    assert len(cache) == 0, "a transient answer must not become a seven-day one"


# --- the feature flag -------------------------------------------------------


@asyncio_test
async def test_the_feature_is_disabled_by_default() -> None:
    assert AcceptAllSettings().enabled is False


@asyncio_test
async def test_a_disabled_feature_probes_nothing() -> None:
    experiment, transport = build(enabled=False)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "feature_disabled"
    assert transport.connect_calls == []
    assert transport.recipient_commands == 0


@asyncio_test
async def test_enabling_the_feature_is_not_authorizing_a_domain() -> None:
    """Two separate decisions, on the precedent Phase 8's beta harness set."""
    experiment, transport = build(enabled=True, external=False)

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "not_authorized"
    assert transport.recipient_commands == 0


@asyncio_test
async def test_an_unauthorized_domain_is_refused_even_when_probing_is_authorized() -> None:
    experiment, transport = build(authorized_domains=frozenset({"elsewhere.test"}))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "not_authorized"
    assert transport.recipient_commands == 0


def test_authorization_needs_both_the_flag_and_the_domain() -> None:
    assert AcceptAllAuthorization().permits(DOMAIN) is False
    assert AcceptAllAuthorization(domains=frozenset({DOMAIN})).permits(DOMAIN) is False
    assert (
        AcceptAllAuthorization(
            domains=frozenset({DOMAIN}), external_probing_authorized=True
        ).permits(DOMAIN)
        is True
    )


# --- the separate domain budget ---------------------------------------------


@asyncio_test
async def test_the_experiment_spends_its_own_domain_budget() -> None:
    """`docs/adr/0017-accept-all-control-experiment.md`: a **separate** domain budget.

    Exhausting it stops experiments. It is not `per_target_domain`, and the two
    are measured apart below.
    """
    settings = QuotaSettings(per_accept_all_domain=1, per_target_domain=500)
    cache = InProcessAcceptAllCache()
    experiment, transport = build(quota=settings, cache=cache, rcpt=RCPT_TEMPORARY)

    first = await run(experiment)
    second = await run(experiment)

    assert first.outcome is AcceptAllOutcome.TEMPORARY
    assert second.outcome is AcceptAllOutcome.REFUSED
    assert second.refused == "controls_refused"
    assert transport.recipient_commands == 1, "the refused experiment probed nothing"


@asyncio_test
async def test_an_exhausted_experiment_budget_is_not_the_ordinary_domain_budget() -> None:
    """The separation is the requirement, so it is measured rather than assumed."""
    settings = QuotaSettings(per_accept_all_domain=1)
    experiment, _ = build(quota=settings, rcpt=RCPT_TEMPORARY)
    guard = experiment.guard

    await run(experiment)
    await run(experiment)

    assert settings.limit_for(BudgetLayer.ACCEPT_ALL_DOMAIN) == 1
    assert settings.limit_for(BudgetLayer.TARGET_DOMAIN) != 1
    # The ordinary domain layer still has room: an ordinary verification of the
    # same domain is unaffected by the experiment running out.
    await guard.authorize_destination(  # type: ignore[attr-defined]
        domain=DOMAIN, mx_host="mx1.test.example", sender_identity="none"
    )


@asyncio_test
async def test_a_refused_experiment_spends_nothing_and_probes_nothing() -> None:
    settings = QuotaSettings(per_accept_all_domain=1)
    experiment, transport = build(quota=settings, enabled=False)

    await run(experiment)

    assert transport.connect_calls == []


# --- the seven-day cache ----------------------------------------------------


@asyncio_test
async def test_a_decided_answer_is_cached_for_seven_days() -> None:
    clock = WallClock()
    cache = InProcessAcceptAllCache()
    experiment, _ = build(cache=cache, clock=clock, rcpt=RCPT_ACCEPTED)

    result = await run(experiment)

    assert result.expires_at is not None and result.checked_at is not None
    assert result.expires_at - result.checked_at == timedelta(days=7)
    assert AcceptAllSettings().cache_seconds == 7 * 24 * 60 * 60


@asyncio_test
async def test_a_cache_hit_probes_nothing() -> None:
    clock = WallClock()
    cache = InProcessAcceptAllCache()
    experiment, transport = build(cache=cache, clock=clock, rcpt=RCPT_ACCEPTED)

    first = await run(experiment)
    second = await run(experiment)

    assert first.from_cache is False
    assert second.from_cache is True
    assert second.outcome is AcceptAllOutcome.SUSPECTED
    assert transport.recipient_commands == 1, "the second experiment probed again"
    assert [item.reason for item in second.evidence] == [ReasonCode.ACCEPT_ALL_SUSPECTED]


@asyncio_test
async def test_the_cache_expires_at_seven_days_and_not_before() -> None:
    clock = WallClock()
    cache = InProcessAcceptAllCache()
    experiment, transport = build(cache=cache, clock=clock, rcpt=RCPT_ACCEPTED)

    await run(experiment)
    clock.advance(7 * 24 * 60 * 60 - 1)
    before = await run(experiment)
    assert before.from_cache is True
    assert transport.recipient_commands == 1

    clock.advance(1)
    at_expiry = await run(experiment)
    assert at_expiry.from_cache is False
    assert transport.recipient_commands == 2


@asyncio_test
async def test_the_cache_key_carries_no_local_part() -> None:
    """Accept-all is a domain property, so the key is a domain digest.

    A key carrying the caller's mailbox would file one domain's answer under
    every address anybody asked about — and would put a target in a store that
    outlives the request by a week.
    """
    experiment, _ = build()

    key = experiment._key(DOMAIN, two_hosts())

    assert key.experiment_version == EXPERIMENT_VERSION
    for forbidden in ("@", DOMAIN, "user"):
        assert forbidden not in key.domain_digest
        assert forbidden not in key.sender_digest


@asyncio_test
async def test_a_different_experiment_version_does_not_reuse_an_answer() -> None:
    """A cached answer means what the version that produced it meant."""
    experiment, _ = build()
    key = experiment._key(DOMAIN, two_hosts())

    assert key.experiment_version == EXPERIMENT_VERSION
    assert EXPERIMENT_VERSION in repr(key)


# --- one RCPT, and no adaptive second probe ---------------------------------


@asyncio_test
async def test_one_experiment_issues_exactly_one_rcpt() -> None:
    """Measured on the wire, across every connection the experiment opened."""
    experiment, transport = build(rcpt=RCPT_ACCEPTED)

    await run(experiment)

    assert transport.recipient_commands == 1


@asyncio_test
async def test_an_accepted_control_does_not_trigger_a_second_probe() -> None:
    """No branch reads the reply to decide what to ask next."""
    experiment, transport = build(rcpt=RCPT_ACCEPTED)

    await run(experiment)

    assert transport.recipient_commands == 1
    assert transport.addresses_reached == [FIRST]


@asyncio_test
async def test_a_rejected_control_does_not_trigger_a_second_probe() -> None:
    experiment, transport = build(rcpt=RCPT_NO_SUCH_USER)

    await run(experiment)

    assert transport.recipient_commands == 1
    assert transport.addresses_reached == [FIRST]


def test_the_cache_floor_is_seven_days_and_is_refused_below() -> None:
    """`docs/requirements.md` section 13 and the prompt agree on seven days.

    A shorter window would re-probe a domain inside the period both documents
    say one answer covers, which is the amplification the separate budget and
    the cache exist together to prevent. So it is a floor, not a default.
    """
    from emailcheck.domain.accept_all import (
        MAX_CACHE_SECONDS,
        MIN_CACHE_SECONDS,
        AcceptAllError,
    )

    week = 7 * 24 * 60 * 60
    assert week == MIN_CACHE_SECONDS
    assert AcceptAllSettings().cache_seconds == week

    for too_short in (0, 1, 3600, week - 1):
        with pytest.raises(AcceptAllError):
            AcceptAllSettings(cache_seconds=too_short)

    # Longer is permitted — "seven-day or longer" — up to a ceiling, so a typo
    # cannot make an answer outlive the deployment that produced it.
    assert AcceptAllSettings(cache_seconds=week).cache_seconds == week
    assert AcceptAllSettings(cache_seconds=MAX_CACHE_SECONDS).cache_seconds == MAX_CACHE_SECONDS
    with pytest.raises(AcceptAllError):
        AcceptAllSettings(cache_seconds=MAX_CACHE_SECONDS + 1)
    with pytest.raises(AcceptAllError):
        AcceptAllSettings(cache_seconds=True)


def test_the_settings_refuse_more_than_one_control_probe() -> None:
    from emailcheck.domain.accept_all import AcceptAllError

    with pytest.raises(AcceptAllError):
        AcceptAllSettings(control_probes=2)


# --- administrative controls ------------------------------------------------


@asyncio_test
async def test_the_global_kill_switch_stops_the_experiment() -> None:
    experiment, transport = build(state=AdminState(active_probing_enabled=False))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "controls_refused"
    assert transport.connect_calls == [], "the kill switch did not stop the experiment"


@asyncio_test
async def test_a_blocked_domain_stops_the_experiment() -> None:
    experiment, transport = build(state=AdminState(blocked_domains=frozenset({DOMAIN})))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "controls_refused"
    assert transport.connect_calls == []


@asyncio_test
async def test_a_blocked_exchanger_stops_the_experiment() -> None:
    experiment, transport = build(
        state=AdminState(blocked_mx_hosts=frozenset({"mx1.test.example"}))
    )

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert transport.connect_calls == []


@asyncio_test
async def test_a_disabled_sender_identity_stops_the_experiment() -> None:
    experiment, transport = build(state=AdminState(disabled_sender_identities=frozenset({"none"})))

    result = await run(experiment)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert transport.connect_calls == []


@asyncio_test
async def test_a_routeless_domain_is_never_probed() -> None:
    experiment, transport = build()
    routeless = MailRoute(domain=two_hosts().domain, outcome=MailRouteOutcome.NULL_MX)

    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        result = await experiment.run(routeless, domain=DOMAIN, principal=PRINCIPAL)

    assert result.outcome is AcceptAllOutcome.REFUSED
    assert result.refused == "no_route"
    assert transport.connect_calls == []


# --- the generator ----------------------------------------------------------


def test_a_control_local_part_is_long_random_and_in_the_alphabet() -> None:
    control = generate_control_local_part(FixedRandom())  # type: ignore[arg-type]

    assert len(control.value) == CONTROL_LOCAL_PART_LENGTH
    assert set(control.value) <= set(CONTROL_ALPHABET)


def test_the_generator_refuses_a_colliding_draw_within_a_finite_bound() -> None:
    """Finite retries, then a refusal. Never an unbounded search.

    `FixedRandom` refuses beyond `MAX_DRAWS`, so removing the retry cap raises
    `ExhaustedRandomSource` here instead of spinning for ever — the property is
    that this test *fails*, and a test that hangs is not one.
    """
    collided = "q7x2m9k4d1p8s5v3n6b0"
    source = FixedRandom(collided * 2)

    with pytest.raises((AcceptAllRefused, ExhaustedRandomSource)):
        generate_control_local_part(source, forbidden=frozenset({collided}))  # type: ignore[arg-type]

    assert source.calls <= MAX_DRAWS
    assert source.calls <= MAX_COLLISION_RETRIES, "the generator drew past its own bound"


def test_the_generator_draws_from_the_random_source_port() -> None:
    source = FixedRandom()

    generate_control_local_part(source)  # type: ignore[arg-type]

    assert source.calls == 1


# --- what the experiment never does -----------------------------------------


@asyncio_test
async def test_the_result_never_carries_a_status_or_the_control_address() -> None:
    experiment, transport = build(rcpt=RCPT_ACCEPTED)

    result = await run(experiment)
    rendered = repr(result) + repr(result.evidence)

    assert "@" not in rendered
    for status in Status:
        assert status.value not in rendered
    for connection in transport.connections:
        assert connection.wire_text().count("RCPT TO") == 1


@asyncio_test
async def test_the_only_risk_flag_this_phase_can_reach_is_accept_all_suspected() -> None:
    """`docs/adr/0017-accept-all-control-experiment.md`'s Result section: "only add" that flag."""
    from emailcheck.application.aggregate import aggregate_evidence

    experiment, _ = build(rcpt=RCPT_ACCEPTED)
    result = await run(experiment)

    verdict = aggregate_evidence(result.evidence)

    assert verdict.risk_flags == frozenset({RiskFlag.ACCEPT_ALL_SUSPECTED})
    assert verdict.status is Status.UNKNOWN


# --- F1: the cache partitions by domain -------------------------------------
#
# An independent review replaced the domain digest with a constant and with the
# sender digest, and the whole suite passed. The old test only asserted that
# forbidden strings were *absent* from the digest, which is true of any digest —
# including one that ignores the domain entirely. What was missing is that the
# key is a **function of the domain**, and the consequence of its absence is
# specific: one domain's answer served for every other domain, for seven days.

OTHER_DOMAIN: Final = "other.test"


async def run_for(experiment, domain: str):  # type: ignore[no-untyped-def]
    """One experiment against a named domain, through the ordinary path."""
    async with asyncio.timeout(OUTER_BOUND_SECONDS):
        return await experiment.run(
            route(
                candidate(FIRST, host="mx1.test.example", preference=10),
                candidate(SECOND, host="mx2.test.example", preference=20),
                domain=domain,
            ),
            domain=domain,
            principal=PRINCIPAL,
        )


def test_two_domains_do_not_share_a_cache_key() -> None:
    """The same sender and the same version, and the keys still differ."""
    experiment, _ = build()

    first = experiment._key(DOMAIN, two_hosts())
    second = experiment._key(OTHER_DOMAIN, two_hosts())

    assert first.domain_digest != second.domain_digest
    # The other two components are held constant on purpose: if they were what
    # differed, this would pass while the domain was ignored.
    assert first.sender_digest == second.sender_digest
    assert first.experiment_version == second.experiment_version


def test_the_same_domain_reaches_the_same_cache_key() -> None:
    """Deterministic, so a hit is a hit rather than a coincidence."""
    experiment, _ = build()

    assert experiment._key(DOMAIN, two_hosts()) == experiment._key(DOMAIN, two_hosts())


@asyncio_test
async def test_one_domains_answer_is_never_served_for_another() -> None:
    """The property the constant-digest mutation broke, measured end to end.

    The two domains are scripted to **opposite** answers, so a shared key would
    publish `accept_all_suspected` about a domain whose control was rejected —
    a wrong claim, cached for a week. Failing on the outcome rather than on the
    key is what makes this test about the consequence.
    """
    cache = InProcessAcceptAllCache()
    peers = {
        FIRST: peer_at(FIRST, rcpt=RCPT_ACCEPTED),
        SECOND: peer_at(SECOND, rcpt=RCPT_ACCEPTED),
    }
    transport = RoutedSMTPTransport(peers=peers)
    experiment = experiment_over(transport, cache=cache, authorized={DOMAIN, OTHER_DOMAIN})

    suspected = await run_for(experiment, DOMAIN)
    assert suspected.outcome is AcceptAllOutcome.SUSPECTED
    assert suspected.from_cache is False

    # A different domain, whose exchangers reject the control.
    transport.peers = {
        FIRST: peer_at(FIRST, rcpt=RCPT_NO_SUCH_USER),
        SECOND: peer_at(SECOND, rcpt=RCPT_NO_SUCH_USER),
    }
    other = await run_for(experiment, OTHER_DOMAIN)

    assert other.from_cache is False, "the second domain was answered from the first's row"
    assert other.outcome is AcceptAllOutcome.NOT_SUSPECTED
    assert other.evidence == ()
    # And the first domain still answers from its own row, unchanged.
    again = await run_for(experiment, DOMAIN)
    assert again.from_cache is True
    assert again.outcome is AcceptAllOutcome.SUSPECTED


@asyncio_test
async def test_a_cache_hit_still_costs_no_probe_after_the_partition_fix() -> None:
    """F1 must not be closed by breaking the suppression it sits beside."""
    cache = InProcessAcceptAllCache()
    experiment, transport = build(cache=cache, rcpt=RCPT_ACCEPTED)

    await run(experiment)
    draws_after_first = experiment.random_source.calls  # type: ignore[attr-defined]
    second = await run(experiment)

    assert second.from_cache is True
    assert transport.recipient_commands == 1
    assert len(transport.connect_calls) == 1
    assert experiment.random_source.calls == draws_after_first  # type: ignore[attr-defined]


def test_the_cache_key_still_carries_no_raw_identifier() -> None:
    """Partitioning by domain must not have been bought with the privacy."""
    experiment, _ = build()

    key = experiment._key(DOMAIN, two_hosts())

    for raw in (DOMAIN, "@", "none", "user"):
        assert raw not in key.domain_digest
        assert raw not in key.sender_digest
    assert len(key.domain_digest) == 64


def test_a_different_experiment_version_is_a_different_key() -> None:
    """Advisable, per the review: the version component must matter too."""
    experiment, _ = build()
    key = experiment._key(DOMAIN, two_hosts())

    other = dataclasses.replace(key, experiment_version="accept-all-elsewhen")

    assert other != key
    assert other.domain_digest == key.domain_digest


# --- F2: the separate budget partitions by domain ---------------------------


@asyncio_test
async def test_exhausting_one_domains_experiment_budget_leaves_another_free() -> None:
    """A *separate domain* budget, not merely a separate counter.

    The review's mutations keyed this layer on a constant and on the sender
    identity, and both passed: the old tests measured *that* it refused, never
    what it partitioned. Every other layer is raised far above one here, so the
    only thing that can refuse the second run is the accept-all domain layer.
    """
    settings = QuotaSettings(
        per_accept_all_domain=1,
        per_api_key=1000,
        per_account=1000,
        per_target=1000,
        per_target_domain=1000,
        per_target_mx=1000,
        per_sender_identity=1000,
        daily_total=1000,
    )
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_at(FIRST, rcpt=RCPT_TEMPORARY),
            SECOND: peer_at(SECOND, rcpt=RCPT_TEMPORARY),
        }
    )
    experiment = experiment_over(transport, quota=settings, authorized={DOMAIN, OTHER_DOMAIN})

    first = await run_for(experiment, DOMAIN)
    second = await run_for(experiment, DOMAIN)
    other = await run_for(experiment, OTHER_DOMAIN)

    assert first.outcome is AcceptAllOutcome.TEMPORARY
    assert second.outcome is AcceptAllOutcome.REFUSED, "one domain's budget did not bind"
    assert second.refused == "controls_refused"
    assert other.outcome is AcceptAllOutcome.TEMPORARY, (
        "a second domain was refused by the first domain's budget"
    )
    assert transport.recipient_commands == 2


@asyncio_test
async def test_two_mailboxes_on_one_domain_share_the_experiment_budget() -> None:
    """Accept-all is a domain property, so the budget is not per mailbox.

    The experiment takes a domain rather than an address, so this is measured
    the only way it can be: the same domain twice exhausts the budget, which a
    per-mailbox key never would because each run generates a different control.
    """
    settings = QuotaSettings(per_accept_all_domain=1, per_target_domain=1000, daily_total=1000)
    transport = RoutedSMTPTransport(
        peers={
            FIRST: peer_at(FIRST, rcpt=RCPT_TEMPORARY),
            SECOND: peer_at(SECOND, rcpt=RCPT_TEMPORARY),
        }
    )
    experiment = experiment_over(transport, quota=settings)

    await run_for(experiment, DOMAIN)
    repeat = await run_for(experiment, DOMAIN)

    assert repeat.outcome is AcceptAllOutcome.REFUSED
    assert transport.recipient_commands == 1


def test_the_experiment_budget_is_its_own_layer_with_its_own_limit() -> None:
    """The layer, the limit, and the window, read from source rather than assumed."""
    settings = QuotaSettings()

    assert settings.limit_for(BudgetLayer.ACCEPT_ALL_DOMAIN) == 5
    assert settings.limit_for(BudgetLayer.TARGET_DOMAIN) == 500
    assert settings.window_for(BudgetLayer.ACCEPT_ALL_DOMAIN) == 3600
    assert BudgetLayer.ACCEPT_ALL_DOMAIN is not BudgetLayer.TARGET_DOMAIN


def test_the_experiment_budget_key_cannot_be_a_mailbox() -> None:
    """`BudgetKey` refuses an `@`, so the layer's value is structurally a domain."""
    from emailcheck.domain.abuse import BudgetKey, BudgetKeyError

    assert BudgetKey(layer=BudgetLayer.ACCEPT_ALL_DOMAIN, value=DOMAIN).value == DOMAIN
    with pytest.raises(BudgetKeyError):
        BudgetKey(layer=BudgetLayer.ACCEPT_ALL_DOMAIN, value=f"user@{DOMAIN}")


# --- F3: the injected cache is the one that is used -------------------------


@asyncio_test
async def test_the_injected_cache_is_the_object_the_experiment_uses() -> None:
    """The dependency-injection contract, independent of whether it is empty.

    `cache or InProcessAcceptAllCache()` discarded an injected *empty* cache,
    because the adapter defines `__len__`. Every assertion on such a cache was
    then about an object nothing wrote to.
    """
    injected = InProcessAcceptAllCache()
    assert not injected, "an empty cache is falsy — which is what made `or` wrong"

    experiment, _ = build(cache=injected)

    assert experiment.cache is injected


@asyncio_test
async def test_a_definitive_result_reaches_the_injected_cache() -> None:
    """Proves the injected cache is load-bearing before the next test relies on it."""
    injected = InProcessAcceptAllCache()
    experiment, transport = build(cache=injected, rcpt=RCPT_ACCEPTED)

    first = await run(experiment)

    assert first.outcome is AcceptAllOutcome.SUSPECTED
    assert len(injected) == 1

    second = await run(experiment)
    assert second.from_cache is True
    assert transport.recipient_commands == 1


@asyncio_test
@pytest.mark.parametrize(
    ("label", "rcpt"),
    [
        ("greylisted", RCPT_GREYLISTED),
        ("temporary", RCPT_TEMPORARY),
        ("bare 550", reply("550 nope")),
        ("policy", reply("550 5.7.1 policy")),
        ("unverifiable", RCPT_UNVERIFIABLE),
    ],
)
async def test_a_transient_or_ambiguous_outcome_never_reaches_the_cache(
    label: str, rcpt: object
) -> None:
    """The direct proof, on the cache the experiment actually used.

    The previous version of this assertion inspected a discarded cache and so
    proved nothing; the mutation "cache a transient outcome" was caught only
    incidentally, by a budget test. This fails for the cache's own reason.
    """
    injected = InProcessAcceptAllCache()
    experiment, transport = build(cache=injected, rcpt=rcpt)

    first = await run(experiment)

    assert first.outcome not in {AcceptAllOutcome.SUSPECTED, AcceptAllOutcome.NOT_SUSPECTED}
    assert len(injected) == 0, f"{label} was frozen for seven days"
    assert first.expires_at is None

    # And the next caller asks again rather than inheriting one bad minute.
    second = await run(experiment)
    assert second.from_cache is False
    assert transport.recipient_commands == 2


# --- F4: the evidence strength is exactly WEAK ------------------------------


@asyncio_test
async def test_the_suspicion_evidence_is_weak_and_non_temporary() -> None:
    """Asserted directly, because Phase 5 reads no strength for this gate.

    `WEAK -> STRONG` changed no status and so failed nothing — which is why the
    contract needs its own assertion rather than an aggregation test.
    """
    experiment, _ = build(rcpt=RCPT_ACCEPTED)

    result = await run(experiment)

    assert len(result.evidence) == 1
    observation = result.evidence[0]
    assert observation.strength is EvidenceStrength.WEAK
    assert observation.temporary is False
    assert observation.layer is EvidenceLayer.ACCEPT_ALL
    assert observation.reason is ReasonCode.ACCEPT_ALL_SUSPECTED


@asyncio_test
async def test_a_cached_suspicion_carries_the_same_contract_as_a_fresh_one() -> None:
    """A cache hit must not upgrade or downgrade what it replays."""
    experiment, _ = build(rcpt=RCPT_ACCEPTED)

    fresh = await run(experiment)
    cached = await run(experiment)

    assert cached.from_cache is True
    assert len(cached.evidence) == len(fresh.evidence) == 1
    assert cached.evidence[0].strength is fresh.evidence[0].strength is EvidenceStrength.WEAK
    assert cached.evidence[0].reason is fresh.evidence[0].reason
    assert cached.evidence[0].layer is fresh.evidence[0].layer
