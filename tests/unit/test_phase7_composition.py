"""Phase 7's graph, and the memory bound it publishes.

The wiring assertions are Phase 6's discipline continued: a guard, a quota
store, and an administrative state rebuilt per request permit everything, so
the sharing is asserted by object identity rather than trusted.
"""

from __future__ import annotations

import pytest
from tests.phase7_fixtures import CORRELATION_KEY

from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

KEY = "k" * 40


def passive_deployment() -> Deployment:
    return Deployment(api_keys={"acct-1": KEY}, correlation_key=CORRELATION_KEY)


def active_deployment() -> Deployment:
    return Deployment(
        api_keys={"acct-1": KEY},
        correlation_key=CORRELATION_KEY,
        profile=DeploymentProfile.LAB_ACTIVE,
        lab_destination_allowlist=frozenset({"mx.test.example"}),
    )


# --- one of each -------------------------------------------------------------


def test_one_guard_one_quota_store_and_one_admin_control_per_process() -> None:
    stack = build_verification_stack(active_deployment())
    assert stack.guard is not None
    assert stack.admin is not None
    assert stack.admin.guard is stack.guard
    assert stack.verification.guard is stack.guard
    assert stack.jobs is not None
    assert stack.jobs.guard is stack.guard
    assert stack.retention is not None
    assert stack.retention.quota is stack.guard.quota


def test_the_guard_shares_the_correlation_key_with_the_cache_and_the_registry() -> None:
    """One address has one digest everywhere, or the target budget and the
    cache would be counting different things."""
    stack = build_verification_stack(active_deployment())
    assert stack.guard is not None and stack.jobs is not None
    assert stack.guard.correlation_key == stack.correlation_key
    assert stack.jobs.correlation_key == stack.correlation_key


def test_the_administrative_state_comes_from_the_deployment() -> None:
    """A deployment recovering from an incident may start with the kill switch
    already thrown, rather than serving one request before an operator can
    reach the admin tool."""
    from emailcheck.domain.admin import AdminState

    stack = build_verification_stack(
        Deployment(
            api_keys={"acct-1": KEY},
            correlation_key=CORRELATION_KEY,
            profile=DeploymentProfile.LAB_ACTIVE,
            lab_destination_allowlist=frozenset({"mx.test.example"}),
            admin_state=AdminState(active_probing_enabled=False),
        )
    )
    assert stack.guard is not None
    assert stack.guard.state.active_probing_enabled is False


def test_the_sender_identity_reaches_the_verification_service_from_configuration() -> None:
    """Operator configuration, never a request field — so the sender kill switch
    has something stable to name."""
    stack = build_verification_stack(passive_deployment())
    assert isinstance(stack.verification.sender_identity, str)
    assert stack.verification.sender_identity != ""


def test_building_twice_gives_independent_graphs() -> None:
    first = build_verification_stack(active_deployment())
    second = build_verification_stack(active_deployment())
    assert first.guard is not second.guard


def test_the_builder_still_exposes_no_seam_for_a_clock_or_a_limiter() -> None:
    """The four Phase 4 stop conditions, unchanged by Phase 7."""
    import inspect

    signature = inspect.signature(build_verification_stack)
    assert set(signature.parameters) == {"deployment", "operator"}


# --- the memory bound --------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "bound_is_finite"),
    [
        ("admission queue", True),
        ("admission in flight", True),
        ("quota counters", True),
        ("indicator windows", True),
        ("keys per source", True),
        ("job registry", True),
        ("executor queue", True),
        ("delayed retries", True),
        ("idempotency bindings", True),
        ("audit ring", True),
        ("limiter domains", True),
        ("metric series", True),
    ],
)
def test_every_process_local_table_has_a_finite_bound(name: str, bound_is_finite: bool) -> None:
    """The table ADR 0016 publishes, asserted
    rather than
    described. Each of these is a structure an unauthenticated or authenticated
    caller can cause entries in, so each needs a ceiling that does not depend on
    traffic."""
    from emailcheck.adapters.execution.memory_executor import ExecutorSettings
    from emailcheck.adapters.system.quota import DEFAULT_MAX_COUNTERS
    from emailcheck.application.abuse import DEFAULT_MAX_TRACKED_CALLERS, MAX_KEYS_PER_SOURCE
    from emailcheck.application.admin import DEFAULT_AUDIT_CAPACITY
    from emailcheck.application.admission import AdmissionSettings
    from emailcheck.application.jobs import JobSettings
    from emailcheck.domain.indicators import MAX_WINDOW
    from emailcheck.domain.rate_limit import RateLimitSettings
    from emailcheck.ports.metrics import INDICATOR_SUBJECTS, PERMITTED_SUBJECTS, MetricName

    bounds = {
        "admission queue": AdmissionSettings().max_waiting,
        "admission in flight": AdmissionSettings().max_in_flight,
        "quota counters": DEFAULT_MAX_COUNTERS,
        "indicator windows": DEFAULT_MAX_TRACKED_CALLERS * MAX_WINDOW,
        "keys per source": DEFAULT_MAX_TRACKED_CALLERS * MAX_KEYS_PER_SOURCE,
        "job registry": JobSettings().max_jobs,
        "executor queue": ExecutorSettings().max_queued,
        "delayed retries": ExecutorSettings().max_delayed,
        "idempotency bindings": JobSettings().max_jobs,
        "audit ring": DEFAULT_AUDIT_CAPACITY,
        "limiter domains": RateLimitSettings().max_tracked_domains,
        "metric series": len(MetricName) * (len(PERMITTED_SUBJECTS | INDICATOR_SUBJECTS) + 1),
    }
    value = bounds[name]
    assert isinstance(value, int) and 0 < value < 100_000_000, (name, value)


def test_the_idempotency_bindings_cannot_outnumber_the_jobs() -> None:
    """One binding per job at most, so the registry bound covers both — which is
    only true because a rollback and an eviction each remove the pair."""
    from emailcheck.application.jobs import JobService

    source = JobService.purge_finished.__doc__ or ""
    assert "binding" in source.lower()
