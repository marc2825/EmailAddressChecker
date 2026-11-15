"""The production object graph, asserted as a graph.

Four Phase 4 stop conditions are properties of *how the objects are wired*
rather than of any class, so they can only be checked here: one shared limiter,
one shared admission gate, the real clock and sleeper, and an SMTP service that
exists only when a deployment permits probing.

Nothing in this file opens a socket. `build_verification_stack` constructs
adapters — a resolver object, a transport object — but constructing them
performs no I/O, and the suite-wide guard would fail the test if it did.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from emailcheck.adapters.observability.logging_sink import LoggingOperatorSink
from emailcheck.adapters.system.clock import SystemClock, SystemMonotonicClock, SystemSleeper
from emailcheck.adapters.system.rate_limit import InProcessRateLimiter
from emailcheck.application.admission import AdmissionSettings
from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack
from emailcheck.domain.principal import Principal

KEY = "k" * 40
CORRELATION_KEY = b"c" * 32

SENDER = {
    "ehlo_hostname": "probe.example.test",
    "envelope_sender": "verify@probe.example.test",
}


def _with_authority(kwargs: dict[str, object]) -> dict[str, object]:
    """A persistent deployment needs the deletion authority beside its stores.

    Composition refuses one without it — a persistent store whose deletions no
    other replica can see is the configuration the focused review used to bring
    an erased account back — so a fixture that persists anything names the file
    next to whichever store it configured.
    """
    if kwargs.get("account_state_path") is None:
        for name in ("job_store_path", "store_path"):
            configured = kwargs.get(name)
            if isinstance(configured, Path):
                kwargs["account_state_path"] = configured.parent / "accounts.sqlite3"
                break
    return kwargs


def passive_deployment(**kwargs: object) -> Deployment:
    return Deployment(  # type: ignore[arg-type]
        api_keys={"acct-1": KEY}, correlation_key=CORRELATION_KEY, **_with_authority(kwargs)
    )


LAB_ALLOWLIST = frozenset({"mx.test.example"})


def active_deployment(**kwargs: object) -> Deployment:
    """A probing deployment, which by `docs/requirements.md` section 15 is not
    the local-passive profile — that one is defined as "no active probes".

    The destination allowlist is not decoration here: section 15 gives
    lab-active one, and Remediation B made a probing lab deployment without it
    refuse to start. A fixture that omitted it would be building a deployment
    the composition root no longer accepts.
    """
    kwargs.setdefault("profile", DeploymentProfile.LAB_ACTIVE)
    if kwargs.get("profile") is DeploymentProfile.LAB_ACTIVE:
        kwargs.setdefault("lab_destination_allowlist", LAB_ALLOWLIST)
    return Deployment(
        api_keys={"acct-1": KEY},
        correlation_key=CORRELATION_KEY,
        sender_identity=SENDER,
        active_probing=True,
        **_with_authority(kwargs),  # type: ignore[arg-type]
    )


# --- one process, one limiter, one gate -------------------------------------


def test_the_stack_shares_one_limiter_and_one_admission_gate() -> None:
    """A limiter constructed per request permits everything.

    Its counters start at zero every time, so a per-request limiter is a
    limiter that has never seen a previous request. The same is true of the
    admission gate. Asserted by identity rather than by type.
    """
    stack = build_verification_stack(active_deployment())

    assert stack.verification.admission is stack.admission
    assert isinstance(stack.limiter, InProcessRateLimiter)
    assert stack.verification.smtp is not None
    assert stack.verification.smtp.probe.rate_limiter is stack.limiter


def test_two_verifications_through_one_stack_use_the_same_objects() -> None:
    """The property the sharing exists for, stated as the graph rather than a run."""
    stack = build_verification_stack(active_deployment())
    first = stack.verification.smtp
    second = stack.verification.smtp
    assert first is second
    assert stack.admission is stack.verification.admission


def test_two_stacks_are_independent() -> None:
    """One process shares; two processes do not. A shared *class* would be a bug."""
    one = build_verification_stack(active_deployment())
    two = build_verification_stack(active_deployment())
    assert one.limiter is not two.limiter
    assert one.admission is not two.admission


# --- the real clock and the real sleeper ------------------------------------


def test_the_production_graph_binds_the_real_clock_and_sleeper() -> None:
    """Phase 4 stop condition 4.

    The dependency-injection seam stays — every component still takes a port,
    which is what makes Phase 4's pacing tests possible without waiting — but
    the production graph has no argument through which a fake reaches it.
    """
    stack = build_verification_stack(active_deployment())

    assert isinstance(stack.limiter.clock, SystemMonotonicClock)
    assert isinstance(stack.limiter.sleeper, SystemSleeper)
    assert isinstance(stack.verification.routes.clock, SystemClock)
    assert isinstance(stack.verification.syntax.clock, SystemClock)
    assert stack.verification.smtp is not None
    assert isinstance(stack.verification.smtp.clock, SystemClock)
    assert isinstance(stack.verification.smtp.probe.clock, SystemMonotonicClock)


def test_the_builder_has_no_parameter_for_a_clock_a_sleeper_or_a_limiter() -> None:
    """The four stop conditions this function exists to close, as a signature.

    A keyword argument for any of them would be the hole each one names, so the
    absence is asserted rather than left to a reviewer's memory. `operator` is
    the one seam, and it is write-only.
    """
    import inspect

    parameters = set(inspect.signature(build_verification_stack).parameters)
    assert parameters == {"deployment", "operator"}
    for forbidden in ("clock", "sleeper", "limiter", "transport", "trust", "tls"):
        offenders = [name for name in parameters if forbidden in name]
        assert offenders == [], (forbidden, offenders)


# --- the passive profile is a shape, not a flag -----------------------------


def test_a_passive_deployment_gets_no_smtp_service_at_all() -> None:
    """`docs/requirements.md` section 15: local-passive has no active probes."""
    stack = build_verification_stack(passive_deployment())
    assert stack.verification.smtp is None


def test_an_active_deployment_without_a_sender_identity_refuses_to_start() -> None:
    """An unconfigured deployment does not probe.

    `adapters/smtp/sender_identity.py` refuses to invent an EHLO name, so this
    fails at start rather than at the first request.
    """
    with pytest.raises(ValueError, match="sender identity"):
        Deployment(
            api_keys={"acct-1": KEY},
            correlation_key=CORRELATION_KEY,
            active_probing=True,
        )


def test_the_sender_identity_comes_from_operator_configuration() -> None:
    """Never from a target and never from a request."""
    stack = build_verification_stack(active_deployment())
    assert stack.verification.smtp is not None
    identity = stack.verification.smtp.probe.identity_provider.current_identity()
    assert identity.ehlo.host.value == "probe.example.test"
    assert identity.envelope_sender.address.smtp_target == "verify@probe.example.test"


# --- TLS trust is operator configuration ------------------------------------


def test_the_transport_uses_the_system_trust_and_exposes_no_override() -> None:
    """Phase 4 stop condition 7.

    `TLSTrust` may only widen trust and comes from `adapters/smtp/tls.py`'s
    default here. There is no `Deployment` field and no builder parameter that
    could carry a CA file, a PEM body, or a verification override.
    """
    from emailcheck.adapters.smtp.tls import SYSTEM_TRUST

    stack = build_verification_stack(active_deployment())
    assert stack.verification.smtp is not None
    assert stack.verification.smtp.probe.transport.trust is SYSTEM_TRUST

    # Substring rather than exact membership: a mutation run added `tls_trust`
    # and an exact check missed it, because the forbidden thing is a field
    # *about* TLS trust rather than a field with one particular name.
    fields = set(Deployment.__dataclass_fields__)
    for forbidden in ("trust", "ca_file", "tls", "verify", "insecure", "cert", "policy"):
        offenders = [name for name in fields if forbidden in name]
        assert offenders == [], (forbidden, offenders)


# --- authentication ---------------------------------------------------------


def test_the_stack_authenticates_only_configured_keys() -> None:
    stack = build_verification_stack(passive_deployment())
    principal = stack.authenticator.authenticate(KEY)
    assert principal is not None
    assert principal.account_id == "acct-1"
    assert principal == Principal(account_id="acct-1", key_id=principal.key_id)
    assert stack.authenticator.authenticate("j" * 40) is None
    assert stack.authenticator.authenticate(None) is None


def test_a_deployment_carries_no_secret_into_its_repr() -> None:
    """A `Deployment` is logged by accident more often than anything else."""
    stack = build_verification_stack(passive_deployment())
    rendered = repr(stack.authenticator)
    assert KEY not in rendered


# --- the store --------------------------------------------------------------


def test_a_store_is_created_and_initialized_only_when_configured(tmp_path: Path) -> None:
    assert build_verification_stack(passive_deployment()).store is None

    path = tmp_path / "verdicts.sqlite3"
    stack = build_verification_stack(passive_deployment(store_path=path))
    assert stack.store is not None
    assert path.exists()


def test_the_operator_sink_defaults_to_the_logging_one() -> None:
    stack = build_verification_stack(passive_deployment())
    assert isinstance(stack.operator, LoggingOperatorSink)
    assert stack.verification.operator is stack.operator


def test_admission_settings_reach_the_gate() -> None:
    stack = build_verification_stack(
        passive_deployment(admission=AdmissionSettings(max_in_flight=3, max_per_principal=2))
    )
    assert stack.admission.settings.max_in_flight == 3
    assert stack.admission.settings.max_per_principal == 2


def test_a_short_correlation_key_is_refused_at_configuration() -> None:
    with pytest.raises(ValueError, match="at least"):
        Deployment(api_keys={}, correlation_key=b"short")


# --- the job store, which was built and then not handed over -----------------
#
# The final system audit found `SQLiteJobStore` implemented, tested, and reachable
# from no configuration: this module constructed none and `JobService` therefore
# ran with `store=None` everywhere. The durable idempotency claim that makes two
# replicas agree and the recipient-touch checkpoint that stops a restarted
# process replaying an operation both live behind that field, so the effect was
# that neither existed in any deployment.


def test_a_configured_job_store_reaches_the_job_service(tmp_path: Path) -> None:
    """Identity, not existence.

    "A store was created" and "the service has it" are different statements and
    only the second one changes behaviour — which is exactly the gap the audit
    measured, so the assertion is `is`.
    """
    path = tmp_path / "jobs.sqlite3"
    stack = build_verification_stack(active_deployment(job_store_path=path))

    assert stack.jobs is not None
    assert stack.job_store is not None
    assert stack.jobs.store is stack.job_store, "the job service was given no persistence"
    assert path.exists(), "the schema was never created"


def test_the_retention_sweep_gets_the_same_job_store(tmp_path: Path) -> None:
    """Otherwise persisted jobs outlive `docs/privacy.md` section 3's window
    while the in-memory registry is swept on time."""
    stack = build_verification_stack(active_deployment(job_store_path=tmp_path / "jobs.sqlite3"))

    assert stack.retention is not None
    assert stack.retention.job_store is stack.job_store


def test_an_unconfigured_job_store_is_visibly_absent_rather_than_silently(
    tmp_path: Path,
) -> None:
    """`None` is a deployment that has none, and every call site checks."""
    stack = build_verification_stack(active_deployment())

    assert stack.jobs is not None
    assert stack.job_store is None
    assert stack.jobs.store is None


def test_the_local_passive_profile_is_refused_a_job_store(tmp_path: Path) -> None:
    """That profile accepts no job, so a job database would be a file nothing
    writes and a retention obligation nothing incurs."""
    with pytest.raises(ValueError, match="job store"):
        passive_deployment(job_store_path=tmp_path / "jobs.sqlite3")


def test_the_deployment_repr_names_the_job_store_and_still_no_secret() -> None:
    """`Deployment` is the object most likely to be logged by accident."""
    text = repr(active_deployment(job_store_path=Path("/var/lib/emailcheck/jobs.sqlite3")))

    assert "jobs.sqlite3" in text
    assert KEY not in text
    assert "correlation_key=<redacted>" in text


# --- the retention schedule (B4) --------------------------------------------
#
# `RetentionService` was built here and called from nowhere, so every window in
# `docs/privacy.md` was enforced by whoever remembered. Which profiles get a
# sweeping daemon is a property of the object graph rather than of any class in
# it, so it can only be pinned here.


@pytest.mark.parametrize(
    ("profile", "scheduled"),
    [
        (DeploymentProfile.LOCAL_PASSIVE, False),
        (DeploymentProfile.LAB_ACTIVE, True),
    ],
    ids=["local-passive", "lab-active"],
)
def test_only_the_profiles_that_own_service_state_get_a_retention_daemon(
    profile: DeploymentProfile, scheduled: bool
) -> None:
    """A developer laptop does not silently acquire a background deletion task
    because the class exists; a lab deployment that owns jobs and batches does.
    """
    deployment = active_deployment() if scheduled else passive_deployment()
    assert deployment.profile is profile

    stack = build_verification_stack(deployment)

    assert (stack.retention_scheduler is not None) is scheduled
    assert stack.retention is not None, "every profile still has the operator trigger"


def test_the_scheduler_sweeps_the_same_service_the_operator_triggers() -> None:
    """One cleanup seam. An operator invoking the trigger can never get
    different policy from the timer."""
    stack = build_verification_stack(active_deployment())

    assert stack.retention_scheduler is not None
    assert stack.retention_scheduler.service is stack.retention
    assert stack.retention_scheduler.settings is stack.retention.settings


@pytest.mark.asyncio
async def test_starting_and_closing_the_stack_starts_and_stops_both_tasks() -> None:
    """The executor and the retention sweep share one lifecycle, and neither
    outlives `aclose` — a sweep left running holds a database connection."""
    stack = build_verification_stack(active_deployment())
    assert stack.executor is not None and stack.retention_scheduler is not None

    await stack.start()
    retention_task = stack.retention_scheduler._task
    assert retention_task is not None and not retention_task.done()

    await stack.aclose()

    assert retention_task.done(), "the retention task outlived the stack"


@pytest.mark.asyncio
async def test_the_operator_trigger_runs_one_sweep_and_needs_no_route() -> None:
    """`docs/threat-model.md`'s "trigger deletion", as an application
    operation on the built stack rather than a public endpoint — a deletion
    route reachable by a caller is a denial-of-service control with an audit
    trail attached."""
    stack = build_verification_stack(active_deployment())

    report = await stack.run_retention()

    assert report.failed is False
    assert report.total_removed == 0
    # And it is not reachable as a request: the API's schema is closed.
    from emailcheck.apps.api import PERMITTED_REQUEST_KEYS

    assert frozenset({"email"}) == PERMITTED_REQUEST_KEYS
