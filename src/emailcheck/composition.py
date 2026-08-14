"""The production composition root. Built once, shared by every request.

Phases 1 to 5 published components and no wiring, deliberately: a composition
root written alongside a component is one shaped by that component's
convenience. This is the wiring, and it is the only place in `src/` that names
a concrete adapter.

Four Phase 4 stop conditions are closed *here* rather than anywhere else,
because each of them is a property of the object graph rather than of any class
in it.

**One limiter, one admission gate, for the process.** A limiter constructed per
request permits everything: its counters start at zero every time. The same is
true of admission control. So both are built once, in `build_verification_stack`,
and a test asserts two requests through one stack observe the *same* objects.

**The real clock and the real sleeper.** `SystemClock`, `SystemMonotonicClock`,
and `SystemSleeper` are bound here with no parameter to replace them. The
dependency-injection seam stays — every component still takes a port, which is
what makes Phase 4's pacing tests possible — but the production graph has no
argument through which a fake reaches it, and an inspection test asserts this
module names no fake.

**`TLSTrust` is operator configuration.** The transport takes the system trust
by default and this function exposes no parameter for a CA file, a PEM body, or
a verification override. `docs/architecture.md` and ADR 0009 make that a stop
condition rather than a convention, and the existing inspection test already
refuses a `TLSTrust` constructed anywhere outside `adapters/smtp/tls.py`.

**The sender identity is operator configuration too.** It comes from a mapping
this function is handed, never from a target and never from a request.

**A component that is built here is a component that is wired here.** The
persistent `JobStore` existed in `adapters/` and this module constructed none,
so `JobService` ran with `store=None` in every deployment: the durable
idempotency claim that makes two replicas agree, and the recipient-touch
checkpoint that stops a restarted process replaying an operation which may
already have contacted a mailbox, were both unreachable from any configuration.
The final system audit found it. The wiring is now here, `VerificationStack`
holds the store as a field, and a composition test asserts the *identity* of
`stack.jobs.store` — because "a store was created" and "the service has it" are
different statements and only the second one matters.

**A profile is a refusal, not a label.** `docs/requirements.md` section 15 gives
service-active an isolated worker and authentication;
`prompts/06-api-cli.md` asks for a configuration that *refuses* the unsafe
combinations. So `DeploymentProfile` is checked here: service-active with active
probing and no API keys does not start, and service-active on the in-process
executor does not start either — an in-memory job runner is a development tool,
and letting it become the production default by omission is exactly how a fake
ships.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from emailcheck.adapters.auth.api_keys import StaticApiKeyAuthenticator, build_authenticator
from emailcheck.adapters.dns.dnspython_resolver import DNSPythonResolver
from emailcheck.adapters.execution.memory_executor import ExecutorSettings, InMemoryJobExecutor
from emailcheck.adapters.observability.logging_sink import LoggingOperatorSink
from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPTransport
from emailcheck.adapters.smtp.sender_identity import (
    ConfiguredSenderIdentityProvider,
    load_sender_identity,
)
from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.adapters.storage.sqlite_store import SQLiteVerdictStore
from emailcheck.adapters.system.clock import SystemClock, SystemMonotonicClock, SystemSleeper
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.adapters.system.random_source import SystemRandomSource
from emailcheck.adapters.system.rate_limit import InProcessRateLimiter
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl
from emailcheck.application.admission import AdmissionControl, AdmissionSettings
from emailcheck.application.jobs import JobService, JobSettings
from emailcheck.application.mail_route import MailRouteService
from emailcheck.application.passive import PassiveClassifier
from emailcheck.application.retention import RetentionService, RetentionSettings
from emailcheck.application.smtp_probe import SMTPProbeService
from emailcheck.application.smtp_verification import SMTPVerificationService
from emailcheck.application.syntax_evidence import SyntaxEvidenceProducer
from emailcheck.application.verdict_cache import NO_SENDER_IDENTITY, VerdictCache
from emailcheck.application.verification import AddressVerificationService, VerificationLimits
from emailcheck.classification.repository import PassiveDatasets
from emailcheck.domain.abuse import QuotaSettings
from emailcheck.domain.admin import AdminState
from emailcheck.domain.rate_limit import RateLimitSettings
from emailcheck.ports.authentication import Authenticator
from emailcheck.ports.metrics import MetricsSink
from emailcheck.ports.observability import OperatorSink
from emailcheck.ports.smtp_sender_identity import SenderIdentity
from emailcheck.security.identifiers import check_correlation_key


class DeploymentProfile(StrEnum):
    """The three profiles `docs/requirements.md` section 15 defines.

    A field rather than a comment, because section 15's requirements differ per
    profile and `prompts/06-api-cli.md` asks for a configuration that refuses
    the unsafe combinations rather than one that documents them.
    """

    LOCAL_PASSIVE = "local-passive"
    LAB_ACTIVE = "lab-active"
    SERVICE_ACTIVE = "service-active"


@dataclass(frozen=True, slots=True)
class Deployment:
    """Operator configuration. Everything a request may not choose.

    Nothing in this type comes from a caller: the sender identity, the API keys,
    the correlation key, the limits, and the store path are all things an
    operator sets before the process starts. That separation is the whole reason
    it is a type rather than a pile of parameters.
    """

    #: `{account_id: api_key}` or `{account_id: [api_keys]}`. Hashed at load;
    #: the plaintext is not retained by the authenticator.
    #:
    #: **`repr=False`, and that is a security property rather than tidiness.**
    #: A `Deployment` is the object most likely to be logged by accident — it is
    #: what a start-up path holds — and a frozen dataclass's generated `repr`
    #: prints every field, so this one printed the API keys and the correlation
    #: secret in full. Phase 7's privacy corpus found it. `__repr__` below names
    #: each as redacted rather than omitting it, so a reader can see that
    #: something is there.
    api_keys: Mapping[str, str | Sequence[str]] = field(repr=False)
    #: The secret an HMAC correlates under. Never logged, never returned.
    correlation_key: bytes = field(repr=False)
    #: The EHLO name and envelope sender, as `adapters/smtp/sender_identity.py`
    #: reads them. An unconfigured deployment does not probe.
    sender_identity: Mapping[str, object] | None = field(default=None, repr=False)
    passive_datasets: PassiveDatasets = field(default_factory=PassiveDatasets)
    rate_limits: RateLimitSettings = field(default_factory=RateLimitSettings)
    admission: AdmissionSettings = field(default_factory=AdmissionSettings)
    verification: VerificationLimits = field(default_factory=VerificationLimits)
    executor: ExecutorSettings = field(default_factory=ExecutorSettings)
    jobs: JobSettings = field(default_factory=JobSettings)
    #: Phase 7's layered budgets. `prompts/07-hardening.md`.
    quotas: QuotaSettings = field(default_factory=QuotaSettings)
    #: How long finished records live. Deliberately separate from the verdict
    #: TTLs ADR 0015 fixed: one is a freshness rule, the other a privacy one.
    retention: RetentionSettings = field(default_factory=RetentionSettings)
    #: The switches an operator starts with. Normally every control off and
    #: probing enabled; a deployment recovering from an incident may start with
    #: the kill switch already thrown.
    admin_state: AdminState = field(default_factory=AdminState)
    #: Local parts an operator considers dictionary-style, for the sequence
    #: indicators. Empty unless configured — `prompts/07-hardening.md` says
    #: "when configured", and this project licenses no name dataset.
    common_names: frozenset[str] = frozenset()
    store_path: Path | None = None
    #: Where job identity, state, the retry budget, and the recipient-touch
    #: checkpoint are kept. A **second** file rather than a second table in
    #: `store_path`: the two have independent schema versions and independent
    #: retention arguments, and `SQLiteJobStore` refuses a file another schema
    #: wrote.
    #:
    #: Configured, never derived. An earlier build shipped the store and left
    #: `JobService(store=...)` unset in this module, so the durable idempotency
    #: binding a restart depends on existed in `adapters/` and was reachable from
    #: nothing — the final system audit found it. Deriving a path from
    #: `store_path` would have hidden the same class of mistake behind a
    #: convention; an operator names it, and a composition test asserts that
    #: naming it is enough.
    job_store_path: Path | None = None
    profile: DeploymentProfile = DeploymentProfile.LOCAL_PASSIVE
    #: Whether this deployment may open SMTP connections at all.
    #: `docs/requirements.md` section 15's local-passive profile sets this false
    #: and gets a stack with no SMTP service in it — absent, not merely unused.
    active_probing: bool = False

    def __post_init__(self) -> None:
        check_correlation_key(self.correlation_key)
        if self.active_probing and self.sender_identity is None:
            # `adapters/smtp/sender_identity.py` refuses to invent an EHLO name,
            # so a deployment that would probe without one must fail at start
            # rather than at the first request.
            raise ValueError("active probing needs a configured sender identity")
        # `prompts/06-api-cli.md`: configuration refuses service-active with
        # active probes but no sender identity, rate limiter, or authentication.
        # The limiter is built unconditionally, the sender is refused above, and
        # this is the third.
        service_active = self.profile is DeploymentProfile.SERVICE_ACTIVE
        if service_active and self.active_probing and not self.api_keys:
            raise ValueError("a service-active deployment must configure authentication")
        if self.profile is DeploymentProfile.LOCAL_PASSIVE and self.active_probing:
            # Section 15's local-passive profile is "no active probes". A
            # deployment claiming both is a misconfiguration, not a preference.
            raise ValueError("the local-passive profile does not probe")
        if self.profile is DeploymentProfile.LOCAL_PASSIVE and self.job_store_path is not None:
            # That profile accepts no job, so a job database would be a file
            # nothing writes and a retention obligation nothing incurs. Refused
            # rather than ignored, on this type's rule that a setting which
            # cannot take effect is a misconfiguration.
            raise ValueError("the local-passive profile accepts no jobs and needs no job store")

    def __repr__(self) -> str:
        """Everything an operator needs, and no secret material.

        The counts are deliberate: "how many keys are configured" is the
        question a start-up log is actually asked, and answering it does not
        require printing one.
        """
        return (
            f"Deployment(profile={self.profile.value!r}, "
            f"active_probing={self.active_probing!r}, "
            f"api_keys=<{len(self.api_keys)} configured>, "
            f"correlation_key=<redacted>, "
            f"sender_identity=<{'configured' if self.sender_identity else 'none'}>, "
            f"store_path={self.store_path!r}, "
            f"job_store_path={self.job_store_path!r})"
        )


@dataclass(frozen=True, slots=True)
class VerificationStack:
    """The built object graph. One per process.

    Holding the limiter and the admission gate as fields is what makes the
    sharing testable: two requests through one stack use these objects, and a
    test can assert their identity rather than trusting the wiring.
    """

    verification: AddressVerificationService
    authenticator: Authenticator
    operator: OperatorSink
    limiter: InProcessRateLimiter
    admission: AdmissionControl
    store: SQLiteVerdictStore | None
    #: Redacted for the reason `Deployment`'s fields are: this object is held
    #: for the process's lifetime and reaches a log the moment anything prints
    #: the stack it belongs to.
    correlation_key: bytes = field(repr=False)
    executor: InMemoryJobExecutor | None = None
    jobs: JobService | None = None
    #: Held as a field so a test can assert **identity** with `jobs.store`
    #: rather than trusting that the wiring happened. The final system audit
    #: found a build where this object existed and `JobService` did not have it.
    job_store: SQLiteJobStore | None = None
    cache: VerdictCache | None = None
    guard: AbuseGuard | None = None
    admin: AdminControl | None = None
    metrics: MetricsSink | None = None
    retention: RetentionService | None = None

    async def start(self) -> None:
        """Start the executor, if this deployment has one.

        Separate from building, because an executor creates tasks and tasks
        need a running loop. A caller that never starts one has a stack that
        accepts no active job — which is the local-passive profile.
        """
        if self.executor is not None:
            self.executor.start()

    async def aclose(self) -> None:
        """Stop every task this stack owns."""
        if self.executor is not None:
            await self.executor.aclose()


def build_verification_stack(
    deployment: Deployment, *, operator: OperatorSink | None = None
) -> VerificationStack:
    """Build the production graph.

    `operator` is the one seam a caller may replace, because an operator sink is
    where a deployment routes its own telemetry and because a test needs to
    assert that Phase 5 stop condition 5 fires. It cannot affect a verdict: the
    sink is write-only and nothing reads it back.

    There is deliberately **no** parameter for a clock, a sleeper, a rate
    limiter, a TLS trust anchor, or an SMTP transport. Those are the four Phase
    4 stop conditions this function exists to close, and a keyword argument for
    any of them would be the hole each one names.
    """
    clock = SystemClock()
    monotonic = SystemMonotonicClock()
    sleeper = SystemSleeper()
    random = SystemRandomSource()
    sink = operator if operator is not None else LoggingOperatorSink()

    metrics = InMemoryMetrics()

    limiter = InProcessRateLimiter(
        clock=monotonic, sleeper=sleeper, settings=deployment.rate_limits
    )
    admission = AdmissionControl(settings=deployment.admission)

    # **One guard, one quota store, one admin control.** The same reason the
    # limiter and the admission gate are built once: counters that start at zero
    # for every request permit everything, and an administrative state that is
    # rebuilt per request has never been suspended.
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=sink,
        correlation_key=deployment.correlation_key,
        settings=deployment.quotas,
        state=deployment.admin_state,
        common_names=deployment.common_names,
    )
    admin = AdminControl(
        guard=guard,
        clock=clock,
        metrics=metrics,
        correlation_key=deployment.correlation_key,
    )

    routes = MailRouteService(resolver=DNSPythonResolver(), clock=clock)
    passive = PassiveClassifier(datasets=deployment.passive_datasets, clock=clock)
    syntax = SyntaxEvidenceProducer(clock=clock)

    smtp = _build_smtp(deployment, limiter=limiter, clock=clock, monotonic=monotonic)

    store = None
    if deployment.store_path is not None:
        store = SQLiteVerdictStore(path=deployment.store_path)
        store.initialize()

    verification = AddressVerificationService(
        syntax=syntax,
        routes=routes,
        passive=passive,
        admission=admission,
        operator=sink,
        smtp=smtp,
        limits=deployment.verification,
        guard=guard,
        sender_identity=_sender_identity_key(deployment),
    )

    cache = None
    if store is not None:
        cache = VerdictCache(
            store=store,
            clock=clock,
            random=random,
            correlation_key=deployment.correlation_key,
            sender_identity=_sender_identity_key(deployment),
        )

    executor = None
    jobs = None
    job_store = None
    if deployment.profile is not DeploymentProfile.LOCAL_PASSIVE:
        # The local-passive profile answers synchronously and accepts no job:
        # `docs/requirements.md` section 15 gives it no queue and no worker, and
        # an executor nothing submits to is a pool of idle tasks.
        executor = InMemoryJobExecutor(
            clock=monotonic, sleeper=sleeper, settings=deployment.executor
        )
        _check_worker_isolation(deployment, executor)
        if deployment.job_store_path is not None:
            job_store = SQLiteJobStore(path=deployment.job_store_path)
            job_store.initialize()
        jobs = JobService(
            verification=verification,
            executor=executor,
            clock=clock,
            random=random,
            operator=sink,
            correlation_key=deployment.correlation_key,
            cache=cache,
            # **Passed, and an inspection test asserts it stays passed.** The
            # store is where the idempotency claim becomes atomic across
            # replicas and where the recipient-touch checkpoint survives a
            # crash; a `JobService` built without it has neither, and the two
            # failures it prevents — a second job for one handle, a replayed
            # operation that may already have touched a recipient — are exactly
            # the ones nothing else would notice.
            store=job_store,
            guard=guard,
            settings=deployment.jobs,
        )

    retention = RetentionService(
        clock=clock,
        admin=admin,
        settings=deployment.retention,
        store=store,
        jobs=jobs,
        job_store=job_store,
        quota=guard.quota,
    )

    return VerificationStack(
        verification=verification,
        authenticator=_build_authenticator(deployment),
        operator=sink,
        limiter=limiter,
        admission=admission,
        store=store,
        correlation_key=deployment.correlation_key,
        executor=executor,
        jobs=jobs,
        job_store=job_store,
        cache=cache,
        guard=guard,
        admin=admin,
        metrics=metrics,
        retention=retention,
    )


def _check_worker_isolation(deployment: Deployment, executor: InMemoryJobExecutor) -> None:
    """Refuse service-active on an in-process worker.

    `docs/requirements.md` section 15 requires an isolated worker for that
    profile. `InMemoryJobExecutor` answers `is_isolated` as `False` because it
    shares this process's memory and dies with it, and the check is on that
    answer rather than on the class name — so an isolated implementation added
    later passes without this function being edited.
    """
    if deployment.profile is DeploymentProfile.SERVICE_ACTIVE and not executor.is_isolated:
        raise ValueError(
            "the service-active profile requires an isolated worker; "
            "the in-memory executor is a development tool"
        )


def _sender_identity_key(deployment: Deployment) -> str:
    """A stable description of what this deployment probes from.

    `docs/requirements.md` section 13 makes the sender identity part of the
    cache key, because a verdict obtained through one envelope sender is not
    evidence about another. It is hashed before it is stored; this is only the
    canonical input to that hash, and it comes from operator configuration.
    """
    if deployment.sender_identity is None:
        return NO_SENDER_IDENTITY
    identity: SenderIdentity = load_sender_identity(deployment.sender_identity)
    sender = identity.envelope_sender.address
    return f"{identity.ehlo.host.value}|{'' if sender is None else sender.smtp_target}"


def _build_authenticator(deployment: Deployment) -> StaticApiKeyAuthenticator:
    """The only place a `Principal` becomes reachable.

    An empty mapping is a legal configuration and produces an authenticator that
    authenticates nobody — which is the right answer for a deployment with no
    accounts yet, and is not the same as an anonymous fallback.
    """
    return build_authenticator(deployment.api_keys)


def _build_smtp(
    deployment: Deployment,
    *,
    limiter: InProcessRateLimiter,
    clock: SystemClock,
    monotonic: SystemMonotonicClock,
) -> SMTPVerificationService | None:
    """The active half, or nothing at all.

    Returning `None` for a passive deployment is deliberate: a stack with no
    SMTP service cannot probe by mistake, whereas a stack holding one behind a
    boolean can. `docs/requirements.md` section 15's local-passive profile is
    "no active probes", and this is that as a shape rather than as a flag.

    The transport is built with its defaults, which is where `TLSPolicy.REQUIRED`
    and the system trust store come from. There is no argument here that
    weakens either.
    """
    if not deployment.active_probing or deployment.sender_identity is None:
        return None
    identity = load_sender_identity(deployment.sender_identity)
    probe = SMTPProbeService(
        transport=AsyncioSMTPTransport(),
        identity_provider=ConfiguredSenderIdentityProvider(identity=identity),
        rate_limiter=limiter,
        clock=monotonic,
    )
    return SMTPVerificationService(probe=probe, clock=clock)
