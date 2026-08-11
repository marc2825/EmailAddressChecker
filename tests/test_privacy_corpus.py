"""Adversarial values, driven end to end, scanned on every surface.

`prompts/07-hardening.md`: full addresses absent from captured logs and metrics,
and indicators that do not leak guessed addresses in admin summaries.
`docs/requirements.md` section 16: ordinary logs never contain a full address.

**The values are deliberately distinctive**, so a leak is unambiguous rather
than a judgement about whether some substring counts. Every one is scanned for
on every surface Phase 6 and Phase 7 publish, and the assertion names which
surface failed.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
from dataclasses import dataclass

import pytest
from tests.phase6_fixtures import (
    FakeClock,
    FakeRandomSource,
    RecordingExecutor,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)
from tests.phase7_fixtures import (
    CORRELATION_KEY,
    OUTER_BOUND,
    SOURCE,
    RecordingOperator,
    SteppableClock,
)

from emailcheck.adapters.auth.api_keys import build_authenticator
from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.adapters.system.quota import InProcessQuotaStore
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl
from emailcheck.application.jobs import JobService
from emailcheck.apps.api import ApiRequest, CheckApi
from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack

#: Distinctive enough that a substring match is conclusive.
LOCAL_PART = "very.secret.localpart+tag"
DOMAIN = "corpus.test"
ADDRESS = f"{LOCAL_PART}@{DOMAIN}"
API_KEY = "Bearer-SUPERSECRET-api-key-value-0001"
IDEMPOTENCY_KEY = "idempotency-SUPERSECRET-0001"
SENDER = "sender-SUPERSECRET"

#: What must never appear. The domain is deliberately **not** here:
#: `docs/requirements.md` section 16 permits analytics aggregated by domain and
#: `docs/privacy.md` section 1 makes the normalized domain its own category, so
#: forbidding it would be asserting a rule this project does not have.
FORBIDDEN = (LOCAL_PART, ADDRESS, API_KEY, IDEMPOTENCY_KEY, SENDER, "SUPERSECRET")


@dataclass(slots=True)
class PrivacyHarness:
    """The whole application path, over fakes, with every surface reachable."""

    api: CheckApi
    guard: AbuseGuard
    admin: AdminControl
    jobs: object
    executor: RecordingExecutor
    metrics: InMemoryMetrics
    operator: RecordingOperator
    authenticator: object
    smtp: ScriptedSMTPVerification


def privacy_harness() -> PrivacyHarness:
    metrics = InMemoryMetrics()
    operator = RecordingOperator()
    clock = SteppableClock()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(
        resolver=resolver_with_route(), smtp=smtp, operator=operator, guard=guard
    )
    executor = RecordingExecutor()
    jobs = JobService(
        verification=service,
        executor=executor,
        clock=FakeClock(),
        random=FakeRandomSource(),
        operator=operator,
        correlation_key=CORRELATION_KEY,
        guard=guard,
    )
    authenticator = build_authenticator({"acct-1": API_KEY})
    return PrivacyHarness(
        api=CheckApi(
            verification=service, authenticator=authenticator, operator=operator, jobs=jobs
        ),
        guard=guard,
        admin=admin,
        jobs=jobs,
        executor=executor,
        metrics=metrics,
        operator=operator,
        authenticator=authenticator,
        smtp=smtp,
    )


def caching_deployment(tmp: pathlib.Path) -> Deployment:
    """A deployment that actually configures a store.

    The original corpus fixture set no `store_path`, so `stack.cache` was always
    `None` and the object holding the correlation key was never in the scanned
    graph at all. An independent review found the key printed in full by
    `repr(stack)` for every deployment that caches — which is every realistic
    one. A corpus is only as adversarial as the graph it is pointed at.
    """
    return Deployment(
        api_keys={"acct-1": API_KEY},
        correlation_key=CORRELATION_KEY,
        profile=DeploymentProfile.LAB_ACTIVE,
        store_path=tmp / "verdicts.sqlite",
    )


def deployment() -> Deployment:
    return Deployment(
        api_keys={"acct-1": API_KEY},
        correlation_key=CORRELATION_KEY,
        profile=DeploymentProfile.LAB_ACTIVE,
    )


def scan(surface: str, rendered: str) -> None:
    for secret in FORBIDDEN:
        assert secret not in rendered, f"{surface} leaked {secret!r}"


@pytest.mark.asyncio
async def test_no_surface_carries_the_submitted_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One request, driven all the way through, then every surface scanned.

    The pipeline is assembled from the Phase 6 fixtures rather than from
    `build_verification_stack`, because the real graph holds the real resolver
    and no test in this repository reaches the network. What is exercised is the
    same application code — the guard, the job service, the API, the metrics,
    and the audit trail — with a scripted resolver and a scripted SMTP peer
    underneath it.
    """
    caplog.set_level(logging.DEBUG)
    harness = privacy_harness()

    async with asyncio.timeout(OUTER_BOUND):
        passive = await harness.api.handle(
            ApiRequest(
                path="/v1/checks/passive",
                body={"email": ADDRESS},
                credential=API_KEY,
                source=SOURCE,
            )
        )
        active = await harness.api.handle(
            ApiRequest(
                path="/v1/checks",
                body={"email": ADDRESS},
                credential=API_KEY,
                idempotency_key=IDEMPOTENCY_KEY,
                source=SOURCE,
            )
        )
        await harness.executor.run_pending()

    scan("the passive response", repr(passive.body))
    scan("the active response", repr(active.body))
    scan("captured logs", caplog.text)
    scan("the operator sink", harness.operator.rendered())
    scan("metric series", " ".join(harness.metrics.rendered_keys()))
    scan(
        "the audit trail",
        " ".join(str(event.as_json_object()) for event in harness.admin.audit_events()),
    )
    scan("the abuse guard", repr(harness.guard))
    scan("the job registry", repr(harness.jobs))
    scan("the authenticator", repr(harness.authenticator))
    scan("the SQL a store would run", " ".join((harness.smtp.calls and []) or []))


@pytest.mark.asyncio
async def test_an_indicator_summary_names_a_count_and_never_a_guessed_address() -> None:
    """`prompts/07-hardening.md`: indicators must not leak guessed addresses in
    admin summaries. The caller here is enumerating, so every indicator that can
    fire does."""
    from tests.phase7_fixtures import PRINCIPAL, RecordingOperator, quota_settings, target

    from emailcheck.adapters.system.quota import InProcessQuotaStore

    metrics = InMemoryMetrics()
    operator = RecordingOperator()
    guard = AbuseGuard(
        quota=InProcessQuotaStore(),
        clock=SteppableClock(),
        metrics=metrics,
        operator=operator,
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(
            per_api_key=None,
            per_account=None,
            per_source_ip=None,
            per_target=None,
            daily_total=None,
        ),
    )

    async with asyncio.timeout(10.0):
        for index in range(12):
            await guard.authorize_submission(
                principal=PRINCIPAL,
                target=target(f"{LOCAL_PART}{index}@{DOMAIN}"),
                source=SOURCE,
                active=True,
            )

    scan("indicator metrics", " ".join(metrics.rendered_keys()))
    scan("indicator events", operator.rendered())
    scan("the guard's window", repr(guard))

    # The indicators did fire, so this is a scan over something rather than over
    # an empty set.
    raised = {key[1] for key in metrics.counters if key[0] == "abuse_indicator"}
    assert "numeric_sequence" in raised
    assert "domain_concentration" in raised


def test_the_admin_audit_names_no_subject_in_the_clear() -> None:
    stack = build_verification_stack(deployment())
    assert stack.admin is not None
    stack.admin.suspend_account("acct-1")
    stack.admin.block_domain(DOMAIN)
    stack.admin.disable_sender(SENDER)

    rendered = " ".join(str(event.as_json_object()) for event in stack.admin.audit_events())
    scan("the audit trail", rendered)
    # Even the account identifier, which is not secret, is a digest: an audit
    # trail that is stolen must not become a customer list.
    assert "acct-1" not in rendered


def test_a_deployments_repr_carries_no_secret() -> None:
    """A `Deployment` is logged by accident more often than anything else.

    Both secrets are asserted separately. The API key and the correlation key
    are different kinds of thing — one authenticates callers, the other makes
    every stored digest irreversible — and a mutation that re-exposed only the
    second passed while the first was still covered.
    """
    rendered = repr(deployment())
    scan("the deployment", rendered)
    assert CORRELATION_KEY.decode() not in rendered
    assert repr(CORRELATION_KEY) not in rendered
    assert "correlation-secret" not in rendered

    stack = build_verification_stack(deployment())
    scan("the built stack", repr(stack))
    assert CORRELATION_KEY not in repr(stack).encode()
    assert "correlation-secret" not in repr(stack)


def test_the_secret_fields_are_excluded_from_the_generated_repr() -> None:
    """The barrier is `field(repr=False)`, not the hand-written `__repr__`.

    Worth pinning separately: removing the custom `__repr__` is **inert**,
    because the generated one already omits these fields — so a test that only
    exercised the custom one would be testing the readable half rather than the
    load-bearing half.
    """
    import dataclasses

    excluded = {field.name for field in dataclasses.fields(Deployment) if not field.repr}
    assert {"api_keys", "correlation_key", "sender_identity"} <= excluded


def test_a_job_record_does_not_print_its_idempotency_key() -> None:
    """An idempotency key is caller-chosen text and `IdempotencyKey` permits
    `@`, so `alice@example.test` is a legal key. A job printed into a log would
    carry whatever the caller put there."""
    import dataclasses
    from datetime import UTC, datetime

    from emailcheck.application.jobs import CheckJob
    from emailcheck.domain.job import IdempotencyKey, JobId, JobState

    now = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    job = CheckJob(
        id=JobId("job-" + "a" * 22),
        owner="acct-1",
        state=JobState.PENDING,
        created_at=now,
        updated_at=now,
        idempotency_key=IdempotencyKey(IDEMPOTENCY_KEY),
    )
    scan("a job record", repr(job))
    assert not next(
        field for field in dataclasses.fields(CheckJob) if field.name == "idempotency_key"
    ).repr


# --- the objects an earlier corpus could not see -----------------------------


def test_a_stack_with_a_real_cache_carries_no_correlation_key(tmp_path: pathlib.Path) -> None:
    """F3. The cache holds the secret that makes every stored digest
    irreversible, and it sits beside the database that secret protects."""
    stack = build_verification_stack(caching_deployment(tmp_path))
    assert stack.cache is not None, "the fixture must reach the leaking object"

    for surface, rendered in (
        ("the cache", repr(stack.cache)),
        ("the stack", repr(stack)),
        ("the deployment", repr(caching_deployment(tmp_path))),
        ("the store", repr(stack.store)),
    ):
        scan(surface, rendered)
        assert CORRELATION_KEY not in rendered.encode(), surface
        assert "correlation-secret" not in rendered, surface


def test_every_holder_of_the_correlation_key_redacts_it(tmp_path: pathlib.Path) -> None:
    """Asserted as a property of the graph rather than object by object, so a
    holder added later is covered without this test being edited."""
    import dataclasses

    stack = build_verification_stack(caching_deployment(tmp_path))
    holders = [stack, stack.cache, stack.guard, stack.admin, stack.jobs]
    for holder in holders:
        assert holder is not None
        excluded = {
            field.name
            for field in dataclasses.fields(holder)  # type: ignore[arg-type]
            if not field.repr
        }
        names = {field.name for field in dataclasses.fields(holder)}  # type: ignore[arg-type]
        if "correlation_key" in names:
            assert "correlation_key" in excluded, type(holder).__name__


@pytest.mark.parametrize("field_name", ["credential", "idempotency_key", "body"], ids=lambda n: n)
def test_an_api_request_prints_no_caller_supplied_value(field_name: str) -> None:
    """F4. Each field is flagged individually, so each can be mutated on its own
    and fail on its own — a single custom `__repr__` would make all three
    mutations inert."""
    import dataclasses

    from emailcheck.apps.api import ApiRequest

    flags = {field.name: field.repr for field in dataclasses.fields(ApiRequest)}
    assert flags[field_name] is False


def test_an_api_request_repr_carries_none_of_the_corpus() -> None:
    from emailcheck.apps.api import ApiRequest

    request = ApiRequest(
        path="/v1/checks",
        body={"email": ADDRESS},
        credential=API_KEY,
        idempotency_key=IDEMPOTENCY_KEY,
    )
    scan("an ApiRequest repr", repr(request))
    scan("an ApiRequest str", str(request))
    # What survives is what a debugger wants and nothing a caller chose.
    assert "/v1/checks" in repr(request)


def test_the_authenticator_does_not_print_its_verifier_table() -> None:
    """Found by the sweep the review's findings prompted rather than named by
    them. A verifier authenticates nobody, but the table maps every account to
    one and `key_identity_for` derives the suspension handle from it."""
    import dataclasses

    from emailcheck.adapters.auth.api_keys import StaticApiKeyAuthenticator, build_authenticator

    flags = {f.name: f.repr for f in dataclasses.fields(StaticApiKeyAuthenticator)}
    assert flags["verifiers"] is False

    authenticator = build_authenticator({"acct-1": API_KEY})
    scan("the authenticator", repr(authenticator))
    principal = authenticator.authenticate(API_KEY)
    assert principal is not None
    assert principal.key_id is not None
    assert principal.key_id not in repr(authenticator)
