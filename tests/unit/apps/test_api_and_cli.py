"""The API surface, and what it will and will not say.

The API layer imports no web framework, so these tests call `handle` directly —
which is the whole contract: routing, method handling, validation, error
mapping, and the public body. Binding an ASGI route to it adds no policy and is
the only untested piece.

The active endpoint is a **job** endpoint. `prompts/06-api-cli.md` requires that
it return quickly with a job and never wait for SMTP in an API worker, so every
test here asserts on the job it returned and drives the executor separately.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from tests.phase6_fixtures import (
    BrokenSyntaxProducer,
    FakeClock,
    FakeRandomSource,
    InMemoryVerdictStore,
    RecordingExecutor,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)

from emailcheck.adapters.auth.api_keys import build_authenticator
from emailcheck.adapters.storage.sqlite_account_state import SQLiteAccountStateStore
from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.application.jobs import JobService
from emailcheck.application.verdict_cache import VerdictCache
from emailcheck.application.verification import VerificationLimits
from emailcheck.apps.api import (
    ACTIVE_PATH,
    ERROR_BODY_KEYS,
    ERROR_CAPACITY,
    ERROR_INVALID_REQUEST,
    ERROR_NOT_FOUND,
    ERROR_TIMEOUT,
    ERROR_UNAUTHENTICATED,
    HEALTH_PATH,
    JOB_PATH_PREFIX,
    PASSIVE_PATH,
    ApiRequest,
    ApiResponse,
    CheckApi,
)
from emailcheck.domain.job import JobFailure, JobState
from emailcheck.domain.verdict import Status
from emailcheck.ports.job_executor import ExecutorFull

pytestmark = pytest.mark.asyncio

KEY = "k" * 40
OTHER_KEY = "z" * 40
VALID = "user@example.test"
CORRELATION_KEY = b"correlation-secret-of-thirty-two"


class Fixture:
    """The whole graph a request touches, with every collaborator inspectable."""

    def __init__(self, **kwargs: object) -> None:
        self.smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
        self.service, self.resolver, self.sink = build_service(smtp=self.smtp, **kwargs)  # type: ignore[arg-type]
        self.executor = RecordingExecutor()
        self.store = InMemoryVerdictStore()
        self.cache = VerdictCache(
            store=self.store,
            clock=FakeClock(),
            random=FakeRandomSource(prefix="rec"),
            correlation_key=CORRELATION_KEY,
        )
        self.jobs = JobService(
            verification=self.service,
            executor=self.executor,
            clock=FakeClock(),
            random=FakeRandomSource(),
            operator=self.sink,
            correlation_key=CORRELATION_KEY,
            cache=self.cache,
        )
        self.api = CheckApi(
            verification=self.service,
            authenticator=build_authenticator({"acct-1": KEY, "acct-2": OTHER_KEY}),
            operator=self.sink,
            jobs=self.jobs,
        )

    async def post(self, path: str, **kwargs: object) -> ApiResponse:
        return await self.api.handle(ApiRequest(path=path, method="POST", **kwargs))  # type: ignore[arg-type]

    async def submit(self, credential: str = KEY, **kwargs: object) -> ApiResponse:
        return await self.post(ACTIVE_PATH, body={"email": VALID}, credential=credential, **kwargs)


def build_api(**kwargs: object) -> tuple[CheckApi, ScriptedSMTPVerification]:
    fixture = Fixture(**kwargs)
    return fixture.api, fixture.smtp


# --- authentication ---------------------------------------------------------


@pytest.mark.parametrize("path", [PASSIVE_PATH, ACTIVE_PATH])
@pytest.mark.parametrize("credential", [None, "", "wrong-key-entirely-and-long-enough-yes"])
async def test_an_unauthenticated_caller_is_refused(path: str, credential: str | None) -> None:
    """No anonymous principal, on either endpoint.

    Per-account isolation is keyed by identity, so a passive endpoint serving
    an anonymous caller would be an endpoint with no per-account bound at all.
    """
    fixture = Fixture()
    response = await fixture.post(path, body={"email": VALID}, credential=credential)

    assert response.status_code == 401
    assert response.body["error"]["code"] == ERROR_UNAUTHENTICATED  # type: ignore[index]
    assert fixture.smtp.calls == []
    assert fixture.executor.submitted == []


async def test_every_unauthenticated_answer_is_byte_identical() -> None:
    """The `401` body must not be an oracle for "this key exists".

    An absent credential, an empty one, one too short to be any configured key,
    and a well-formed unknown one all answer the same way. A message that
    distinguished them would let a caller learn which keys are real, which is
    exactly what the constant-time comparison below it exists to prevent.
    """
    fixture = Fixture()
    bodies = []
    for credential in (None, "", "short", "q" * 40, "K" * 40, " " + KEY):
        response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=credential)
        assert response.status_code == 401
        bodies.append(json.dumps(response.body, sort_keys=True))

    assert len(set(bodies)) == 1, bodies


# --- methods ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "method"),
    [
        (PASSIVE_PATH, "GET"),
        (ACTIVE_PATH, "GET"),
        (ACTIVE_PATH, "DELETE"),
        (HEALTH_PATH, "POST"),
        (f"{JOB_PATH_PREFIX}abcdefghijklmnopqrstuvwx", "POST"),
    ],
)
async def test_a_wrong_method_is_refused_rather_than_routed(path: str, method: str) -> None:
    fixture = Fixture()
    response = await fixture.api.handle(
        ApiRequest(path=path, method=method, body={"email": VALID}, credential=KEY)
    )
    assert response.status_code == 405
    assert fixture.executor.submitted == []
    assert fixture.smtp.calls == []


# --- the closed request schema ---------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"email": ""},
        {"email": 42},
        {"address": VALID},
        {"email": VALID, "mx_host": "mx.attacker.test"},
        {"email": VALID, "tls_verify": False},
        {"email": VALID, "ca_file": "ca.pem"},
        {"email": VALID, "sender": "spoof@example.test"},
        {"email": VALID, "ehlo": "attacker.test"},
        {"email": VALID, "retries": 10},
        {"email": VALID, "accept_all_probe": True},
        {"email": VALID, "tls_policy": "opportunistic"},
        {"email": VALID, "account": "acct-2"},
        {"email": VALID, "refresh": True},
        {"email": VALID, "cache": False},
    ],
    ids=[
        "empty",
        "blank",
        "not text",
        "wrong key",
        "MX override",
        "TLS verify",
        "CA file",
        "sender",
        "EHLO",
        "retries",
        "accept-all",
        "TLS policy",
        "account",
        "cache refresh",
        "cache bypass",
    ],
)
async def test_any_body_but_one_email_field_is_refused(body: dict[str, object]) -> None:
    """One closed schema refuses every knob, including the ones nobody listed.

    A deny list needs updating for each new hazard; a closed schema refuses a
    field nobody thought of by the same rule that refuses a typo. `refresh` and
    `cache` are here because ADR 0015 declines to implement a request-controlled
    cache bypass: the repository defines no way to authorize one.
    """
    fixture = Fixture()
    response = await fixture.post(ACTIVE_PATH, body=body, credential=KEY)

    assert response.status_code == 400
    assert response.body["error"]["code"] == ERROR_INVALID_REQUEST  # type: ignore[index]
    assert fixture.smtp.calls == []
    assert fixture.executor.submitted == []


async def test_a_rejected_body_is_not_echoed_back() -> None:
    """A validation error must not repeat what was submitted."""
    fixture = Fixture()
    secret = "victim.person+tag@target.test"
    response = await fixture.post(ACTIVE_PATH, body={"email": secret, "x": 1}, credential=KEY)
    rendered = json.dumps(response.body)
    assert "victim.person" not in rendered
    assert secret not in rendered


async def test_an_over_long_address_is_refused_without_being_echoed() -> None:
    fixture = Fixture()
    response = await fixture.post(
        ACTIVE_PATH, body={"email": "a" * 4000 + "@x.test"}, credential=KEY
    )
    assert response.status_code == 400
    assert "aaa" not in json.dumps(response.body)


@pytest.mark.parametrize("presented", ["", "short", "x" * 300, "has space", "line\nbreak"])
async def test_an_unusable_idempotency_key_is_refused(presented: str) -> None:
    fixture = Fixture()
    response = await fixture.post(
        ACTIVE_PATH, body={"email": VALID}, credential=KEY, idempotency_key=presented
    )
    assert response.status_code == 400
    assert fixture.executor.submitted == []


# --- the passive endpoint ---------------------------------------------------


async def test_the_passive_endpoint_never_reaches_smtp() -> None:
    """`docs/requirements.md` section 11: the passive check performs no SMTP."""
    fixture = Fixture()
    response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=KEY)

    assert response.status_code == 200
    assert fixture.smtp.calls == []
    assert fixture.executor.submitted == []
    assert response.body["status"] == Status.UNKNOWN.value


# --- the active endpoint is a job endpoint ----------------------------------


async def test_the_active_endpoint_returns_a_job_without_waiting_for_smtp() -> None:
    """`prompts/06-api-cli.md`: no synchronous waiting for active SMTP.

    The response is a job in `pending`, the SMTP fake has not been called at
    all, and the work is sitting in the executor — which is the difference
    between an asynchronous API and a synchronous one wearing a job's clothes.
    """
    fixture = Fixture()
    response = await fixture.submit()

    assert response.status_code == 202
    job = response.body["job"]
    assert isinstance(job, dict)
    assert job["state"] == JobState.PENDING.value
    assert job["result"] is None
    assert fixture.smtp.calls == []
    assert fixture.executor.submitted == [job["id"]]


async def test_the_submission_carries_the_passive_evidence_immediately() -> None:
    """`docs/requirements.md` section 11: passive evidence when available."""
    fixture = Fixture()
    response = await fixture.submit()

    passive = response.body["passive"]
    assert isinstance(passive, dict)
    assert passive["status"] == Status.UNKNOWN.value
    assert fixture.smtp.calls == []


async def test_a_pending_job_publishes_no_status_of_any_kind() -> None:
    """A verdict that does not exist must not be implied by the response.

    This is Phase 5 stop condition 1 at its most tempting: `unknown` is a real
    published status and a pending job is genuinely unknown, so a serializer
    could put one there and look correct.
    """
    fixture = Fixture()
    response = await fixture.submit()
    job = response.body["job"]
    assert isinstance(job, dict)

    assert set(job) == {"id", "state", "created_at", "updated_at", "result", "failure"}
    for value in {member.value for member in Status}:
        assert value not in json.dumps(job)


async def test_a_completed_job_carries_the_aggregators_verdict() -> None:
    fixture = Fixture()
    submitted = await fixture.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    await fixture.executor.run_pending()

    response = await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method="GET", credential=KEY)
    )

    assert response.status_code == 200
    assert response.body["state"] == JobState.COMPLETED.value
    result = response.body["result"]
    assert isinstance(result, dict)
    assert result["status"] == Status.LIKELY_DELIVERABLE.value
    assert result["primary_reason"] == "rcpt_accepted"
    assert len(fixture.smtp.calls) == 1


async def test_a_job_can_be_cancelled_and_cancellation_is_idempotent() -> None:
    fixture = Fixture()
    submitted = await fixture.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    path = f"{JOB_PATH_PREFIX}{job_id}"

    first = await fixture.api.handle(ApiRequest(path=path, method="DELETE", credential=KEY))
    second = await fixture.api.handle(ApiRequest(path=path, method="DELETE", credential=KEY))

    assert first.status_code == 200
    assert first.body["state"] == JobState.CANCELLED.value
    assert second.status_code == 200
    assert second.body["state"] == JobState.CANCELLED.value
    assert fixture.executor.cancelled == [job_id]


# --- ownership --------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_another_account_can_neither_read_nor_cancel_the_job(method: str) -> None:
    """`prompts/06-api-cli.md`: cross-account result access forbidden.

    The answer is the same one an unknown identifier gets. ADR 0014: a `403`
    would confirm that the identifier names a real job belonging to somebody
    else, which is the fact the ownership rule exists to withhold.
    """
    fixture = Fixture()
    submitted = await fixture.submit(credential=KEY)
    job_id = submitted.body["job"]["id"]  # type: ignore[index]

    mine = await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method=method, credential=KEY)
    )
    theirs = await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method=method, credential=OTHER_KEY)
    )
    unknown = await fixture.api.handle(
        ApiRequest(
            path=f"{JOB_PATH_PREFIX}nosuchjobnosuchjobnosuch", method=method, credential=OTHER_KEY
        )
    )

    assert mine.status_code == 200
    assert theirs.status_code == 404
    assert theirs.body["error"]["code"] == ERROR_NOT_FOUND  # type: ignore[index]
    assert json.dumps(theirs.body) == json.dumps(unknown.body)


async def test_a_foreign_cancellation_does_not_touch_the_job() -> None:
    fixture = Fixture()
    submitted = await fixture.submit(credential=KEY)
    job_id = submitted.body["job"]["id"]  # type: ignore[index]

    await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method="DELETE", credential=OTHER_KEY)
    )
    mine = await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method="GET", credential=KEY)
    )

    assert mine.body["state"] == JobState.PENDING.value
    assert fixture.executor.cancelled == []


async def test_a_malformed_job_identifier_is_not_found_rather_than_an_error() -> None:
    fixture = Fixture()
    for bad in ("short", "has spaces here and there!!", "a" * 500, "with@at.sign.in.it.here"):
        response = await fixture.api.handle(
            ApiRequest(path=f"{JOB_PATH_PREFIX}{bad}", method="GET", credential=KEY)
        )
        assert response.status_code == 404, bad


async def test_an_unknown_path_is_a_not_found_rather_than_a_verdict() -> None:
    fixture = Fixture()
    response = await fixture.api.handle(
        ApiRequest(path="/v1/anything", method="GET", credential=KEY)
    )
    assert response.status_code == 404


async def test_the_health_endpoint_reveals_no_configuration() -> None:
    fixture = Fixture()
    response = await fixture.api.handle(ApiRequest(path=HEALTH_PATH, method="GET"))
    assert response.status_code == 200
    assert response.body == {"status": "ok"}


# --- refusals are service-level, never a verdict ----------------------------


async def test_the_total_deadline_is_a_gateway_timeout_carrying_no_verdict() -> None:
    resolver = resolver_with_route()
    resolver.delay_seconds = 30.0
    service, _, sink = build_service(
        resolver=resolver, limits=VerificationLimits(total_deadline_seconds=0.01)
    )
    api = CheckApi(
        verification=service,
        authenticator=build_authenticator({"acct-1": KEY}),
        operator=sink,
    )

    response = await api.handle(
        ApiRequest(path=PASSIVE_PATH, method="POST", body={"email": VALID}, credential=KEY)
    )

    assert response.status_code == 504
    assert response.body["error"]["code"] == ERROR_TIMEOUT  # type: ignore[index]
    assert "status" not in response.body


async def test_an_unexpected_failure_becomes_a_stable_error_and_reaches_the_operator() -> None:
    """No traceback, no exception message, no module name — and not silence.

    `docs/requirements.md` section 11 forbids full exception text in a public
    response. An independent review measured the other half of this: the first
    build answered `500` and told nobody, so a failure of this project's own was
    invisible to the people who could fix it.
    """
    service, _, sink = build_service()
    service = replace(service, syntax=BrokenSyntaxProducer(message="secret"))
    api = CheckApi(
        verification=service, authenticator=build_authenticator({"acct-1": KEY}), operator=sink
    )

    response = await api.handle(
        ApiRequest(
            path=PASSIVE_PATH, method="POST", body={"email": "not-an-address"}, credential=KEY
        )
    )

    rendered = json.dumps(response.body)
    assert response.status_code == 500
    assert "secret" not in rendered
    assert "RuntimeError" not in rendered
    assert "Traceback" not in rendered
    assert "internal_error" in sink.kinds()


async def test_capacity_is_a_service_unavailable() -> None:
    from emailcheck.application.admission import AdmissionControl, AdmissionSettings

    gate = AdmissionControl(AdmissionSettings(max_in_flight=1, max_waiting=1, max_per_principal=1))
    fixture = Fixture(admission=gate)

    release = asyncio.Event()

    async def hold() -> None:
        async with gate.admit("acct-1"):
            await release.wait()

    async with asyncio.timeout(5.0):
        first = asyncio.create_task(hold())
        second = asyncio.create_task(hold())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=KEY)
        release.set()
        await asyncio.gather(first, second)

    assert response.status_code == 503
    assert response.body["error"]["code"] == ERROR_CAPACITY  # type: ignore[index]


async def test_a_deployment_with_no_job_service_refuses_active_checks() -> None:
    """No executor means no active work, reported as unavailable rather than
    as a bad request: nothing about the request was wrong."""
    service, _, sink = build_service()
    api = CheckApi(
        verification=service, authenticator=build_authenticator({"acct-1": KEY}), operator=sink
    )
    response = await api.handle(
        ApiRequest(path=ACTIVE_PATH, method="POST", body={"email": VALID}, credential=KEY)
    )
    assert response.status_code == 503


# --- the error body is closed too -------------------------------------------


async def test_every_error_body_carries_exactly_two_keys() -> None:
    """A response that grew a `detail` field would be one that leaked one.

    Asserted over every error this module can produce, because "we only ever
    put safe things in it" is a habit rather than a property.
    """
    fixture = Fixture()
    responses = [
        await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=None),
        await fixture.post(PASSIVE_PATH, body={"nope": 1}, credential=KEY),
        await fixture.api.handle(ApiRequest(path="/v1/nothing", method="GET", credential=KEY)),
        await fixture.api.handle(ApiRequest(path=HEALTH_PATH, method="DELETE")),
        await fixture.api.handle(
            ApiRequest(path=f"{JOB_PATH_PREFIX}{'q' * 24}", method="GET", credential=KEY)
        ),
    ]
    for response in responses:
        assert set(response.body) == {"error"}
        error = response.body["error"]
        assert isinstance(error, dict)
        assert set(error) == ERROR_BODY_KEYS, error


# --- the public body --------------------------------------------------------


async def test_the_public_body_carries_no_number_and_no_evidence_detail() -> None:
    """The two Phase 5 stop conditions this schema exists for.

    No score, no percentage, no rank; and no `Evidence.details` key of any kind.
    """
    fixture = Fixture()
    response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=KEY)
    body = response.body

    assert set(body) == {
        "status",
        "confidence",
        "primary_reason",
        "reasons",
        "risk_flags",
        "checks",
        "no_message_data_sent",
        "ruleset",
    }
    for forbidden in ("score", "percentage", "rank", "details", "evidence", "diagnostic"):
        assert forbidden not in json.dumps(body)
    assert isinstance(body["confidence"], str)

    def has_float(value: object) -> bool:
        if isinstance(value, float):
            return True
        if isinstance(value, dict):
            return any(has_float(item) for item in value.values())
        if isinstance(value, list):
            return any(has_float(item) for item in value)
        return False

    assert not has_float(body)


async def test_a_completed_job_body_carries_nothing_internal() -> None:
    """The job envelope adds no surface the result did not already have."""
    fixture = Fixture()
    submitted = await fixture.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    await fixture.executor.run_pending()
    response = await fixture.api.handle(
        ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method="GET", credential=KEY)
    )

    rendered = json.dumps(response.body)
    for forbidden in (
        "details",
        "attempts",
        "transcript",
        "evidence",
        "digest",
        "acct-1",
        "sender",
        "diagnostic",
        "RCPT",
        "250",
        "Traceback",
    ):
        assert forbidden not in rendered, forbidden
    assert "@" not in rendered


async def test_the_public_checks_carry_only_the_allowlisted_key() -> None:
    """`Verdict.checks` also holds counts; a caller counting our attempts is
    reading this project's fan-out rather than anything about the address."""
    fixture = Fixture()
    response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=KEY)

    checks = response.body["checks"]
    assert isinstance(checks, dict)
    for summary in checks.values():
        assert set(summary) == {"result"}
    assert "internal" not in checks


async def test_the_response_carries_no_part_of_the_address() -> None:
    fixture = Fixture()
    target = "probe.target+secret@example.test"
    response = await fixture.post(PASSIVE_PATH, body={"email": target}, credential=KEY)
    rendered = json.dumps(response.body)
    assert "probe.target" not in rendered
    assert "@" not in rendered


async def test_the_response_never_names_the_principal() -> None:
    fixture = Fixture()
    response = await fixture.post(PASSIVE_PATH, body={"email": VALID}, credential=KEY)
    rendered = json.dumps(response.body)
    assert "acct-1" not in rendered
    assert KEY not in rendered


# --- the durable read path (RA-05) ------------------------------------------
#
# `GET /v1/checks/{id}` goes through `JobService.fetch`, not `JobService.get`.
# The difference is not stylistic: `get` answers from this process's registry
# alone, and a job's authoritative state lives in the job store the moment a
# deployment has one. The Remediation A focused review measured what the
# in-memory read publishes — a persisted job answered `404` after a restart, and
# a job another replica had already terminalized answered `pending` for ever —
# and measured that reverting the one line left the whole suite green.
#
# So these tests are the API-level half of that fix. Every one of them uses the
# real `SQLiteJobStore` over a temporary file and asserts on the HTTP-shaped
# response, because the property is what a caller sees rather than which method
# the handler happens to call.


@dataclass
class RefusesAfterObservation(RecordingExecutor):
    """Blocks inside `submit`, then refuses.

    The pause is the whole point: an executor that refuses immediately never
    lets a second replica observe the `pending` job, so the stale-snapshot case
    would be unreachable and the test would pass against the defect.
    """

    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def submit(self, job_id, work) -> None:  # type: ignore[no-untyped-def]
        self.entered.set()
        await self.release.wait()
        raise ExecutorFull("the queue refused after another replica observed the job")


class DurableApi:
    """One process's API over a job database that outlives the process.

    A "restart" is a second instance built over the same directory: new
    registry, new executor, new `JobService`, new `CheckApi`, and nothing shared
    but the file. Carrying the executor across would be carrying a queue this
    project does not have, which is the mistake an earlier restart suite made.
    """

    def __init__(
        self,
        root: Path,
        *,
        executor: RecordingExecutor | None = None,
        prefix: str = "job",
    ) -> None:
        self.root = root
        self.smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
        self.service, self.resolver, self.sink = build_service(
            smtp=self.smtp, resolver=resolver_with_route()
        )
        self.executor = executor if executor is not None else RecordingExecutor()
        self.jobs = JobService(
            verification=self.service,
            executor=self.executor,
            clock=FakeClock(),
            # Distinct per instance, so a second process cannot mint the
            # identifier the first one already used and pass by coincidence.
            random=FakeRandomSource(prefix=prefix),
            operator=self.sink,
            correlation_key=CORRELATION_KEY,
            store=self.job_store,
            # A durable store means a durable deletion authority: the two are
            # composed together or not at all, which is what this fixture's
            # "whole process restart" is meant to model.
            account_state=self.account_state,
        )
        self.api = CheckApi(
            verification=self.service,
            authenticator=build_authenticator({"acct-1": KEY, "acct-2": OTHER_KEY}),
            operator=self.sink,
            jobs=self.jobs,
        )

    @property
    def job_store(self) -> SQLiteJobStore:
        store = SQLiteJobStore(path=self.root / "jobs.sqlite3")
        store.initialize()
        store.bind_authority(self.account_state.authority_id())
        return store

    @property
    def account_state(self) -> SQLiteAccountStateStore:
        state = SQLiteAccountStateStore(path=self.root / "accounts.sqlite3")
        state.initialize()
        return state

    async def submit(self, credential: str = KEY, **kwargs: object) -> ApiResponse:
        return await self.api.handle(
            ApiRequest(
                path=ACTIVE_PATH,
                method="POST",
                body={"email": VALID},
                credential=credential,
                **kwargs,  # type: ignore[arg-type]
            )
        )

    async def read(self, job_id: str, credential: str | None = KEY) -> ApiResponse:
        return await self.api.handle(
            ApiRequest(path=f"{JOB_PATH_PREFIX}{job_id}", method="GET", credential=credential)
        )


async def test_a_persisted_job_is_still_readable_after_a_whole_process_restart(
    tmp_path: Path,
) -> None:
    """The restart the in-memory read path answers `404`.

    A completed job with a stored result is the most ordinary thing a caller
    polls for, and a process restart is the most ordinary thing that happens to
    a service. The published answer must not depend on which process is
    serving, so this asserts the *whole body* is identical across the boundary
    as well as the fields individually — and that reading it re-ran nothing.
    """
    first = DurableApi(tmp_path, prefix="first")
    submitted = await first.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    await first.executor.run_pending()
    before = await first.read(job_id)
    assert before.status_code == 200
    assert before.body["state"] == JobState.COMPLETED.value

    second = DurableApi(tmp_path, prefix="second")
    # The registry really is empty, so a 200 below can only have come from disk.
    assert second.jobs._jobs == {}

    response = await second.read(job_id)

    assert response.status_code == 200, "a persisted job was answered 404 after a restart"
    assert response.body["id"] == job_id
    assert response.body["state"] == JobState.COMPLETED.value
    result = response.body["result"]
    assert isinstance(result, dict)
    assert result["status"] == Status.LIKELY_DELIVERABLE.value
    assert result["primary_reason"] == "rcpt_accepted"
    assert json.dumps(response.body) == json.dumps(before.body), "the restart was visible"
    # Reading a job is a read. The second process probed nothing and enqueued
    # nothing to produce this answer.
    assert second.executor.submitted == []
    assert second.smtp.calls == []


async def test_the_published_result_is_the_one_the_store_actually_holds(
    tmp_path: Path,
) -> None:
    """The expectation comes from the durable row, not from the read path.

    Asserting only that two API calls agree would pass against a handler that
    invented the same answer twice. This compares the published projection
    against what a third party — the store — independently holds.
    """
    first = DurableApi(tmp_path, prefix="first")
    submitted = await first.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    await first.executor.run_pending()
    stored = await first.job_store.load(job_id)
    assert stored is not None

    response = await DurableApi(tmp_path, prefix="second").read(job_id)

    result = response.body["result"]
    assert isinstance(result, dict)
    assert response.body["state"] == stored.state.value
    assert result["status"] == stored.status
    assert result["confidence"] == stored.confidence
    assert result["primary_reason"] == stored.primary_reason
    assert list(result["reasons"]) == list(stored.reasons)  # type: ignore[call-overload]


async def test_a_replica_publishes_the_durable_state_rather_than_its_own_snapshot(
    tmp_path: Path,
) -> None:
    """RA-01's public symptom, at the API.

    One replica owns the job and its executor refuses; another has already
    answered a request about that job and holds a `pending` snapshot of it. The
    second replica must publish what the store says, not what it remembers —
    otherwise a caller polling the observing replica is told `pending` for ever
    about an operation that terminally failed on the other one.

    Both submissions and the assertion all go through `handle`, so nothing here
    depends on a service method a caller cannot reach.
    """
    gate = RefusesAfterObservation()
    owner = DurableApi(tmp_path, executor=gate, prefix="owner")
    observer = DurableApi(tmp_path, prefix="observer")
    key = "shared-handle-" + "a" * 12

    submitting = asyncio.create_task(owner.submit(idempotency_key=key))
    async with asyncio.timeout(5.0):
        await gate.entered.wait()
        # The observing replica answers a request about the owner's job, which
        # is what leaves it holding a snapshot.
        seeded = await observer.submit(idempotency_key=key)
        job_id = seeded.body["job"]["id"]  # type: ignore[index]
        assert seeded.body["job"]["state"] == JobState.PENDING.value  # type: ignore[index]

        gate.release.set()
        refused = await submitting

    assert refused.status_code == 503, "the owning caller was not told the queue refused"
    assert observer.jobs._jobs[job_id].state is JobState.PENDING, "the snapshot was not stale"

    response = await observer.read(job_id)

    assert response.status_code == 200
    assert response.body["state"] == JobState.FAILED.value, "a stale pending snapshot was published"
    assert response.body["failure"] == JobFailure.CAPACITY_UNAVAILABLE.value
    assert response.body["result"] is None, "an admission failure published a mailbox result"
    # The observing replica read the state. It never admitted the job itself.
    assert observer.executor.submitted == []


async def test_a_persisted_job_is_not_disclosed_to_another_account_after_a_restart(
    tmp_path: Path,
) -> None:
    """Reading from disk changes state freshness and nothing about ownership.

    A foreign job answers exactly what an unknown identifier answers, byte for
    byte — the property ADR 0014 keeps and the one a store lookup is most
    likely to erode, because the row is right there.
    """
    first = DurableApi(tmp_path, prefix="first")
    submitted = await first.submit(credential=KEY)
    job_id = submitted.body["job"]["id"]  # type: ignore[index]

    second = DurableApi(tmp_path, prefix="second")
    mine = await second.read(job_id, credential=KEY)
    theirs = await second.read(job_id, credential=OTHER_KEY)
    unknown = await second.read("nosuchjobnosuchjobnosuch", credential=OTHER_KEY)

    assert mine.status_code == 200
    assert theirs.status_code == 404
    assert theirs.body["error"]["code"] == ERROR_NOT_FOUND  # type: ignore[index]
    assert json.dumps(theirs.body) == json.dumps(unknown.body)


async def test_a_durable_read_needs_authentication_before_it_discloses_anything(
    tmp_path: Path,
) -> None:
    """Authentication is still first, and a refused request names no job."""
    first = DurableApi(tmp_path, prefix="first")
    submitted = await first.submit()
    job_id = submitted.body["job"]["id"]  # type: ignore[index]

    second = DurableApi(tmp_path, prefix="second")
    anonymous = await second.read(job_id, credential=None)

    assert anonymous.status_code == 401
    assert set(anonymous.body) == {"error"}
    error = anonymous.body["error"]
    assert isinstance(error, dict)
    assert error["code"] == ERROR_UNAUTHENTICATED
    assert set(error) == ERROR_BODY_KEYS
    # Nothing about the job was disclosed on the way to the refusal.
    assert job_id not in json.dumps(anonymous.body)


async def test_a_durable_read_publishes_no_part_of_the_new_internal_state_machine(
    tmp_path: Path,
) -> None:
    """The regression is about freshness, not about a wider surface.

    `JobAdmission`, `RecipientTouch`, and both correlation digests are the
    fields Remediation A added to the stored row. A read that answers from that
    row is exactly the place they could reach a response by being added to a
    projection later, so the published body is asserted to be the same six keys
    it always was, and each stored value is checked absent by its own text.
    """
    first = DurableApi(tmp_path, prefix="first")
    key = "internals-" + "b" * 12
    submitted = await first.submit(idempotency_key=key)
    job_id = submitted.body["job"]["id"]  # type: ignore[index]
    await first.executor.run_pending()
    stored = await first.job_store.load(job_id)
    assert stored is not None
    assert stored.idempotency_digest is not None and stored.target_digest is not None

    response = await DurableApi(tmp_path, prefix="second").read(job_id)
    rendered = json.dumps(response.body)

    assert set(response.body) == {"id", "state", "created_at", "updated_at", "result", "failure"}
    for hidden in (
        stored.admission.value,
        stored.recipient_touch.value,
        stored.idempotency_digest,
        stored.target_digest,
        key,
    ):
        assert hidden not in rendered, hidden
