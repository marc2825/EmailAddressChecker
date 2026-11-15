"""The HTTP contract, as a function from a request to a response.

**No web framework is imported here, and that is the design rather than a
limitation.** `docs/architecture.md` section 1 puts frameworks in `apps/` and
keeps them out of everything below; this module is the layer that decides what
a request means, what a response says, and which status code carries it. Binding
an ASGI route to `handle` is the remaining step, and it holds no policy.

The routes are `docs/requirements.md` section 11's, and no others:

```text
POST   /v1/checks/passive   synchronous, no SMTP
POST   /v1/checks           creates an asynchronous job
GET    /v1/checks/{id}      job state, and result when there is one
DELETE /v1/checks/{id}      cancellation
GET    /v1/health           reveals no configuration
```

`DELETE` is on the resource section 11 already names, because
`docs/architecture.md` requires cancellation and names no route for it; adding
a path would have been inventing API surface. ADR 0014.

Four rules shape everything below.

**Nothing here derives a status.** Every value in a response is read from the
`Verdict` that `aggregate_evidence` produced, projected by
`application/public_result.py`. Phase 5 stop condition 1, and an inspection test
refuses the published reason sets in this module entirely.

**The active endpoint never waits for SMTP.** It returns a job.
`docs/architecture.md` states that as a requirement of its own, and the first
Phase 6 build failed it.

**The request schema is closed.** A body carrying a key this module does not
name is refused, which is what makes "no low-level knobs" structural: an MX
override, a sender override, a TLS policy, a CA file, a retry count, a cache
bypass, and a catch-all flag are all rejected by the same rule that rejects a
typo, and nobody has to remember to add each one to a deny list.

**A refusal from this service is never a statement about the address.** Capacity,
pacing, and the total deadline map to service-level codes carrying no verdict at
all — because `unknown` is a status a caller retries, and answering `unknown`
when the real problem is our own capacity would add load exactly when there is
none to spare. ADR 0013.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from emailcheck.application.abuse import AbuseRefused
from emailcheck.application.jobs import (
    CheckJob,
    IdempotencyConflict,
    JobService,
    JobsFull,
)
from emailcheck.application.public_job import public_job
from emailcheck.application.public_result import public_result
from emailcheck.application.verification import (
    AddressVerificationService,
    SubmittedInputTooLong,
    VerificationRefused,
)
from emailcheck.domain.job import IdempotencyKey, JobError, JobId
from emailcheck.domain.principal import Principal
from emailcheck.domain.source import SourceIdentity
from emailcheck.ports.authentication import Authenticator
from emailcheck.ports.job_executor import ExecutorFull
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink

#: The published paths, from `docs/requirements.md` section 11.
PASSIVE_PATH: Final = "/v1/checks/passive"
ACTIVE_PATH: Final = "/v1/checks"
HEALTH_PATH: Final = "/v1/health"
#: One job, addressed by identifier: `f"{JOB_PATH_PREFIX}{job_id}"`.
JOB_PATH_PREFIX: Final = "/v1/checks/"

#: Every key a request body may carry. Anything else is a `400`.
#:
#: One key, deliberately. Every low-level knob this project must never expose —
#: an MX host, an IP, a sender, an EHLO name, a CA file, a TLS policy, a retry
#: count, an accept-all probe, a cache bypass — is refused by this set rather
#: than by a list of forbidden names, so a knob nobody thought of is refused
#: too. The idempotency key travels as a header for the same reason: adding it
#: to the body would widen the one thing that keeps the body closed.
PERMITTED_REQUEST_KEYS: Final[frozenset[str]] = frozenset({"email"})

#: Every key an error object may carry, asserted by a test. A body that grew a
#: `detail` or an `account_exists` field would be a body that leaked one, and
#: "we only ever put safe things in it" is not a property.
ERROR_BODY_KEYS: Final[frozenset[str]] = frozenset({"code", "message"})

#: Stable public error codes. A caller branches on these; they are not prose.
ERROR_UNAUTHENTICATED: Final = "unauthenticated"
ERROR_INVALID_REQUEST: Final = "invalid_request"
ERROR_CAPACITY: Final = "capacity_unavailable"
ERROR_TIMEOUT: Final = "verification_timeout"
#: Deliberately not `"internal_error"`. That string is a published *reason
#: code* — a deliverability observation meaning a failure of this project's own
#: prevented a determination — and an API error code spelled identically would
#: put one word in a response body with two meanings. A caller reading
#: `{"error": {"code": ...}}` is being told the request failed, not being told
#: something about the address.
ERROR_INTERNAL: Final = "service_error"
ERROR_NOT_FOUND: Final = "not_found"
ERROR_METHOD: Final = "method_not_allowed"
#: One idempotency key, two different addresses. The body names neither, so a
#: caller learns the key is in use and nothing about what it was used for.
ERROR_IDEMPOTENCY_CONFLICT: Final = "idempotency_conflict"

#: The one message every unauthenticated request gets, whatever was wrong with
#: the credential. An absent key and an unknown key are indistinguishable to a
#: caller — otherwise the `401` body is an oracle for "this key exists".
_UNAUTHENTICATED_MESSAGE: Final = "authentication required"

_STATUS_OK: Final = 200
_STATUS_ACCEPTED: Final = 202
_STATUS_BAD_REQUEST: Final = 400
_STATUS_UNAUTHENTICATED: Final = 401
_STATUS_NOT_FOUND: Final = 404
_STATUS_METHOD: Final = 405
_STATUS_CONFLICT: Final = 409
_STATUS_INTERNAL: Final = 500
_STATUS_UNAVAILABLE: Final = 503
_STATUS_TIMEOUT: Final = 504


@dataclass(frozen=True, slots=True)
class ApiRequest:
    """One request, already parsed out of whatever transport carried it."""

    path: str
    method: str = "POST"
    #: `repr=False` as well, and not because the review named it: the body
    #: carries the submitted address, and `docs/requirements.md` section 16
    #: forbids a full address in an ordinary log just as firmly as it forbids a
    #: credential. Hiding only the two fields a review pointed at would leave
    #: the same object leaking the same class of value through a different
    #: field. `path`, `method`, and `source` survive, which is what a debugger
    #: actually wants.
    body: Mapping[str, object] = field(default_factory=dict, repr=False)
    #: The API key, as presented.
    #:
    #: **`repr=False`, which is what makes "never logged" true.** The field said
    #: so and the generated `repr` printed it anyway, and the ASGI
    #: request-logging middleware `docs/architecture.md` records as a stop
    #: condition is precisely the code that logs a request object. An
    #: independent review measured it.
    credential: str | None = field(default=None, repr=False)
    #: The `Idempotency-Key` header, as presented. Caller-chosen text, and
    #: `IdempotencyKey` permits `@` — so `alice@example.test` is a legal key and
    #: this is exactly as sensitive as whatever a caller put in it. Redacted for
    #: the reason `CheckJob.idempotency_key` is.
    idempotency_key: str | None = field(default=None, repr=False)
    #: Where the request came from, when the transport boundary knows.
    #:
    #: **Set by the binding from the connection, never parsed out of `body`.**
    #: `PERMITTED_REQUEST_KEYS` holds exactly `email`, so a body carrying
    #: `source_ip` or `x_forwarded_for` is refused as a malformed request rather
    #: than believed — a spoofable source turns a per-source budget into a
    #: per-*claimed*-source budget, which an attacker resets by changing a
    #: string. `None` is the honest answer when nothing trustworthy knows, and
    #: the source layer is then simply not counted.
    source: SourceIdentity | None = None


@dataclass(frozen=True, slots=True)
class ApiResponse:
    """One response: a status code and a JSON-safe object."""

    status_code: int
    body: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CheckApi:
    """The published endpoints, over one verification service and one job service.

    `verification` is the *high-level* service and there is no field here for
    anything below it. Phase 4 stop condition 1 forbids an API reaching
    `SMTPProbeService`, `SMTPConnector`, or `SMTPTransport`, and this type has
    no attribute through which one could arrive.
    """

    verification: AddressVerificationService
    authenticator: Authenticator
    operator: OperatorSink
    jobs: JobService | None = None

    async def handle(self, request: ApiRequest) -> ApiResponse:
        """Route one request. The only entry point."""
        method = request.method.upper()
        if request.path == HEALTH_PATH:
            if method != "GET":
                return _error(_STATUS_METHOD, ERROR_METHOD, "this endpoint accepts GET")
            # Deliberately empty of configuration. A health endpoint that
            # reported the sender identity, the store path, or the key count
            # would be reporting operator configuration to anyone who can reach
            # it. `docs/architecture.md`: reveals no secrets.
            return ApiResponse(_STATUS_OK, {"status": "ok"})

        if request.path == PASSIVE_PATH:
            if method != "POST":
                return _error(_STATUS_METHOD, ERROR_METHOD, "this endpoint accepts POST")
            return await self._passive(request)

        if request.path == ACTIVE_PATH:
            if method != "POST":
                return _error(_STATUS_METHOD, ERROR_METHOD, "this endpoint accepts POST")
            return await self._active(request)

        if request.path.startswith(JOB_PATH_PREFIX):
            return await self._job(request, method=method)

        return _error(_STATUS_NOT_FOUND, ERROR_NOT_FOUND, "no such endpoint")

    # --- the two check endpoints -------------------------------------------

    async def _passive(self, request: ApiRequest) -> ApiResponse:
        principal = self._authenticate(request)
        if principal is None:
            return _unauthenticated()
        submitted = _submitted_address(request.body)
        if submitted is None:
            return _invalid_body()
        try:
            outcome = await self.verification.verify(
                submitted, principal=principal, active=False, source=request.source
            )
        except SubmittedInputTooLong:
            return _error(_STATUS_BAD_REQUEST, ERROR_INVALID_REQUEST, "the address is too long")
        except VerificationRefused as refusal:
            return _refusal(refusal)
        except Exception:
            return self._service_error()
        return ApiResponse(_STATUS_OK, public_result(outcome.verdict).as_json_object())

    async def _active(self, request: ApiRequest) -> ApiResponse:
        """Create a job. Returns without waiting for any SMTP dialogue."""
        if self.jobs is None:
            # A deployment with no executor cannot accept active work. Reported
            # as unavailable rather than as a bad request: nothing about the
            # request was wrong.
            return _error(_STATUS_UNAVAILABLE, ERROR_CAPACITY, "active checks are not enabled here")
        principal = self._authenticate(request)
        if principal is None:
            return _unauthenticated()
        submitted = _submitted_address(request.body)
        if submitted is None:
            return _invalid_body()

        presented = request.idempotency_key
        try:
            key = None if presented is None else IdempotencyKey(presented)
        except JobError:
            return _error(
                _STATUS_BAD_REQUEST, ERROR_INVALID_REQUEST, "the idempotency key is not usable"
            )

        try:
            outcome = await self.jobs.submit(
                submitted, principal=principal, idempotency_key=key, source=request.source
            )
        except SubmittedInputTooLong:
            return _error(_STATUS_BAD_REQUEST, ERROR_INVALID_REQUEST, "the address is too long")
        except VerificationRefused as refusal:
            return _refusal(refusal)
        except IdempotencyConflict:
            # `docs/architecture.md` section 6 pairs the key with a derived
            # target HMAC. Reusing one for another address is caller error, and
            # answering with the first address's job would be a confident
            # verdict about a mailbox nobody asked about.
            return _error(
                _STATUS_CONFLICT,
                ERROR_IDEMPOTENCY_CONFLICT,
                "this idempotency key was already used for a different address",
            )
        except AbuseRefused:
            # An administrative control refused before any work began. Answered
            # as unavailable and with the same body every capacity refusal
            # uses: which of nine budgets was reached, and whether this caller
            # is suspended at all, is operator information. A distinct code
            # would let anyone probe the deployment's control state.
            return _error(_STATUS_UNAVAILABLE, ERROR_CAPACITY, "the service is at capacity")
        except (ExecutorFull, JobsFull):
            return _error(_STATUS_UNAVAILABLE, ERROR_CAPACITY, "the service is at capacity")
        except Exception:
            return self._service_error()

        body: dict[str, object] = {
            "job": _job_body(outcome.job),
            "passive": None if outcome.passive is None else outcome.passive.as_json_object(),
        }
        return ApiResponse(_STATUS_OK if outcome.existing else _STATUS_ACCEPTED, body)

    # --- one job ------------------------------------------------------------

    async def _job(self, request: ApiRequest, *, method: str) -> ApiResponse:
        if method not in {"GET", "DELETE"}:
            return _error(_STATUS_METHOD, ERROR_METHOD, "this endpoint accepts GET and DELETE")
        if self.jobs is None:
            return _no_such_job()
        principal = self._authenticate(request)
        if principal is None:
            return _unauthenticated()

        try:
            job_id = JobId(request.path[len(JOB_PATH_PREFIX) :])
        except JobError:
            # A malformed identifier names no job, and saying so more precisely
            # would describe what a real one looks like.
            return _no_such_job()

        try:
            job = (
                await self.jobs.fetch(job_id, principal=principal)
                if method == "GET"
                else await self.jobs.cancel(job_id, principal=principal)
            )
        except Exception:
            return self._service_error()

        if job is None:
            # Unknown and somebody else's are the same answer. ADR 0014: a
            # `403` would confirm that the identifier names a real job.
            return _no_such_job()
        return ApiResponse(_STATUS_OK, _job_body(job))

    # --- shared -------------------------------------------------------------

    def _authenticate(self, request: ApiRequest) -> Principal | None:
        """Authentication comes first for every check endpoint.

        `docs/requirements.md` section 11 permits a low anonymous quota for
        passive checks and prefers authentication; per-account isolation depends
        on an identity, so this build requires one for both rather than
        inventing a default principal for the passive path.
        """
        return self.authenticator.authenticate(request.credential)

    def _service_error(self) -> ApiResponse:
        """A stable public error, and an operator who finds out.

        The caller gets no traceback, no exception message, and no module name:
        `docs/requirements.md` section 11 forbids full exception text in a
        public response. The operator gets a categorical event, because a `500`
        nobody is told about is a failure this project cannot see — which an
        earlier build shipped, and which an independent review measured.
        """
        self.operator.record(
            OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail="api request")
        )
        return _error(_STATUS_INTERNAL, ERROR_INTERNAL, "the request could not be completed")


def _job_body(job: CheckJob) -> dict[str, object]:
    """The published job object, built by the allowlist rather than from the record."""
    return public_job(
        job_id=job.id,
        state=job.state,
        created_at=job.created_at,
        updated_at=job.updated_at,
        result=job.result,
        failure=job.failure,
    ).as_json_object()


def _submitted_address(body: Mapping[str, object]) -> str | None:
    """The one field a request may carry, or `None` if the body is not that.

    A closed schema: unknown keys are refused rather than ignored. Ignoring them
    is how a client comes to believe `{"tls_verify": false}` did something.
    """
    if not isinstance(body, Mapping):
        return None
    if set(body) != PERMITTED_REQUEST_KEYS:
        return None
    value = body.get("email")
    if not isinstance(value, str) or not value:
        return None
    return value


def _unauthenticated() -> ApiResponse:
    """One answer for an absent, malformed, unknown, or wrong credential."""
    return _error(_STATUS_UNAUTHENTICATED, ERROR_UNAUTHENTICATED, _UNAUTHENTICATED_MESSAGE)


def _no_such_job() -> ApiResponse:
    """One answer for an unknown job, a malformed identifier, and a foreign job."""
    return _error(_STATUS_NOT_FOUND, ERROR_NOT_FOUND, "no such job")


def _invalid_body() -> ApiResponse:
    return _error(
        _STATUS_BAD_REQUEST,
        ERROR_INVALID_REQUEST,
        "the request body must carry exactly one field, 'email', as text",
    )


def _refusal(refusal: VerificationRefused) -> ApiResponse:
    """Map a local operational refusal to a service-level code.

    Neither carries a verdict. `docs/requirements.md` fixes no status codes, so
    ADR 0013 chooses them: `503` for capacity, because the condition is
    transient and the request may be repeated; `504` for the total deadline,
    because the work was started and abandoned rather than declined.
    """
    if refusal.scope == "the verification deadline":
        return _error(_STATUS_TIMEOUT, ERROR_TIMEOUT, "the verification did not complete in time")
    return _error(_STATUS_UNAVAILABLE, ERROR_CAPACITY, "the service is at capacity")


def _error(status_code: int, code: str, message: str) -> ApiResponse:
    """One error shape, for every failure.

    `message` is a fixed string chosen in this module. It never contains the
    submitted address, a local part, a remote reply, an exception message, a
    job identifier, or a principal identifier. The object carries exactly the
    two keys `ERROR_BODY_KEYS` names.
    """
    return ApiResponse(status_code, {"error": {"code": code, "message": message}})
