"""The published API schema, its examples, and its limitations.

`docs/architecture.md` requires "generated schema with examples and
limitations", and its acceptance criterion is that **API examples state
explicitly that no existence or delivery guarantee is made**. That sentence is
`NO_GUARANTEE` below, it appears in the schema document itself, and a docs test
fails if it disappears.

**Generated, not transcribed.** Every example body here is produced by the same
code paths a real response goes through: the result example is
`public_result(aggregate_evidence(...))`, and the job examples are
`public_job(...)`. There is no second, hand-written copy of the response
contract to drift from the first — which is the failure mode a written-out
schema has.

Every value a field may take is listed by iterating the published enum rather
than by spelling the values out, so a status, reason, risk flag, or job state
added later appears in the schema without this module being edited.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.public_job import public_job
from emailcheck.application.public_result import PUBLIC_LAYERS, public_result
from emailcheck.apps.api import (
    ACTIVE_PATH,
    ERROR_CAPACITY,
    ERROR_IDEMPOTENCY_CONFLICT,
    ERROR_INVALID_REQUEST,
    ERROR_NOT_FOUND,
    ERROR_TIMEOUT,
    ERROR_UNAUTHENTICATED,
    HEALTH_PATH,
    JOB_PATH_PREFIX,
    PASSIVE_PATH,
    PERMITTED_REQUEST_KEYS,
)
from emailcheck.domain.job import JobFailure, JobId, JobState
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import ConfidenceLevel, RiskFlag, Status

#: The sentence `docs/architecture.md` makes an acceptance criterion.
#:
#: `docs/requirements.md` section 1 lists what this system does not prove, and
#: section 2 requires the documentation to say that a remote mail server may be
#: contacted even though no message content is transmitted. Both are here,
#: because a caller reading only the schema must still be told.
NO_GUARANTEE: Final = (
    "This service does not prove mailbox existence and does not guarantee "
    "message delivery. A result is an estimate from observed evidence about "
    "one address at one moment. No message content, header, body, or "
    "attachment is ever transmitted, and neither VRFY nor EXPN is ever issued "
    "- but an active check may open an SMTP session to a remote mail server."
)

#: Fixed so the document is byte-identical between runs. A schema that changed
#: on every call would be a schema nobody could diff.
_EXAMPLE_MOMENT: Final = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC)
_EXAMPLE_JOB_ID: Final = "P9x2Kq7YbN4mZr1Tf6HvJ0wLsD3gAeUc"
_EXAMPLE_ADDRESS: Final = "user@example.com"


def _example_result() -> dict[str, object]:
    """A result body, produced by the real aggregator and the real projection.

    Built from the empty evidence set, which is the one input whose answer needs
    no observation to explain: nothing was observed, so nothing is claimed. Its
    *status* comes from `aggregate_evidence`, not from this module — there is no
    status written down anywhere here.
    """
    return public_result(aggregate_evidence(())).as_json_object()


def _example_job(
    state: JobState, *, with_result: bool, failure: JobFailure | None
) -> dict[str, object]:
    return public_job(
        job_id=JobId(_EXAMPLE_JOB_ID),
        state=state,
        created_at=_EXAMPLE_MOMENT,
        updated_at=_EXAMPLE_MOMENT,
        result=public_result(aggregate_evidence(())) if with_result else None,
        failure=failure,
    ).as_json_object()


def _error(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}}


def api_schema() -> dict[str, object]:
    """The whole published document, as a JSON-safe object."""
    return {
        "service": "emailcheck",
        "version": "v1",
        "limitations": {
            "no_guarantee": NO_GUARANTEE,
            "statuses": [member.value for member in Status],
            "confidence_levels": [member.value for member in ConfidenceLevel],
            "confidence_score": (
                "Always absent. A probability requires a calibrated study, and "
                "until one exists the confidence is categorical only."
            ),
            "risk_flags": [member.value for member in RiskFlag],
            "risk_is_not_deliverability": (
                "Risk flags are independent of the status. A disposable address "
                "may be likely deliverable, and a role address may be invalid."
            ),
            "reason_codes": [member.value for member in ReasonCode],
            "check_layers": [layer.value for layer in PUBLIC_LAYERS],
            "job_states": [member.value for member in JobState],
            "job_failures": [member.value for member in JobFailure],
        },
        "authentication": {
            "scheme": "Bearer",
            "header": "Authorization",
            "note": "Required by every check endpoint. No anonymous access.",
        },
        "idempotency": {
            "header": "Idempotency-Key",
            "scope": "One principal. The same key from another account is a different request.",
            "behaviour": "A repeat with the same key returns the same job and enqueues nothing.",
            "identity": (
                "The key is paired with a derived HMAC of the normalized "
                "target. The same key for a different address is a conflict, "
                "not a second meaning for the key."
            ),
        },
        "request_body": {
            "keys": sorted(PERMITTED_REQUEST_KEYS),
            "note": (
                "Closed. A body carrying any other key is refused, including "
                "any attempt to choose an MX host, a sender, a TLS policy, a "
                "trust anchor, a retry count, or a cache bypass."
            ),
        },
        "endpoints": [
            {
                "method": "POST",
                "path": PASSIVE_PATH,
                "summary": "Passive check. Synchronous, and opens no SMTP connection.",
                "status_codes": [200, 400, 401, 405, 500, 503, 504],
                "example_request": {"body": {"email": _EXAMPLE_ADDRESS}},
                "example_response": {"status_code": 200, "body": _example_result()},
            },
            {
                "method": "POST",
                "path": ACTIVE_PATH,
                "summary": (
                    "Active check. Creates a job and returns immediately; the "
                    "SMTP dialogue happens afterwards. Passive evidence is "
                    "returned with the job when it is available."
                ),
                "status_codes": [200, 202, 400, 401, 405, 409, 500, 503, 504],
                "example_request": {
                    "headers": {"Idempotency-Key": "3f2a91c4-order-42"},
                    "body": {"email": _EXAMPLE_ADDRESS},
                },
                "example_response": {
                    "status_code": 202,
                    "body": {
                        "job": _example_job(JobState.PENDING, with_result=False, failure=None),
                        "passive": _example_result(),
                    },
                },
            },
            {
                "method": "GET",
                "path": f"{JOB_PATH_PREFIX}{{id}}",
                "summary": "One job's state, and its result once it has completed.",
                "status_codes": [200, 401, 404, 405, 500],
                "example_responses": {
                    JobState.PENDING.value: _example_job(
                        JobState.PENDING, with_result=False, failure=None
                    ),
                    JobState.RUNNING.value: _example_job(
                        JobState.RUNNING, with_result=False, failure=None
                    ),
                    JobState.RETRY_SCHEDULED.value: _example_job(
                        JobState.RETRY_SCHEDULED, with_result=False, failure=None
                    ),
                    JobState.COMPLETED.value: _example_job(
                        JobState.COMPLETED, with_result=True, failure=None
                    ),
                    JobState.FAILED.value: _example_job(
                        JobState.FAILED, with_result=False, failure=JobFailure.SERVICE_ERROR
                    ),
                    JobState.CANCELLED.value: _example_job(
                        JobState.CANCELLED, with_result=False, failure=None
                    ),
                },
            },
            {
                "method": "DELETE",
                "path": f"{JOB_PATH_PREFIX}{{id}}",
                "summary": (
                    "Cancel one job. Idempotent: a job already in a terminal "
                    "state is returned unchanged."
                ),
                "status_codes": [200, 401, 404, 405, 500],
                "example_response": {
                    "status_code": 200,
                    "body": _example_job(JobState.CANCELLED, with_result=False, failure=None),
                },
            },
            {
                "method": "GET",
                "path": HEALTH_PATH,
                "summary": "Liveness. Reveals no configuration and no secret.",
                "status_codes": [200, 405],
                "example_response": {"status_code": 200, "body": {"status": "ok"}},
            },
        ],
        "errors": {
            "shape": "Every failure is {'error': {'code': ..., 'message': ...}} and nothing else.",
            "examples": {
                ERROR_UNAUTHENTICATED: {
                    "status_code": 401,
                    "body": _error(ERROR_UNAUTHENTICATED, "authentication required"),
                },
                ERROR_INVALID_REQUEST: {
                    "status_code": 400,
                    "body": _error(
                        ERROR_INVALID_REQUEST,
                        "the request body must carry exactly one field, 'email', as text",
                    ),
                },
                ERROR_NOT_FOUND: {
                    "status_code": 404,
                    "body": _error(ERROR_NOT_FOUND, "no such job"),
                },
                ERROR_IDEMPOTENCY_CONFLICT: {
                    "status_code": 409,
                    "body": _error(
                        ERROR_IDEMPOTENCY_CONFLICT,
                        "this idempotency key was already used for a different address",
                    ),
                },
                ERROR_CAPACITY: {
                    "status_code": 503,
                    "body": _error(ERROR_CAPACITY, "the service is at capacity"),
                },
                ERROR_TIMEOUT: {
                    "status_code": 504,
                    "body": _error(ERROR_TIMEOUT, "the verification did not complete in time"),
                },
            },
            "note": (
                "An error never carries the submitted address, a remote reply, "
                "an exception message, or an account identifier."
            ),
        },
    }
