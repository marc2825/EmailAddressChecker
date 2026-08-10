"""What a caller is told about a job, and nothing more.

`docs/requirements.md` section 11: `GET /v1/checks/{id}` returns job state and
result. ADR 0014 fixes what "and result" may carry — the existing
`application/public_result.py` allowlist, and only when the job is `completed`.

**A job that has not completed carries no status.** There is no verdict yet, and
inventing one — `unknown` while pending, say — would be a status decided by a
serializer rather than by `aggregate_evidence`, which is precisely Phase 5 stop
condition 1. The `result` field is `None` until there is something real to put
in it.

**Nothing internal crosses this boundary.** No `Evidence`, no
`Evidence.details`, no attempt record, no transcript, no exception text, no
principal, no digest, no cache key. A failure is a stable category, chosen from
`JobFailure`, because `docs/requirements.md` section 11 forbids full exception
text in a public response.

The same type parses a *remote* job in `--remote` mode, so a response from
another instance is validated against this project's published vocabulary before
the CLI prints it: a server answering with a status this build does not publish
is refused rather than displayed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from emailcheck.application.public_result import PublicResult, public_result_from_json_object
from emailcheck.domain.job import JobFailure, JobId, JobState


@dataclass(frozen=True, slots=True)
class PublicJob:
    """One job, as published."""

    id: str
    state: str
    created_at: str
    updated_at: str
    result: PublicResult | None = None
    failure: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {member.value for member in JobState}:
            raise ValueError("a public job must carry a published state")
        if self.failure is not None and self.failure not in {member.value for member in JobFailure}:
            raise ValueError("a public job failure must be a published category")
        if self.result is not None and self.state != JobState.COMPLETED.value:
            raise ValueError("only a completed job publishes a result")
        if self.failure is not None and self.state != JobState.FAILED.value:
            raise ValueError("only a failed job publishes a failure")
        JobId(self.id)

    def as_json_object(self) -> dict[str, object]:
        """A JSON-safe mapping. Strings, objects, null — and no number."""
        return {
            "id": self.id,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": None if self.result is None else self.result.as_json_object(),
            "failure": self.failure,
        }


def public_job(
    *,
    job_id: JobId,
    state: JobState,
    created_at: datetime,
    updated_at: datetime,
    result: PublicResult | None,
    failure: JobFailure | None,
) -> PublicJob:
    """Project a job record onto the public schema. Reads; never decides.

    Timestamps are serialized with an explicit offset, which is what
    `AGENTS.md` requires and what makes them unambiguous to a client in another
    zone.
    """
    return PublicJob(
        id=job_id.value,
        state=state.value,
        created_at=created_at.isoformat(),
        updated_at=updated_at.isoformat(),
        result=result,
        failure=None if failure is None else failure.value,
    )


def public_job_from_json_object(payload: object) -> PublicJob:
    """Parse a remote instance's answer, refusing anything unpublished.

    Used by `--remote`. The validation is the point: a remote server is not a
    trusted source of vocabulary, and `PublicJob` and `PublicResult` both refuse
    a status, confidence, reason, or flag this build does not publish. A
    malformed answer raises rather than being displayed as a result.
    """
    if not isinstance(payload, dict):
        raise ValueError("a job response must be an object")
    for name in ("id", "state", "created_at", "updated_at"):
        if not isinstance(payload.get(name), str):
            raise ValueError(f"a job response needs a text {name}")
    failure = payload.get("failure")
    if failure is not None and not isinstance(failure, str):
        raise ValueError("a job failure must be text or null")
    body = payload.get("result")
    return PublicJob(
        id=str(payload["id"]),
        state=str(payload["state"]),
        created_at=str(payload["created_at"]),
        updated_at=str(payload["updated_at"]),
        result=None if body is None else public_result_from_json_object(body),
        failure=failure,
    )
