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

from datetime import datetime

from emailcheck.domain.job import JobFailure, JobId, JobState
from emailcheck.ports.public_contract import (
    PublicJob,
    PublicResult,
    public_job_from_json_object,
)


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


#: Re-exported so every existing import keeps working. See
#: `ports/public_contract.py` for why the shape lives a layer down.
__all__ = ["PublicJob", "PublicResult", "public_job", "public_job_from_json_object"]
