"""Running an accepted job, later and elsewhere.

`prompts/06-api-cli.md` requires a memory executor for tests and a Redis-backed
executor "or a clearly isolated adapter" for the service profile. This is the
seam between them: `application/jobs.py` submits work and never learns which one
it has.

**This port is deliberately narrower than `ports/executor.py`.** That Phase 0
stub takes any awaitable and returns an opaque string, which is a thread pool
rather than a job system: it has nowhere to put a delay, no way to cancel one
piece of work, and no identity to cancel it by. Those three are exactly what
`prompts/06-api-cli.md` asks for, so the port that carries them says so in its
signature.

`is_isolated` is the one property `docs/requirements.md` section 15 needs and
that a type cannot otherwise express. The service-active profile requires an
isolated worker; an in-process executor is not one, and the composition root
refuses that combination rather than letting a development fake become the
production default by omission.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from emailcheck.domain.job import JobId


class ExecutorFull(Exception):
    """The queue is at capacity. Nothing was accepted and nothing will run.

    Not a `TimeoutError` and not an `OSError`, on the precedent
    `RateLimitTimeout`, `AdmissionRefused`, and `VerificationRefused` set: this
    project running out of room is not a fact about anybody's mailbox.
    """


class JobExecutor(Protocol):
    @property
    def is_isolated(self) -> bool:
        """Whether work runs outside this process.

        `docs/requirements.md` section 15's service-active profile requires an
        isolated worker. An implementation that answers `True` is claiming to be
        one.
        """
        ...

    async def submit(self, job_id: JobId, work: Callable[[], Awaitable[None]]) -> None:
        """Accept `work` to run later, or raise `ExecutorFull`.

        Must return without running `work`, so a caller never waits for the job
        it just submitted — `prompts/06-api-cli.md`: no synchronous waiting for
        active SMTP in API workers.
        """
        ...

    async def schedule(
        self, job_id: JobId, work: Callable[[], Awaitable[None]], *, delay_seconds: float
    ) -> None:
        """Accept `work` to run after `delay_seconds`, or raise `ExecutorFull`.

        A delayed job must not hold a worker while it waits: the retry delay
        `docs/requirements.md` section 14 describes is measured in minutes, and
        a handful of them would otherwise occupy the whole pool.
        """
        ...

    async def cancel(self, job_id: JobId) -> bool:
        """Stop `job_id` if it is queued, delayed, or running.

        Returns whether anything was stopped. Cancellation must propagate into
        the running coroutine rather than merely marking a flag, so the SMTP
        dialogue, the rate-limit lease, and the admission permit are released.
        """
        ...
