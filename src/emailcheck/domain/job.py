"""What an asynchronous active check *is*, as vocabulary.

`docs/requirements.md` section 11 makes `POST /v1/checks` create a job;
`docs/architecture.md` fixes the six states, the idempotency key, the bounded
retry, and cancellation. ADR 0014 records the decisions. This module holds the
values and the state table, and nothing else: no scheduling, no I/O, no
deliverability rule, and no dependency on anything above the domain.

**The state names are the repository's, verbatim.** Not `queued`, not
`succeeded`. `retry_scheduled` exists because `docs/requirements.md` section 14
allows exactly one automatic retry, and renaming a published state to a more
familiar word would be new API vocabulary invented to match a convention nobody
asked for.

**The transition table is closed and refuses at run time.** A terminal state has
no exit, so `cancelled -> completed` is unreachable rather than merely unused,
and `pending -> completed` is refused because a job that never ran cannot have a
result. `domain/smtp_session.py` set the precedent: the table is data, and a
forbidden move raises instead of being ignored.

The job *record* lives in `application/jobs.py`, because it carries the public
projection of a verdict and `docs/architecture.md` section 1 does not let the
domain depend on the layer above it.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: The longest an identifier may be, and the shortest. A short identifier is a
#: guessable one; a long one is a place to hide data.
MIN_JOB_ID_LENGTH: Final = 22
MAX_JOB_ID_LENGTH: Final = 128

#: URL-safe base64 without padding, which is what `secrets.token_urlsafe`
#: produces. Deliberately narrow: an identifier appears in a path, and every
#: character outside this set is one that could change what the path means.
_ID_PERMITTED: Final = frozenset(string.ascii_letters + string.digits + "-_")

#: An idempotency key is chosen by the caller, so it is bounded and screened
#: like every other caller-supplied string in this project.
MAX_IDEMPOTENCY_KEY_LENGTH: Final = 128
MIN_IDEMPOTENCY_KEY_LENGTH: Final = 8

#: `docs/requirements.md` section 14: at most one automatic retry in the MVP.
MAX_RETRIES: Final = 1


class JobError(ValueError):
    """A job value was asked to be something it may not be."""


class JobTransitionError(JobError):
    """A state change the table does not permit."""


class JobState(StrEnum):
    """The six states `docs/architecture.md` publishes."""

    PENDING = "pending"
    RUNNING = "running"
    RETRY_SCHEDULED = "retry_scheduled"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobAdmission(StrEnum):
    """The durable executor-handoff fact, separate from public job state.

    `HANDOFF_COMMITTED` is written before the executor is called. It grants
    only the claiming process the right to make that call; it does not claim a
    queue acknowledged it. A crash on either side of the call may lose work,
    conservatively, but can never authorize a second executor admission.
    """

    CLAIMED = "claimed"
    HANDOFF_COMMITTED = "handoff_committed"
    ADMISSION_FAILED = "admission_failed"
    NOT_REQUIRED = "not_required"
    INTERRUPTED = "interrupted"


#: Terminal states, named once. A job in one of these is finished, and the
#: transition table gives it no exit.
TERMINAL_STATES: Final[frozenset[JobState]] = frozenset(
    {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
)

#: The closed transition table. ADR 0014, amended by Remediation A.
#:
#: Every terminal state maps to the empty set rather than being absent, so a
#: lookup never has to decide what a missing key means.
#:
#: **`pending -> failed` and `retry_scheduled -> failed` exist because work can
#: stop being arrangeable.** Both were absent while the only way to leave those
#: states was to run, and the final system audit found the two places where that
#: is untrue: a `retry_scheduled` job whose `schedule()` call is refused, and a
#: nonterminal job found in the store by a process that has no queue to resume it
#: on. Without these rows the honest outcome — an operational failure, carrying a
#: category and **no status** — was unreachable, and the job stayed nonterminal
#: with nothing that would ever run it. `pending -> completed` is still refused:
#: a job that never ran cannot have a *result*, and `JobFailure` is not one.
PERMITTED_TRANSITIONS: Final[dict[JobState, frozenset[JobState]]] = {
    JobState.PENDING: frozenset({JobState.RUNNING, JobState.FAILED, JobState.CANCELLED}),
    JobState.RUNNING: frozenset(
        {
            JobState.COMPLETED,
            JobState.FAILED,
            JobState.RETRY_SCHEDULED,
            JobState.CANCELLED,
        }
    ),
    JobState.RETRY_SCHEDULED: frozenset({JobState.RUNNING, JobState.FAILED, JobState.CANCELLED}),
    JobState.COMPLETED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
}


def check_transition(current: JobState, target: JobState) -> None:
    """Refuse a move the table does not permit.

    A function rather than a method, so the table is enforced in one place and
    the record type that uses it can live in the layer that needs it.
    """
    if not isinstance(current, JobState) or not isinstance(target, JobState):
        raise JobError("a transition names two published states")
    if target not in PERMITTED_TRANSITIONS[current]:
        raise JobTransitionError(f"a job may not move from {current.value} to {target.value}")


class JobFailure(StrEnum):
    """Why a job failed, as a stable category rather than as a message.

    A caller branches on these. None of them carries a remote reply, an
    exception message, a module name, or anything about the address:
    `docs/requirements.md` section 11 forbids full exception text in a public
    response, and a category is what is left that is still useful.
    """

    #: A failure of this project's own. The operator gets the detail.
    SERVICE_ERROR = "service_error"
    #: Capacity, pacing, or the verification-total deadline refused it.
    CAPACITY_UNAVAILABLE = "capacity_unavailable"
    #: The process that owned this job stopped, and no later process may resume
    #: it automatically.
    #:
    #: **A category, and deliberately not a status.** This project cannot know
    #: whether the one `RCPT TO` had already been issued when the process died,
    #: and `docs/threat-model.md` bounds one active operation at one recipient
    #: contact — so re-running the verification on the assumption that it had not
    #: is precisely the duplicate that bound exists to prevent. The honest answer
    #: is that the operation did not finish, which is an operational fact about
    #: this service. Turning "we do not know whether we touched the recipient"
    #: into `unknown`, `temporary_unknown`, or any other published status would
    #: be making a statement about a mailbox out of a statement about a crash.
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class JobId:
    """An unguessable handle. Validated for shape, granted by a generator.

    The split is the one `PeerEndpoint` and `Principal` already use: this type
    fixes what an identifier may look like, and `application/jobs.py` decides
    where one comes from. Nothing here makes a value unguessable — a caller can
    construct `JobId("a" * 22)` — so the entropy guarantee lives with the
    `RandomSource` that produces one, and ADR 0014 records it.
    """

    value: str

    def __post_init__(self) -> None:
        value = self.value
        if not isinstance(value, str):
            raise JobError("a job identifier must be a string")
        if not MIN_JOB_ID_LENGTH <= len(value) <= MAX_JOB_ID_LENGTH:
            raise JobError(
                f"a job identifier must be {MIN_JOB_ID_LENGTH}..{MAX_JOB_ID_LENGTH} characters"
            )
        if not _ID_PERMITTED.issuperset(value):
            # `@` is refused by this, so an identifier can never be a mailbox
            # even by construction accident — the shape check `rate_limit_key`
            # and `OperatorEvent` already make, for the same reason.
            raise JobError("a job identifier carries an unpermitted character")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class IdempotencyKey:
    """A caller-chosen handle for "this is the same request as before".

    Scoped to a principal by `application/jobs.py`, never global: two accounts
    choosing the same key are two requests, and a key that collided across
    accounts would return one caller's job to another.
    """

    value: str

    def __post_init__(self) -> None:
        value = self.value
        if not isinstance(value, str):
            raise JobError("an idempotency key must be a string")
        if not MIN_IDEMPOTENCY_KEY_LENGTH <= len(value) <= MAX_IDEMPOTENCY_KEY_LENGTH:
            raise JobError(
                f"an idempotency key must be {MIN_IDEMPOTENCY_KEY_LENGTH}"
                f"..{MAX_IDEMPOTENCY_KEY_LENGTH} characters"
            )
        if not value.isprintable() or " " in value:
            # A control character in a key reaches a log line and a dictionary
            # key. Refused rather than stripped, so the key a caller sends is
            # the key this project uses.
            raise JobError("an idempotency key carries an unprintable character")
