"""The job vocabulary, and the table that keeps its states honest.

`prompts/06-api-cli.md` publishes six states; ADR 0014 closes the transitions
between them. These tests assert both as data rather than as behaviour, because
a state machine is exactly the thing a behavioural test covers only where
somebody thought to drive it.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.job import (
    MAX_IDEMPOTENCY_KEY_LENGTH,
    MAX_JOB_ID_LENGTH,
    MAX_RETRIES,
    MIN_JOB_ID_LENGTH,
    PERMITTED_TRANSITIONS,
    TERMINAL_STATES,
    IdempotencyKey,
    JobError,
    JobFailure,
    JobId,
    JobState,
    JobTransitionError,
    check_transition,
)

# --- the published vocabulary ----------------------------------------------


def test_the_states_are_the_repositorys_six_and_no_others() -> None:
    """`prompts/06-api-cli.md`: pending/running/retry_scheduled/completed/failed/cancelled.

    Written out here on purpose. Not `queued`, not `succeeded`, not
    `in_progress`: renaming a published state to a more familiar word would be
    new API vocabulary invented to match a convention nobody asked for.
    """
    assert [member.value for member in JobState] == [
        "pending",
        "running",
        "retry_scheduled",
        "completed",
        "failed",
        "cancelled",
    ]


def test_at_most_one_automatic_retry() -> None:
    """`docs/requirements.md` section 14, as a number rather than as a habit."""
    assert MAX_RETRIES == 1


def test_a_failure_category_carries_no_prose() -> None:
    """Every value is a stable code a caller can branch on."""
    for member in JobFailure:
        assert member.value.replace("_", "").isalnum()
        assert " " not in member.value


# --- the transition table ---------------------------------------------------


def test_every_state_has_a_row_so_a_lookup_never_guesses() -> None:
    assert set(PERMITTED_TRANSITIONS) == set(JobState)


def test_a_terminal_state_has_no_exit() -> None:
    """`cancelled -> completed` is unreachable rather than merely unused."""
    assert {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED} == TERMINAL_STATES
    for state in TERMINAL_STATES:
        assert PERMITTED_TRANSITIONS[state] == frozenset()


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (JobState.PENDING, JobState.RUNNING),
        (JobState.PENDING, JobState.CANCELLED),
        (JobState.RUNNING, JobState.COMPLETED),
        (JobState.RUNNING, JobState.FAILED),
        (JobState.RUNNING, JobState.RETRY_SCHEDULED),
        (JobState.RUNNING, JobState.CANCELLED),
        (JobState.RETRY_SCHEDULED, JobState.RUNNING),
        (JobState.RETRY_SCHEDULED, JobState.CANCELLED),
    ],
)
def test_a_permitted_transition_is_permitted(current: JobState, target: JobState) -> None:
    check_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        # A job that never ran cannot have a result.
        (JobState.PENDING, JobState.COMPLETED),
        (JobState.PENDING, JobState.FAILED),
        (JobState.PENDING, JobState.RETRY_SCHEDULED),
        # Nothing moves backwards.
        (JobState.RUNNING, JobState.PENDING),
        (JobState.RETRY_SCHEDULED, JobState.PENDING),
        # Terminal is terminal, in every direction.
        (JobState.CANCELLED, JobState.COMPLETED),
        (JobState.CANCELLED, JobState.RUNNING),
        (JobState.COMPLETED, JobState.RUNNING),
        (JobState.COMPLETED, JobState.FAILED),
        (JobState.FAILED, JobState.RETRY_SCHEDULED),
        (JobState.FAILED, JobState.COMPLETED),
    ],
)
def test_a_forbidden_transition_raises_rather_than_being_ignored(
    current: JobState, target: JobState
) -> None:
    """Refused loudly. A silently ignored move leaves a caller reading a state
    that never changed and no record of why."""
    with pytest.raises(JobTransitionError):
        check_transition(current, target)


def test_a_transition_needs_two_published_states() -> None:
    with pytest.raises(JobError):
        check_transition("pending", JobState.RUNNING)  # type: ignore[arg-type]


# --- identifiers ------------------------------------------------------------


def test_a_job_identifier_accepts_what_a_csprng_token_looks_like() -> None:
    assert JobId("P9x2Kq7YbN4mZr1Tf6HvJ0wLsD3gAeUc").value.startswith("P9x2")
    assert str(JobId("a" * MIN_JOB_ID_LENGTH)) == "a" * MIN_JOB_ID_LENGTH


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        "a" * (MIN_JOB_ID_LENGTH - 1),
        "a" * (MAX_JOB_ID_LENGTH + 1),
        "has spaces in it here!!",
        "user@example.test-padding-x",
        "slash/in/the/identifier/x",
        "dots.are.not.permitted.xx",
        "control\nchar-padding-here",
        "../../etc/passwd-padding-x",
    ],
)
def test_a_job_identifier_refuses_anything_that_could_change_a_path(value: str) -> None:
    """An identifier appears in a URL path, so every character outside the
    URL-safe set is one that could change what the path means. `@` is refused
    too, so an identifier can never be a mailbox by construction accident."""
    with pytest.raises(JobError):
        JobId(value)


def test_a_job_identifier_must_be_a_string() -> None:
    with pytest.raises(JobError):
        JobId(12345)  # type: ignore[arg-type]


# --- idempotency keys -------------------------------------------------------


def test_an_idempotency_key_accepts_an_ordinary_caller_handle() -> None:
    assert IdempotencyKey("order-4711-attempt-1").value == "order-4711-attempt-1"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        "x" * (MAX_IDEMPOTENCY_KEY_LENGTH + 1),
        "has a space",
        "carriage\rreturn",
        "line\nfeed",
        "null\0byte",
        "zero​width",
    ],
)
def test_an_idempotency_key_is_bounded_and_printable(value: str) -> None:
    """Caller-supplied, so it is screened like every other caller string here:
    it becomes a dictionary key and could reach a log line."""
    with pytest.raises(JobError):
        IdempotencyKey(value)
