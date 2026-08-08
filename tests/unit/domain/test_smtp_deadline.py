"""The budget that bounds a whole probe, and what it refuses to be.

The same validation rules as `TransportTimeouts`, for the same reasons, plus
the one property that makes it different from a per-operation timeout: it is
recomputed from the clock rather than decremented, so a stage that overran
cannot leave the budget looking healthy.
"""

from __future__ import annotations

import math

import pytest

from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_deadline import (
    DEFAULT_SESSION_SECONDS,
    MAX_SESSION_SECONDS,
    SessionBudget,
    start_deadline,
)

# --- the budget is a validated value ---------------------------------------


def test_the_default_budget_is_within_the_maximum() -> None:
    assert 0 < DEFAULT_SESSION_SECONDS <= MAX_SESSION_SECONDS
    assert SessionBudget().total_seconds == DEFAULT_SESSION_SECONDS


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (0, "zero"),
        (-1.0, "negative"),
        (float("nan"), "not a number"),
        (float("inf"), "infinite"),
        (MAX_SESSION_SECONDS + 0.1, "beyond the maximum"),
        (3600.0, "an hour, which is a configuration mistake"),
    ],
)
def test_an_unusable_budget_is_refused(value: float, label: str) -> None:
    with pytest.raises(SMTPContractError):
        SessionBudget(total_seconds=value)


@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_budget_is_refused(value: bool) -> None:
    """`True` is `1` in Python, so this would silently mean a one-second probe."""
    with pytest.raises(SMTPContractError, match="not a boolean"):
        SessionBudget(total_seconds=value)


@pytest.mark.parametrize("value", ["30", None, [30], object()])
def test_a_budget_must_be_a_number(value: object) -> None:
    with pytest.raises(SMTPContractError):
        SessionBudget(total_seconds=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [0.001, 1, 15.5, MAX_SESSION_SECONDS])
def test_a_usable_budget_is_accepted(value: float) -> None:
    assert SessionBudget(total_seconds=value).total_seconds == value


# --- the deadline ----------------------------------------------------------


def test_the_remaining_time_counts_down_with_the_clock() -> None:
    deadline = start_deadline(SessionBudget(total_seconds=10.0), now=1000.0)
    assert deadline.remaining(1000.0) == 10.0
    assert deadline.remaining(1004.0) == 6.0
    assert deadline.remaining(1010.0) == 0.0


def test_the_remaining_time_never_goes_negative() -> None:
    """A caller comparing `remaining` to a timeout must not be handed a negative."""
    deadline = start_deadline(SessionBudget(total_seconds=5.0), now=1000.0)
    assert deadline.remaining(2000.0) == 0.0
    assert deadline.is_expired(2000.0) is True


def test_a_deadline_is_not_expired_before_its_budget() -> None:
    deadline = start_deadline(SessionBudget(total_seconds=5.0), now=1000.0)
    assert deadline.is_expired(1000.0) is False
    assert deadline.is_expired(1004.9) is False
    assert deadline.is_expired(1005.0) is True


def test_the_remaining_time_is_recomputed_rather_than_decremented() -> None:
    """A stage that overran cannot leave the budget looking healthy.

    The value is a function of the clock, so asking twice at the same instant
    gives the same answer and asking later gives less — there is no accumulator
    a missed update could leave stale.
    """
    deadline = start_deadline(SessionBudget(total_seconds=30.0), now=1000.0)
    assert deadline.remaining(1010.0) == deadline.remaining(1010.0)
    assert deadline.remaining(1020.0) < deadline.remaining(1010.0)


def test_elapsed_milliseconds_is_reported_for_the_observation() -> None:
    deadline = start_deadline(SessionBudget(total_seconds=30.0), now=1000.0)
    assert deadline.elapsed_milliseconds(1000.0) == 0
    assert deadline.elapsed_milliseconds(1001.25) == 1250
    # A clock that somehow reads backwards produces no negative duration.
    assert deadline.elapsed_milliseconds(999.0) == 0


def test_the_deadline_is_immutable() -> None:
    deadline = start_deadline(SessionBudget(), now=1000.0)
    with pytest.raises(AttributeError):
        deadline.started_at = 0.0  # type: ignore[misc]


def test_the_maximum_is_a_bound_somebody_would_reach() -> None:
    """A bound nobody would reach is not a bound. Two minutes is reachable."""
    assert MAX_SESSION_SECONDS <= 300.0
    assert not math.isinf(MAX_SESSION_SECONDS)
