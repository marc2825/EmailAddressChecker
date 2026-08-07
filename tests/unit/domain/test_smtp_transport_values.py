"""The bounds a transport must respect, and what they refuse.

Pure values, no socket. A timeout that is a boolean, infinite, or an hour long
is a configuration mistake, and `docs/requirements.md` section 9 requires every
operation to be bounded — a bound nobody would reach is not one.
"""

from __future__ import annotations

import math

import pytest

from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_transport import (
    MAX_TIMEOUT_SECONDS,
    LineRead,
    ReadFailed,
    TransportError,
    TransportFailure,
    TransportLimits,
    TransportTimeouts,
)

TIMEOUT_FIELDS = ("connect_seconds", "read_seconds", "write_seconds", "close_seconds")


# --- timeouts --------------------------------------------------------------


def test_the_defaults_are_all_bounded_and_positive() -> None:
    timeouts = TransportTimeouts()
    for field in TIMEOUT_FIELDS:
        value = getattr(timeouts, field)
        assert 0 < value <= MAX_TIMEOUT_SECONDS


@pytest.mark.parametrize("field", TIMEOUT_FIELDS)
@pytest.mark.parametrize(
    ("value", "label"),
    [
        (0, "zero"),
        (-1.0, "negative"),
        (float("nan"), "NaN"),
        (float("inf"), "infinity"),
        (float("-inf"), "negative infinity"),
        (MAX_TIMEOUT_SECONDS + 1, "beyond the maximum"),
        (86400.0, "a day"),
    ],
)
def test_an_unusable_timeout_is_refused(field: str, value: float, label: str) -> None:
    with pytest.raises(SMTPContractError):
        TransportTimeouts(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", TIMEOUT_FIELDS)
@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_timeout_is_refused(field: str, value: bool) -> None:
    """`True` is `1` in Python, so a boolean would silently mean one second."""
    with pytest.raises(SMTPContractError, match="not a boolean"):
        TransportTimeouts(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", TIMEOUT_FIELDS)
@pytest.mark.parametrize("value", ["3", None, [3], {"seconds": 3}])
def test_a_non_numeric_timeout_is_refused(field: str, value: object) -> None:
    with pytest.raises(SMTPContractError, match="number of seconds"):
        TransportTimeouts(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", TIMEOUT_FIELDS)
def test_an_ordinary_timeout_is_accepted(field: str) -> None:
    timeouts = TransportTimeouts(**{field: 2.5})  # type: ignore[arg-type]
    assert getattr(timeouts, field) == 2.5


def test_the_close_timeout_exists_so_a_close_cannot_hang() -> None:
    """A peer that accepts a FIN and never answers must not hold a worker."""
    assert "close_seconds" in TransportTimeouts.__dataclass_fields__
    assert not math.isinf(TransportTimeouts().close_seconds)


# --- limits ----------------------------------------------------------------


def test_the_default_limits_are_bounded() -> None:
    limits = TransportLimits()
    assert limits.max_line_bytes > 0
    assert limits.max_total_bytes >= limits.max_line_bytes


@pytest.mark.parametrize("field", ["max_line_bytes", "max_total_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, False, 2.5, "4096", None])
def test_an_unusable_limit_is_refused(field: str, value: object) -> None:
    with pytest.raises(SMTPContractError):
        TransportLimits(**{field: value})  # type: ignore[arg-type]


def test_a_total_smaller_than_one_line_is_refused() -> None:
    """It would make every connection fail on its first full line."""
    with pytest.raises(SMTPContractError, match="smaller than one line"):
        TransportLimits(max_line_bytes=4096, max_total_bytes=1024)


# --- failures --------------------------------------------------------------


def test_no_transport_failure_is_evidence_about_the_address() -> None:
    """A refused connection is a fact about the network, not about a mailbox."""
    for failure in TransportFailure:
        assert failure.is_about_the_target is False


def test_the_peer_rejections_are_the_ones_that_happen_before_any_write() -> None:
    peer_rejections = {failure for failure in TransportFailure if failure.is_peer_rejection}
    assert peer_rejections == {
        TransportFailure.PEER_DENIED_BY_POLICY,
        TransportFailure.PEER_ADDRESS_MISMATCH,
        TransportFailure.PEER_PORT_MISMATCH,
        TransportFailure.PEER_MALFORMED,
        TransportFailure.PEER_UNEXPECTED_FAMILY,
    }


def test_a_transport_error_carries_a_failure_and_no_library_text() -> None:
    error = TransportError(TransportFailure.READ_TIMEOUT)
    assert error.failure is TransportFailure.READ_TIMEOUT
    assert str(error) == "read_timeout"
    for noisy in ("Traceback", "errno", "OSError", "asyncio"):
        assert noisy not in str(error)


def test_every_failure_value_is_this_projects_vocabulary() -> None:
    """Stable, lower-case, and nothing an OS or a library chose."""
    for failure in TransportFailure:
        assert failure.value == failure.value.lower()
        assert " " not in failure.value


# --- read outcomes ---------------------------------------------------------


def test_a_read_outcome_is_a_line_or_a_named_failure() -> None:
    assert LineRead(line=b"220 mx.example.com").line == b"220 mx.example.com"
    assert ReadFailed(failure=TransportFailure.READ_TIMEOUT).failure is (
        TransportFailure.READ_TIMEOUT
    )
