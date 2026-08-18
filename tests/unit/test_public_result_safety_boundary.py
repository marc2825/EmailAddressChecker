"""`no_message_data_sent` cannot be laundered into `True` by any layer.

`docs/requirements.md` section 2 makes "no message content was sent" a promise
to the user rather than a field. For a result this build produced it is an
invariant; for a result that arrived over `--remote` it is a claim another
instance made, and the final system audit found four ways this project turned
somebody else's silence into its own promise:

- the field **absent** from a remote body became `True`;
- the string `"false"` became `True`, through `bool("false")`;
- a persisted job rebuilt the field as `True` on reload, because it was not
  stored at all;
- the CLI printed "No message content was sent." unconditionally.

Every one of those is asserted here as the behaviour that now holds, and the
`True` path is asserted alongside so an overcorrection that refuses the
legitimate safe result would fail too.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest
from tests.phase6_fixtures import OBSERVED_AT

from emailcheck.adapters.storage.sqlite_job_store import SQLiteJobStore
from emailcheck.application.jobs import _public, _stored
from emailcheck.application.public_result import (
    PublicCheck,
    PublicResult,
    public_result_from_json_object,
)
from emailcheck.apps.cli import _render
from emailcheck.domain.job import JobAdmission, JobError, JobId, JobState
from emailcheck.domain.verdict import ConfidenceLevel, Status
from emailcheck.ports.job_store import StoredJob

asyncio_test = pytest.mark.asyncio

NOW: Final = datetime(2026, 8, 17, tzinfo=UTC)
AFFIRMATIVE: Final = "No message content was sent."


def body(**overrides: object) -> dict[str, object]:
    """A well-formed published result body, before any field is broken."""
    payload: dict[str, object] = {
        "status": Status.UNKNOWN.value,
        "confidence": ConfidenceLevel.LOW.value,
        "primary_reason": None,
        "reasons": [],
        "risk_flags": [],
        "checks": {},
        "no_message_data_sent": True,
        "ruleset": "aggregation-1",
    }
    payload.update(overrides)
    return payload


def result(*, no_message_data_sent: bool) -> PublicResult:
    return PublicResult(
        status=Status.UNKNOWN.value,
        confidence=ConfidenceLevel.LOW.value,
        primary_reason=None,
        reasons=(),
        risk_flags=(),
        checks={"syntax": PublicCheck(result="ok")},
        no_message_data_sent=no_message_data_sent,
        ruleset="aggregation-1",
    )


# --- strict parsing at the remote boundary -----------------------------------


def test_a_well_formed_body_parses_both_values() -> None:
    """The positive control, both directions.

    An overcorrection that rejected every result, or that only ever produced
    `True`, would pass a suite that tested the failures alone.
    """
    assert public_result_from_json_object(body()).no_message_data_sent is True
    assert (
        public_result_from_json_object(body(no_message_data_sent=False)).no_message_data_sent
        is False
    )


def test_a_missing_safety_field_is_a_malformed_body_rather_than_a_promise() -> None:
    """The audit's first finding. Absence used to become `True`.

    `--remote` is the one path where this value is not this build's own
    invariant, so there is no honest way to infer it: a server that had sent
    message content and simply omitted the field was displayed as one that had
    not.
    """
    payload = body()
    del payload["no_message_data_sent"]

    with pytest.raises(ValueError, match="no_message_data_sent"):
        public_result_from_json_object(payload)


@pytest.mark.parametrize(
    "value",
    ["false", "true", "", 0, 1, [], {}, None, 0.0],
    ids=["'false'", "'true'", "empty string", "0", "1", "list", "dict", "null", "float"],
)
def test_only_a_real_boolean_is_accepted(value: object) -> None:
    """`"false"` is the one that mattered — every non-empty string is truthy, so
    `bool("false")` is `True`, and a loosely-typed remote encoder producing
    strings is the most likely shape in the wild. `0` and `1` are refused too:
    they reached the right answer by the wrong rule, and would have flipped the
    moment the encoder changed."""
    with pytest.raises(ValueError, match="no_message_data_sent"):
        public_result_from_json_object(body(no_message_data_sent=value))


def test_a_malformed_body_is_a_validation_failure_and_never_a_mailbox_verdict() -> None:
    """A remote server's broken JSON says nothing about an address.

    `ValueError` — the operational/protocol failure `--remote` already maps —
    rather than `Status.INVALID` or any other published status.
    """
    published = {member.value for member in Status}
    for payload in (body(status="not-a-status"), body(ruleset=None), "not an object", 7):
        with pytest.raises(ValueError) as refusal:
            public_result_from_json_object(payload)
        assert not any(status in str(refusal.value) for status in published)


def test_a_parse_failure_carries_no_remote_payload() -> None:
    """The message names the field, never what the remote host said."""
    secret = "550 5.7.1 alice@example.test rejected by policy"
    with pytest.raises(ValueError) as refusal:
        public_result_from_json_object(body(no_message_data_sent=secret))

    rendered = str(refusal.value)
    assert secret not in rendered
    assert "@" not in rendered


# --- persistence -------------------------------------------------------------


def stored_for(value: bool) -> StoredJob:
    """A completed stored job, through the real projection `JobService` uses."""
    from emailcheck.application.jobs import CheckJob

    job = CheckJob(
        id=JobId("safety-job-0001xxxxxxxx"),
        owner="acct-1",
        state=JobState.COMPLETED,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
        result=result(no_message_data_sent=value),
    )
    return _stored(job, target_digest=None, idempotency=None, admission=JobAdmission.NOT_REQUIRED)


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
@asyncio_test
async def test_the_safety_field_round_trips_through_a_fresh_store(
    tmp_path: Path, value: bool
) -> None:
    """The audit's third finding: the field was not persisted and a reload
    rebuilt it as `True` — the strongest promise this project makes,
    manufactured by a database read.

    A **second** `SQLiteJobStore` over the same file, so nothing in memory can
    be supplying the answer.
    """
    store = SQLiteJobStore(path=tmp_path / "jobs.db")
    store.initialize()
    await store.save(stored_for(value), expected_generation=0)

    reopened = SQLiteJobStore(path=tmp_path / "jobs.db")
    reopened.initialize()
    reloaded = await reopened.load("safety-job-0001xxxxxxxx")

    assert reloaded is not None
    assert reloaded.no_message_data_sent is value
    rebuilt = _public(reloaded)
    assert rebuilt is not None
    assert rebuilt.no_message_data_sent is value


def test_a_completed_row_must_carry_the_assertion_it_completed_with() -> None:
    """Paired with the result, both directions, so neither a completed row can
    lose it nor an unfinished row can carry a safety claim about work that has
    not run."""
    with pytest.raises(JobError, match="no_message_data_sent"):
        StoredJob(
            job_id="safety-job-0002xxxxxxxx",
            owner="acct-1",
            state=JobState.COMPLETED,
            admission=JobAdmission.NOT_REQUIRED,
            created_at=NOW,
            updated_at=NOW,
            status=Status.UNKNOWN.value,
            confidence=ConfidenceLevel.LOW.value,
            ruleset="aggregation-1",
        )
    with pytest.raises(JobError, match="no_message_data_sent"):
        StoredJob(
            job_id="safety-job-0003xxxxxxxx",
            owner="acct-1",
            state=JobState.PENDING,
            admission=JobAdmission.CLAIMED,
            created_at=NOW,
            updated_at=NOW,
            no_message_data_sent=True,
        )


def test_rebuilding_a_result_without_the_assertion_refuses_rather_than_assumes() -> None:
    """The branch that used to hardcode `True`. It now has nothing to fall back
    on, which is the point."""
    row = stored_for(True)
    without = StoredJob(
        job_id=row.job_id,
        owner=row.owner,
        state=row.state,
        admission=row.admission,
        created_at=row.created_at,
        updated_at=row.updated_at,
        status=row.status,
        confidence=row.confidence,
        ruleset=row.ruleset,
        no_message_data_sent=True,
    )
    # Constructed legally, then stripped the way a version-3 row would arrive.
    object.__setattr__(without, "no_message_data_sent", None)
    with pytest.raises(JobError, match="no_message_data_sent"):
        _public(without)


def test_a_store_written_by_the_previous_schema_is_refused_by_version(tmp_path: Path) -> None:
    """A version 3 file has no column for the assertion, and the value a reload
    would have to invent is exactly the one this column exists to stop being
    invented. Refused loudly rather than read with an assumed `True`."""
    import sqlite3

    from emailcheck.adapters.storage.sqlite_job_store import SCHEMA_VERSION, JobStoreSchemaError

    path = tmp_path / "jobs.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE job_schema_version (version INTEGER NOT NULL);"
            "INSERT INTO job_schema_version (version) VALUES (3);"
        )

    with pytest.raises(JobStoreSchemaError) as refusal:
        SQLiteJobStore(path=path).initialize()

    assert str(SCHEMA_VERSION) in str(refusal.value)


# --- rendering ---------------------------------------------------------------


def test_the_cli_prints_the_affirmative_statement_only_when_the_result_makes_it() -> None:
    """The audit's fourth finding: the line was an unconditional literal, so
    this build printed a promise over a result that contradicted it."""
    safe = _render(result(no_message_data_sent=True), verbose=False)
    unsafe = _render(result(no_message_data_sent=False), verbose=False)

    assert AFFIRMATIVE in safe
    assert AFFIRMATIVE not in unsafe, "the CLI claimed no message content was sent"
    # Something is still always printed, so the affirmative statement is never
    # merely missing and left to be assumed.
    assert "WARNING" in unsafe
    # And the estimate caveat is unconditional in both.
    assert "does not prove that a mailbox exists" in safe
    assert "does not prove that a mailbox exists" in unsafe


def test_the_negative_cli_line_names_no_host_reply_or_address() -> None:
    unsafe = _render(result(no_message_data_sent=False), verbose=True)

    assert "@" not in unsafe
    assert "550" not in unsafe


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_the_published_json_carries_the_exact_boolean(value: bool) -> None:
    """`false` stays JSON `false`, never the string `"false"` and never absent."""
    rendered = result(no_message_data_sent=value).as_json_object()

    assert rendered["no_message_data_sent"] is value
    assert json.loads(json.dumps(rendered))["no_message_data_sent"] is value


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_body_survives_a_full_publish_and_reparse_round_trip(value: bool) -> None:
    """The remote boundary in both directions: what this build publishes is what
    a strict parser on the other side accepts, unchanged."""
    published = result(no_message_data_sent=value).as_json_object()

    reparsed = public_result_from_json_object(json.loads(json.dumps(published)))

    assert reparsed.no_message_data_sent is value


def test_the_value_type_still_refuses_a_non_boolean() -> None:
    """The innermost barrier, unchanged by the parser above it."""
    for bad in ("false", 1, None, []):
        with pytest.raises(ValueError, match="no_message_data_sent"):
            PublicResult(
                status=Status.UNKNOWN.value,
                confidence=ConfidenceLevel.LOW.value,
                primary_reason=None,
                reasons=(),
                risk_flags=(),
                checks={},
                no_message_data_sent=bad,  # type: ignore[arg-type]
                ruleset="aggregation-1",
            )
