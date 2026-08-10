"""The authenticator, the operator sink, and the store.

Three adapters, three properties that are easy to get wrong quietly: a
credential compared in variable time, an event carrying an address, and a cache
answering with a row the current rules did not produce.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from emailcheck.adapters.auth.api_keys import (
    ApiKeyConfigurationError,
    StaticApiKeyAuthenticator,
    build_authenticator,
    verifier_for,
)
from emailcheck.adapters.observability.logging_sink import LoggingOperatorSink
from emailcheck.adapters.storage.sqlite_store import (
    SCHEMA_VERSION,
    SQLiteVerdictStore,
    StoreSchemaError,
)
from emailcheck.domain.principal import Principal
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Status
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind
from emailcheck.ports.verdict_store import StoredVerdict
from emailcheck.security.identifiers import CorrelationKeyError, correlation_digest

KEY = "k" * 40
OTHER_KEY = "j" * 40
CORRELATION_KEY = b"c" * 32


# --- authentication ---------------------------------------------------------


def test_a_known_key_authenticates_to_its_account() -> None:
    authenticator = build_authenticator({"acct-1": KEY})
    principal = authenticator.authenticate(KEY)
    assert principal == Principal(account_id="acct-1")


@pytest.mark.parametrize(
    "credential",
    [None, "", "wrong", OTHER_KEY, "k" * 39],
    ids=["none", "empty", "short", "other", "near"],
)
def test_anything_else_authenticates_to_nobody(credential: str | None) -> None:
    """There is no anonymous principal and no default account.

    `docs/requirements.md` section 5 excludes anonymous active checks and
    section 15 keys budgets by account; a fallback identity would satisfy both
    types and defeat both rules.
    """
    authenticator = build_authenticator({"acct-1": KEY})
    assert authenticator.authenticate(credential) is None


def test_the_plaintext_key_is_not_retained() -> None:
    """A dump of the configuration must not let anyone authenticate."""
    authenticator = build_authenticator({"acct-1": KEY})
    rendered = repr(authenticator)
    assert KEY not in rendered
    assert verifier_for(KEY) in rendered


def test_an_empty_configuration_authenticates_nobody_rather_than_everybody() -> None:
    authenticator = build_authenticator({})
    assert authenticator.authenticate(KEY) is None


def test_a_short_key_is_refused_at_configuration_rather_than_hidden_by_a_hash() -> None:
    with pytest.raises(ApiKeyConfigurationError, match="at least"):
        build_authenticator({"acct-1": "short"})


def test_two_accounts_may_not_share_one_key() -> None:
    with pytest.raises(ApiKeyConfigurationError, match="share"):
        build_authenticator({"acct-1": KEY, "acct-2": KEY})


def test_an_account_identifier_that_is_an_address_fails_at_load() -> None:
    """`Principal` validates, so a bad configuration fails at start."""
    with pytest.raises(ValueError):
        build_authenticator({"user@example.test": KEY})


def test_the_authenticator_reads_no_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configuration comes from the caller, on the sender-identity precedent."""
    monkeypatch.setenv("EMAILCHECK_API_KEYS", f"acct-9:{KEY}")
    authenticator = StaticApiKeyAuthenticator(verifiers={})
    assert authenticator.authenticate(KEY) is None


# --- observability ----------------------------------------------------------


def test_an_operator_event_refuses_an_address_in_any_field() -> None:
    """The same shape check `rate_limit_key` makes, for the same reason."""
    for field in ("domain", "detail"):
        with pytest.raises(ValueError, match="may not carry an address"):
            OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, **{field: "user@example.test"})


def test_an_operator_event_is_bounded() -> None:
    with pytest.raises(ValueError, match="too long"):
        OperatorEvent(kind=OperatorEventKind.INTERNAL_ERROR, detail="x" * 500)


def test_the_logging_sink_writes_published_vocabulary_and_no_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`docs/requirements.md` section 16: no full address in an ordinary log."""
    sink = LoggingOperatorSink()
    with caplog.at_level("WARNING"):
        sink.record(
            OperatorEvent(
                kind=OperatorEventKind.INTERNAL_ERROR,
                reason=ReasonCode.INTERNAL_ERROR,
                domain="example.test",
            )
        )

    rendered = caplog.text
    assert "@" not in rendered
    assert "emailcheck.operator" in rendered


def test_a_broken_logging_handler_does_not_become_a_request_failure() -> None:
    """`record` is called from a failure path; it must not raise a second one."""

    class Exploding:
        def warning(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("the handler failed")

    sink = LoggingOperatorSink(logger=Exploding())  # type: ignore[arg-type]
    sink.record(OperatorEvent(kind=OperatorEventKind.ADMISSION_REFUSED))


# --- correlation ------------------------------------------------------------


def test_a_correlation_digest_is_stable_and_keyed() -> None:
    first = correlation_digest(CORRELATION_KEY, "user@example.test")
    assert first == correlation_digest(CORRELATION_KEY, "user@example.test")
    assert first != correlation_digest(b"d" * 32, "user@example.test")
    assert "user" not in first
    assert "@" not in first


def test_a_short_correlation_key_is_refused() -> None:
    """A key shorter than the digest adds nothing and hides that it does not."""
    with pytest.raises(CorrelationKeyError, match="at least"):
        correlation_digest(b"short", "user@example.test")


# --- persistence ------------------------------------------------------------


WRITTEN_AT = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
SENDER = "probe.example.test|verify@probe.example.test"


def stored(
    ruleset: str = "aggregation-2026-08-09",
    record_id: str = "rec-1",
    *,
    account: str = "acct-1",
    sender: str = SENDER,
    lifetime_seconds: int = 3600,
) -> StoredVerdict:
    return StoredVerdict(
        record_id=record_id,
        account_digest=correlation_digest(CORRELATION_KEY, account),
        target_digest=correlation_digest(CORRELATION_KEY, "user@example.test"),
        sender_identity_digest=correlation_digest(CORRELATION_KEY, sender),
        status=Status.LIKELY_DELIVERABLE,
        confidence="medium",
        primary_reason="rcpt_accepted",
        reasons=("rcpt_accepted", "mx_available"),
        risk_flags=(),
        checks=(("dns", "mx_available"), ("smtp", "rcpt_accepted")),
        aggregation_ruleset=ruleset,
        created_at=WRITTEN_AT,
        expires_at=WRITTEN_AT + timedelta(seconds=lifetime_seconds),
    )


def lookup(record: StoredVerdict, **overrides: object) -> dict[str, object]:
    """The whole key, so a test that changes one component changes only that."""
    key: dict[str, object] = {
        "account_digest": record.account_digest,
        "target_digest": record.target_digest,
        "sender_identity_digest": record.sender_identity_digest,
        "aggregation_ruleset": record.aggregation_ruleset,
        "now": WRITTEN_AT,
    }
    key.update(overrides)
    return key


@pytest.mark.asyncio
async def test_a_saved_verdict_is_found_under_the_ruleset_that_produced_it(
    tmp_path: Path,
) -> None:
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    record = stored()
    await store.save(record)

    found = await store.find(**lookup(record))  # type: ignore[arg-type]
    assert found is not None
    assert found.status is Status.LIKELY_DELIVERABLE
    assert found.reasons == ("rcpt_accepted", "mx_available")
    assert found.checks == (("dns", "mx_available"), ("smtp", "rcpt_accepted"))
    assert found.created_at.utcoffset() is not None
    assert found.expires_at.utcoffset() is not None


@pytest.mark.asyncio
async def test_a_verdict_from_a_different_ruleset_is_invisible(tmp_path: Path) -> None:
    """Phase 5 stop condition 4, as a lookup rather than as a comparison.

    A row written by rules that no longer exist is not stale data to be checked
    afterwards — it is a result nothing produced, and the `WHERE` clause is what
    makes it unreachable rather than merely unused.
    """
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    record = stored(ruleset="aggregation-1999-01-01")
    await store.save(record)

    assert (
        await store.find(**lookup(record, aggregation_ruleset="aggregation-2026-08-09"))  # type: ignore[arg-type]
        is None
    )


@pytest.mark.asyncio
async def test_one_account_never_sees_another_accounts_result(tmp_path: Path) -> None:
    """`prompts/06-api-cli.md`: cross-account result access is forbidden."""
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    record = stored()
    await store.save(record)

    assert (
        await store.find(
            **lookup(record, account_digest=correlation_digest(CORRELATION_KEY, "acct-2"))  # type: ignore[arg-type]
        )
        is None
    )


def test_a_database_from_a_different_schema_version_is_refused(tmp_path: Path) -> None:
    """Explicit rather than inferred: a different shape fails at start."""
    path = tmp_path / "verdicts.sqlite3"
    store = SQLiteVerdictStore(path=path)
    store.initialize()

    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))

    with pytest.raises(StoreSchemaError, match="schema version"):
        SQLiteVerdictStore(path=path).initialize()


def test_initializing_twice_is_safe(tmp_path: Path) -> None:
    path = tmp_path / "verdicts.sqlite3"
    SQLiteVerdictStore(path=path).initialize()
    SQLiteVerdictStore(path=path).initialize()


def bare_record(**overrides: object) -> StoredVerdict:
    """The minimum legal record, with one field replaced per test."""
    fields: dict[str, object] = {
        "record_id": "rec-1",
        "account_digest": "a",
        "target_digest": "b",
        "sender_identity_digest": "c",
        "status": Status.UNKNOWN,
        "confidence": "low",
        "primary_reason": None,
        "reasons": (),
        "risk_flags": (),
        "checks": (),
        "aggregation_ruleset": "r",
        "created_at": datetime(2026, 8, 10, tzinfo=UTC),
        "expires_at": datetime(2026, 8, 10, 1, tzinfo=UTC),
    }
    fields.update(overrides)
    return StoredVerdict(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field_name", ["record_id", "account_digest", "target_digest", "sender_identity_digest"]
)
def test_a_stored_verdict_refuses_an_address_in_a_digest_field(field_name: str) -> None:
    """Every digest field, not only the first: each is a place an address could
    be put by a caller that meant well."""
    with pytest.raises(ValueError, match="may not carry an address"):
        bare_record(**{field_name: "user@example.test"})


@pytest.mark.parametrize("field_name", ["created_at", "expires_at"])
def test_a_stored_verdict_refuses_a_naive_timestamp(field_name: str) -> None:
    """`AGENTS.md`: UTC internally, serialized with an explicit offset."""
    with pytest.raises(ValueError, match="timezone-aware"):
        bare_record(**{field_name: datetime(2026, 8, 10)})


def test_a_stored_verdict_refuses_an_expiry_that_has_already_passed() -> None:
    """A row that is dead when written costs a write and can never be read."""
    with pytest.raises(ValueError, match="expire after"):
        bare_record(expires_at=datetime(2026, 8, 9, tzinfo=UTC))


@pytest.mark.asyncio
async def test_a_verdict_obtained_through_another_sender_is_invisible(tmp_path: Path) -> None:
    """`docs/requirements.md` section 13 puts the sender identity in the key.

    A verdict obtained from one envelope sender is not evidence about another:
    reputation, SPF alignment, and policy responses are all properties of the
    sender that asked. The predicate is what makes the row unreachable rather
    than merely mismatched, and a mutation that removes it fails here.
    """
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    record = stored(sender="probe.example.test|verify@probe.example.test")
    await store.save(record)

    other = correlation_digest(CORRELATION_KEY, "other.example.test|verify@other.example.test")
    assert await store.find(**lookup(record, sender_identity_digest=other)) is None  # type: ignore[arg-type]
    assert await store.find(**lookup(record)) is not None  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_an_expired_row_is_unreachable_rather_than_merely_stale(tmp_path: Path) -> None:
    """ADR 0015: expiry is a `WHERE` predicate, for the reason the ruleset is.

    A row filtered after selection is a row an implementation can still answer
    with. Asserted at three points around the boundary, so "expired" means the
    moment the row says and not a rounding of it.
    """
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    record = stored(lifetime_seconds=3600)
    await store.save(record)

    just_before = record.expires_at - timedelta(seconds=1)
    after = record.expires_at + timedelta(seconds=1)

    assert await store.find(**lookup(record, now=just_before)) is not None  # type: ignore[arg-type]
    assert await store.find(**lookup(record, now=record.expires_at)) is None  # type: ignore[arg-type]
    assert await store.find(**lookup(record, now=after)) is None  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_expired_rows_can_be_purged(tmp_path: Path) -> None:
    """A cache that only grows is a retention policy nobody wrote."""
    store = SQLiteVerdictStore(path=tmp_path / "verdicts.sqlite3")
    store.initialize()
    await store.save(stored(record_id="live", lifetime_seconds=7200))
    await store.save(stored(record_id="dead", lifetime_seconds=60))

    removed = await store.purge_expired(now=WRITTEN_AT + timedelta(seconds=600))

    assert removed == 1
    assert await store.find(**lookup(stored(record_id="live"))) is not None  # type: ignore[arg-type]


def test_the_schema_version_moved_with_the_shape() -> None:
    """A version-1 database is refused rather than misread: it has no sender
    identity column and no expiry, so every lookup against it would be wrong."""
    from emailcheck.adapters.storage.sqlite_store import SCHEMA_VERSION

    assert SCHEMA_VERSION == 2
