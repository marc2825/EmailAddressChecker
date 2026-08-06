"""Typed DNS values: host names from remote data, MX shapes, and TTL policy."""

import pytest

from emailcheck.domain.dns import (
    DEFAULT_TTL_SECONDS,
    NEGATIVE_TTL_CAP_SECONDS,
    POSITIVE_TTL_CAP_SECONDS,
    TTL,
    AddressLookup,
    CNAMEChain,
    DNSCacheKey,
    DNSContractError,
    DNSFailure,
    DNSRecordType,
    HostName,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)

# --- host names built from remote data ------------------------------------


@pytest.mark.parametrize(
    ("served", "expected"),
    [
        ("mx.example.com", "mx.example.com"),
        ("mx.example.com.", "mx.example.com"),
        ("MX.Example.COM.", "mx.example.com"),
        ("  mx.example.com.  ", "mx.example.com"),
        ("mx1.example.co.uk.", "mx1.example.co.uk"),
    ],
)
def test_exchange_names_are_normalized(served: str, expected: str) -> None:
    host = HostName.normalize(served)
    assert host is not None
    assert host.value == expected


@pytest.mark.parametrize(
    "served",
    ["", ".", "  ", "mx..example.com", "-mx.example.com", "mx_host.example.com", "mx example.com"],
)
def test_unusable_exchange_names_are_reported_not_raised(served: str) -> None:
    """Remote data that cannot be used is an observation, not a crash."""
    assert HostName.normalize(served) is None


def test_constructing_a_host_name_directly_still_validates() -> None:
    with pytest.raises(DNSContractError):
        HostName("not a host")


# --- MX record shapes -----------------------------------------------------


def test_standards_compliant_null_mx_is_recognized() -> None:
    record = MXRecord(preference=0, exchange=".")
    assert record.is_null_mx is True
    assert record.is_root_exchange is True


@pytest.mark.parametrize(
    ("preference", "exchange"),
    [(10, "."), (1, "."), (0, "mx.example.com"), (0, ""), (0, "..")],
)
def test_other_shapes_are_not_null_mx(preference: int, exchange: str) -> None:
    assert MXRecord(preference=preference, exchange=exchange).is_null_mx is False


# --- lookups --------------------------------------------------------------


def test_a_lookup_cannot_both_answer_and_fail() -> None:
    with pytest.raises(DNSContractError):
        MXLookup(records=(MXRecord(10, "mx.example.com"),), failure=DNSFailure.SERVFAIL)
    with pytest.raises(DNSContractError):
        AddressLookup(addresses=("192.0.2.1",), failure=DNSFailure.TIMEOUT)


@pytest.mark.parametrize(
    ("failure", "temporary", "absence"),
    [
        (DNSFailure.NXDOMAIN, False, True),
        (DNSFailure.NO_RECORDS, False, True),
        (DNSFailure.SERVFAIL, True, False),
        (DNSFailure.TIMEOUT, True, False),
        (DNSFailure.REFUSED, True, False),
        (DNSFailure.MALFORMED, False, False),
    ],
)
def test_failures_separate_temporary_from_authoritative_absence(
    failure: DNSFailure, temporary: bool, absence: bool
) -> None:
    assert failure.is_temporary is temporary
    assert failure.is_authoritative_absence is absence


def test_cname_chain_reports_its_length() -> None:
    chain = CNAMEChain(names=(HostName("a.example.com"), HostName("b.example.com")))
    assert chain.length == 2
    assert chain.truncated is False


# --- TTL policy -----------------------------------------------------------


def test_positive_ttl_is_capped_at_twenty_four_hours() -> None:
    ttl = apply_ttl_policy(60 * 60 * 48, positive=True)
    assert ttl.applied_seconds == POSITIVE_TTL_CAP_SECONDS
    assert ttl.authoritative_seconds == 60 * 60 * 48
    assert ttl.was_capped is True


def test_negative_ttl_is_capped_at_three_hours() -> None:
    ttl = apply_ttl_policy(60 * 60 * 24, positive=False)
    assert ttl.applied_seconds == NEGATIVE_TTL_CAP_SECONDS
    assert ttl.was_capped is True


def test_a_ttl_below_the_cap_is_honored_exactly() -> None:
    ttl = apply_ttl_policy(300, positive=True)
    assert ttl.applied_seconds == 300
    assert ttl.was_capped is False


def test_zero_ttl_means_do_not_cache() -> None:
    ttl = apply_ttl_policy(0, positive=True)
    assert ttl.applied_seconds == 0
    assert ttl.was_supplied is True


@pytest.mark.parametrize("served", [None, -1, -3600])
def test_missing_or_nonsensical_ttl_falls_back_to_a_short_default(served: int | None) -> None:
    """A broken answer is re-checked soon rather than pinned for hours."""
    ttl = apply_ttl_policy(served, positive=True)
    assert ttl.applied_seconds == DEFAULT_TTL_SECONDS
    assert ttl.applied_seconds < POSITIVE_TTL_CAP_SECONDS


def test_the_caps_match_the_documented_defaults() -> None:
    assert POSITIVE_TTL_CAP_SECONDS == 24 * 60 * 60
    assert NEGATIVE_TTL_CAP_SECONDS == 3 * 60 * 60


def test_an_extremely_large_ttl_is_capped_not_overflowed() -> None:
    ttl = apply_ttl_policy(2**63, positive=True)
    assert ttl.applied_seconds == POSITIVE_TTL_CAP_SECONDS
    assert ttl.was_capped is True


@pytest.mark.parametrize("served", [True, False, 3.5, "300", None, -1])
def test_a_wrongly_typed_ttl_is_normalized_rather_than_stored(served: object) -> None:
    """The value type never holds a bool, float, string, or negative number."""
    ttl = apply_ttl_policy(served, positive=True)
    assert ttl.authoritative_seconds is None
    assert ttl.was_supplied is False
    assert ttl.applied_seconds == DEFAULT_TTL_SECONDS


# --- TTL invariants -------------------------------------------------------


@pytest.mark.parametrize(
    ("authoritative", "applied", "positive"),
    [
        (100, 999_999, True),
        (300, -5, True),
        (None, -1, True),
        (-1, 60, True),
        (None, 60 * 60 * 25, True),
        (None, 60 * 60 * 4, False),
        (60 * 60 * 25, 60 * 60 * 25, True),
    ],
)
def test_an_inconsistent_ttl_cannot_be_constructed(
    authoritative: int | None, applied: int, positive: bool
) -> None:
    with pytest.raises(DNSContractError):
        TTL(authoritative_seconds=authoritative, applied_seconds=applied, positive=positive)


@pytest.mark.parametrize("value", [True, False, 3.5, "300"])
def test_a_ttl_rejects_values_that_are_not_whole_seconds(value: object) -> None:
    with pytest.raises(DNSContractError):
        TTL(authoritative_seconds=None, applied_seconds=value, positive=True)  # type: ignore[arg-type]
    with pytest.raises(DNSContractError):
        TTL(authoritative_seconds=value, applied_seconds=60, positive=True)  # type: ignore[arg-type]


def test_a_capped_ttl_keeps_the_served_value_for_reference() -> None:
    ttl = apply_ttl_policy(60 * 60 * 48, positive=True)
    assert ttl.authoritative_seconds == 60 * 60 * 48
    assert ttl.applied_seconds == POSITIVE_TTL_CAP_SECONDS
    assert ttl.was_supplied is True
    assert ttl.was_capped is True


# --- a lookup answers or fails, never neither -----------------------------


def test_a_lookup_must_report_something() -> None:
    with pytest.raises(DNSContractError, match="either records or a failure"):
        MXLookup()
    with pytest.raises(DNSContractError, match="either addresses or a failure"):
        AddressLookup()


# --- cache keys -----------------------------------------------------------


def test_a_cache_key_is_a_host_and_a_record_type() -> None:
    key = DNSCacheKey(HostName("example.com"), DNSRecordType.MX)
    assert key.host.value == "example.com"
    assert key.record_type is DNSRecordType.MX


def test_cache_keys_compare_by_value_and_separate_record_types() -> None:
    host = HostName("example.com")
    assert DNSCacheKey(host, DNSRecordType.MX) == DNSCacheKey(
        HostName("example.com"), DNSRecordType.MX
    )
    assert DNSCacheKey(host, DNSRecordType.MX) != DNSCacheKey(host, DNSRecordType.A)
    assert len({DNSCacheKey(host, t) for t in DNSRecordType}) == 3
