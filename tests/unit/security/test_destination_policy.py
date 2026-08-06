"""The SSRF destination policy.

Every forbidden range is pinned by itself. The three cases at the bottom are the
reason the policy does not lean on `ipaddress` convenience properties.
"""

import ipaddress

import pytest

from emailcheck.security.destination import (
    METADATA_ADDRESSES,
    DestinationDenyReason,
    evaluate_destination,
    evaluate_destinations,
)

# --- addresses that may be connected to -----------------------------------


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.114.1", "199.7.83.42", "17.253.144.10"],
)
def test_public_ipv4_is_allowed(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is True
    assert decision.version == 4
    assert decision.deny_reason is None


@pytest.mark.parametrize(
    "address",
    ["2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001:82f::200e"],
)
def test_public_ipv6_is_allowed(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is True
    assert decision.version == 6
    assert decision.deny_reason is None


def test_an_allowed_decision_reports_the_normalized_address() -> None:
    assert evaluate_destination("2001:4860:4860:0000::8888").address == "2001:4860:4860::8888"
    assert evaluate_destination("  8.8.8.8  ").address == "8.8.8.8"


# --- forbidden IPv4 -------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        # The suppression below is deliberate: this case asserts the address
        # is refused as a destination, which is the opposite of binding to it.
        ("0.0.0.0", DestinationDenyReason.UNSPECIFIED),  # noqa: S104
        ("0.1.2.3", DestinationDenyReason.UNSPECIFIED),
        ("127.0.0.1", DestinationDenyReason.LOOPBACK),
        ("127.1.2.3", DestinationDenyReason.LOOPBACK),
        ("10.0.0.1", DestinationDenyReason.PRIVATE),
        ("172.16.5.4", DestinationDenyReason.PRIVATE),
        ("172.31.255.254", DestinationDenyReason.PRIVATE),
        ("192.168.1.1", DestinationDenyReason.PRIVATE),
        ("100.64.0.1", DestinationDenyReason.CARRIER_GRADE_NAT),
        ("100.127.255.255", DestinationDenyReason.CARRIER_GRADE_NAT),
        ("169.254.1.1", DestinationDenyReason.LINK_LOCAL),
        ("192.0.2.1", DestinationDenyReason.DOCUMENTATION),
        ("198.51.100.7", DestinationDenyReason.DOCUMENTATION),
        ("203.0.113.9", DestinationDenyReason.DOCUMENTATION),
        ("198.18.0.1", DestinationDenyReason.BENCHMARK),
        ("198.19.255.254", DestinationDenyReason.BENCHMARK),
        ("192.0.0.8", DestinationDenyReason.RESERVED),
        ("192.88.99.1", DestinationDenyReason.RESERVED),
        ("224.0.0.1", DestinationDenyReason.MULTICAST),
        ("239.255.255.250", DestinationDenyReason.MULTICAST),
        ("240.0.0.1", DestinationDenyReason.RESERVED),
        ("255.255.255.255", DestinationDenyReason.BROADCAST),
    ],
)
def test_forbidden_ipv4_ranges(address: str, reason: DestinationDenyReason) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.deny_reason is reason
    assert decision.version == 4


# --- forbidden IPv6 -------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("::", DestinationDenyReason.UNSPECIFIED),
        ("::1", DestinationDenyReason.LOOPBACK),
        ("fc00::1", DestinationDenyReason.UNIQUE_LOCAL),
        ("fd00::1", DestinationDenyReason.UNIQUE_LOCAL),
        ("fe80::1", DestinationDenyReason.LINK_LOCAL),
        ("febf::1", DestinationDenyReason.LINK_LOCAL),
        ("ff02::1", DestinationDenyReason.MULTICAST),
        ("ff00::1", DestinationDenyReason.MULTICAST),
        ("2001:db8::1", DestinationDenyReason.DOCUMENTATION),
        ("3fff::1", DestinationDenyReason.DOCUMENTATION),
        ("2001:2::1", DestinationDenyReason.BENCHMARK),
        ("100::1", DestinationDenyReason.RESERVED),
    ],
)
def test_forbidden_ipv6_ranges(address: str, reason: DestinationDenyReason) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.deny_reason is reason
    assert decision.version == 6


# --- the fe00::/9 neighbourhood, boundary by boundary ---------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        # Just below fe00::/9 is unique-local, already covered by fc00::/7.
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DestinationDenyReason.UNIQUE_LOCAL),
        # fe00::/9 itself, outside the two more specific blocks inside it.
        ("fe00::", DestinationDenyReason.RESERVED),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DestinationDenyReason.RESERVED),
        # Link-local.
        ("fe80::", DestinationDenyReason.LINK_LOCAL),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DestinationDenyReason.LINK_LOCAL),
        # The deprecated site-local range, which used to be allowed through.
        ("fec0::", DestinationDenyReason.DEPRECATED_SITE_LOCAL),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DestinationDenyReason.DEPRECATED_SITE_LOCAL),
        # Multicast starts immediately after.
        ("ff00::", DestinationDenyReason.MULTICAST),
    ],
)
def test_the_reserved_and_site_local_boundaries(
    address: str, reason: DestinationDenyReason
) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.deny_reason is reason


def test_the_more_specific_block_wins_inside_fe00() -> None:
    """A wider reserved rule must not absorb link-local or site-local."""
    assert evaluate_destination("fe80::1").deny_reason is DestinationDenyReason.LINK_LOCAL
    assert (
        evaluate_destination("fec0::1").deny_reason is DestinationDenyReason.DEPRECATED_SITE_LOCAL
    )


def test_ordinary_global_ipv6_is_not_caught_by_the_new_rules() -> None:
    for address in (
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "2a00:1450:4001:82f::200e",
        "2400:cb00::1",
        "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ):
        assert evaluate_destination(address).allowed is True, address


# --- addresses that carry an IPv4 address inside an IPv6 one --------------


@pytest.mark.parametrize(
    "address",
    ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.1.1"],
)
def test_ipv4_mapped_addresses_are_judged_by_what_they_reach(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.version == 6


def test_a_mapped_public_address_is_still_refused() -> None:
    """A mail host has no reason to publish a mapped address; refuse the form."""
    decision = evaluate_destination("::ffff:8.8.8.8")
    assert decision.allowed is False
    assert decision.deny_reason is DestinationDenyReason.IPV4_MAPPED


@pytest.mark.parametrize(
    "address", ["64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:c0a8:101::1"]
)
def test_translated_addresses_embedding_a_forbidden_ipv4_are_refused(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False


# --- metadata endpoints ---------------------------------------------------


@pytest.mark.parametrize("address", sorted(METADATA_ADDRESSES))
def test_known_metadata_endpoints_report_the_real_hazard(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.deny_reason is DestinationDenyReason.METADATA


# --- malformed input ------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["", "not-an-ip", "999.999.999.999", "192.0.2", "::gg", "1.2.3.4.5", "mx.example.com"],
)
def test_unparsable_addresses_are_denied_not_raised(address: str) -> None:
    decision = evaluate_destination(address)
    assert decision.allowed is False
    assert decision.deny_reason is DestinationDenyReason.MALFORMED
    assert decision.version is None


# --- batches --------------------------------------------------------------


def test_a_mixed_batch_keeps_order_and_judges_each_address() -> None:
    decisions = evaluate_destinations(("8.8.8.8", "127.0.0.1", "2606:4700:4700::1111", "10.0.0.1"))
    assert [d.allowed for d in decisions] == [True, False, True, False]
    assert [d.address for d in decisions][1] == "127.0.0.1"
    assert decisions[3].deny_reason is DestinationDenyReason.PRIVATE


# --- why the policy is explicit -------------------------------------------


def test_the_stdlib_shortcuts_that_would_have_been_unsafe() -> None:
    """Pin the reason `is_private` and `is_global` are not used as the filter.

    If a future CPython changes these, this test tells us the justification
    moved, and the policy above still stands on its own.
    """
    assert ipaddress.ip_address("100.64.0.1").is_private is False
    assert ipaddress.ip_address("ff02::1").is_global is True
    assert ipaddress.ip_address("64:ff9b::7f00:1").is_global is True

    for address in ("100.64.0.1", "ff02::1", "64:ff9b::7f00:1"):
        assert evaluate_destination(address).allowed is False, address
