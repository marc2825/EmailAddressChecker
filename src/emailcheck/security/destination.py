"""Whether a resolved address may ever be connected to.

This is the SSRF control from `docs/threat-model.md`. It is a pure function, so
the same policy runs twice in Phase 4: once on the candidates DNS returned, and
again on the address a socket actually connected to.

The forbidden ranges are listed explicitly rather than expressed through the
`ipaddress` convenience properties. Measured on CPython 3.12:

    ipaddress.ip_address("100.64.0.1").is_private   -> False   # carrier-grade NAT
    ipaddress.ip_address("ff02::1").is_global       -> True    # IPv6 multicast
    ipaddress.ip_address("64:ff9b::7f00:1").is_global -> True  # NAT64 of 127.0.0.1

A filter built on those properties would allow multicast and a translated
loopback address. Each range below is therefore named, ordered, and tested by
itself.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

IPv4Network = ipaddress.IPv4Network
IPv6Network = ipaddress.IPv6Network


class DestinationDenyReason(StrEnum):
    """Why an address may not be a destination.

    One member per class of range, so an operator can tell a private network
    from a metadata endpoint without reading free text.
    """

    MALFORMED = "malformed"
    UNSPECIFIED = "unspecified"
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    RESERVED = "reserved"
    DOCUMENTATION = "documentation"
    BENCHMARK = "benchmark"
    CARRIER_GRADE_NAT = "carrier_grade_nat"
    METADATA = "metadata"
    IPV4_MAPPED = "ipv4_mapped"
    TRANSLATED = "translated"
    UNIQUE_LOCAL = "unique_local"
    DEPRECATED_SITE_LOCAL = "deprecated_site_local"


#: Well-known cloud instance metadata endpoints. Listed before the generic
#: link-local rule so the report names the real hazard.
METADATA_ADDRESSES: Final = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",
    }
)

_IPV4_RULES: Final[tuple[tuple[IPv4Network, DestinationDenyReason], ...]] = (
    (IPv4Network("0.0.0.0/8"), DestinationDenyReason.UNSPECIFIED),
    (IPv4Network("127.0.0.0/8"), DestinationDenyReason.LOOPBACK),
    (IPv4Network("10.0.0.0/8"), DestinationDenyReason.PRIVATE),
    (IPv4Network("172.16.0.0/12"), DestinationDenyReason.PRIVATE),
    (IPv4Network("192.168.0.0/16"), DestinationDenyReason.PRIVATE),
    (IPv4Network("100.64.0.0/10"), DestinationDenyReason.CARRIER_GRADE_NAT),
    (IPv4Network("169.254.0.0/16"), DestinationDenyReason.LINK_LOCAL),
    (IPv4Network("192.0.0.0/24"), DestinationDenyReason.RESERVED),
    (IPv4Network("192.0.2.0/24"), DestinationDenyReason.DOCUMENTATION),
    (IPv4Network("198.51.100.0/24"), DestinationDenyReason.DOCUMENTATION),
    (IPv4Network("203.0.113.0/24"), DestinationDenyReason.DOCUMENTATION),
    (IPv4Network("198.18.0.0/15"), DestinationDenyReason.BENCHMARK),
    (IPv4Network("192.88.99.0/24"), DestinationDenyReason.RESERVED),
    (IPv4Network("224.0.0.0/4"), DestinationDenyReason.MULTICAST),
    # Ordered before 240.0.0.0/4, which contains it, so the report names the
    # broadcast address rather than the wider reserved block.
    (IPv4Network("255.255.255.255/32"), DestinationDenyReason.BROADCAST),
    (IPv4Network("240.0.0.0/4"), DestinationDenyReason.RESERVED),
)

_IPV6_RULES: Final[tuple[tuple[IPv6Network, DestinationDenyReason], ...]] = (
    (IPv6Network("::/128"), DestinationDenyReason.UNSPECIFIED),
    (IPv6Network("::1/128"), DestinationDenyReason.LOOPBACK),
    (IPv6Network("fc00::/7"), DestinationDenyReason.UNIQUE_LOCAL),
    # The three rules below all sit inside fe00::/9 and must precede it, so the
    # report names link-local or the deprecated site-local range rather than
    # the wider reserved block they share.
    (IPv6Network("fe80::/10"), DestinationDenyReason.LINK_LOCAL),
    (IPv6Network("fec0::/10"), DestinationDenyReason.DEPRECATED_SITE_LOCAL),
    (IPv6Network("fe00::/9"), DestinationDenyReason.RESERVED),
    (IPv6Network("ff00::/8"), DestinationDenyReason.MULTICAST),
    (IPv6Network("2001:db8::/32"), DestinationDenyReason.DOCUMENTATION),
    (IPv6Network("3fff::/20"), DestinationDenyReason.DOCUMENTATION),
    (IPv6Network("2001:2::/48"), DestinationDenyReason.BENCHMARK),
    (IPv6Network("100::/64"), DestinationDenyReason.RESERVED),
    (IPv6Network("2001::/32"), DestinationDenyReason.RESERVED),
    (IPv6Network("5f00::/16"), DestinationDenyReason.RESERVED),
)

#: Prefixes that carry an IPv4 address inside an IPv6 one. The embedded address
#: is re-evaluated with the IPv4 rules, so a translated loopback is not allowed
#: through by a prefix that looks globally routable.
_IPV6_EMBEDDING_PREFIXES: Final[tuple[tuple[IPv6Network, DestinationDenyReason], ...]] = (
    (IPv6Network("::ffff:0:0/96"), DestinationDenyReason.IPV4_MAPPED),
    (IPv6Network("64:ff9b::/96"), DestinationDenyReason.TRANSLATED),
    (IPv6Network("64:ff9b:1::/48"), DestinationDenyReason.TRANSLATED),
    (IPv6Network("2002::/16"), DestinationDenyReason.TRANSLATED),
)


@dataclass(frozen=True, slots=True)
class DestinationDecision:
    """Whether one address may be connected to, and why not when it may not."""

    allowed: bool
    address: str
    version: int | None
    deny_reason: DestinationDenyReason | None

    def __post_init__(self) -> None:
        if self.allowed and self.deny_reason is not None:
            raise ValueError("an allowed destination cannot carry a deny reason")
        if not self.allowed and self.deny_reason is None:
            raise ValueError("a denied destination must name a reason")


def _denied(
    address: str, version: int | None, reason: DestinationDenyReason
) -> DestinationDecision:
    return DestinationDecision(allowed=False, address=address, version=version, deny_reason=reason)


def _embedded_ipv4(parsed: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address carried inside an IPv6 address, when there is one."""
    if parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    if parsed.sixtofour is not None:
        return parsed.sixtofour
    for network, _reason in _IPV6_EMBEDDING_PREFIXES:
        if parsed in network:
            return ipaddress.IPv4Address(int(parsed) & 0xFFFFFFFF)
    return None


def evaluate_destination(address: str) -> DestinationDecision:
    """Decide whether `address` is a permitted destination.

    Unparsable text is denied rather than raised on: an address arrives from a
    remote resolver, so bad data is an observation.
    """
    text = address.strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return _denied(text, None, DestinationDenyReason.MALFORMED)

    normalized = str(parsed)
    if normalized in METADATA_ADDRESSES or text in METADATA_ADDRESSES:
        return _denied(normalized, parsed.version, DestinationDenyReason.METADATA)

    if isinstance(parsed, ipaddress.IPv4Address):
        for v4_network, v4_reason in _IPV4_RULES:
            if parsed in v4_network:
                return _denied(normalized, 4, v4_reason)
        return DestinationDecision(allowed=True, address=normalized, version=4, deny_reason=None)

    embedded = _embedded_ipv4(parsed)
    if embedded is not None:
        inner = evaluate_destination(str(embedded))
        if not inner.allowed:
            # Report the outer form, but keep the reason from the address that
            # would actually be reached.
            return _denied(normalized, 6, inner.deny_reason or DestinationDenyReason.RESERVED)
        for embedding_network, embedding_reason in _IPV6_EMBEDDING_PREFIXES:
            if parsed in embedding_network:
                return _denied(normalized, 6, embedding_reason)

    for v6_network, v6_reason in _IPV6_RULES:
        if parsed in v6_network:
            return _denied(normalized, 6, v6_reason)
    return DestinationDecision(allowed=True, address=normalized, version=6, deny_reason=None)


def evaluate_destinations(addresses: tuple[str, ...]) -> tuple[DestinationDecision, ...]:
    """Evaluate every candidate, keeping the resolver's order."""
    return tuple(evaluate_destination(address) for address in addresses)
