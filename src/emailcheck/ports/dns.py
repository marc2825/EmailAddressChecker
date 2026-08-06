"""The resolver interface the application owns.

Queries are low level on purpose: the mail-route algorithm is application
policy, so an adapter cannot answer a different question or apply a different
rule. Every method takes a validated value, never raw text, and returns a typed
result. A resolver library's exception must be converted by the adapter and
never reaches a caller.
"""

from __future__ import annotations

from typing import Protocol

from emailcheck.domain.dns import AddressLookup, HostName, MXLookup


class DNSResolver(Protocol):
    async def query_mx(self, domain: HostName) -> MXLookup:
        """Return MX evidence for a domain. Never opens an SMTP connection."""
        ...

    async def query_a(self, host: HostName) -> AddressLookup:
        """Return IPv4 answers for a host, unjudged."""
        ...

    async def query_aaaa(self, host: HostName) -> AddressLookup:
        """Return IPv6 answers for a host, unjudged."""
        ...
