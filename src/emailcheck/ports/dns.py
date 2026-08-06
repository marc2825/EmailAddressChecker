from __future__ import annotations

from typing import Protocol

from emailcheck.domain.address import NormalizedAddress


class DNSResult(Protocol):
    """Marker protocol replaced by a concrete immutable result in Phase 2."""


class DNSResolver(Protocol):
    async def resolve_mail_route(self, address: NormalizedAddress) -> DNSResult:
        """Return structured DNS evidence without opening an SMTP connection."""
        ...
