from __future__ import annotations

from typing import Protocol

from emailcheck.domain.address import NormalizedAddress


class SMTPProbeResult(Protocol):
    """Marker protocol replaced by a concrete immutable result in Phase 4."""


class SMTPProber(Protocol):
    async def probe_recipient(self, address: NormalizedAddress) -> SMTPProbeResult:
        """Observe the recipient stage without transmitting message content."""
        ...
