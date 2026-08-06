from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawAddressInput:
    """Untrusted input at the application boundary.

    Phase 1 replaces this baseline container with parser result types. Raw input
    must never be sent directly to a DNS or SMTP adapter.
    """

    value: str


@dataclass(frozen=True, slots=True)
class NormalizedAddress:
    """A validated address safe to pass to later typed ports.

    Construction rules are implemented in Phase 1. The local part is retained
    exactly as validated; only the domain may have an ASCII canonical form.
    """

    local_part: str
    ascii_domain: str

    @property
    def smtp_target(self) -> str:
        return f"{self.local_part}@{self.ascii_domain}"
