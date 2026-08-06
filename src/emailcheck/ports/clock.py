"""Time as a port.

Cache expiry and evidence timestamps must be reproducible in a test, so nothing
outside an adapter reads the wall clock.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time as an aware UTC datetime."""
        ...
