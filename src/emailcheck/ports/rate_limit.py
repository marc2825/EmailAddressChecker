from __future__ import annotations

from types import TracebackType
from typing import Protocol


class RateLimitLease(Protocol):
    async def __aenter__(self) -> None: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...


class RateLimiter(Protocol):
    def acquire(self, *, account: str, domain: str, mx_host: str) -> RateLimitLease:
        """Acquire all required budgets before opening a socket."""
        ...
