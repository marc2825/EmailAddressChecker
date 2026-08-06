from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol, TypeVar

T = TypeVar("T")


class Executor(Protocol):
    async def submit(self, job: Callable[[], Awaitable[T]]) -> str:
        """Submit a job and return an opaque job identifier."""
        ...
