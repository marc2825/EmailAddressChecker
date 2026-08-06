from __future__ import annotations

from datetime import timedelta
from typing import Protocol


class Cache(Protocol):
    async def get(self, key: str) -> object | None: ...

    async def set(self, key: str, value: object, ttl: timedelta) -> None: ...

    async def delete(self, key: str) -> None: ...
