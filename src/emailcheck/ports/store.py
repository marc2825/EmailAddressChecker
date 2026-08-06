from __future__ import annotations

from typing import Protocol


class Store(Protocol):
    async def save(self, record: object) -> None: ...

    async def get(self, record_id: str) -> object | None: ...
