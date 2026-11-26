"""Bounded passive orchestration using the ordinary verification service."""

from __future__ import annotations

import asyncio
import hmac
import secrets
from collections.abc import AsyncGenerator, Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

from emailcheck.adapters.dns.cached_resolver import dns_cache_used
from emailcheck.application.public_result import public_result
from emailcheck.application.verification import (
    AddressVerificationService,
    SubmittedInputTooLong,
    VerificationRefused,
)
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.batch import BatchLimits
from emailcheck.domain.principal import Principal

DEFAULT_LIMITS = BatchLimits()


@dataclass(frozen=True)
class InputRow:
    number: int
    address: str = field(repr=False)
    error: str | None = None


def _base_record(row: InputRow, include_address: bool) -> dict[str, object]:
    record: dict[str, object] = {
        "row": row.number,
        "state": "completed",
        "smtp_executed": False,
        "dns_cache_used": False,
        "verdict_cache_used": False,
    }
    if include_address:
        record["email"] = row.address
    return record


#: Why a check was refused, as a stable category for the row. The scope text of
#: `VerificationRefused` is this project's own wording and stays internal.
_DEADLINE_SCOPE: Final = "the verification deadline"
_ABUSE_SCOPE: Final = "an abuse control"


def _refusal_category(scope: str) -> str:
    if scope == _DEADLINE_SCOPE:
        return "deadline"
    if scope == _ABUSE_SCOPE:
        return "limit"
    return "capacity"


async def check_row(
    row: InputRow,
    *,
    service: AddressVerificationService,
    principal: Principal,
    include_address: bool = False,
    active: bool = False,
) -> dict[str, object]:
    """One row through the ordinary verification service.

    `active=True` is used only by the single-address `check --mode active`
    (ADR 0022). `passive_rows` never passes it, so a file can never be checked
    over SMTP. The service still decides whether a probe can happen at all: a
    deployment without an SMTP service, or a route with nowhere to connect,
    probes nothing.
    """
    record = _base_record(row, include_address)
    if row.error:
        return {**record, "state": "rejected", "error": row.error}
    token = dns_cache_used.set(False)
    try:
        outcome = await service.verify(row.address, principal=principal, active=active)
        record.update(public_result(outcome.verdict).as_json_object())
        record["dns_cache_used"] = dns_cache_used.get()
        record["smtp_executed"] = outcome.active
    except SubmittedInputTooLong:
        record.update(state="rejected", error="input_too_long")
    except VerificationRefused as refusal:
        record.update(
            state="refused",
            error="verification_refused",
            refusal=_refusal_category(refusal.scope),
        )
    except (AssertionError, MemoryError):
        raise
    except Exception:
        # Exception text can contain addresses, SQL, or remote prose.
        record.update(state="failed", error="processing_failed")
    finally:
        dns_cache_used.reset(token)
    return record


async def passive_rows(
    rows: Iterable[InputRow],
    *,
    service: AddressVerificationService,
    principal: Principal,
    limits: BatchLimits = DEFAULT_LIMITS,
    duplicates: str = "keep",
    start_row: int = 1,
    include_address: bool = False,
    progress: Callable[[int], None] | None = None,
) -> AsyncGenerator[dict[str, object]]:
    """Ordered windows bound tasks and buffering; cancellation joins every task.

    No job/store, SMTP switch, or second verifier exists here. Each check uses
    the same service/guard/admission/DNS cache as a single request. Dedup retains
    only process-keyed HMACs, at most max_rows, never plaintext addresses.
    """
    if duplicates not in {"keep", "skip"} or type(start_row) is not int or start_row < 1:
        raise ValueError("invalid duplicate policy or starting row")
    key = secrets.token_bytes(32)
    seen: dict[bytes, int] = {}
    pending: list[asyncio.Task[dict[str, object]]] = []
    completed = 0
    input_bytes = 0

    async def one(row: InputRow, duplicate_of: int | None) -> dict[str, object]:
        if duplicate_of is not None and duplicates == "skip":
            record = _base_record(row, include_address)
            return {**record, "state": "duplicate", "duplicate_of": duplicate_of}
        return await check_row(
            row, service=service, principal=principal, include_address=include_address
        )

    try:
        for count, row in enumerate(rows, 1):
            input_bytes += len(row.address.encode("utf-8"))
            if input_bytes > limits.max_input_bytes:
                raise ValueError("input exceeds the byte limit")
            if count > limits.max_rows:
                raise ValueError("input exceeds the row limit")
            duplicate_of = None
            if duplicates == "skip":
                parsed = parse_address(RawAddressInput(row.address))
                material = (
                    parsed.address.hmac_material
                    if isinstance(parsed, AddressAccepted)
                    else row.address
                )
                digest = hmac.digest(key, material.encode("utf-8"), "sha256")
                duplicate_of = seen.get(digest)
                seen.setdefault(digest, row.number)
            if row.number < start_row:
                continue
            pending.append(asyncio.create_task(one(row, duplicate_of)))
            if len(pending) == limits.max_in_flight:
                for task in pending:
                    result = await task
                    completed += 1
                    if progress:
                        progress(completed)
                    yield result
                pending.clear()
        for task in pending:
            result = await task
            completed += 1
            if progress:
                progress(completed)
            yield result
    finally:
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
