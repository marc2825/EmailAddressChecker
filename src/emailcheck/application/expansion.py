"""Bounded, offline local-part expansion. No network or verification dependencies."""

from __future__ import annotations

import hashlib
import itertools
import math
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from emailcheck.domain.address import AddressRejected, RawAddressInput, parse_address
from emailcheck.domain.batch import MAX_ROWS

MAX_PATTERN_LENGTH = 254
MAX_TOKEN_LENGTH = 64
MAX_POOL_SIZE = 10_000
MAX_POOL_BYTES = 1024 * 1024


class ExpansionError(ValueError):
    """A fixed, privacy-safe input refusal."""


def candidate_pool(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate in first-seen order; empty strings are explicit substitutions."""
    unique: dict[str, None] = {}
    size = 0
    for number, value in enumerate(values, 1):
        if number > MAX_POOL_SIZE:
            raise ExpansionError("too many substitution entries")
        if len(value) > MAX_TOKEN_LENGTH or not all(c.isprintable() for c in value):
            raise ExpansionError("a substitution exceeds 64 characters or contains controls")
        if any(c in value for c in "@\\"):
            raise ExpansionError("substitutions cannot contain @ or backslash")
        size += len(value.encode("utf-8"))
        if size > MAX_POOL_BYTES:
            raise ExpansionError("substitutions exceed the byte limit")
        unique[value] = None
    if not unique:
        raise ExpansionError("a substitution pool cannot be empty")
    return tuple(unique)


def _parts(pattern: str) -> tuple[str, ...]:
    if len(pattern) > MAX_PATTERN_LENGTH or pattern.count("@") != 1:
        raise ExpansionError("pattern must be one address of at most 254 characters")
    local, domain = pattern.split("@")
    if "*" in domain or "\\" in domain:
        raise ExpansionError("domain wildcards and escapes are not supported")
    parts = [""]
    escaped = False
    for character in local:
        if escaped:
            if character not in "*\\":
                raise ExpansionError("only star and backslash may be escaped")
            parts[-1] += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "*":
            parts.append("")
        else:
            parts[-1] += character
    if escaped:
        raise ExpansionError("unfinished pattern escape")
    parts[-1] += "@" + domain
    return tuple(parts)


@dataclass(frozen=True)
class Expansion:
    """A plan whose count bounds work, including colliding concatenations.

    Pools and the product count are checked eagerly; addresses are produced and
    syntax-checked lazily. Output collisions are suppressed by SHA-256 digests
    (bounded by max_candidates). Count is an upper bound on unique output.
    """

    parts: tuple[str, ...] = field(repr=False)
    pools: tuple[tuple[str, ...], ...] = field(repr=False)
    count: int

    def __iter__(self) -> Iterator[str]:
        seen: set[bytes] = set()
        for values in itertools.product(*self.pools):
            address = self.parts[0] + "".join(
                value + suffix for value, suffix in zip(values, self.parts[1:], strict=True)
            )
            if isinstance(parse_address(RawAddressInput(address)), AddressRejected):
                raise ExpansionError("an expanded address has invalid or unsupported syntax")
            digest = hashlib.sha256(address.encode("utf-8")).digest()
            if digest not in seen:
                seen.add(digest)
                yield address


def plan_expansion(
    pattern: str,
    *,
    candidates: Iterable[str] = "abcdefghijklmnopqrstuvwxyz",
    positions: Sequence[Iterable[str]] | None = None,
    max_candidates: int = 10_000,
) -> Expansion:
    if type(max_candidates) is not int or not 1 <= max_candidates <= MAX_ROWS:
        raise ExpansionError(f"max_candidates must be 1..{MAX_ROWS}")
    parts = _parts(pattern)
    slots = len(parts) - 1
    if positions is not None:
        if len(positions) != slots:
            raise ExpansionError("provide exactly one pool per wildcard")
        pools = tuple(candidate_pool(pool) for pool in positions)
    else:
        pool = candidate_pool(candidates)
        pools = (pool,) * slots
    count = math.prod(len(pool) for pool in pools)
    if count > max_candidates:
        raise ExpansionError(f"candidate count {count} exceeds limit {max_candidates}")
    plan = Expansion(parts, pools, count)
    # Check fixed syntax and domain without enumerating the Cartesian product.
    sample = parts[0] + "".join(
        pool[0] + suffix for pool, suffix in zip(pools, parts[1:], strict=True)
    )
    if isinstance(parse_address(RawAddressInput(sample)), AddressRejected):
        raise ExpansionError("pattern produces invalid or unsupported address syntax")
    return plan
