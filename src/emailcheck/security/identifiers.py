"""Correlation without storing the thing being correlated.

`docs/requirements.md` section 16 asks for an HMAC for correlation and duplicate
detection, and section 13 says a cache key includes the normalized target HMAC.
This is that function, and it exists so that no other module has to decide how
a target becomes a stored key.

**Keyed, not hashed.** A bare SHA-256 of an email address is reversible for any
address anyone can guess, which is all of them: the space of plausible addresses
at a known domain is small enough to enumerate. An HMAC under a secret the
operator holds is what makes a stored digest useless to whoever obtains the
database without also obtaining the key.

**Versioned, because canonicalization changes.** `docs/privacy.md` section 5
specifies `HMAC-SHA-256(key, canonical_input_version || normalized_target)` and
asks that the version be stored. Without it, a digest is a number nobody can
identify the derivation of: the day the canonical form changes — an IDNA
revision, a normalization fix — every stored digest silently stops matching,
and there is no way to tell an old one from a new one. The version is part of
the HMAC *input* rather than a column beside it, so two canonicalizations can
never collide onto one digest.

Adding the version changed every digest this project produces, once. ADR 0016
records that, and `adapters/storage/sqlite_store.py` moved its schema version in
the same change so an older file is refused rather than quietly matching
nothing.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

#: A key shorter than the digest adds no security and hides that it does not.
MIN_KEY_BYTES: Final = 32

#: The canonicalization this project's digests are taken over, as
#: `docs/privacy.md` section 5's `canonical_input_version`. Bump it when the
#: canonical form of any digested value changes, and expect every stored digest
#: to change with it.
CANONICAL_INPUT_VERSION: Final = "v1"

#: The separator between the version and the value. A byte that cannot occur in
#: any canonical input this project digests, so `("v1", "a") ` and `("v1a", "")`
#: cannot produce one string.
_SEPARATOR: Final = "\x00"


class CorrelationKeyError(ValueError):
    """The correlation key is unusable."""


def check_correlation_key(key: bytes) -> None:
    """Refuse a key that is absent, short, or not bytes."""
    if not isinstance(key, bytes):
        raise CorrelationKeyError("a correlation key must be bytes")
    if len(key) < MIN_KEY_BYTES:
        raise CorrelationKeyError(f"a correlation key must be at least {MIN_KEY_BYTES} bytes")


def correlation_digest(key: bytes, value: str, *, version: str = CANONICAL_INPUT_VERSION) -> str:
    """A stable, keyed digest of one canonical value.

    The caller decides what is canonical — `NormalizedAddress.hmac_material` for
    a target, an account identifier for a principal — so this function never
    normalizes and never guesses.

    `version` is `docs/privacy.md` section 5's `canonical_input_version` and is
    prefixed to the input rather than appended, so no value can be constructed
    that reproduces another version's digest.
    """
    check_correlation_key(key)
    if not isinstance(value, str) or not value:
        raise CorrelationKeyError("a correlation value must be non-empty text")
    if not isinstance(version, str) or not version or _SEPARATOR in version:
        raise CorrelationKeyError("a canonicalization version must be simple non-empty text")
    material = f"{version}{_SEPARATOR}{value}".encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()
