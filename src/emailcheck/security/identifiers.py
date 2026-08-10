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
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

#: A key shorter than the digest adds no security and hides that it does not.
MIN_KEY_BYTES: Final = 32


class CorrelationKeyError(ValueError):
    """The correlation key is unusable."""


def check_correlation_key(key: bytes) -> None:
    """Refuse a key that is absent, short, or not bytes."""
    if not isinstance(key, bytes):
        raise CorrelationKeyError("a correlation key must be bytes")
    if len(key) < MIN_KEY_BYTES:
        raise CorrelationKeyError(f"a correlation key must be at least {MIN_KEY_BYTES} bytes")


def correlation_digest(key: bytes, value: str) -> str:
    """A stable, keyed digest of one canonical value.

    The caller decides what is canonical — `NormalizedAddress.hmac_material` for
    a target, an account identifier for a principal — so this function never
    normalizes and never guesses.
    """
    check_correlation_key(key)
    if not isinstance(value, str) or not value:
        raise CorrelationKeyError("a correlation value must be non-empty text")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
