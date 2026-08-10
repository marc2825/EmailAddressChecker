"""Turning a credential into a `Principal`, or into nothing.

The one rule this port exists to carry: **there is no anonymous principal.**
`authenticate` answers `None` for an absent, malformed, or unknown credential,
and a caller that wants per-account isolation must refuse the request rather
than inventing an identity to proceed with.

`docs/requirements.md` section 5 excludes anonymous active checks outright, and
section 15 makes per-account budgets part of the service-active profile. A
default account would satisfy the type and defeat both.
"""

from __future__ import annotations

from typing import Protocol

from emailcheck.domain.principal import Principal


class Authenticator(Protocol):
    def authenticate(self, credential: str | None) -> Principal | None:
        """Return the caller this credential proves, or `None`.

        Implementations must be constant-time in the credential comparison and
        must not distinguish "unknown key" from "wrong key" to the caller.
        """
        ...
