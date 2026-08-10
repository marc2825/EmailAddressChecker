"""API keys, stored as verifiers rather than as keys.

`prompts/06-api-cli.md`: store only a secure verifier, not the recoverable key.
So the mapping this adapter holds is `digest -> account`, and a credential is
hashed before it is looked up. A dump of the configuration does not let anyone
authenticate.

**No anonymous fallback, and no default account.** An absent, malformed, or
unknown credential answers `None`, and the caller refuses the request.
`docs/requirements.md` section 5 excludes anonymous active checks, and section
15 makes per-account budgets part of the service-active profile — a default
identity would satisfy both types and defeat both rules.

**No environment read.** Like the sender identity provider, this takes a mapping
the caller loaded deliberately. An adapter that read `EMAILCHECK_API_KEYS` would
be a trust anchor configured by whoever can set a variable in the worker's
environment, which is the shape the Phase 4 `TLSTrust` inspection already
refuses elsewhere in this tree.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from emailcheck.domain.principal import Principal

#: The shortest credential this adapter will accept at configuration time. A
#: short API key is a guessable one, and the digest hides that from a reviewer.
MIN_KEY_LENGTH: Final = 32


class ApiKeyConfigurationError(ValueError):
    """The key configuration is unusable, and an unusable one must not load."""


def verifier_for(key: str) -> str:
    """The stored form of one API key.

    SHA-256 over the UTF-8 bytes. This is a *verifier* for a high-entropy
    machine-generated credential, not a password hash: there is nothing to
    stretch, because a 32-character random key is not guessable by iteration.
    An operator issuing low-entropy keys is refused at load rather than
    protected by a slow hash.
    """
    if not isinstance(key, str) or len(key) < MIN_KEY_LENGTH:
        raise ApiKeyConfigurationError(f"an API key must be at least {MIN_KEY_LENGTH} characters")
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StaticApiKeyAuthenticator:
    """Authenticates against a fixed mapping of verifier to account.

    The mapping is built by the composition root from operator configuration.
    Nothing in this class reads a file, an environment variable, or a request.
    """

    verifiers: Mapping[str, Principal]

    def authenticate(self, credential: str | None) -> Principal | None:
        """The caller this credential proves, or `None`.

        The comparison is constant-time over the digest, and an unknown key and
        a wrong key are indistinguishable to the caller: both are `None`, and
        the caller answers `401` for both.
        """
        if not isinstance(credential, str) or not credential:
            return None
        try:
            digest = verifier_for(credential)
        except ApiKeyConfigurationError:
            # A credential shorter than any key this adapter would ever have
            # been configured with. Refused as unknown rather than reported as
            # malformed, so probing cannot learn the minimum length.
            return None
        for known, principal in self.verifiers.items():
            if hmac.compare_digest(known, digest):
                return principal
        return None


def build_authenticator(configuration: Mapping[str, str]) -> StaticApiKeyAuthenticator:
    """Build an authenticator from `{account_id: api_key}`.

    The key is hashed here and the plaintext is not retained by the returned
    object. Every account identifier is validated by `Principal`, so a
    configuration carrying an address or a control character fails at load.
    """
    verifiers: dict[str, Principal] = {}
    for account_id, key in configuration.items():
        principal = Principal(account_id=account_id)
        digest = verifier_for(key)
        if digest in verifiers:
            raise ApiKeyConfigurationError("two accounts may not share one API key")
        verifiers[digest] = principal
    return StaticApiKeyAuthenticator(verifiers=verifiers)
