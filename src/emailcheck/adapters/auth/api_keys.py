"""API keys, stored as verifiers rather than as keys.

`docs/architecture.md`: store only a secure verifier, not the recoverable key.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from emailcheck.domain.principal import Principal

#: The shortest credential this adapter will accept at configuration time. A
#: short API key is a guessable one, and the digest hides that from a reviewer.
MIN_KEY_LENGTH: Final = 32

#: How much of the key-identity digest is kept. Sixteen bytes of a keyed-domain
#: digest is far past collision-resistance for the number of keys one
#: deployment issues, and a shorter identifier is a shorter log line.
KEY_ID_LENGTH: Final = 32

#: Domain separation, so a `key_id` cannot be confused with — or derived back
#: into — the verifier it comes from. The verifier is what authenticates; the
#: identity is what a budget and an audit event name.
_KEY_ID_DOMAIN: Final = b"emailcheck/api-key-id/v1"


def key_identity_for(verifier: str) -> str:
    """The opaque per-credential handle for one stored verifier.

    Derived from the verifier rather than from the key, so this function never
    sees key material, and domain-separated so the result cannot be replayed as
    a verifier. It is stable across restarts because the verifier is, which is
    what a budget counter and a suspension list both need.
    """
    digest = hashlib.sha256(_KEY_ID_DOMAIN + verifier.encode("ascii")).hexdigest()
    return digest[:KEY_ID_LENGTH]


class ApiKeyConfigurationError(ValueError):
    """The key configuration is unusable, and an unusable one must not load."""


def verifier_for(key: str) -> str:
    """The stored form of one API key.

    SHA-256 over the UTF-8 bytes. This is a *verifier* for a high-entropy
    machine-generated credential, not a password hash: there is nothing to
    stretch, because a 32-character random key is not guessable by iteration.
    Configuration validates length, not entropy. Operators must generate random
    keys; repeated or guessable strings can satisfy the length check.
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

    #: `repr=False`. Not one of the values the review named, and found by the
    #: sweep those findings prompted: a verifier is a digest rather than a key,
    #: so printing one authenticates nobody — but the table maps every account
    #: to its verifier, and `key_identity_for` derives the suspension and budget
    #: handles from exactly that value. It serves no debugging purpose and there
    #: is no reason for it to travel.
    verifiers: Mapping[str, Principal] = field(repr=False)

    def authenticate(self, credential: str | None) -> Principal | None:
        """The caller this credential proves, or `None`.

        The comparison is constant-time over the digest, and an unknown key and
        a wrong key are indistinguishable to the caller: both are `None`, and
        the caller answers `401` for both.

        **Every credential is compared, including after a match.** Returning
        early on the first hit makes the work depend on where in the mapping the
        key sits, which is a timing signal about the configuration. The loop
        runs to the end and the answer is chosen afterwards.
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
        found: Principal | None = None
        for known, principal in self.verifiers.items():
            if hmac.compare_digest(known, digest):
                found = principal
        return found


def build_authenticator(
    configuration: Mapping[str, str | Sequence[str]],
) -> StaticApiKeyAuthenticator:
    """Build an authenticator from `{account_id: api_key}` or `{account_id: [keys]}`.

    **One account may hold several keys.** `docs/threat-model.md` budgets and
    suspends per key *and* per account, which are two layers only if a key is
    not simply another name for the account. Each key gets its own `key_id`, so
    a leaked credential is containable without suspending the account that owns
    it, and the account's own budget still covers all of them together.

    The key is hashed here and the plaintext is not retained by the returned
    object. Every account identifier is validated by `Principal`, so a
    configuration carrying an address or a control character fails at load.
    """
    verifiers: dict[str, Principal] = {}
    for account_id, configured in configuration.items():
        keys = (configured,) if isinstance(configured, str) else tuple(configured)
        if not keys:
            raise ApiKeyConfigurationError("an account with no key cannot authenticate")
        for key in keys:
            if not isinstance(key, str):
                raise ApiKeyConfigurationError("an API key must be a string")
            digest = verifier_for(key)
            if digest in verifiers:
                # Across accounts this would hand one account another's
                # identity; within one account it is a configuration mistake
                # that would make a key look revocable when it is duplicated.
                raise ApiKeyConfigurationError("two accounts may not share one API key")
            verifiers[digest] = Principal(account_id=account_id, key_id=key_identity_for(digest))
    return StaticApiKeyAuthenticator(verifiers=verifiers)
