"""Who is asking, established by authentication and by nothing else.

Phase 4 carried an `account` string into the rate limiter and deliberately let
it divide no budget, because a caller-supplied account is per-account isolation
in appearance only: bypassed by sending a different string.
`docs/adr/0009-smtp-dialogue-and-tls.md` records that as a Phase 6 stop condition, and this type
is the thing that closes it.

**A `Principal` is not a request field, and the type cannot say so.** Nothing
about a frozen dataclass prevents an API handler writing
`Principal(account_id=body["account"])`. So the provenance guarantee is carried
by two things outside the value: `ports/authentication.py` is the only interface
that produces one, and an inspection test refuses the constructor anywhere in
`apps/` or `application/`. The value fixes the *shape*; the authenticator grants
the *identity* — the same split `PeerEndpoint` and `confirm_peer` use.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from typing import Final

#: Long enough for an opaque operator-issued identifier, short enough that it
#: cannot be used to smuggle data through a budget key or a log line.
MAX_ACCOUNT_ID_LENGTH: Final = 64

#: A key identifier is a truncated hexadecimal digest, so this is generous.
MAX_KEY_ID_LENGTH: Final = 64

#: Deliberately narrow. An account identifier is an opaque handle this project
#: issues, so there is no reason for it to contain anything else — and every
#: character outside this set is one that could change the meaning of a log
#: line, a budget key, or a stored row.
_PERMITTED: Final = frozenset(string.ascii_letters + string.digits + "-_.")


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller.

    `account_id` is an opaque operator-issued handle. It is never an email
    address, never a domain, and never anything the caller chose.
    """

    account_id: str
    #: Which of this account's credentials was presented, as an opaque handle.
    #:
    #: `docs/threat-model.md` lists "API key" and "account" as **separate**
    #: budget layers, and they are only separate if one account may hold several
    #: keys: a leaked key has to be containable without suspending the account
    #: that owns it. Phase 6 had one key per account, so the two layers were the
    #: same layer under two names.
    #:
    #: **Never the key, and never anything derived from it that could verify
    #: it.** `adapters/auth/api_keys.py` derives this through a domain-separated
    #: hash of the stored verifier, so possessing an issued `key_id` proves
    #: nothing and authenticates nothing. `None` is legal and means the caller
    #: was authenticated by something that issues no per-credential identity;
    #: the key layer is then simply not counted, rather than silently collapsing
    #: onto the account.
    key_id: str | None = None

    def __post_init__(self) -> None:
        value = self.account_id
        if not isinstance(value, str):
            raise ValueError("an account identifier must be a string")
        if not value:
            raise ValueError("an account identifier must not be empty")
        if len(value) > MAX_ACCOUNT_ID_LENGTH:
            raise ValueError(
                f"an account identifier must be at most {MAX_ACCOUNT_ID_LENGTH} characters"
            )
        if not _PERMITTED.issuperset(value):
            # `@` is refused here as well as by `rate_limit_key`, so an
            # identifier can never be a mailbox even before it reaches a budget.
            raise ValueError("an account identifier carries an unpermitted character")
        key_id = self.key_id
        if key_id is None:
            return
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("a key identifier must be non-empty text")
        if len(key_id) > MAX_KEY_ID_LENGTH:
            raise ValueError(f"a key identifier must be at most {MAX_KEY_ID_LENGTH} characters")
        if not _PERMITTED.issuperset(key_id):
            raise ValueError("a key identifier carries an unpermitted character")

    @property
    def rate_limit_account(self) -> str:
        """The value the rate limiter partitions this caller's budget by.

        Named rather than passing `account_id` directly, so the inspection test
        has something specific to require: a call site reading this property is
        reading an authenticated identity, and a call site reading a request
        body is visibly not.
        """
        return self.account_id

    @property
    def suspension_subjects(self) -> tuple[str, ...]:
        """The identities an operator can suspend this caller by.

        Both, when both exist: `docs/threat-model.md`'s admin interface can
        suspend a key *or* an account, and a request presenting a suspended key
        must be refused even when its account is fine — and the other way round.
        Returned as a tuple so the caller checks every one rather than choosing.
        """
        if self.key_id is None:
            return (self.account_id,)
        return (self.account_id, self.key_id)
