"""The two values this project puts on the wire about itself.

`docs/requirements.md` section 9 requires a stable EHLO FQDN and a managed
envelope sender, both aligned with the sending host. Choosing them is
configuration and DNS work that belongs to a later gate; this module only fixes
what they may be, so that nothing unvalidated can reach a command line.

Both types are built from values that already passed the Phase 1 address
boundary, so neither can carry CR, LF, or NUL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_contract import SMTPContractError

#: An EHLO argument is a domain, and a bare hostname says nothing about who is
#: connecting. Requiring a dot is the cheapest check that rejects `localhost`.
MIN_EHLO_LABELS: Final = 2


@dataclass(frozen=True, slots=True)
class EhloIdentity:
    """The fully qualified name this project introduces itself as.

    It is a `HostName`, so it is already a validated ASCII LDH name in canonical
    form, and it must be fully qualified: a remote server that cannot resolve
    the EHLO name back to the connecting host treats the session as anonymous,
    which is exactly the reputation problem `docs/threat-model.md` describes.
    """

    host: HostName

    def __post_init__(self) -> None:
        if len(self.host.value.split(".")) < MIN_EHLO_LABELS:
            raise SMTPContractError("an EHLO identity must be fully qualified")

    @property
    def value(self) -> str:
        return self.host.value

    @classmethod
    def parse(cls, text: str) -> EhloIdentity | None:
        """Build an identity from configuration text, or None when unusable."""
        host = HostName.normalize(text)
        if host is None:
            return None
        try:
            return cls(host=host)
        except SMTPContractError:
            return None


@dataclass(frozen=True, slots=True)
class EnvelopeSender:
    """The managed return path offered in `MAIL FROM`.

    `address` is `None` for the null sender, `<>`, which is what a server
    expects from a bounce or a verification probe. Anything else is a
    `NormalizedAddress`, so the encoder never interpolates unvalidated text.

    This type does not decide which sender to use. That is a deployment
    decision requiring SPF, PTR, and a monitored mailbox.
    """

    address: NormalizedAddress | None = None

    @property
    def is_null_sender(self) -> bool:
        return self.address is None

    @property
    def path(self) -> str:
        """The reverse path exactly as it appears between the angle brackets."""
        return "" if self.address is None else self.address.smtp_target

    @classmethod
    def null(cls) -> EnvelopeSender:
        return cls(address=None)
