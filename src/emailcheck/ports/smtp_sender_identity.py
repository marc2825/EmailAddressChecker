"""Where the sender this project presents comes from.

`EnvelopeSender` and `EhloIdentity` fix what a sender *may look like*: validated,
CR/LF/NUL-free, fully qualified. Neither says where one comes from, and a review
found that nothing stopped the probe recipient itself being used as the envelope
sender — `EnvelopeSender(address=target)` builds fine, and `MAIL FROM` would then
carry the address being probed.

Answering that in the value type would mean giving it a reference to the target,
which is the wrong shape: a sender is not a function of the address being
checked. So provenance is a port instead. This one.

**The contract.**

- an identity comes from operator-controlled configuration and nothing else;
- it is never derived from the probe target, from raw user input, or from any
  request field;
- it is stable. `docs/requirements.md` section 9 requires a static IP, a PTR
  aligned with the EHLO name, forward DNS resolving back to it, SPF authorizing
  it, and monitored `postmaster` and `abuse` mailboxes. None of that is true of
  an identity picked per request;
- it is not rotated to get a different answer from a remote server, which
  `docs/threat-model.md` lists as an abuse control rather than a feature.

No implementation exists yet. Gate 4C needs one, because that is where
`MAIL FROM` is first issued; `plans/phase-04-smtp.md` records that as a stop
condition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender


@dataclass(frozen=True, slots=True)
class SenderIdentity:
    """One configured identity: what to say, and who to say it as.

    The two travel together because they must agree. An EHLO name from one host
    with an envelope sender from another domain is the configuration mistake
    that gets a probe treated as forgery.
    """

    ehlo: EhloIdentity
    envelope_sender: EnvelopeSender


class SenderIdentityProvider(Protocol):
    """Supplies the identity a probe presents.

    The method takes no argument. That is deliberate: a provider that received
    the target could return a sender derived from it, and there is no legitimate
    reason for the identity to depend on who is being checked.
    """

    def current_identity(self) -> SenderIdentity:
        """Return the configured identity for this deployment."""
        ...
