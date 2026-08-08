"""The one `SSLContext` this project builds, and the one thing about it that is
adjustable.

Verification is not a policy here. `check_hostname` is always `True`,
`verify_mode` is always `CERT_REQUIRED`, and there is **no parameter through
which either can be turned off** — not a flag, not an environment variable, not
an "insecure" mode for the lab profile. A context that skips verification turns
STARTTLS into decoration: an active attacker on the path completes the handshake
with any certificate and reads the `RCPT TO` this project was trying to protect.

The one seam is `TLSTrust`, and its shape is deliberate. A caller may supply an
**extra trust anchor**; it cannot supply a context, a verify mode, or a hostname
override. The worst a misuse can do is trust one more CA. That is what the TLS
integration tests use, and it is why they can exercise a real handshake without
production code ever learning what a test is — `docs/test-strategy.md` forbids
the `if testing:` shape, not dependency injection whose default is the secure
one.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Final

#: TLS 1.0 and 1.1 are deprecated by RFC 8996 and offer nothing a mail server
#: still needs. `ssl` already defaults to this on a modern build; setting it
#: explicitly means a system-wide configuration cannot quietly lower it.
MINIMUM_TLS_VERSION: Final = ssl.TLSVersion.TLSv1_2


@dataclass(frozen=True, slots=True)
class TLSTrust:
    """Where certificate verification finds its anchors.

    `ca_file` is *additional*. The system trust store is always loaded, and
    there is no way to express "trust only this" or "trust nothing", because
    both of those are ways to end up trusting the wrong thing.
    """

    ca_file: str | None = None

    @property
    def uses_system_trust_only(self) -> bool:
        return self.ca_file is None


#: What production uses. Named so that a test can assert production passes it.
SYSTEM_TRUST: Final = TLSTrust()


def build_client_context(trust: TLSTrust = SYSTEM_TRUST) -> ssl.SSLContext:
    """Build the client context used for every STARTTLS upgrade.

    `create_default_context` already enables verification and hostname checking;
    both are then set again explicitly, because this function is what a reviewer
    reads to answer "is verification on", and the answer should not depend on
    knowing a library default.
    """
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = MINIMUM_TLS_VERSION
    if trust.ca_file is not None:
        # Added to the default anchors, never replacing them.
        context.load_verify_locations(cafile=trust.ca_file)
    return context
