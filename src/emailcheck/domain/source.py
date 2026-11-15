"""Where a request came from, when — and only when — something knows.

`docs/threat-model.md` lists source IP among the layered budgets.
`docs/threat-model.md` puts "public client to API" first among the trust
boundaries, and this is the value that crosses it.

**No header is trusted, and none is read.** `X-Forwarded-For` and `Forwarded`
are written by whoever sent the request unless a trusted proxy list says which
hops may set them, and this project has no such list because it has no ASGI
binding yet. A spoofable value in a budget key is worse than no budget at all:
it converts a per-source limit into a per-*claimed*-source limit, which an
attacker resets by changing a string. So this module reads nothing. A
`SourceIdentity` is constructed by a transport adapter from the connection's own
peer address, or it does not exist, and `application/abuse.py` simply does not
count the source layer when it does not.

That is the deliberate stop condition: `docs/adr/0016-abuse-controls-privacy-and-observability.md`
and `docs/architecture.md` record proxy trust as work belonging to the binding
Phase, not as something inferable here.

**Canonical, so one client is one budget.** `2001:db8::1` and `2001:DB8:0:0:0:0:0:1`
are one address written twice, and counting them separately is a bypass costing
nothing. `ipaddress` canonicalizes both families, and an IPv4-mapped IPv6
address is **refused** rather than unwrapped — the policy
`security/destination.py` already applies to peers, for the same reason: a
mapped address is a value from a dual-stack socket that has not been normalized
by whatever produced it, and unwrapping it here would be this project deciding
what another layer meant.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum


class SourceIdentityError(ValueError):
    """A source address that cannot be used as an identity."""


class SourceFamily(StrEnum):
    """Which address family a source belongs to. A bounded metric label."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """One client address, canonicalized, ready to key a budget by.

    The value guarantees the *shape*; a transport boundary grants the
    *provenance* — the split `PeerEndpoint`/`confirm_peer` and
    `Principal`/`Authenticator` already use. Nothing about this dataclass stops
    an API handler writing `SourceIdentity(body["ip"])`, so an inspection test
    refuses its constructor in `apps/` and `application/`, exactly as one
    refuses `Principal`'s.
    """

    address: str

    def __post_init__(self) -> None:
        value = self.address
        if not isinstance(value, str) or not value:
            raise SourceIdentityError("a source address must be non-empty text")
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            # No name resolution, ever. A source identity is numeric or it is
            # nothing: resolving here would make an inbound request cause an
            # outbound lookup, which is a request-triggered network call.
            raise SourceIdentityError("a source address must be a numeric IP address") from None
        if parsed.version == 6 and (parsed.ipv4_mapped is not None or parsed.sixtofour is not None):
            raise SourceIdentityError("an IPv4-mapped or 6to4 source address is not canonical")
        if str(parsed) != value:
            # Refused rather than rewritten, so the caller's value and the
            # budget key are the same string and nobody has to remember which
            # form was counted.
            raise SourceIdentityError("a source address must already be canonical")

    @property
    def family(self) -> SourceFamily:
        parsed = ipaddress.ip_address(self.address)
        return SourceFamily.IPV4 if parsed.version == 4 else SourceFamily.IPV6

    @property
    def budget_value(self) -> str:
        """The string a source budget counts against.

        The address itself. It is not a mailbox, it carries no local part, and
        `docs/privacy.md` section 1 lists it among the categories this project
        handles — so it is not digested here, which would only make an operator
        unable to act on an abusive source they can already see in their own
        connection logs.

        `BudgetKey` permits the colon an IPv6 address needs, and a layer name
        contains none — so `layer:value` stays unambiguous without this
        rewriting anything.
        """
        return self.address
