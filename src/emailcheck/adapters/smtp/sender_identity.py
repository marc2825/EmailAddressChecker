"""Where the sender comes from, in the one place it is allowed to come from.

`ports/smtp_sender_identity.py` states the contract; this is the implementation
gate 4C was blocked on. It reads **operator configuration and nothing else**.

What it cannot do, by construction rather than by care:

- it takes no address, so it cannot derive a sender from the probe recipient;
- it takes no request, so no API field can reach it;
- `current_identity()` takes no argument, so a caller cannot pass the target in
  through a side door;
- it reads no environment variable and no ambient default. Configuration is
  handed in as a mapping the caller loaded deliberately, and every value in it
  is validated before it can reach a command line.

**The null reverse path is refused here.** `EnvelopeSender.null()` remains a
legal value — `docs/requirements.md` and RFC 5321 both have uses for `<>` — but
a configured probing identity may not be one. `docs/requirements.md` section 9
requires a managed envelope sender with SPF authorizing the IP and monitored
`postmaster` and `abuse` channels; none of that exists for `<>`, and a
`MAIL FROM:<>` followed by a single `RCPT TO` is the exact shape a receiving
site fingerprints as harvesting. Deciding it here, once and loudly, is the point:
the alternative is a deployment discovering at run time which branch it took.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender
from emailcheck.ports.smtp_sender_identity import SenderIdentity

#: The two configuration keys this reads. An unknown key is refused rather than
#: ignored, on the Phase 3 precedent: a silently ignored typo is a deployment
#: running with a default nobody chose.
EHLO_KEY: Final = "ehlo_hostname"
SENDER_KEY: Final = "envelope_sender"
KNOWN_KEYS: Final[frozenset[str]] = frozenset({EHLO_KEY, SENDER_KEY})


class SenderIdentityError(ValueError):
    """The configured sender identity cannot be used.

    A configuration error, raised at load time rather than carried as a value:
    a deployment with no usable identity must not start probing and then report
    a network failure.
    """


@dataclass(frozen=True, slots=True)
class ConfiguredSenderIdentityProvider:
    """Supplies one fixed identity, loaded once from operator configuration.

    Frozen and stateless. `docs/threat-model.md` requires one stable identity
    per deployment that is never rotated to obtain a different answer, and the
    cheapest way to keep that true is to hold a value rather than a strategy.
    """

    identity: SenderIdentity

    def current_identity(self) -> SenderIdentity:
        """Return the configured identity. Takes no argument, deliberately."""
        return self.identity


def load_sender_identity(configuration: Mapping[str, object]) -> SenderIdentity:
    """Build a `SenderIdentity` from operator configuration, or refuse.

    Every failure is a refusal. There is no default identity and no fallback:
    an unconfigured deployment must not probe, and inventing a plausible EHLO
    name would put an unowned host name on the wire.
    """
    unknown = sorted(set(configuration) - KNOWN_KEYS)
    if unknown:
        raise SenderIdentityError(f"unknown sender configuration keys: {', '.join(unknown)}")

    ehlo = _read_ehlo(configuration)
    sender = _read_envelope_sender(configuration)
    _check_alignment(ehlo, sender)
    return SenderIdentity(ehlo=ehlo, envelope_sender=sender)


def _read_ehlo(configuration: Mapping[str, object]) -> EhloIdentity:
    raw = configuration.get(EHLO_KEY)
    if raw is None:
        raise SenderIdentityError(f"{EHLO_KEY} is required; there is no default EHLO name")
    if not isinstance(raw, str):
        raise SenderIdentityError(f"{EHLO_KEY} must be text")
    identity = EhloIdentity.parse(raw)
    if identity is None:
        raise SenderIdentityError(
            f"{EHLO_KEY} must be a fully qualified host name this deployment owns"
        )
    return identity


def _read_envelope_sender(configuration: Mapping[str, object]) -> EnvelopeSender:
    raw = configuration.get(SENDER_KEY)
    if raw is None:
        raise SenderIdentityError(f"{SENDER_KEY} is required; the null sender is not configurable")
    if not isinstance(raw, str):
        raise SenderIdentityError(f"{SENDER_KEY} must be text")
    if not raw.strip():
        raise SenderIdentityError(
            f"{SENDER_KEY} cannot be empty: a probe needs a managed return path, and "
            "the null reverse path has no SPF, no PTR, and no monitored mailbox"
        )
    accepted = parse_address(RawAddressInput(value=raw))
    if not isinstance(accepted, AddressAccepted):
        # The same address boundary a probe target passes. A sender that Phase 1
        # would refuse cannot reach a command line either.
        raise SenderIdentityError(f"{SENDER_KEY} is not a supported mailbox")
    return EnvelopeSender(address=accepted.address)


def _check_alignment(ehlo: EhloIdentity, sender: EnvelopeSender) -> None:
    """Refuse an EHLO name and a sender domain that are unrelated.

    `SenderIdentity` says the two must agree, and this is what "agree" means
    here: one of the names is the other, or one is a subdomain of the other.
    `mx1.probe.example.com` with `verify@probe.example.com` passes;
    `mx.attacker.example` with `verify@example.com` does not.

    It is an alignment check, not an ownership proof. Only DNS can show that the
    PTR, the forward record, and the SPF record line up, and
    `docs/requirements.md` section 9 makes that a deployment requirement. This
    catches the configuration mistake that turns a probe into apparent forgery.
    """
    if sender.address is None:  # pragma: no cover - refused before this point
        raise SenderIdentityError("a configured envelope sender cannot be the null reverse path")
    sender_domain = sender.address.domain.ascii_form
    ehlo_host = ehlo.value
    if not _one_contains_the_other(ehlo_host, sender_domain):
        raise SenderIdentityError(
            "the EHLO host name and the envelope sender domain must be the same name or "
            f"one a subdomain of the other; {ehlo_host!r} and {sender_domain!r} are unrelated"
        )


def _one_contains_the_other(first: str, second: str) -> bool:
    """Whether either name is the other or a subdomain of it, on label boundaries."""
    if first == second:
        return True
    return first.endswith(f".{second}") or second.endswith(f".{first}")
