"""TLS is required for every probe, including internal library use.

This is the one place the trade-off is written down, because it is a real one
and picking a default silently would hide it.

**The recipient address travels in `RCPT TO`.** `docs/threat-model.md` lists
submitted email addresses as an asset, and a plaintext SMTP session puts one in
front of every device on the path. That argues for requiring TLS.

**Plenty of real mail servers still do not offer STARTTLS.** Refusing to probe
them produces `unknown`, which is a conservative answer rather than a wrong one —
but it is an answer about this project's configuration, not about the address.

So the only policy is `REQUIRED` (ADR 0021). What it must never
become is mailbox evidence: a server without STARTTLS is not a server without
that mailbox. `RecipientStageOutcome.TLS_ERROR` is in `NON_TARGET_OUTCOMES`, and
that is enforced by the taxonomy rather than by remembering.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TLSPolicy(StrEnum):
    """The supported policy; plaintext continuation is not available."""

    #: TLS must be negotiated. A server that does not advertise STARTTLS, or one
    #: whose handshake fails, ends the probe with a TLS error and no recipient
    #: observation. The default, because the alternative sends an address in the
    #: clear to a host chosen by DNS.
    REQUIRED = "required"


#: What a deployment gets if it does not choose. See the module docstring.
DEFAULT_TLS_POLICY = TLSPolicy.REQUIRED


class TLSFailureReason(StrEnum):
    """Why TLS did not happen. None of these is ever about the recipient."""

    #: The server advertised no `STARTTLS` and the policy requires it.
    NOT_OFFERED = "not_offered"
    #: The server refused the `STARTTLS` command itself.
    COMMAND_REJECTED = "command_rejected"
    #: The handshake failed for a reason that is not the certificate.
    HANDSHAKE_FAILED = "handshake_failed"
    #: The certificate chain did not verify.
    CERTIFICATE_INVALID = "certificate_invalid"
    #: The chain verified but the name did not match the MX host.
    HOSTNAME_MISMATCH = "hostname_mismatch"
    #: The handshake did not finish inside its deadline.
    TIMEOUT = "timeout"
    #: The peer changed, or could not be re-confirmed, across the upgrade.
    PEER_CHANGED = "peer_changed"


@dataclass(frozen=True, slots=True)
class TLSOutcomeDetail:
    """What happened to TLS in one session, for the report.

    Carries no certificate, no chain, no subject, and no library message.
    Any public summary follows `docs/requirements.md` section 11, which forbids
    full exception text in it, so the reason is this project's own vocabulary.
    """

    negotiated: bool = False
    reason: TLSFailureReason | None = None

    def __post_init__(self) -> None:
        if self.negotiated and self.reason is not None:
            raise ValueError("a negotiated TLS session has no failure reason")

    @property
    def is_about_the_target(self) -> bool:
        """Always false. TLS says nothing about whether a mailbox exists."""
        return False
