"""Strict TOML settings for local commands and explicitly configured deployments.

`[batch]`, `[rate_limit]`, `[quota]`, and `[passive_quota]` set budgets. `[smtp]`
is the local Active Mode (ADR 0022): the sender identity this machine probes
from and the user's acknowledgement of what a probe does. Nothing here can set
TLS, a destination, authentication, or a store.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from emailcheck.domain.abuse import QuotaSettings
from emailcheck.domain.batch import BatchLimits
from emailcheck.domain.rate_limit import RateLimitSettings

if TYPE_CHECKING:
    from emailcheck.composition import Deployment


#: The `[smtp]` keys. An unknown key is refused, like every other section.
SMTP_KEYS: frozenset[str] = frozenset({"ehlo_hostname", "envelope_sender", "acknowledged"})


@dataclass(frozen=True)
class SmtpSettings:
    """The user's local Active Mode configuration.

    `ehlo_hostname` and `envelope_sender` go to `load_sender_identity`, which
    refuses the null sender and an EHLO name unrelated to the sender's domain.
    `acknowledged` must be exactly `true`: it records that the user read the
    notice the CLI prints before the first probe. Without it nothing connects.
    """

    ehlo_hostname: str
    envelope_sender: str
    acknowledged: bool = False

    def sender_identity(self) -> dict[str, object]:
        return {"ehlo_hostname": self.ehlo_hostname, "envelope_sender": self.envelope_sender}


@dataclass(frozen=True)
class Settings:
    batch: BatchLimits = field(default_factory=BatchLimits)
    rate_limit: RateLimitSettings = field(default_factory=RateLimitSettings)
    quota: QuotaSettings = field(default_factory=QuotaSettings)
    passive_quota: QuotaSettings = field(default_factory=QuotaSettings)
    smtp: SmtpSettings | None = None

    def apply(self, deployment: Deployment) -> Deployment:
        """Only budgets can change. Authentication, TLS and destinations cannot."""
        return replace(
            deployment,
            rate_limits=self.rate_limit,
            quotas=self.quota,
            passive_quotas=self.passive_quota,
        )

    def as_json_object(self) -> dict[str, Any]:
        return {**asdict(self), "scope": "one process; active workers must be 1"}


def load_settings(path: Path | None = None) -> Settings:
    if path is None:
        return Settings()
    try:
        with path.open("rb") as handle:
            raw = handle.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("configuration exceeds 65536 bytes")
        data = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise ValueError("configuration must be a readable UTF-8 TOML file") from None
    schemas = {
        "batch": BatchLimits,
        "rate_limit": RateLimitSettings,
        "quota": QuotaSettings,
        "passive_quota": QuotaSettings,
    }
    if set(data) - schemas.keys() - {"smtp"}:
        raise ValueError("unknown configuration section")
    loaded: dict[str, Any] = {}
    if "smtp" in data:
        loaded["smtp"] = _smtp_settings(data["smtp"])
    for name, schema in schemas.items():
        values = data.get(name, {})
        if not isinstance(values, dict) or set(values) - {f.name for f in fields(schema)}:
            raise ValueError("unknown or malformed configuration setting")
        loaded[name] = schema(**values)
    return Settings(**loaded)


def _smtp_settings(values: object) -> SmtpSettings:
    if not isinstance(values, dict) or set(values) - SMTP_KEYS:
        raise ValueError("unknown or malformed configuration setting")
    ehlo = values.get("ehlo_hostname")
    sender = values.get("envelope_sender")
    acknowledged = values.get("acknowledged", False)
    if not isinstance(ehlo, str) or not isinstance(sender, str):
        raise ValueError("[smtp] needs ehlo_hostname and envelope_sender as text")
    if type(acknowledged) is not bool:
        raise ValueError("[smtp] acknowledged must be true or false")
    # Validated here, so a bad identity is a configuration error before any
    # network use rather than a refusal halfway through a check.
    from emailcheck.adapters.smtp.sender_identity import SenderIdentityError, load_sender_identity

    smtp = SmtpSettings(ehlo_hostname=ehlo, envelope_sender=sender, acknowledged=acknowledged)
    try:
        load_sender_identity(smtp.sender_identity())
    except SenderIdentityError as refusal:
        raise ValueError(f"[smtp] {refusal}") from None
    return smtp
