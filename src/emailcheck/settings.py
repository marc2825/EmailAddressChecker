"""Strict TOML settings for local commands and explicitly configured deployments."""

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


@dataclass(frozen=True)
class Settings:
    batch: BatchLimits = field(default_factory=BatchLimits)
    rate_limit: RateLimitSettings = field(default_factory=RateLimitSettings)
    quota: QuotaSettings = field(default_factory=QuotaSettings)
    passive_quota: QuotaSettings = field(default_factory=QuotaSettings)

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
    if set(data) - schemas.keys():
        raise ValueError("unknown configuration section")
    loaded: dict[str, Any] = {}
    for name, schema in schemas.items():
        values = data.get(name, {})
        if not isinstance(values, dict) or set(values) - {f.name for f in fields(schema)}:
            raise ValueError("unknown or malformed configuration setting")
        loaded[name] = schema(**values)
    return Settings(**loaded)
