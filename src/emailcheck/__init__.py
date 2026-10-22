"""Email deliverability evidence engine."""

from emailcheck.domain.address import (
    AddressAccepted,
    AddressRejected,
    AddressSyntaxIssue,
    NormalizedAddress,
    RawAddressInput,
    RejectionKind,
    parse_address,
)
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import ConfidenceLevel, RiskFlag, Status

__all__ = [
    "AddressAccepted",
    "AddressRejected",
    "AddressSyntaxIssue",
    "ConfidenceLevel",
    "NormalizedAddress",
    "RawAddressInput",
    "ReasonCode",
    "RejectionKind",
    "RiskFlag",
    "Status",
    "parse_address",
]
__version__ = "0.1.0"
