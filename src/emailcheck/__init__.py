"""Email deliverability evidence engine."""

from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import ConfidenceLevel, RiskFlag, Status

__all__ = ["ConfidenceLevel", "ReasonCode", "RiskFlag", "Status"]
__version__ = "0.0.0"
