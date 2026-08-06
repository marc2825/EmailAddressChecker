from datetime import UTC, datetime

from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Confidence, ConfidenceLevel, Status, Verdict


def test_evidence_and_verdict_are_immutable() -> None:
    evidence = Evidence(
        layer=EvidenceLayer.DNS,
        reason=ReasonCode.MX_AVAILABLE,
        strength=EvidenceStrength.MODERATE,
        observed_at=datetime.now(UTC),
    )
    verdict = Verdict(
        status=Status.UNKNOWN,
        confidence=Confidence(level=ConfidenceLevel.LOW),
        primary_reason=ReasonCode.MX_AVAILABLE,
        reason_codes=(ReasonCode.MX_AVAILABLE,),
    )
    assert evidence.reason is ReasonCode.MX_AVAILABLE
    assert verdict.no_message_data_sent is True
