from emailcheck import __version__
from emailcheck.domain.verdict import ConfidenceLevel, Status


def test_package_imports() -> None:
    assert __version__ == "0.0.0"
    assert Status.UNKNOWN.value == "unknown"
    assert ConfidenceLevel.MEDIUM.value == "medium"
