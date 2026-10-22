import tomllib
from pathlib import Path

from emailcheck import __version__
from emailcheck.domain.verdict import ConfidenceLevel, Status


def test_package_imports() -> None:
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["dynamic"] == ["version"]
    assert config["tool"]["hatch"]["version"]["path"] == "src/emailcheck/__init__.py"
    assert __version__ == "0.1.0"
    assert Status.UNKNOWN.value == "unknown"
    assert ConfidenceLevel.MEDIUM.value == "medium"
