import pytest

from emailcheck import __version__
from emailcheck.__main__ import main


def test_version_flag_prints_version_and_exits_successfully(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["emailcheck", "--version"])
    assert main() == 0
    assert capsys.readouterr().out.strip() == __version__


def test_bare_invocation_prints_help_and_exits_successfully(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["emailcheck"])
    assert main() == 0
    assert "emailcheck" in capsys.readouterr().out


def test_baseline_cli_has_no_address_checking_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 0 performs no DNS or SMTP work; an address argument would imply it."""
    monkeypatch.setattr("sys.argv", ["emailcheck", "user@example.com"])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code != 0
