"""The console entry point, and what the default command will not do.

The Phase 0 baseline asserted that an address argument *failed*, because Phase 0
performed no DNS or SMTP work and accepting one would have implied it did. Phase
6 is where the command became real, so that assertion is replaced by the two
that matter now: the default performs a local passive check, and there is no
flag that turns it into an active one.

`tests/unit/apps/test_cli.py` covers the output; this file covers the entry
point `pyproject.toml` binds.
"""

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


def test_an_address_now_produces_a_local_passive_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The Phase 6 behaviour that replaces the Phase 0 refusal.

    The suite-wide network guard fails any test that opens a socket, so this
    passing is also the evidence that the default reached no network.
    """
    monkeypatch.setattr("sys.argv", ["emailcheck", "not-an-address"])
    assert main() == 0
    assert "status" in capsys.readouterr().out


def test_the_entry_point_is_the_cli_rather_than_a_second_parser() -> None:
    """One parser. Two would drift, and one of them would grow a probe flag."""
    from emailcheck.apps import cli

    assert main is cli.main
