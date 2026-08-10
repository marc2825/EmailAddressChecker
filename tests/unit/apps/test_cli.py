"""The local command, which performs no SMTP because it has none to perform.

`build_verification_stack` returns a service with no SMTP component for the
local-passive profile, so the CLI cannot probe by mistake — a flag can be
flipped, an absent object cannot. The suite-wide network guard would fail every
test here if one opened anything.
"""

from __future__ import annotations

import json

import pytest

from emailcheck.apps.cli import build_parser, main


def test_the_cli_default_reaches_no_network(capsys: pytest.CaptureFixture[str]) -> None:
    """The suite-wide guard would fail this test if it opened anything."""
    assert main(["not-an-address"]) == 0
    out = capsys.readouterr().out
    assert "invalid" in out
    assert "does not prove" in out


def test_the_cli_json_output_is_the_same_schema_the_api_returns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One allowlist, two renderings.

    `--json` cannot print something the API would refuse to, because both are
    built from the same `PublicResult`.
    """
    assert main(["not-an-address", "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert set(body) == {
        "status",
        "confidence",
        "primary_reason",
        "reasons",
        "risk_flags",
        "checks",
        "no_message_data_sent",
        "ruleset",
    }


def test_the_cli_verbose_output_stays_inside_the_privacy_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A debug flag that widened the boundary would leak the first time it was set."""
    assert main(["secret.person+tag@@example.test", "--verbose"]) == 0
    out = capsys.readouterr().out
    assert "secret.person" not in out
    assert "@" not in out


def test_the_cli_has_no_flag_that_makes_this_process_probe() -> None:
    """`docs/requirements.md` section 12: no convenient unrestricted flag.

    `--remote` is not one of these and is required by section 12: it submits to
    another instance, which does the probing under its own authentication,
    budgets, and sender identity. What section 12 refuses is a flag that makes
    *this* process open an SMTP connection, and there is none.
    """

    options = {action.dest for action in build_parser()._actions}
    for forbidden in ("active", "smtp", "probe", "insecure", "tls", "ca", "sender", "lab"):
        assert forbidden not in options
