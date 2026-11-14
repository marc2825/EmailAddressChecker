"""The two reporting-only commands, at the boundary a person actually types.

`docs/beta-report-template.md`. `tests/unit/test_readiness_reporting.py`
covers the reports themselves; this file covers what the command does with them:
it answers without an address, it reaches nothing, it prints no secret, and its
exit code is not a pass/fail somebody can script a deployment against.

The suite-wide guard in `tests/conftest.py` fails any test that opens a socket
or resolves a name, so every test here passing is also the evidence that a
"validation" command validated nothing over the network.
"""

from __future__ import annotations

import json
from typing import Final

import pytest

from emailcheck.apps.cli import EXIT_OK, main
from emailcheck.classification.repository import load_shipped_datasets
from emailcheck.domain.readiness import DEPLOYMENT_GATES

GATE_COUNT: Final = 13


def run(*argv: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


# --- the deployment report --------------------------------------------------


def test_check_deployment_answers_without_an_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """It reports on a deployment, not on an address, so it needs none."""
    code, out = run("--check-deployment", capsys=capsys)

    assert code == EXIT_OK
    assert "deployment gates" in out


def test_check_deployment_prints_every_gate(capsys: pytest.CaptureFixture[str]) -> None:
    _, out = run("--check-deployment", capsys=capsys)

    for gate in DEPLOYMENT_GATES:
        assert gate.title in out
    assert out.count("[requires_human_verification]") == 10


def test_check_deployment_says_what_it_did_not_do(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The disclaimer is printed, not only carried in the JSON."""
    _, out = run("--check-deployment", capsys=capsys)

    assert "advisory" in out
    assert "No gate can be passed by software" in out
    assert "only after a human verifies" in out


def test_check_deployment_exits_zero_although_ten_gates_are_unverified(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-zero code would turn an advisory report into a gate somebody scripts.

    Ten of the thirteen can only be verified outside this process, so a command
    that failed on them would fail forever — and the fix somebody would reach
    for is making it pass, which is the opposite of what the gates are for.
    """
    code, out = run("--check-deployment", capsys=capsys)

    assert code == EXIT_OK
    assert "10 of 13 gates" in out


def test_check_deployment_json_is_machine_readable_and_still_disclaims(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out = run("--check-deployment", "--json", capsys=capsys)
    payload = json.loads(out)

    assert len(payload["gates"]) == GATE_COUNT
    assert payload["requires_human_verification"] == 10
    assert payload["active_probing"] is False
    assert "advisory" in payload["disclaimer"]


def test_verbose_adds_the_reason_and_the_operator_action(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The checklist half: a gate an operator cannot act on is one they tick."""
    _, plain = run("--check-deployment", capsys=capsys)
    _, verbose = run("--check-deployment", "--verbose", capsys=capsys)

    assert "why:" not in plain
    assert "why:" in verbose
    assert "action:" in verbose
    assert len(verbose) > len(plain)


def test_the_deployment_report_prints_no_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """It is pasted into tickets and checklists."""
    _, out = run("--check-deployment", "--json", capsys=capsys)
    lowered = out.lower()

    for secret in ("api key", "hmac", "correlation", "password", "token"):
        assert secret not in lowered


# --- the version report -----------------------------------------------------


def test_report_versions_answers_without_an_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out = run("--report-versions", capsys=capsys)

    assert code == EXIT_OK
    assert "aggregation ruleset" in out


def test_report_versions_names_the_declared_unavailable_datasets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The Phase 8 declaration, where an operator will actually meet it."""
    _, out = run("--report-versions", capsys=capsys)

    assert "unavailable-by-declaration" in out
    assert "Absence is not a negative answer" in out
    for dataset in ("disposable", "free_mail", "provider"):
        assert dataset in out


def test_report_versions_carries_the_versions_a_beta_result_is_compared_against(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out = run("--report-versions", "--json", capsys=capsys)
    payload = json.loads(out)

    assert payload["aggregation_ruleset"].startswith("aggregation-")
    assert payload["canonical_input_version"]
    assert set(payload["unavailable_datasets"]) == {"disposable", "free_mail", "provider"}
    # The regression the review named: the shipped role list is populated, and
    # the command must report **its** version rather than a default's.
    shipped = load_shipped_datasets()
    assert payload["dataset_versions"]["role"] == shipped.versions["role"]
    assert payload["dataset_entry_counts"]["role"] == shipped.entry_counts["role"] > 0


def test_report_versions_prints_no_secret(capsys: pytest.CaptureFixture[str]) -> None:
    _, out = run("--report-versions", "--json", capsys=capsys)
    payload = json.loads(out)

    assert set(payload) == {
        "package_version",
        "aggregation_ruleset",
        "canonical_input_version",
        "dataset_versions",
        "unavailable_datasets",
        "dataset_entry_counts",
    }


# --- what the flags are not -------------------------------------------------


def test_neither_flag_performs_a_check_on_an_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An address supplied alongside them is not checked. The report is the answer."""
    code, out = run("--check-deployment", "user@example.test", capsys=capsys)

    assert code == EXIT_OK
    assert "status" not in out
    assert "user@example.test" not in out


def test_the_help_text_says_the_command_is_advisory(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Somebody reading `--help` should not think this validates a deployment."""
    code, out = run(capsys=capsys)

    assert code == EXIT_OK
    assert "--check-deployment" in out
    assert "--report-versions" in out
