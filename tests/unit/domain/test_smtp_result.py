"""The observation records what happened. It must not record what it means.

`250` at RCPT does not mean the mailbox exists, because an accept-all server
says it to everyone, and a bare `550` does not mean it does not, because policy
rejections share the code. These tests keep the mapping out of Phase 4 rather
than trusting a reviewer to notice it arriving.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from emailcheck.domain.smtp_contract import SMTPState
from emailcheck.domain.smtp_reply import EnhancedStatusCode, ReplyDefect, SMTPReply
from emailcheck.domain.smtp_result import (
    NON_TARGET_OUTCOMES,
    RecipientObservation,
    RecipientStageOutcome,
)

SMTP_MODULES = sorted(
    (Path(__file__).resolve().parents[3] / "src" / "emailcheck" / "domain").glob("smtp*.py")
)

#: Vocabulary that belongs to Phase 5. None of it may appear in Phase 4 code.
VERDICT_VOCABULARY = (
    "Status",
    "Verdict",
    "Confidence",
    "likely_deliverable",
    "temporary_unknown",
    "RiskFlag",
)


def observation(**kwargs: object) -> RecipientObservation:
    base: dict[str, object] = {
        "outcome": RecipientStageOutcome.ACCEPTED,
        "final_state": SMTPState.RCPT_RESULT_RECEIVED,
        "reply": SMTPReply(code=250, diagnostic="OK"),
        "recipients_attempted": 1,
    }
    base.update(kwargs)
    return RecipientObservation(**base)  # type: ignore[arg-type]


# --- the taxonomy ----------------------------------------------------------


def test_the_taxonomy_holds_the_seven_published_outcomes() -> None:
    assert {outcome.value for outcome in RecipientStageOutcome} == {
        "accepted",
        "rejected",
        "temporary_failure",
        "protocol_error",
        "tls_error",
        "connection_error",
        "internal_error",
    }


def test_the_outcomes_that_say_nothing_about_the_target_are_named() -> None:
    """A TLS failure and a timeout are about the connection, not the address."""
    expected = frozenset(
        {
            RecipientStageOutcome.PROTOCOL_ERROR,
            RecipientStageOutcome.TLS_ERROR,
            RecipientStageOutcome.CONNECTION_ERROR,
            RecipientStageOutcome.INTERNAL_ERROR,
        }
    )
    assert expected == NON_TARGET_OUTCOMES


@pytest.mark.parametrize("outcome", sorted(NON_TARGET_OUTCOMES))
def test_a_non_target_outcome_reports_that_it_is_not_about_the_target(
    outcome: RecipientStageOutcome,
) -> None:
    result = observation(
        outcome=outcome,
        final_state=SMTPState.FAILED,
        reply=None,
        recipients_attempted=0,
        defect=ReplyDefect.MALFORMED_LINE
        if outcome is RecipientStageOutcome.PROTOCOL_ERROR
        else None,
    )
    assert result.is_about_the_target is False


def test_an_accepted_recipient_is_about_the_target_but_is_not_a_verdict() -> None:
    result = observation()
    assert result.is_about_the_target is True
    assert result.basic_code == 250
    assert not hasattr(result, "status")
    assert not hasattr(result, "is_deliverable")


# --- the promise that is published -----------------------------------------


def test_no_message_data_was_sent_and_there_is_no_way_to_say_otherwise() -> None:
    result = observation()
    assert result.no_message_data_sent is True
    assert "no_message_data_sent" not in RecipientObservation.__dataclass_fields__
    assert result.summary["no_message_data_sent"] is True


def test_the_summary_is_structured_and_carries_no_remote_prose() -> None:
    result = observation(
        reply=SMTPReply(
            code=550,
            enhanced=EnhancedStatusCode(status_class=5, subject=1, detail=1),
            diagnostic="Recipient address rejected",
        ),
        outcome=RecipientStageOutcome.REJECTED,
    )
    assert result.summary == {
        "result": "rejected",
        "final_state": "rcpt_result_received",
        "basic_code": 550,
        "enhanced_code": "5.1.1",
        "tls_used": False,
        "recipients_attempted": 1,
        "no_message_data_sent": True,
    }
    assert "diagnostic" not in result.summary


# --- invariants ------------------------------------------------------------


def test_more_than_one_recipient_is_unrepresentable() -> None:
    with pytest.raises(ValueError, match="at most one recipient"):
        observation(recipients_attempted=2)


def test_an_accepted_or_rejected_result_must_carry_the_reply_that_said_so() -> None:
    for outcome in (RecipientStageOutcome.ACCEPTED, RecipientStageOutcome.REJECTED):
        with pytest.raises(ValueError, match="must carry the reply"):
            observation(outcome=outcome, reply=None)


def test_a_protocol_error_must_name_the_defect() -> None:
    with pytest.raises(ValueError, match="must name the defect"):
        observation(
            outcome=RecipientStageOutcome.PROTOCOL_ERROR,
            reply=None,
            defect=None,
            final_state=SMTPState.FAILED,
        )


def test_negative_counters_and_times_are_refused() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        observation(recipients_attempted=-1)
    with pytest.raises(ValueError, match="cannot be negative"):
        observation(elapsed_milliseconds=-1)


# --- Phase 5 vocabulary is absent ------------------------------------------


@pytest.mark.parametrize("module", SMTP_MODULES, ids=lambda p: p.name)
def test_no_smtp_module_imports_verdict_vocabulary(module: Path) -> None:
    """A code becoming a status here would put the decision in the thinnest layer."""
    source = module.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            imported.update(alias.name for alias in node.names)
    for name in VERDICT_VOCABULARY:
        assert name not in imported, f"{module.name} imports {name}"


@pytest.mark.parametrize("module", SMTP_MODULES, ids=lambda p: p.name)
def test_no_smtp_module_names_a_status(module: Path) -> None:
    source = module.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in {"likely_deliverable", "invalid", "temporary_unknown"}
        for attribute in ("id", "attr", "name"):
            value = getattr(node, attribute, None)
            if isinstance(value, str):
                assert value not in {"likely_deliverable", "temporary_unknown"}


@pytest.mark.parametrize("module", SMTP_MODULES, ids=lambda p: p.name)
def test_no_smtp_module_opens_a_connection(module: Path) -> None:
    """Phase 4A has no transport. The stop condition in the plan depends on it."""
    source = module.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in {
                    "socket",
                    "ssl",
                    "smtplib",
                    "asyncio",
                    "http",
                    "urllib",
                    "requests",
                }, f"{module.name} imports {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in {
                "socket",
                "ssl",
                "smtplib",
                "asyncio",
                "http",
                "urllib",
                "requests",
            }, f"{module.name} imports from {node.module}"
