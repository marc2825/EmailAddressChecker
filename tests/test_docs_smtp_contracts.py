"""Documented decisions that a later gate must not quietly lose.

Most documentation does not need a test. These four do, because each is a
*decision made in one gate that binds a later one*, and the failure mode is
silence: a Phase 4D author who never reads the `252` warning writes the mapping
that classifies a refusal to verify as an acceptance, and nothing anywhere fails.

The assertions are on substance rather than on wording — the reason codes the
mapping must produce, the distinctions it must draw, the presence of the two
dated obligations — so the prose can be rewritten without breaking them, and the
commitments cannot be deleted without breaking them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATUS_MODEL = ROOT / "docs" / "status-model.md"
STATE_MACHINE = ROOT / "docs" / "smtp-state-machine.md"
DIALOGUE_ADR = ROOT / "docs" / "adr" / "0009-smtp-dialogue-and-tls.md"
PLAN = ROOT / "plans" / "phase-04-smtp.md"
STATUS_FILE = ROOT / "IMPLEMENTATION_STATUS.md"


def text_of(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _section(path: Path, start: str, end: str) -> str:
    """The text between two headings, so a check reads the table it means.

    Searching the whole file is what let a mutation past: `rcpt_unverifiable`
    also appears in the published reason-code table of section 5, so the
    mapping row could be rewritten and a file-wide marker check still passed.
    """
    body = text_of(path)
    assert start in body, f"{path.name} has no {start}"
    after = body.split(start, 1)[1]
    assert end in after, f"{path.name} has no {end} after {start}"
    return after.split(end, 1)[0]


# --- the Phase 4D mapping is specified before Phase 4D ---------------------


def test_the_mapping_table_exists_before_the_code_that_implements_it() -> None:
    """4A came before 4B for this reason, and the mapping is the same shape."""
    mapping = text_of(STATUS_MODEL)
    assert "for Phase 4D" in mapping
    for field in (
        "stage_reached",
        "basic_code",
        "enhanced_code",
        "deadline_exhausted",
        "RecipientStageOutcome",
    ):
        assert field in mapping, f"the mapping does not name its input {field}"


@pytest.mark.parametrize(
    ("distinction", "marker"),
    [
        ("banner invalid", "smtp_banner_invalid"),
        ("EHLO rejected", "smtp_policy_blocked"),
        ("STARTTLS not offered", "not_offered"),
        ("TLS handshake or certificate failure", "smtp_tls_failure"),
        ("hostname mismatch", "hostname_mismatch"),
        ("MAIL FROM rejected", "mail_from_rejected"),
        ("transport timeout", "smtp_connection_timeout"),
        ("connection refused", "smtp_connection_refused"),
        ("recipient accepted", "rcpt_accepted"),
        ("recipient forwarded", "rcpt_forwarded"),
        ("recipient unverifiable", "rcpt_unverifiable"),
        ("recipient does not exist", "rcpt_rejected_address"),
        ("recipient refused by policy", "rcpt_rejected_policy"),
        ("bare permanent rejection", "smtp_ambiguous_permanent_failure"),
        ("explicit temporary condition", "smtp_temporary_failure"),
    ],
)
def test_the_mapping_distinguishes_every_case_the_review_required(
    distinction: str, marker: str
) -> None:
    assert marker in text_of(STATUS_MODEL), f"the mapping does not cover {distinction}"


def test_a_pre_recipient_failure_is_never_target_evidence() -> None:
    """The rule the whole taxonomy exists to keep."""
    mapping = text_of(STATUS_MODEL)
    assert "never `rcpt_rejected_address`" in mapping
    assert "never mailbox invalidity" in mapping


# --- 252 is the trap the mapping exists to disarm --------------------------


def test_252_is_documented_as_unverifiable_rather_than_accepted() -> None:
    mapping = text_of(STATUS_MODEL)
    assert "`252` is not an acceptance" in mapping
    section = mapping.split("`252` is not an acceptance", 1)[1]
    for claim in ("an accepted recipient", "`likely_deliverable`", "the mailbox exists"):
        assert claim in section, f"the section does not refuse {claim}"


def test_the_mapping_row_for_252_binds_it_to_the_unverifiable_code() -> None:
    """A marker somewhere in the file is not the same as the right row.

    `rcpt_unverifiable` also appears in the published reason-code table, so
    rewriting the mapping row to `rcpt_accepted` left the coarser check above
    passing. This reads the row itself.
    """
    recipient_table = _section(STATUS_MODEL, "### 7.3", "### 7.4")
    rows = [line for line in recipient_table.splitlines() if line.startswith("|") and "252" in line]
    assert rows, "the recipient-stage mapping has no row for 252"
    for row in rows:
        assert "rcpt_unverifiable" in row, f"252 is not mapped as unverifiable: {row}"
        assert "rcpt_accepted" not in row, f"252 is mapped as an acceptance: {row}"

    # And every other 2xx row is a different code, so the three cannot collapse.
    codes = {"rcpt_accepted", "rcpt_forwarded", "rcpt_unverifiable"}
    assert codes <= {code for code in codes if code in recipient_table}


def test_the_generic_accepted_mapping_is_called_out_as_wrong() -> None:
    """The warning has to name the shape, not only the conclusion.

    A 4D author writing `if observation.outcome is ACCEPTED` should find the
    exact line they are about to write, marked as the mistake.
    """
    mapping = text_of(STATUS_MODEL)
    assert "outcome is RecipientStageOutcome.ACCEPTED" in mapping
    assert "is_about_the_target" in mapping
    assert "basic_code" in mapping


def test_the_252_entry_condition_is_carried_in_the_plan() -> None:
    plan = text_of(PLAN)
    assert "Stop conditions for 4D" in plan
    assert "252" in plan
    assert "basic_code" in plan


def test_the_taxonomy_is_not_extended_by_phase_4d() -> None:
    plan = text_of(PLAN)
    assert "No new `RecipientStageOutcome` member" in plan


# --- the TLS default has an argument, and a date --------------------------


def test_the_adr_gives_downgrade_resistance_as_the_reason_for_requiring_tls() -> None:
    """The exposure argument alone does not settle the default.

    DNS and the connection already reveal the domain. What settles it is that an
    on-path attacker can strip `STARTTLS` from an EHLO reply, so opportunistic
    TLS protects against a passive observer and nobody else.
    """
    adr = text_of(DIALOGUE_ADR).lower()
    assert "downgrade" in adr
    assert "strip" in adr
    assert "on-path" in adr
    assert "opportunistic" in adr


@pytest.mark.parametrize("document", [STATUS_FILE, PLAN])
def test_the_not_offered_rate_has_a_dated_measurement_obligation(document: Path) -> None:
    """A guess about real-world STARTTLS deployment is not an acceptable input."""
    body = text_of(document)
    assert "not_offered" in body
    assert "Phase 8" in body
    lowered = body.lower()
    assert "measure" in lowered
    assert "default" in lowered


def test_the_default_may_not_change_without_the_measurement() -> None:
    for document in (STATUS_FILE, PLAN):
        body = text_of(document)
        assert "is not one of the options" in body, document.name


# --- TLSTrust provenance ---------------------------------------------------


@pytest.mark.parametrize("document", [PLAN, ROOT / "docs" / "threat-model.md"])
def test_trust_anchors_are_operator_configuration_only(document: Path) -> None:
    body = text_of(document)
    assert "TLSTrust" in body
    lowered = body.lower()
    assert "operator" in lowered
    for forbidden_source in ("request", "api"):
        assert forbidden_source in lowered


def test_the_phase_6_stop_condition_is_recorded() -> None:
    assert "Stop condition for Phase 6" in text_of(PLAN)


# --- the state table and its description agree -----------------------------


def test_the_documented_tls_state_matches_the_table() -> None:
    """`TLS_NEGOTIATED` permits `EHLO` and `QUIT`, and the prose now says so."""
    from emailcheck.domain.smtp_contract import SMTPCommand, SMTPState, allowed_commands

    assert allowed_commands(SMTPState.TLS_NEGOTIATED) == frozenset(
        {SMTPCommand.EHLO, SMTPCommand.QUIT}
    )
    described = text_of(STATE_MACHINE)
    assert "`TLS_NEGOTIATED` permits `EHLO` and `QUIT`" in described
    assert "cannot reach `MAIL FROM`" in described


def test_the_smuggling_refusal_is_documented_as_a_shared_category() -> None:
    """Two diagnostics, one decision, and the collapse is written down."""
    described = text_of(STATE_MACHINE)
    assert "CVE-2011-0411" in described
    assert "tls_handshake_failed" in described
    assert "section 7.2" in described


# --- ADR numbering and its references line up ------------------------------

ADR_DIRECTORY = ROOT / "docs" / "adr"
ADR_HEADING = re.compile(r"^#\s*ADR\s*(\d{4})\b", re.MULTILINE)
ADR_REFERENCE = re.compile(r"ADR\s+(\d{4})")


def test_every_adr_heading_matches_its_filename() -> None:
    mismatches: list[str] = []
    for adr in sorted(ADR_DIRECTORY.glob("*.md")):
        heading = ADR_HEADING.search(text_of(adr))
        if heading is None or not adr.name.startswith(f"{heading.group(1)}-"):
            mismatches.append(adr.name)
    assert mismatches == [], f"an ADR's number and filename disagree: {mismatches}"


def test_every_referenced_adr_exists() -> None:
    """A reference by number is only useful while the number resolves."""
    numbered = {adr.name[:4] for adr in ADR_DIRECTORY.glob("*.md") if adr.name[:4].isdigit()}
    dangling: list[str] = []
    for document in sorted(ROOT.glob("docs/**/*.md")) + sorted(ROOT.glob("plans/*.md")):
        for reference in ADR_REFERENCE.findall(text_of(document)):
            if reference not in numbered:
                dangling.append(f"{document.name} -> ADR {reference}")
    assert dangling == [], f"a document references an ADR that does not exist: {dangling}"


def test_the_dialogue_adr_is_the_one_the_documents_point_at() -> None:
    assert DIALOGUE_ADR.is_file()
    assert not (ADR_DIRECTORY / "0009-smtp-dialogue-and-starttls.md").exists()
