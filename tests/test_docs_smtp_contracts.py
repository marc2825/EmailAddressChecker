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

pytestmark = pytest.mark.docs_contract

ROOT = Path(__file__).resolve().parents[1]
STATUS_MODEL = ROOT / "docs" / "status-model.md"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
STATE_MACHINE = ROOT / "docs" / "smtp-state-machine.md"
DIALOGUE_ADR = ROOT / "docs" / "adr" / "0009-smtp-dialogue-and-tls.md"
OPERATIONS = ROOT / "docs" / "operations.md"


def text_of(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def flattened(text: str) -> str:
    """Lower-cased, blockquote-stripped, one-space text.

    A commitment that spans a line break is still the commitment. Matching the
    raw file would make these tests fail on a reflow and pass on a deletion that
    happened to keep the wrapping, which is the wrong way round.
    """
    without_quotes = re.sub(r"(?m)^\s*>\s?", "", text)
    return re.sub(r"\s+", " ", without_quotes).lower()


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


def test_the_smtp_mapping_is_documented_with_its_inputs() -> None:
    """The SMTP-to-evidence mapping has its own section and names every input."""
    mapping = text_of(STATUS_MODEL)
    assert "## 7. SMTP observation to evidence" in mapping
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


# --- section 7.3 names a stage a real session actually reports --------------


def test_the_recipient_stage_condition_names_both_stages() -> None:
    """The old wording described a state no session reaches.

    Section 7.3 said target evidence is produced "only when `stage_reached` is
    `rcpt_to`", and every real recipient answer reports `cleanup`: `rcpt_to` is
    the stage a dialogue is *in* while the command is outstanding. The code
    accepted both and was right. A Phase 5 author filtering as documented would
    have discarded every recipient answer this project produces, with the whole
    suite still passing — nothing in the mapping matrix could catch a
    specification that is wrong about the code it specifies.
    """
    section = _section(STATUS_MODEL, "### 7.3", "### 7.4")

    assert "`rcpt_to`" in section
    assert "`cleanup`" in section
    assert "reached or passed" in section
    # And the correction is explicit, so the old contract cannot come back by
    # someone tidying the prose.
    assert 'stage_reached == "rcpt_to"' in section
    assert "discards" in section


def test_the_recipient_stage_condition_names_its_other_two_barriers() -> None:
    """Three barriers, and the document must not describe only the stage."""
    section = _section(STATUS_MODEL, "### 7.3", "### 7.4")

    assert "recipients_attempted" in section
    for outcome in ("accepted", "rejected", "temporary_failure"):
        assert f"`{outcome}`" in section


def test_the_documented_stage_set_is_the_one_the_code_uses() -> None:
    """Substance rather than wording: the document and the module must agree."""
    from emailcheck.application.smtp_evidence import _AT_OR_PAST_RECIPIENT
    from emailcheck.domain.smtp_protocol import DialogueStage

    assert set(_AT_OR_PAST_RECIPIENT) == {DialogueStage.RCPT_TO, DialogueStage.CLEANUP}


# --- the Phase 5 stop conditions are recorded where a Phase 5 author looks ---


@pytest.mark.parametrize("document", [STATUS_MODEL])
def test_the_positive_set_is_recorded_as_a_category_and_not_a_rule(document: Path) -> None:
    """The shortest correct-looking aggregation an author could write."""
    body = text_of(document)

    assert "POSITIVE_RECIPIENT_REASONS" in body, document.name
    flat = flattened(body)
    assert "semantic category" in flat, document.name
    assert "not an aggregation rule" in flat, document.name
    assert "likely_deliverable" in flat, document.name


@pytest.mark.parametrize("document", [STATUS_MODEL])
def test_strength_is_recorded_as_evidence_and_never_as_truth(document: Path) -> None:
    body = text_of(document)

    assert "STRONG" in body, document.name
    flat = flattened(body)
    assert "never final truth" in flat, document.name
    assert "invalid" in flat, document.name
    assert "non_target_smtp_reasons" in flat, document.name


def test_the_strength_type_carries_the_stop_condition_where_it_is_read() -> None:
    """A document a Phase 5 author may not open; a docstring they will."""
    from emailcheck.domain.evidence import EvidenceStrength

    assert EvidenceStrength.__doc__ is not None
    documented = flattened(EvidenceStrength.__doc__)
    assert "never final truth" in documented
    assert "non_target_smtp_reasons" in documented


def test_the_privacy_guarantee_is_stated_at_the_size_of_what_holds() -> None:
    """Remote prose containing `RCPT TO` survives, and that is not a leak.

    The wording that forbade "a raw wire command" claimed more than the code
    does: a server may write `550 RCPT TO is not allowed here` and the bounded
    sanitized diagnostic keeps it. What may never be stored is a reply or a
    command *this project issued*.
    """
    flat = flattened(_section(STATUS_MODEL, "### 7.5", "### 7.6"))

    assert "locally-issued" in flat
    assert "remote diagnostic may itself contain smtp command words" in flat
    assert "remote prose is not a wire command" in flat


def test_the_generic_accepted_mapping_is_called_out_as_wrong() -> None:
    """The warning has to name the shape, not only the conclusion.

    A 4D author writing `if observation.outcome is ACCEPTED` should find the
    exact line they are about to write, marked as the mistake.
    """
    mapping = text_of(STATUS_MODEL)
    assert "outcome is RecipientStageOutcome.ACCEPTED" in mapping
    assert "is_about_the_target" in mapping
    assert "basic_code" in mapping


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


@pytest.mark.parametrize("document", [STATUS_MODEL])
def test_the_not_offered_rate_has_a_dated_measurement_obligation(document: Path) -> None:
    """A guess about real-world STARTTLS deployment is not an acceptable input."""
    body = text_of(document)
    assert "not_offered" in body
    assert "Phase 8" in body
    lowered = body.lower()
    assert "measure" in lowered
    assert "default" in lowered


def test_the_default_may_not_change_without_the_measurement() -> None:
    for document in (STATUS_MODEL,):
        body = text_of(document)
        assert "is not one of the options" in body, document.name


# --- TLSTrust provenance ---------------------------------------------------


@pytest.mark.parametrize("document", [ROOT / "docs" / "threat-model.md"])
def test_trust_anchors_are_operator_configuration_only(document: Path) -> None:
    body = text_of(document)
    assert "TLSTrust" in body
    lowered = body.lower()
    assert "operator" in lowered
    for forbidden_source in ("request", "api"):
        assert forbidden_source in lowered


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
    for document in sorted(ROOT.glob("docs/**/*.md")):
        for reference in ADR_REFERENCE.findall(text_of(document)):
            if reference not in numbered:
                dangling.append(f"{document.name} -> ADR {reference}")
    assert dangling == [], f"a document references an ADR that does not exist: {dangling}"


def test_the_dialogue_adr_is_the_one_the_documents_point_at() -> None:
    assert DIALOGUE_ADR.is_file()
    assert not (ADR_DIRECTORY / "0009-smtp-dialogue-and-starttls.md").exists()


# --- Phase 6 stop conditions, from the Phase 4 final review -----------------
#
# Seven conditions, all about *composition*: Phase 4 builds components that are
# safe on their own and leaves no composition root, so Phase 6 writes the wiring
# from scratch. A stop condition that is not written down is one the next author
# has no way to find.

PHASE_6_STOP_CONDITIONS = {
    "high-level entry point": (
        "smtpverificationservice",
        "higher-level service",
    ),
    "authenticated account provenance": (
        "authenticated principal",
        "shape check, not a provenance",
    ),
    "shared process-scoped limiter": (
        "process-scoped production limiter",
        "one per request resets",
    ),
    "production clock and sleeper": ("real monotonic clock and `systemsleeper`",),
    "bounded admission control": (
        "admission control",
        "caller fan-out",
    ),
    "verification-total deadline": (
        "overall request or job deadline",
        "32 minutes",
    ),
    "operator-controlled trust": (
        "tlstrust",
        "operator-controlled configuration",
    ),
}


# --- the documented rate-limit semantics match the implementation -----------


@pytest.mark.parametrize("document", [ARCHITECTURE, THREAT_MODEL])
def test_the_documented_budget_is_per_recipient_domain(document: Path) -> None:
    """Three documents once described a three-part key the code never had.

    `acquire` takes an account, a domain, and an MX host; the limiter partitions
    on the domain alone. Overclaiming here is the failure ADR 0008 named, and
    this is the fourth time this project has made it.
    """
    flat = flattened(text_of(document))

    assert "domain" in flat
    assert "per-account" in flat or "account" in flat
    # The claim that must not come back, in the forms it took.
    for overclaim in (
        "the budget key is the account, the recipient's domain, and the mx host",
        "budgets are keyed by an account, the recipient's domain, and the mx host",
    ):
        assert overclaim not in flat, f"{document.name} claims a three-part budget key"


@pytest.mark.inspection
def test_the_limiter_partitions_on_domain_and_mx() -> None:
    """The documentation above is checked against the code, not only itself."""
    import ast
    import inspect

    from emailcheck.adapters.system.rate_limit import InProcessRateLimiter

    source = inspect.getsource(InProcessRateLimiter._enter)
    tree = ast.parse(source.lstrip())
    claims = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_claim"
    ]
    assert len(claims) == 2
    assert {claim.args[0].attr for claim in claims} == {"domain", "mx_host"}


# --- the documented worst case includes the rate-limit waits ----------------


@pytest.mark.parametrize("document", [ARCHITECTURE])
def test_the_worst_case_latency_counts_the_rate_limit_waits(document: Path) -> None:
    """ "Three session budgets" left out a term and understated the bound."""
    flat = flattened(text_of(document))

    assert "wait" in flat and "session budget" in flat
    assert "120 s" in flat or "120 seconds" in flat
    assert "32 minutes" in flat
    assert "a verification's worst case is three session budgets" not in flat


def test_the_documented_worst_case_matches_the_configured_bounds() -> None:
    """The arithmetic in the documents, recomputed from the constants."""
    from emailcheck.application.smtp_verification import DEFAULT_MAX_ATTEMPTS, MAX_ATTEMPTS_CEILING
    from emailcheck.domain.rate_limit import DEFAULT_WAIT_BUDGET_SECONDS, MAX_WAIT_BUDGET_SECONDS
    from emailcheck.domain.smtp_deadline import DEFAULT_SESSION_SECONDS, MAX_SESSION_SECONDS

    assert DEFAULT_MAX_ATTEMPTS * (DEFAULT_WAIT_BUDGET_SECONDS + DEFAULT_SESSION_SECONDS) == 120.0
    ceiling = MAX_ATTEMPTS_CEILING * (MAX_WAIT_BUDGET_SECONDS + MAX_SESSION_SECONDS)
    assert ceiling == 1920.0
    assert ceiling / 60 == 32.0


# --- the limiter's memory bound is stated at the size that holds ------------


@pytest.mark.parametrize("document", [ARCHITECTURE])
def test_the_memory_bound_names_in_flight_callers(document: Path) -> None:
    """The bound is the cap *plus* in-flight callers, and they are not capped.

    Saying "bounded" without the second term would claim more than the code
    does — in-flight entries are bounded by caller concurrency, which is Phase 6
    admission control's to fix.
    """
    flat = flattened(text_of(document))

    assert "in flight" in flat or "in-flight" in flat
    assert "admission control" in flat


def test_the_ttl_is_documented_as_applying_to_idle_entries_only() -> None:
    """And therefore as not needing to exceed the longest SMTP session."""
    flat = flattened(text_of(ARCHITECTURE))

    assert "applies to idle entries only" in flat
    assert "not** required to exceed the longest smtp session" in flat or (
        "not required to exceed the longest smtp session" in flat
    )
