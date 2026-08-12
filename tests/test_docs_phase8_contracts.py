"""The Phase 8 documents and the code that shares their vocabulary.

Three lists in this repository have to agree, and each is maintained by hand in
at least two places:

- the thirteen deployment gates, in `docs/operations.md` section 1, in
  `domain/readiness.py`, and in `docs/readiness-checklist.md`;
- the seven runbooks, in `prompts/08-limited-beta.md` work item 3 and in
  `docs/runbooks/`;
- the dataset declaration, in `src/emailcheck/data/passive/README.md`, ADR 0007, and
  `application/readiness.py`.

A checklist that quietly loses a row is the failure these tests exist for. The
gates are read **from the document**, not from a list retyped here, so a row
added to one side and not the other fails rather than passing on the copy the
test happened to hold.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from emailcheck.application.beta import Agreement
from emailcheck.application.readiness import UNAVAILABLE_DATASETS
from emailcheck.domain.beta import BetaExecutionState
from emailcheck.domain.readiness import DEPLOYMENT_GATES, GateStatus

REPO: Final = Path(__file__).resolve().parents[1]
DOCS: Final = REPO / "docs"
RUNBOOKS: Final = DOCS / "runbooks"
#: The dataset snapshot now lives inside the package, so the provenance record
#: sits beside the data it describes rather than in a directory the wheel left
#: behind.
DATASETS: Final = REPO / "src" / "emailcheck" / "data" / "passive"

#: The seven, exactly as `prompts/08-limited-beta.md` work item 3 lists them.
SEVEN_RUNBOOKS: Final = (
    "stop-active-checks.md",
    "sender-identity-incident.md",
    "abuse-complaint.md",
    "false-invalid-investigation.md",
    "privacy-deletion.md",
    "destination-ssrf-alert.md",
    "queue-store-outage.md",
)

#: Every runbook answers these five questions, in this order.
REQUIRED_SECTIONS: Final = (
    "When this fires",
    "Do this now",
    "Then diagnose",
    "Do not",
    "Record and escalate",
)

#: Phrases that must never appear in a runbook's *prescriptive* sections.
#:
#: Each is an action `AGENTS.md` or the threat model forbids, and each is
#: plausible enough that somebody under incident pressure would reach for it.
#: The check is deliberately on the sections that tell an operator what to do —
#: a "Do not" section naming the same action is the document working.
#:
#: **This is a regression aid and nothing more.** It is a finite list of
#: phrasings matched against a fixed negation window; a paraphrase walks past
#: it, and no list of phrases could do otherwise. It catches the specific
#: wordings somebody deleted a "do not" from. What actually keeps unsafe advice
#: out of these files is review, plus the structural contracts beside this one:
#: the five required sections, the rule restated in every file, and the index.
#: Reading a green run here as "the runbooks contain no unsafe advice" would be
#: exactly the overclaim the runbooks themselves warn against.
FORBIDDEN_ADVICE: Final = (
    "rotate the ip",
    "rotate the egress",
    "change the egress ip",
    "disable tls",
    "disable rate limit",
    "disable the rate limit",
    "raise the rate limit",
    "send data",
    "issue data",
    "use vrfy",
    "use expn",
    "additional recipients",
    "more recipients",
    "second rcpt",
)


def read(path: Path) -> str:
    assert path.is_file(), f"{path.relative_to(REPO)} does not exist"
    return path.read_text(encoding="utf-8")


def gate_titles_in_operations() -> tuple[str, ...]:
    """The thirteen, read out of `docs/operations.md` section 1 itself."""
    text = read(DOCS / "operations.md")
    section = text.split("## 1. Deployment gates", 1)[1].split("## 2.", 1)[0]
    return tuple(
        line.strip().lstrip("- ").rstrip(";.").strip()
        for line in section.splitlines()
        if line.strip().startswith("- ")
    )


def flat(text: str) -> str:
    """One line, so an assertion is about wording rather than about line wrapping."""
    return " ".join(text.split())


def sections_of(text: str) -> dict[str, str]:
    """Second-level headings to their bodies."""
    parts = re.split(r"^## +", text, flags=re.MULTILINE)[1:]
    return {part.splitlines()[0].strip(): part for part in parts}


# --- the thirteen gates -----------------------------------------------------


def test_the_gate_table_matches_the_document_exactly() -> None:
    """Same titles, same order, same count. Read from the document.

    `domain/readiness.py` is the single vocabulary the validation command and
    the checklist both use, and it is only single if it says what
    `docs/operations.md` says.
    """
    document = gate_titles_in_operations()

    assert len(document) == 13, "docs/operations.md section 1 no longer lists thirteen gates"
    assert tuple(gate.title for gate in DEPLOYMENT_GATES) == document


def test_every_gate_is_in_the_readiness_checklist() -> None:
    checklist = read(DOCS / "readiness-checklist.md")

    for gate in DEPLOYMENT_GATES:
        assert gate.title in checklist, f"{gate.title!r} has no row in the checklist"


def test_the_checklist_records_who_verified_each_gate() -> None:
    """A checklist with no place for a name is a document, not a control."""
    checklist = read(DOCS / "readiness-checklist.md")

    assert checklist.count("| Verified by |") == 13
    assert checklist.count("| Date (UTC) |") == 13
    assert checklist.count("| Evidence |") == 13


def test_no_gate_can_be_reported_as_passed() -> None:
    """There is no `passed` status, and the documents must not imply one.

    Every gate is an external fact or a human commitment, so the strongest
    honest report is `configured_in_process`. A document promising more would
    be worse than one promising less.
    """
    assert "passed" not in {status.value for status in GateStatus}

    checklist = read(DOCS / "readiness-checklist.md")
    assert "it does not mean the gate is satisfied" in checklist.lower()
    assert "human" in checklist.lower()


def test_the_checklist_says_a_human_starts_the_beta() -> None:
    """`prompts/08-limited-beta.md`'s exit criteria, restated where it is used."""
    checklist = read(DOCS / "readiness-checklist.md").lower()

    assert "external_probing_authorized" in checklist
    assert "ready for manual gate" in checklist
    assert "production approved" in checklist


def test_the_checklist_asks_for_no_secret() -> None:
    """It is circulated and copied, so it says so explicitly."""
    checklist = read(DOCS / "readiness-checklist.md").lower()

    assert "do not record any secret" in checklist
    assert "no api key" in checklist


# --- the seven runbooks -----------------------------------------------------


@pytest.mark.parametrize("name", SEVEN_RUNBOOKS)
def test_each_runbook_exists_and_answers_the_five_questions(name: str) -> None:
    headings = sections_of(read(RUNBOOKS / name))

    for required in REQUIRED_SECTIONS:
        assert any(required in heading for heading in headings), (
            f"{name} has no {required!r} section"
        )


def test_there_are_exactly_seven_runbooks() -> None:
    """An eighth is a Phase 8 scope change, not a documentation tidy-up."""
    present = {path.name for path in RUNBOOKS.glob("*.md")} - {"README.md"}

    assert present == set(SEVEN_RUNBOOKS)


@pytest.mark.parametrize("name", SEVEN_RUNBOOKS)
def test_no_runbook_prescribes_a_forbidden_action(name: str) -> None:
    """The prescriptive sections are scanned; the "Do not" section is not.

    A runbook naming `DATA` under "Do not" is the document doing its job. The
    same phrase under "Do this now" is the failure this test exists for.
    """
    for heading, body in sections_of(read(RUNBOOKS / name)).items():
        if "Do not" in heading:
            continue
        lowered = body.lower()
        for phrase in FORBIDDEN_ADVICE:
            # A sentence that forbids the action is not a sentence prescribing
            # it, and every runbook contains both kinds.
            for match in re.finditer(re.escape(phrase), lowered):
                window = lowered[max(0, match.start() - 90) : match.start()]
                assert "do not" in window or "never" in window or "forbidden" in window, (
                    f"{name} section {heading!r} appears to prescribe {phrase!r}"
                )


@pytest.mark.parametrize("name", SEVEN_RUNBOOKS)
def test_every_runbook_carries_the_do_not_bypass_rule(name: str) -> None:
    """The rule that outranks every runbook, restated in each of them."""
    text = read(RUNBOOKS / name).lower()

    assert "do not bypass" in text or "do not disable" in text


def test_the_runbook_index_states_the_rule_that_outranks_them() -> None:
    index = read(RUNBOOKS / "README.md").lower()

    assert "do not bypass a safety control" in index
    for name in SEVEN_RUNBOOKS:
        assert name in index, f"{name} is missing from the runbook index"


def test_turning_a_control_off_is_never_gated_by_the_runbooks() -> None:
    """Every switch fails toward less outbound activity, and the index says so."""
    index = read(RUNBOOKS / "README.md").lower()

    assert "turning things off is always allowed" in index


# --- the dataset declaration ------------------------------------------------


def test_the_declaration_names_the_same_three_datasets_everywhere() -> None:
    readme = read(DATASETS / "README.md")
    adr = read(DOCS / "adr" / "0007-passive-classification-and-datasets.md")

    for dataset in ("disposable", "free-mail", "provider"):
        assert dataset in readme.lower()
        assert dataset in adr.lower()
    assert frozenset({"disposable", "free_mail", "provider"}) == UNAVAILABLE_DATASETS


def test_the_declaration_says_absence_is_not_a_negative_answer() -> None:
    """The one sentence that stops a caller reading a missing flag as a clean bill."""
    readme = read(DATASETS / "README.md").lower()

    assert "no evidence at all" in readme
    assert "does not produce negative evidence" in readme
    for negative in (
        '"this domain is not disposable"',
        '"this domain is not free mail"',
        "any `verdict`, any `status`, any confidence level",
    ):
        assert negative in readme, f"the declaration does not rule out {negative}"


def test_the_declaration_refuses_a_placeholder_dataset() -> None:
    readme = read(DATASETS / "README.md").lower()
    adr = read(DOCS / "adr" / "0007-passive-classification-and-datasets.md").lower()

    assert "no placeholder dataset was created" in readme
    assert "no placeholder dataset was created" in adr


def test_the_adr_records_the_phase_8_decision_and_how_to_reverse_it() -> None:
    adr = read(DOCS / "adr" / "0007-passive-classification-and-datasets.md")

    assert "Decision (Phase 8)" in adr
    assert "declared unavailable" in adr.lower()
    assert "reversible by data" in adr.lower()


# --- the beta report template -----------------------------------------------


def test_the_report_template_puts_its_limitations_first() -> None:
    """Every mistake this report can cause is a mistake of over-reading."""
    template = read(DOCS / "beta-report-template.md")
    headings = list(sections_of(template))

    assert headings[0].startswith("0."), "the limitations are not the first section"
    assert "not" in headings[0].lower()


def test_the_report_template_refuses_the_word_accuracy_as_a_measurement() -> None:
    template = read(DOCS / "beta-report-template.md").lower()

    assert "this is not an accuracy measurement" in template
    assert "no value called `correct`" in template


def test_the_report_template_keeps_not_offered_out_of_the_failure_bucket() -> None:
    """A server advertising no STARTTLS has not failed at anything."""
    template = read(DOCS / "beta-report-template.md").lower()

    assert "`not_offered` is its own category" in template
    assert "never be merged into a failure bucket" in template


def test_the_report_template_makes_no_policy_decision() -> None:
    template = read(DOCS / "beta-report-template.md")

    assert "Policy decision: NOT made by this report" in template
    assert "does not resolve ADR" in template


def test_the_report_template_uses_the_exact_agreement_vocabulary() -> None:
    """F3's other half: the document and the enum publish the same four strings.

    Read from `Agreement` rather than retyped, so a rename fails here as well as
    in the code — a template naming a value the harness cannot produce is a
    template describing a different report.
    """
    template = read(DOCS / "beta-report-template.md")

    for member in Agreement:
        assert f"`{member.value}`" in template, f"the template never names {member.value!r}"
    for invented in ("accuracy", "false_positive", "true_positive", "`correct`"):
        if invented == "`correct`":
            # Named once, in the sentence saying the vocabulary has no such value.
            assert "no value called `correct`" in template
            continue
        assert invented not in template.lower().replace("this is not an accuracy measurement", "")


def test_the_report_template_separates_execution_from_deliverability() -> None:
    """F8: a status distribution is over answers, not over harness bookkeeping."""
    template = read(DOCS / "beta-report-template.md")

    for state in BetaExecutionState:
        assert f"`{state.value}`" in template, f"the template never names {state.value!r}"
    assert "must equal `selected_targets`" in template
    assert "over `completed` rows only" in template
    assert "`not_run` is not a kind of `unknown`" in flat(template)


def test_the_report_template_does_not_claim_connections_per_job() -> None:
    """F5: nothing in this repository measures it, so the template says so."""
    template = read(DOCS / "beta-report-template.md")

    assert "**not measured by this report**" in template
    assert "no test in this repository measures it" in flat(template)


def test_the_loopback_load_test_does_not_claim_a_production_metric() -> None:
    """F5: the file says what it exercises, and what it therefore cannot measure.

    An earlier version's docstring claimed to pin `connections per job` while
    counting the connection pairs the test itself created. The claim is the
    thing under test here, because nothing else can catch a docstring.
    """
    load_test = flat(read(REPO / "tests" / "integration" / "test_load_loopback.py"))

    assert "measures none of" in load_test
    assert "beta metrics" in load_test
    assert "fixture accounting, not a production metric" in load_test
    # It must name what is *not* in its path, so a reader cannot assume it.
    for absent in ("AddressVerificationService", "admission gate", "quota", "rate limiter"):
        assert absent in load_test


def test_the_report_template_flags_a_truncated_run() -> None:
    template = read(DOCS / "beta-report-template.md")

    assert "`truncated`" in template
    assert "A truncated run is not a smaller complete run" in flat(template)
    assert "outbound contact with no recorded answer" in template


def test_operations_points_at_the_runbooks_that_exist() -> None:
    """An operator reading section 4 must be able to find the seven files."""
    operations = read(DOCS / "operations.md")
    section = operations.split("## 4. Runbooks", 1)[1].split("## 5.", 1)[0]

    assert "runbooks/README.md" in section
    for name in SEVEN_RUNBOOKS:
        assert f"runbooks/{name}" in section, f"{name} is unreachable from operations.md"


def test_the_report_template_numbers_its_sections_once_each() -> None:
    """R1: a duplicate `## 5` shipped once, and an operator cross-references these.

    Unique and monotonically increasing. No Markdown parser is needed for that,
    and the check is deliberately the smallest one that fails if the duplicate
    comes back.
    """
    numbers = [
        int(match)
        for match in re.findall(r"^## (\d+)\. ", read(DOCS / "beta-report-template.md"), re.M)
    ]

    assert numbers, "the template has no numbered sections"
    assert len(numbers) == len(set(numbers)), f"a section number is used twice: {numbers}"
    assert numbers == sorted(numbers), f"section numbers are out of order: {numbers}"


def test_every_section_reference_in_the_template_points_at_a_section() -> None:
    """R1's other half: renumbering headings must not break the prose."""
    template = read(DOCS / "beta-report-template.md")
    sections = {int(match) for match in re.findall(r"^## (\d+)\. ", template, re.M)}

    # Only this document's own sections. References naming another document —
    # "docs/requirements.md section 1" — belong to that document's numbering.
    for match in re.finditer(r"(?<!\.md )\bsection (\d+)", template):
        if template[max(0, match.start() - 40) : match.start()].rstrip().endswith(".md"):
            continue
        assert int(match.group(1)) in sections, (
            f"the template references its section {match.group(1)}, which does not exist"
        )


def test_the_template_states_what_one_rows_tls_value_describes() -> None:
    """R2: the aggregation limitation, in the artefact an analyst fills in.

    It was in a docstring and in IMPLEMENTATION_STATUS but not in the TLS
    section, which is where somebody carrying a `not_offered` count forward
    would need it.
    """
    tls = flat(sections_of(read(DOCS / "beta-report-template.md"))["6. TLS"])

    assert "preferred reachable exchanger" in tls
    assert "not a complete per-attempt TLS measurement" in tls
    assert "upper bound" in tls
    assert "no raw SMTP or TLS transcript is retained" in tls


def test_the_tls_section_still_makes_no_policy_decision() -> None:
    """R2 must not have loosened the boundary it was written beside."""
    tls = flat(sections_of(read(DOCS / "beta-report-template.md"))["6. TLS"])

    assert "Policy decision: NOT made by this report" in tls
    assert "`TLSPolicy.REQUIRED` stays as it is" in tls
    assert "does not resolve ADR" in tls
    assert "own ADR" in tls
    assert "not a representative" in tls or "is not, by construction" in tls


def test_the_report_template_authorizes_nothing() -> None:
    template = read(DOCS / "beta-report-template.md").lower()

    assert "ready for manual gate" in template
    assert "external_probing_authorized" in template
