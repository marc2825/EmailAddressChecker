"""What Phase 9 must be unable to do, asserted where behaviour cannot show it.

The risk in this Phase is not a wrong answer — it is a *reachable* one. An
accept-all probe folded into `verify()`, a feature flag a request could set, or
a module that decided a `Status` would each be short, plausible code that no
scenario test catches until the day it is wrong. So these are inspection tests,
and every scan reads the **syntax tree with docstrings excluded**: these modules
explain at length what they do not do, and a raw text scan fails on their own
prose — a mistake this repository has now made in seven separate gates.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from typing import Final
from unittest import mock

import pytest

from emailcheck.application import accept_all as accept_all_application
from emailcheck.domain import accept_all as accept_all_domain
from emailcheck.domain.accept_all import (
    CONTROL_ALPHABET,
    CONTROL_LOCAL_PART_LENGTH,
    MAX_COLLISION_RETRIES,
    AcceptAllOutcome,
    AcceptAllSettings,
)
from emailcheck.domain.verdict import RiskFlag, Status

ROOT: Final = pathlib.Path(__file__).resolve().parents[2]

PHASE_9_MODULES: Final = {
    "domain": "src/emailcheck/domain/accept_all.py",
    "application": "src/emailcheck/application/accept_all.py",
    "cache_port": "src/emailcheck/ports/accept_all_cache.py",
    "cache_adapter": "src/emailcheck/adapters/system/accept_all_cache.py",
}

#: Mailbox names a control probe must never be. Not a production blocklist —
#: the generator is non-dictionary by construction — but the specific words
#: `docs/adr/0017-accept-all-control-experiment.md` and `docs/threat-model.md` name, so a generator
#: rewritten around a word list fails here.
DICTIONARY_NAMES: Final = (
    "admin",
    "administrator",
    "info",
    "support",
    "sales",
    "test",
    "user",
    "john",
    "alice",
    "postmaster",
    "abuse",
    "contact",
    "hello",
    "office",
)


def tree_of(relative: str) -> ast.Module:
    return ast.parse((ROOT / relative).read_text(encoding="utf-8"))


def code_without_docstrings(relative: str) -> str:
    tree = tree_of(relative)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def imported_names(relative: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree_of(relative)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


# --- the ordinary path does not reach the experiment ------------------------


def test_the_ordinary_verification_path_never_imports_the_experiment() -> None:
    """The central separation, and the only one that keeps one `RCPT TO` true.

    A control recipient inside a caller's verification would make that
    verification issue two — `docs/threat-model.md`'s first enumeration control
    — however carefully the code distinguished them. The experiment is
    unreachable from `verify()` because the module is not imported there.
    """
    for ordinary in (
        "src/emailcheck/application/verification.py",
        "src/emailcheck/application/smtp_verification.py",
        "src/emailcheck/application/jobs.py",
        "src/emailcheck/apps/api.py",
        "src/emailcheck/apps/cli.py",
    ):
        imported = imported_names(ordinary)
        assert not any("accept_all" in name for name in imported), (
            f"{ordinary} can reach the accept-all experiment"
        )


def test_the_experiment_does_not_import_the_high_level_verification_service() -> None:
    """The dependency runs one way, so neither can quietly call the other."""
    imported = imported_names(PHASE_9_MODULES["application"])

    assert "emailcheck.application.verification" not in imported


def test_the_experiment_reaches_no_transport_or_probe_directly() -> None:
    """It goes through the production verification service or not at all.

    Reaching past it would mean the destination policy, the limiter, the sender
    identity, TLS, and the one-`RCPT TO` bound were all things this module had
    to remember rather than inherit.
    """
    code = code_without_docstrings(PHASE_9_MODULES["application"])

    for shortcut in (
        "SMTPProbeService",
        "SMTPTransport",
        "AsyncioSMTPConnection",
        "ApprovedDestination",
        "DNSResolver",
        "TLSPolicy",
        "TLSTrust",
        "EnvelopeSender",
    ):
        assert shortcut not in code, shortcut


# --- the feature flag is an operator's, not a caller's ----------------------


def test_the_feature_flag_is_disabled_by_default() -> None:
    assert AcceptAllSettings().enabled is False


def test_no_request_surface_names_the_feature() -> None:
    """`docs/adr/0017-accept-all-control-experiment.md`: no public caller may enable it.

    The API body already accepts exactly one key, so this is the second barrier:
    nothing in the request-facing modules names the feature at all, which is
    what stops a body key, a query parameter, or a CLI flag from being added
    without somebody reading this test.
    """
    for surface in (
        "src/emailcheck/apps/api.py",
        "src/emailcheck/apps/cli.py",
        "src/emailcheck/apps/schema.py",
        "src/emailcheck/application/public_result.py",
        "src/emailcheck/application/public_job.py",
    ):
        code = code_without_docstrings(surface).lower()
        for name in ("accept_all", "acceptall", "catch_all", "catchall"):
            assert name not in code, (surface, name)


def test_the_experiment_takes_no_caller_supplied_enablement() -> None:
    """`run` takes a route, a domain, and a principal. Nothing else.

    A `force=`, an `enable=`, or an `accept_all=` parameter would be the shape
    a public caller could eventually reach.
    """
    signature = inspect.signature(accept_all_application.AcceptAllExperiment.run)

    assert set(signature.parameters) == {"self", "route", "domain", "principal"}


# --- nothing here decides a status ------------------------------------------


@pytest.mark.parametrize("name", sorted(PHASE_9_MODULES))
def test_no_phase_9_module_names_a_deliverability_status(name: str) -> None:
    """The experiment produces evidence. Phase 5 decides what evidence means."""
    code = code_without_docstrings(PHASE_9_MODULES[name])

    for status in Status:
        assert status.value not in code, (name, status.value)
    for forbidden in ("Status.", "Verdict", "Confidence", "aggregate_evidence"):
        assert forbidden not in code, (name, forbidden)


def test_the_only_risk_flag_phase_9_can_produce_is_accept_all_suspected() -> None:
    code = code_without_docstrings(PHASE_9_MODULES["application"])

    named = [flag for flag in RiskFlag if flag.value in code]
    assert named == [] or named == [RiskFlag.ACCEPT_ALL_SUSPECTED]
    assert "ACCEPT_ALL_SUSPECTED" in code


def test_the_experiment_re_derives_no_status_from_a_reply_code() -> None:
    """No `if reply == 250`, anywhere.

    The mapping is from Phase 4D's **reason codes**, which is what
    `docs/adr/0017-accept-all-control-experiment.md`'s "compare structured evidence, not only the
    basic code" asks for.
    """
    code = code_without_docstrings(PHASE_9_MODULES["application"])

    for raw in ("250", "550", "5.1.1", "basic_code", "SMTPReply", "reply"):
        assert raw not in code, raw


# --- the generator ----------------------------------------------------------


def test_no_phase_9_module_carries_a_dictionary_of_mailbox_names() -> None:
    """A generator built from a word list would be a dictionary attack.

    The property is that the generator cannot *produce* one, which twenty
    uniform characters give for free; this asserts that no such list was added
    in order to sample from it.
    """
    for relative in PHASE_9_MODULES.values():
        code = code_without_docstrings(relative).lower()
        for name in DICTIONARY_NAMES:
            assert f'"{name}"' not in code, (relative, name)
            assert f"'{name}'" not in code, (relative, name)


def test_the_generator_uses_the_random_source_port_rather_than_a_module() -> None:
    """`docs/architecture.md` section 2 makes randomness a port for this reason."""
    code = code_without_docstrings(PHASE_9_MODULES["application"])

    assert "random_source.token" in code
    for direct in ("import random", "import secrets", "uuid", "time.time"):
        assert direct not in code, direct


def test_the_control_alphabet_carries_nothing_structural() -> None:
    """No dot, no `+`, no hyphen: each makes a generated address look owned."""
    for structural in (".", "+", "-", "_", "@"):
        assert structural not in CONTROL_ALPHABET

    assert CONTROL_LOCAL_PART_LENGTH >= 16
    assert 0 < MAX_COLLISION_RETRIES <= 5


def test_a_control_local_part_parses_through_the_ordinary_grammar() -> None:
    """No second syntax policy: a generated address is an ordinary address."""
    from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address

    sample = CONTROL_ALPHABET[0] * CONTROL_LOCAL_PART_LENGTH
    parsed = parse_address(RawAddressInput(f"{sample}@example.test"))

    assert isinstance(parsed, AddressAccepted)


# --- the outcome vocabulary is closed ---------------------------------------


def test_the_outcome_vocabulary_is_exactly_five_values() -> None:
    """Published, closed, and none of them a `Status`."""
    assert {member.value for member in AcceptAllOutcome} == {
        "suspected",
        "not_suspected",
        "inconclusive",
        "temporary",
        "refused",
    }
    assert not {member.value for member in AcceptAllOutcome} & {status.value for status in Status}


def test_only_decided_outcomes_may_be_cached() -> None:
    """A transient answer must not become a seven-day one."""
    assert (
        frozenset({AcceptAllOutcome.SUSPECTED, AcceptAllOutcome.NOT_SUSPECTED})
        == accept_all_domain.CACHEABLE_OUTCOMES
    )
    for transient in (
        AcceptAllOutcome.TEMPORARY,
        AcceptAllOutcome.INCONCLUSIVE,
        AcceptAllOutcome.REFUSED,
    ):
        assert transient not in accept_all_domain.CACHEABLE_OUTCOMES


# --- privacy ----------------------------------------------------------------


def test_the_cache_key_has_no_field_a_local_part_could_occupy() -> None:
    """Accept-all is a domain property; the key's shape says so."""
    from emailcheck.ports.accept_all_cache import AcceptAllCacheKey

    fields = set(AcceptAllCacheKey.__dataclass_fields__)

    # `route_digest` joined them in Remediation D: an answer is about the mail
    # system behind the domain, so a domain that moved to different exchangers
    # must not inherit its predecessor's policy for the rest of the window.
    assert fields == {"domain_digest", "sender_digest", "experiment_version", "route_digest"}
    for absent in ("local_part", "target", "address", "mailbox"):
        assert absent not in fields


def test_the_experiment_never_puts_the_control_into_evidence_details() -> None:
    """The generated address reaches `RCPT TO` and nothing else."""
    code = code_without_docstrings(PHASE_9_MODULES["application"])

    # The one place the control value is read is where the address is built.
    assert code.count("control.value") == 1
    assert "details={'experiment_version': EXPERIMENT_VERSION}" in code.replace('"', "'")


# --- F5: the reason mapping is a closed contract ----------------------------


def test_the_mapping_names_exactly_the_recipient_stage_reasons() -> None:
    """Exhaustive and closed, read from Phase 4D's published set.

    An independent review measured the correspondence true and unpinned, which
    is the state in which it stops being true without anybody noticing. The
    module now refuses to import when it drifts; this states the contract where
    a reader looks for it.
    """
    from emailcheck.application.accept_all import OUTCOME_BY_REASON
    from emailcheck.application.smtp_evidence import RECIPIENT_STAGE_REASONS

    assert set(OUTCOME_BY_REASON) == RECIPIENT_STAGE_REASONS
    assert len(OUTCOME_BY_REASON) == 8


def test_suspicion_is_exactly_phase_5s_positive_recipient_set() -> None:
    """The two lists mean the same thing, so they are pinned to be the same list.

    An acceptance of a recipient nobody created is what this experiment
    measures, and `POSITIVE_RECIPIENT_REASONS` is what Phase 5 calls an
    acceptance. Two lists that mean one thing drift.
    """
    from emailcheck.application.accept_all import OUTCOME_BY_REASON
    from emailcheck.application.smtp_evidence import POSITIVE_RECIPIENT_REASONS

    suspected = {
        reason
        for reason, outcome in OUTCOME_BY_REASON.items()
        if outcome is AcceptAllOutcome.SUSPECTED
    }

    assert suspected == POSITIVE_RECIPIENT_REASONS


def test_an_unmapped_recipient_reason_raises_rather_than_defaulting() -> None:
    """The runtime barrier behind the import guard.

    A `.get` returning `None` for a recipient answer would read as "transient" —
    the direction that looks safe and is wrong, because a reason the mapper
    emitted *about the recipient* is exactly what this experiment classifies.
    `_CONNECT_REASONS` set the precedent: fail loudly rather than default.
    """
    from datetime import UTC, datetime

    from emailcheck.application.accept_all import OUTCOME_BY_REASON, AcceptAllExperiment
    from emailcheck.domain.accept_all import AcceptAllError
    from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
    from emailcheck.domain.reasons import ReasonCode

    read = AcceptAllExperiment._read
    observation = Evidence(
        layer=EvidenceLayer.SMTP,
        reason=ReasonCode.RCPT_ACCEPTED,
        strength=EvidenceStrength.MODERATE,
        observed_at=datetime(2026, 8, 12, tzinfo=UTC),
    )

    # With the entry present, it maps.
    assert read(None, (observation,)) is AcceptAllOutcome.SUSPECTED  # type: ignore[arg-type]

    # With it absent, it raises rather than answering `temporary`.
    without = {k: v for k, v in OUTCOME_BY_REASON.items() if k is not ReasonCode.RCPT_ACCEPTED}
    with (
        mock.patch.object(accept_all_application, "OUTCOME_BY_REASON", without),
        pytest.raises(AcceptAllError),
    ):
        read(None, (observation,))  # type: ignore[arg-type]


def test_non_recipient_evidence_is_still_temporary_rather_than_an_error() -> None:
    """The fallback that must survive: a TLS failure says nothing about a domain."""
    from datetime import UTC, datetime

    from emailcheck.application.accept_all import AcceptAllExperiment
    from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
    from emailcheck.domain.reasons import ReasonCode

    tls = Evidence(
        layer=EvidenceLayer.SMTP,
        reason=ReasonCode.SMTP_TLS_FAILURE,
        strength=EvidenceStrength.WEAK,
        observed_at=datetime(2026, 8, 12, tzinfo=UTC),
    )

    assert AcceptAllExperiment._read(None, (tls,)) is AcceptAllOutcome.TEMPORARY  # type: ignore[arg-type]
    assert AcceptAllExperiment._read(None, ()) is AcceptAllOutcome.TEMPORARY  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("rcpt_accepted", "suspected"),
        ("rcpt_forwarded", "suspected"),
        ("rcpt_unverifiable", "inconclusive"),
        ("rcpt_rejected_address", "not_suspected"),
        ("rcpt_rejected_policy", "inconclusive"),
        ("smtp_ambiguous_permanent_failure", "inconclusive"),
        ("smtp_temporary_failure", "temporary"),
        ("mailbox_full", "temporary"),
    ],
)
def test_the_published_mapping_row_by_row(reason: str, expected: str) -> None:
    """The whole table, by published reason-code name rather than by reply code."""
    from emailcheck.application.accept_all import OUTCOME_BY_REASON

    by_value = {code.value: outcome for code, outcome in OUTCOME_BY_REASON.items()}

    assert by_value[reason].value == expected


# --- repr hardening ---------------------------------------------------------


def test_the_experiment_repr_shows_configuration_and_hides_collaborators() -> None:
    """A generated `repr` prints whatever it is handed.

    An independent review found it reaching a test transport's recorded wire
    bytes, including the control local part. Production transports record
    nothing, so that was not a production leak — and hiding the collaborators
    makes it not a leak whatever is wired in. The configuration stays visible:
    an operator reading a `repr` needs to see which settings and which
    authorized domains are in force.
    """
    import dataclasses

    from emailcheck.application.accept_all import AcceptAllExperiment

    hidden = {field.name for field in dataclasses.fields(AcceptAllExperiment) if not field.repr}

    assert hidden == {"verification", "guard", "cache", "clock", "random_source", "correlation_key"}
    shown = {field.name for field in dataclasses.fields(AcceptAllExperiment) if field.repr}
    assert shown == {"settings", "authorization", "sender_identity"}
