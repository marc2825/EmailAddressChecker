"""The pure half of gate 4E: which endpoints, in what order, and how many.

Planning is a function of a Phase 2 `MailRoute` and nothing else — no clock, no
limiter, no socket — so it is tested as one. Two questions live here that a
behavioural test could only answer indirectly: whether the plan preserves the
ordering a domain published, and whether "the recipient was touched" is decided
by two independent barriers rather than by one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dialogue_fixtures import candidate, route
from emailcheck.application.smtp_verification import (
    AttemptOutcome,
    AttemptRecord,
    VerificationReport,
    VerificationSettings,
    VerificationStop,
    plan_attempts,
    touched_the_recipient,
)
from emailcheck.domain.mail_route import MailRouteOutcome
from emailcheck.domain.smtp_capabilities import Capabilities
from emailcheck.domain.smtp_contract import SMTPCommand, SMTPContractError, SMTPState
from emailcheck.domain.smtp_protocol import CleanupStatus, DialogueStage, SessionReport
from emailcheck.domain.smtp_result import RecipientObservation, RecipientStageOutcome
from emailcheck.domain.smtp_tls import TLSOutcomeDetail

FIRST = "93.184.216.34"
SECOND = "93.184.216.35"


def two_host_route():  # type: ignore[no-untyped-def]
    """A primary and a secondary, in preference order."""
    return route(
        candidate(FIRST, host="mx1.test.example", preference=10),
        candidate(SECOND, host="mx2.test.example", preference=20),
    )


# --- planning ---------------------------------------------------------------


def test_the_plan_keeps_phase_2s_preference_order() -> None:
    """MX preference is a publisher's instruction, not this gate's to re-decide."""
    planned = plan_attempts(
        route(
            candidate(SECOND, host="mx2.test.example", preference=20),
            candidate(FIRST, host="mx1.test.example", preference=10),
        )
    )

    # `connectable_candidates` preserves the route's own order, and so does this.
    assert [item.address for item in planned] == [SECOND, FIRST]


def test_the_plan_expands_every_address_of_one_candidate_in_order() -> None:
    planned = plan_attempts(route(candidate(FIRST, SECOND, host="mx1.test.example")))

    assert [item.address for item in planned] == [FIRST, SECOND]


def test_the_plan_is_deterministic() -> None:
    """Nothing is sorted, shuffled, or read out of a set.

    A randomized scan would make one verification's behaviour unreproducible,
    and choosing a different endpoint to get a different answer is the rotation
    shape `CONTRIBUTING.md` forbids outright.
    """
    mail_route = two_host_route()
    first = plan_attempts(mail_route)
    second = plan_attempts(mail_route)

    assert [item.identity for item in first] == [item.identity for item in second]


def test_one_endpoint_is_never_planned_twice() -> None:
    """Two candidates can resolve to the same address, and often do."""
    planned = plan_attempts(
        route(
            candidate(FIRST, host="mx1.test.example", preference=10),
            candidate(FIRST, SECOND, host="mx1.test.example", preference=20),
        )
    )

    assert [item.address for item in planned] == [FIRST, SECOND]


def test_the_same_address_behind_two_exchangers_is_two_attempts() -> None:
    """De-duplicating on the address alone would collapse two TLS identities.

    The certificate is verified against the MX host name, so `mx1` and `mx2`
    sharing an address are still two different things to connect to — and
    treating them as one would silently accept one host's certificate for the
    other's name.
    """
    planned = plan_attempts(
        route(
            candidate(FIRST, host="mx1.test.example", preference=10),
            candidate(FIRST, host="mx2.test.example", preference=20),
        )
    )

    assert [item.identity for item in planned] == [
        ("mx1.test.example", FIRST, 25),
        ("mx2.test.example", FIRST, 25),
    ]


@pytest.mark.parametrize(
    "outcome",
    [
        MailRouteOutcome.NULL_MX,
        MailRouteOutcome.NO_MAIL_ROUTE,
        MailRouteOutcome.DOMAIN_NOT_FOUND,
        MailRouteOutcome.TEMPORARY_FAILURE,
        MailRouteOutcome.CONFIGURATION_ANOMALY,
        MailRouteOutcome.UNSAFE_DESTINATION,
        MailRouteOutcome.INTERNAL_ERROR,
    ],
)
def test_a_routeless_outcome_plans_nothing(outcome: MailRouteOutcome) -> None:
    """Phase 2's boundary, kept rather than re-derived."""
    assert plan_attempts(route(candidate(FIRST), outcome=outcome)) == ()


@pytest.mark.parametrize("value", [0, -1, True, False, 9, 100, "3", None])
def test_the_attempt_cap_refuses_a_value_that_is_not_a_cap(value: object) -> None:
    with pytest.raises(SMTPContractError):
        VerificationSettings(max_attempts=value)  # type: ignore[arg-type]


# --- the recipient-touched rule has two barriers ----------------------------


def report_with(
    *,
    stage: DialogueStage,
    transcript: tuple[SMTPCommand, ...],
    recipients: int,
) -> SessionReport:
    """A report assembled field by field, so exactly one barrier refuses it."""
    return SessionReport(
        observation=RecipientObservation(
            outcome=RecipientStageOutcome.CONNECTION_ERROR,
            final_state=SMTPState.CLOSED,
            recipients_attempted=recipients,
        ),
        stage_reached=stage,
        tls=TLSOutcomeDetail(),
        capabilities=Capabilities(),
        cleanup=CleanupStatus.NOT_ATTEMPTED,
        commands_issued=transcript,
    )


def test_the_transcript_barrier_alone_catches_a_written_recipient() -> None:
    """`SessionReport` permits a transcript naming `RCPT TO` before that stage.

    It is the shape gate 4D's own barrier tests are built from, so it is a shape
    this project has already decided is constructible. The stage check alone
    would let it through.
    """
    touched = report_with(
        stage=DialogueStage.MAIL_FROM,
        transcript=(SMTPCommand.EHLO, SMTPCommand.RCPT_TO),
        recipients=1,
    )

    assert touched_the_recipient(touched) is True


def test_the_stage_barrier_alone_catches_a_recipient_write_that_failed() -> None:
    """The stage is set before the command is written, and a failed write leaves
    the transcript empty — so only the stage says this happened."""
    touched = report_with(stage=DialogueStage.RCPT_TO, transcript=(), recipients=0)

    assert touched_the_recipient(touched) is True


def test_a_session_that_never_reached_the_recipient_is_not_touched() -> None:
    for stage in (
        DialogueStage.CONNECTED,
        DialogueStage.BANNER,
        DialogueStage.EHLO,
        DialogueStage.STARTTLS,
        DialogueStage.TLS_HANDSHAKE,
        DialogueStage.EHLO_AFTER_TLS,
        DialogueStage.MAIL_FROM,
    ):
        untouched = report_with(stage=stage, transcript=(SMTPCommand.EHLO,), recipients=0)
        assert touched_the_recipient(untouched) is False, stage


def test_the_cleanup_stage_counts_as_past_the_recipient() -> None:
    """Every real recipient answer arrives at `cleanup`, not at `rcpt_to`."""
    assert (
        touched_the_recipient(report_with(stage=DialogueStage.CLEANUP, transcript=(), recipients=0))
        is True
    )


def test_a_report_refuses_to_claim_two_recipient_attempts() -> None:
    """The loop enforces it, and the type refuses it. Two barriers."""
    from emailcheck.application.smtp_verification import AttemptRecord

    def record(index: int) -> AttemptRecord:
        return AttemptRecord(
            index=index,
            mx_host=f"mx{index}.test.example",
            outcome=AttemptOutcome.RECIPIENT_ATTEMPTED,
            stage_reached="cleanup",
            recipient_attempted=True,
            reached_the_network=True,
        )

    with pytest.raises(SMTPContractError):
        VerificationReport(
            attempts=(record(0), record(1)),
            evidence=(),
            stopped_because=VerificationStop.RECIPIENT_ATTEMPTED,
        )


# --- inspection: what the orchestration tree may not contain ----------------
#
# A behavioural test cannot enumerate the shortcuts it has not thought of. These
# read the source of the two modules gate 4E added, on the precedent set when a
# provider-specific TLS branch passed every dialogue test in the repository.

ORCHESTRATION = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
FOURE_MODULES = (
    ORCHESTRATION / "application" / "smtp_verification.py",
    ORCHESTRATION / "domain" / "rate_limit.py",
    ORCHESTRATION / "adapters" / "system" / "rate_limit.py",
)


def _code_tokens(module: Path) -> list[tuple[int, str]]:
    """Every identifier and every non-docstring literal, lower-cased.

    Docstrings are excluded and comments never enter the syntax tree at all, so
    a module may explain at length that it does not back off without its own
    explanation failing the check. Both of these tests were written against the
    raw text first and both failed on their own prose, which is the third time
    this repository has made that mistake.
    """
    import ast

    tree = ast.parse(module.read_text(encoding="utf-8"))
    documented: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                documented.add(id(first.value))

    tokens: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in documented
        ):
            tokens.append((node.lineno, node.value.lower()))
        for attribute in ("id", "attr", "name"):
            value = getattr(node, attribute, None)
            if isinstance(value, str):
                tokens.append((node.lineno, value.lower()))
        if isinstance(node, ast.Import):
            tokens.extend((node.lineno, alias.name.lower()) for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            tokens.append((node.lineno, node.module.lower()))
    return tokens


@pytest.mark.inspection
def test_no_module_retries_or_backs_off() -> None:
    """Bounded fallback to a *different* candidate is the only movement here.

    `docs/requirements.md` section 14 puts one automatic retry in the pipeline,
    on a schedule, with a delay measured in minutes — not inside a probe and not
    against the endpoint that just failed. A retry loop here would also defeat
    the one-`RCPT TO` invariant the moment it retried the recipient stage.
    """
    forbidden = ("backoff", "exponential", "jitter", "reconnect", "retry", "reattempt")
    offences: list[str] = []
    for module in FOURE_MODULES:
        for lineno, token in _code_tokens(module):
            offences.extend(f"{module.name}:{lineno} {name}" for name in forbidden if name in token)
    assert offences == [], f"a retry mechanism appears in the 4E tree: {offences}"


@pytest.mark.inspection
def test_only_the_limiter_may_suspend() -> None:
    """Pacing is a limiter's job; an orchestration sleep would be a backoff.

    The limiter suspends through the injected `Sleeper`, which is why it may.
    The verification loop has no delay of any kind between attempts.
    """
    import ast

    verification = (ORCHESTRATION / "application" / "smtp_verification.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(verification)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr != "sleep", f"the verification loop sleeps at line {node.lineno}"
        if isinstance(node, ast.Name):
            assert node.id != "sleep", f"the verification loop sleeps at line {node.lineno}"
    assert "asyncio" not in verification


@pytest.mark.inspection
def test_no_module_generates_a_recipient() -> None:
    """Accept-all detection is Phase 9, and it starts with an invented mailbox.

    A random or synthetic local part is the one thing this gate could add that
    would put an address on the wire that nobody asked about.
    """
    forbidden = ("random", "uuid", "secrets", "accept_all", "catch_all", "catchall", "shuffle")
    offences: list[str] = []
    for module in FOURE_MODULES:
        for lineno, token in _code_tokens(module):
            offences.extend(f"{module.name}:{lineno} {name}" for name in forbidden if name in token)
    assert offences == [], f"the 4E tree can invent a recipient: {offences}"


@pytest.mark.inspection
def test_no_module_produces_a_status() -> None:
    """Phase 5's vocabulary, kept out of the layer that would reach for it first.

    Docstrings are exempt for the reason the dialogue's version of this test
    exempts them: this module's own prose explains that it produces no status,
    and a text search would find its own explanation.
    """
    import ast

    forbidden = {
        "Status",
        "Verdict",
        "Confidence",
        "ConfidenceLevel",
        "RiskFlag",
        "aggregate_evidence",
        "likely_deliverable",
        "temporary_unknown",
    }
    offences: list[str] = []
    for module in FOURE_MODULES:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in forbidden:
                offences.append(f"{module.name}:{node.lineno} {node.value}")
            for attribute in ("id", "attr", "name"):
                value = getattr(node, attribute, None)
                if isinstance(value, str) and value in forbidden:
                    offences.append(f"{module.name}:{node.lineno} {value}")
    assert offences == [], f"the 4E tree names Phase 5 vocabulary: {offences}"


@pytest.mark.inspection
def test_the_orchestrator_owns_no_transport_and_no_raw_address() -> None:
    """A raw address handed to a transport would skip `approve_destination`.

    The loop holds a `SMTPProbeService` and nothing lower, so there is no
    `connect` for it to call and no way to reach a socket except through the
    chain gate 4B built. An import is what such a shortcut would need first.
    """
    import ast

    tree = ast.parse((ORCHESTRATION / "application" / "smtp_verification.py").read_text("utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.name for alias in node.names)
        if isinstance(node, ast.Attribute):
            assert node.attr != "connect", "the loop reaches a transport directly"
    for forbidden in ("SMTPTransport", "SMTPConnection", "SMTPConnector", "ApprovedDestination"):
        assert forbidden not in imported, f"the loop imports {forbidden}"


@pytest.mark.inspection
def test_the_limiter_key_is_built_from_no_local_part() -> None:
    """The three components `RateLimiter.acquire` takes, and nothing else."""
    import ast

    probe = (ORCHESTRATION / "application" / "smtp_probe.py").read_text(encoding="utf-8")
    tree = ast.parse(probe)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "acquire"
    ]
    assert calls, "nothing acquires a budget in the probe service"
    for call in calls:
        keywords = {keyword.arg for keyword in call.keywords}
        assert keywords == {"account", "domain", "mx_host"}, keywords
        for keyword in call.keywords:
            rendered = ast.dump(keyword.value)
            assert "local" not in rendered.lower(), f"a budget key reads a local part: {rendered}"


def test_every_attempt_outcome_decides_whether_it_stops_the_loop() -> None:
    """A member absent from the table continues, which is the permissive answer.

    `_stop_for` is a table rather than a chain of `if`s so that adding an
    outcome without deciding this question is visible here instead of being
    discovered as a verification that walked on after something it should have
    stopped for.
    """
    from emailcheck.application.smtp_verification import _STOPS, _stop_for

    continues = {AttemptOutcome.PRE_RECIPIENT_FAILURE, AttemptOutcome.NOT_CONNECTED}
    for outcome in AttemptOutcome:
        decided = outcome in _STOPS or outcome in continues
        assert decided, f"{outcome} is neither a stop nor a documented continue"
        assert (_stop_for(outcome) is None) is (outcome in continues), outcome
