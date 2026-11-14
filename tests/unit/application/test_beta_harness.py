"""The limited-beta harness: off by default, allowlisted, and bounded.

`docs/beta-report-template.md`. Every test here uses fakes —
the harness is the one component whose *purpose* is to reach real hosts, so it
is exactly the component whose default must be measured rather than assumed.
"""

from __future__ import annotations

import asyncio
import dataclasses
import pathlib

import pytest
from tests.phase6_fixtures import (
    PRINCIPAL,
    ScriptedSMTPVerification,
    build_service,
    resolver_with_route,
)
from tests.phase7_fixtures import CORRELATION_KEY, SteppableClock

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.beta import (
    Agreement,
    BetaHarness,
    BetaRefused,
    BetaReport,
    BetaRow,
    classify_agreement,
)
from emailcheck.domain.beta import (
    BetaAuthorization,
    BetaCorpus,
    BetaExecutionState,
    BetaLimits,
    BetaTarget,
    ControlledTruth,
)
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Status
from emailcheck.security.identifiers import CorrelationKeyError

asyncio_test = pytest.mark.asyncio

AUTH = "TICKET-1001 domain owner agreed in writing"


def corpus(*entries: tuple[str, ControlledTruth]) -> BetaCorpus:
    return BetaCorpus(targets=tuple(BetaTarget(address, truth, AUTH) for address, truth in entries))


def harness(
    authorization: BetaAuthorization, *, smtp: ScriptedSMTPVerification | None = None
) -> tuple[BetaHarness, ScriptedSMTPVerification]:
    probe = smtp or ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=probe)
    return (
        BetaHarness(
            verification=service,
            principal=PRINCIPAL,
            clock=SteppableClock(),
            authorization=authorization,
            correlation_key=CORRELATION_KEY,
            ruleset="aggregation-test",
            dataset_versions={"disposable": "empty-2026-08-07"},
        ),
        probe,
    )


# --- default off -------------------------------------------------------------


@asyncio_test
async def test_the_default_run_is_a_dry_run_and_opens_nothing() -> None:
    """`run()` with no argument is the reflex invocation, so it is the one that
    must probe nothing."""
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized)

    report = await runner.run()

    assert report.dry_run is True
    assert probe.calls == []
    assert [row.execution_state for row in report.rows] == [BetaExecutionState.NOT_RUN.value]
    assert [row.status for row in report.rows] == [None]


@asyncio_test
async def test_a_live_run_without_operator_authorization_is_refused() -> None:
    """`external_probing_authorized` is `False` by default and nothing infers
    it. `docs/beta-report-template.md`'s exit criteria give that decision to a
    human who has verified every gate in `docs/operations.md`."""
    runner, probe = harness(
        BetaAuthorization(corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)))
    )

    with pytest.raises(BetaRefused):
        await runner.run(dry_run=False)
    assert probe.calls == []


@asyncio_test
async def test_a_live_run_with_an_empty_corpus_is_refused() -> None:
    """Authorization alone is not enough: there must be something an operator
    wrote down that this run is allowed to reach."""
    runner, probe = harness(BetaAuthorization(external_probing_authorized=True))

    with pytest.raises(BetaRefused):
        await runner.run(dry_run=False)
    assert probe.calls == []


@asyncio_test
async def test_a_dry_run_needs_no_authorization_and_still_probes_nothing() -> None:
    """So an operator can inspect what *would* happen before deciding."""
    runner, probe = harness(
        BetaAuthorization(corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)))
    )
    report = await runner.run()
    assert probe.calls == []
    assert report.corpus_size == 1


# --- the allowlist is the authorization --------------------------------------


@asyncio_test
async def test_an_address_outside_the_corpus_is_refused_even_when_handed_in() -> None:
    """The membership check is re-asserted per target rather than trusted from
    the loop, because this is the function anything added later would call."""
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized)

    stranger = BetaTarget("stranger@elsewhere.test", ControlledTruth.OWNED_MAILBOX, AUTH)
    with pytest.raises(BetaRefused):
        await runner._one(stranger, "d" * 64)
    assert probe.calls == []


@asyncio_test
async def test_only_corpus_members_are_probed() -> None:
    authorized = BetaAuthorization(
        corpus=corpus(
            ("a@example.test", ControlledTruth.OWNED_MAILBOX),
            ("b@example.test", ControlledTruth.OWNED_NONEXISTENT),
        ),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized)
    await runner.run(dry_run=False)
    assert len(probe.calls) == 2


# --- hard bounds -------------------------------------------------------------


@asyncio_test
async def test_a_run_stops_at_the_target_ceiling() -> None:
    """`docs/beta-report-template.md` forbids mass tests; the ceiling is what
    stops an operator's larger corpus becoming one."""
    authorized = BetaAuthorization(
        corpus=corpus(*((f"u{i}@example.test", ControlledTruth.OWNED_MAILBOX) for i in range(10))),
        limits=BetaLimits(max_targets=3),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized)

    report = await runner.run(dry_run=False)

    assert len(probe.calls) == 3
    assert len(report.rows) == 3
    assert report.corpus_size == 10


@asyncio_test
async def test_a_run_is_bounded_in_time_and_accounts_for_every_target() -> None:
    """The bound cuts the run short and **loses nothing**.

    An independent review measured the earlier build starting a verification,
    being cut off, and reporting no row for it — an address contacted with no
    trace in the record. Every selected target now lands in exactly one
    execution state, and the three states are distinguishable: completed, the
    one that was in flight, and the ones that never started.
    """
    slow = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",), delay_seconds=0.05)
    authorized = BetaAuthorization(
        corpus=corpus(*((f"u{i}@example.test", ControlledTruth.OWNED_MAILBOX) for i in range(20))),
        limits=BetaLimits(max_targets=20, max_runtime_seconds=0.12),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized, smtp=slow)

    async with asyncio.timeout(10.0):
        report = await runner.run(dry_run=False)

    summary = report.execution_summary
    assert report.selected_targets == 20
    assert len(report.rows) == 20
    assert sum(summary.values()) == 20
    assert summary[BetaExecutionState.COMPLETED.value] > 0
    assert summary[BetaExecutionState.TIMED_OUT.value] == 1
    assert summary[BetaExecutionState.NOT_RUN.value] > 0
    assert report.truncated is True
    # Every target the SMTP layer was reached for has a row. The count is the
    # completed ones plus the single one that was in flight when time ran out.
    assert len(probe.calls) == (
        summary[BetaExecutionState.COMPLETED.value] + summary[BetaExecutionState.TIMED_OUT.value]
    )


@asyncio_test
async def test_a_timed_out_target_carries_no_fabricated_verdict() -> None:
    """Execution failure and mailbox `Status` stay separate.

    `unknown` and `temporary_unknown` are real published answers. A run this
    project cut short produced no answer at all, and writing one there would be
    the most misleading possible use of a conservative status.
    """
    slow = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",), delay_seconds=0.05)
    authorized = BetaAuthorization(
        corpus=corpus(*((f"u{i}@example.test", ControlledTruth.OWNED_MAILBOX) for i in range(6))),
        limits=BetaLimits(max_targets=6, max_runtime_seconds=0.12),
        external_probing_authorized=True,
    )
    runner, _ = harness(authorized, smtp=slow)

    async with asyncio.timeout(10.0):
        report = await runner.run(dry_run=False)

    cut = [row for row in report.rows if row.execution_state == BetaExecutionState.TIMED_OUT.value]
    assert len(cut) == 1
    assert cut[0].status is None
    assert cut[0].confidence is None
    assert cut[0].primary_reason is None
    assert cut[0].attempted_active is True
    assert cut[0].agreement == Agreement.NOT_APPLICABLE.value
    # And the status distribution is over answers only.
    assert set(report.status_summary) <= {member.value for member in Status}


@asyncio_test
async def test_an_unstarted_target_is_not_reported_as_timed_out() -> None:
    """ "Never contacted" and "contacted and cut off" are different facts."""
    slow = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",), delay_seconds=0.05)
    authorized = BetaAuthorization(
        corpus=corpus(*((f"u{i}@example.test", ControlledTruth.OWNED_MAILBOX) for i in range(6))),
        limits=BetaLimits(max_targets=6, max_runtime_seconds=0.12),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized, smtp=slow)

    async with asyncio.timeout(10.0):
        report = await runner.run(dry_run=False)

    not_run = [
        row for row in report.rows if row.execution_state == BetaExecutionState.NOT_RUN.value
    ]
    assert not_run
    for row in not_run:
        assert row.attempted_active is False
        assert row.refused is None
    assert len(probe.calls) < report.selected_targets


def test_a_row_may_not_carry_a_sentinel_in_the_status_field() -> None:
    """The barrier that keeps the two vocabularies apart, on its own."""
    for sentinel in ("not_run", "refused", "timed_out", "completed"):
        with pytest.raises(BetaRefused):
            BetaRow(
                target_digest="d" * 64,
                truth=ControlledTruth.OWNED_MAILBOX.value,
                execution_state=BetaExecutionState.COMPLETED.value,
                status=sentinel,
                confidence="low",
                primary_reason=None,
                agreement=Agreement.NOT_APPLICABLE.value,
                attempted_active=True,
            )


def test_a_status_exists_exactly_when_a_verification_completed() -> None:
    with pytest.raises(BetaRefused):
        BetaRow(
            target_digest="d" * 64,
            truth=ControlledTruth.OWNED_MAILBOX.value,
            execution_state=BetaExecutionState.NOT_RUN.value,
            status=Status.UNKNOWN.value,
            confidence="low",
            primary_reason=None,
            agreement=Agreement.NOT_APPLICABLE.value,
            attempted_active=False,
        )
    with pytest.raises(BetaRefused):
        BetaRow(
            target_digest="d" * 64,
            truth=ControlledTruth.OWNED_MAILBOX.value,
            execution_state=BetaExecutionState.COMPLETED.value,
            status=None,
            confidence=None,
            primary_reason=None,
            agreement=Agreement.NOT_APPLICABLE.value,
            attempted_active=True,
        )


def test_a_report_refuses_to_lose_a_selected_target() -> None:
    """The accounting invariant, refused at construction rather than in a test."""
    clock = SteppableClock()
    with pytest.raises(BetaRefused):
        BetaReport(
            started_at=clock.now(),
            finished_at=clock.now(),
            ruleset="r",
            dataset_versions={},
            canonical_input_version="v1",
            corpus_size=3,
            corpus_by_truth={},
            dry_run=False,
            selected_targets=3,
            rows=(),
        )


def test_a_truncated_run_says_so_in_the_report_it_writes() -> None:
    """`truncated` is published, not inferred, and it must be honest.

    A reader with the JSON and nothing else has to be able to tell a truncated
    run from a complete one; a field that is always `False` is worse than no
    field, because it looks like an answer.
    """
    clock = SteppableClock()

    def report(rows: tuple[BetaRow, ...]) -> BetaReport:
        return BetaReport(
            started_at=clock.now(),
            finished_at=clock.now(),
            ruleset="r",
            dataset_versions={},
            canonical_input_version="v1",
            corpus_size=len(rows),
            corpus_by_truth={},
            dry_run=False,
            selected_targets=len(rows),
            rows=rows,
        )

    def row(state: BetaExecutionState) -> BetaRow:
        completed = state is BetaExecutionState.COMPLETED
        return BetaRow(
            target_digest="d" * 64,
            truth=ControlledTruth.OWNED_MAILBOX.value,
            execution_state=state.value,
            status=Status.UNKNOWN.value if completed else None,
            confidence="low" if completed else None,
            primary_reason=None,
            agreement=Agreement.INCONCLUSIVE.value,
            attempted_active=completed,
        )

    complete = report((row(BetaExecutionState.COMPLETED),))
    assert complete.truncated is False
    assert complete.as_json_object()["truncated"] is False

    for cut in (BetaExecutionState.TIMED_OUT, BetaExecutionState.NOT_RUN):
        short = report((row(BetaExecutionState.COMPLETED), row(cut)))
        assert short.truncated is True, cut
        assert short.as_json_object()["truncated"] is True, cut

    # A dry run reaches nothing on purpose and is not "truncated".
    dry = BetaReport(
        started_at=clock.now(),
        finished_at=clock.now(),
        ruleset="r",
        dataset_versions={},
        canonical_input_version="v1",
        corpus_size=1,
        corpus_by_truth={},
        dry_run=True,
        selected_targets=1,
        rows=(row(BetaExecutionState.NOT_RUN),),
    )
    assert dry.truncated is False


def test_every_beta_limit_is_a_bound_the_harness_actually_reads() -> None:
    """F6: no knob that lies.

    A field validated and never read is a setting an operator can change with no
    effect, which is worse than no setting at all — an independent review found
    `max_concurrency` in exactly that state. Rather than remembering to check,
    this reads `BetaLimits`' fields and requires the harness to name each one.
    """
    module = (
        pathlib.Path(__file__).resolve().parents[3] / "src/emailcheck/application/beta.py"
    ).read_text()

    for limit in dataclasses.fields(BetaLimits):
        assert f"limits.{limit.name}" in module, (
            f"BetaLimits.{limit.name} is validated but never read by the harness"
        )


def test_the_harness_requires_a_correlation_key_at_construction() -> None:
    """F7: a default that can never work is a footgun, not a default.

    `b""` fails `check_correlation_key` every time, so the advertised-safe
    `run()` raised out of a security module instead of producing a dry-run
    report. The key now comes from composition, like every other secret.
    """
    assert not any(
        field.name == "correlation_key" and field.default is not dataclasses.MISSING
        for field in dataclasses.fields(BetaHarness)
    ), "correlation_key has a default again"

    with pytest.raises(TypeError):
        BetaHarness(  # type: ignore[call-arg]
            verification=None,  # type: ignore[arg-type]
            principal=PRINCIPAL,
            clock=SteppableClock(),
            authorization=BetaAuthorization(),
        )


def test_an_unusable_correlation_key_is_refused_before_a_run_starts() -> None:
    """Refused at construction, by the existing validator, not part way through."""
    for unusable in (b"", b"too-short"):
        with pytest.raises(CorrelationKeyError):
            BetaHarness(
                verification=None,  # type: ignore[arg-type]
                principal=PRINCIPAL,
                clock=SteppableClock(),
                authorization=BetaAuthorization(),
                correlation_key=unusable,
            )


@asyncio_test
async def test_the_default_run_is_reflex_safe_once_the_key_is_supplied() -> None:
    """The docstring's promise, measured: no argument, no socket, a real report."""
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, probe = harness(authorized)

    report = await runner.run()

    assert report.dry_run is True
    assert probe.calls == []
    assert report.selected_targets == len(report.rows) == 1


def test_the_published_agreement_vocabulary_is_exactly_four_values() -> None:
    """F3: the exported strings, pinned as a closed set.

    The earlier guard was a blocklist of five words compared against the *set of
    values*, so renaming `consistent` to `accuracy_correct` walked straight
    past it. A closed-set equality is the only form that catches an arbitrary
    rename, and these four strings are what a beta report file carries.
    """
    assert {member.value for member in Agreement} == {
        "consistent",
        "contradicts",
        "inconclusive",
        "not_applicable",
    }


# --- no status is re-derived -------------------------------------------------


@pytest.mark.parametrize(
    ("truth", "status", "expected"),
    [
        (ControlledTruth.OWNED_MAILBOX, Status.LIKELY_DELIVERABLE, Agreement.CONSISTENT),
        (ControlledTruth.OWNED_MAILBOX, Status.INVALID, Agreement.CONTRADICTS),
        (ControlledTruth.OWNED_MAILBOX, Status.UNKNOWN, Agreement.INCONCLUSIVE),
        (ControlledTruth.OWNED_MAILBOX, Status.TEMPORARY_UNKNOWN, Agreement.INCONCLUSIVE),
        (ControlledTruth.OWNED_NONEXISTENT, Status.INVALID, Agreement.CONSISTENT),
        (ControlledTruth.OWNED_NONEXISTENT, Status.LIKELY_DELIVERABLE, Agreement.CONTRADICTS),
        (ControlledTruth.OWNED_ACCEPT_ALL, Status.LIKELY_DELIVERABLE, Agreement.NOT_APPLICABLE),
        (ControlledTruth.AUTHORIZED_TENANT, Status.INVALID, Agreement.NOT_APPLICABLE),
    ],
    ids=lambda v: getattr(v, "value", str(v)),
)
def test_agreement_is_named_as_agreement_never_as_correctness(
    truth: ControlledTruth, status: Status, expected: Agreement
) -> None:
    """`docs/requirements.md` section 1: this project does not prove existence.
    A `250` beside an arranged mailbox is two observations pointing the same
    way, which is what `consistent` says and what `correct` would not."""
    verdict = _verdict_with(status)
    assert classify_agreement(truth, verdict) is expected


def test_an_unknown_status_is_never_scored_as_a_failure() -> None:
    """A beta that counted `unknown` as wrong would create pressure to widen the
    statuses, and section 17 makes conservatism the requirement."""
    for truth in ControlledTruth:
        for status in (Status.UNKNOWN, Status.TEMPORARY_UNKNOWN):
            assert classify_agreement(truth, _verdict_with(status)) is Agreement.INCONCLUSIVE


def test_the_agreement_vocabulary_names_no_correctness() -> None:
    values = {member.value for member in Agreement}
    for forbidden in ("correct", "incorrect", "accuracy", "true_positive", "false_positive"):
        assert forbidden not in values


# --- the report is safe to write ---------------------------------------------


@asyncio_test
async def test_no_report_row_carries_an_address() -> None:
    local = "very.secret.localpart+tag"
    authorized = BetaAuthorization(
        corpus=corpus((f"{local}@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, _ = harness(authorized)

    report = await runner.run(dry_run=False)
    rendered = str(report.as_json_object())

    assert local not in rendered
    assert f"{local}@example.test" not in rendered
    assert len(report.rows[0].target_digest) == 64


@asyncio_test
async def test_the_report_carries_the_reproducibility_metadata_and_no_secret() -> None:
    """Work item 6: ruleset and dataset version reporting. A measurement whose
    ruleset nobody recorded cannot be compared with a later one."""
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, _ = harness(authorized)

    report = await runner.run(dry_run=False)
    body = report.as_json_object()

    assert body["ruleset"] == "aggregation-test"
    assert body["dataset_versions"] == {"disposable": "empty-2026-08-07"}
    assert body["canonical_input_version"] == "v1"
    rendered = str(body)
    assert CORRELATION_KEY.decode() not in rendered
    assert "correlation" not in rendered


@asyncio_test
async def test_only_allowlisted_detail_keys_reach_a_row() -> None:
    """`Evidence.details` wholesale is forbidden: a detail a producer adds later
    must not silently join a beta export."""
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, _ = harness(authorized)
    report = await runner.run(dry_run=False)

    exported = set(report.rows[0].as_json_object())
    assert exported == {
        "target_digest",
        "truth",
        "execution_state",
        "status",
        "confidence",
        "primary_reason",
        "agreement",
        "attempted_active",
        "tls_negotiated",
        "tls_reason",
        "stage_reached",
        "elapsed_milliseconds",
        "refused",
    }


def test_the_tls_summary_uses_the_existing_taxonomy_only() -> None:
    """ADR 0009's obligation is measured with `tls_reason`, whose values are
    `TLSFailureReason`'s. No new vocabulary is invented for the beta."""
    from emailcheck.application.beta import BetaReport
    from emailcheck.domain.smtp_tls import TLSFailureReason

    rows = tuple(
        BetaRow(
            target_digest="d" * 64,
            truth=ControlledTruth.OWNED_MAILBOX.value,
            execution_state=BetaExecutionState.COMPLETED.value,
            status="unknown",
            confidence="low",
            primary_reason=None,
            agreement=Agreement.INCONCLUSIVE.value,
            attempted_active=True,
            tls_negotiated=False,
            tls_reason=reason.value,
        )
        for reason in TLSFailureReason
    )
    clock = SteppableClock()
    report = BetaReport(
        started_at=clock.now(),
        finished_at=clock.now(),
        ruleset="r",
        dataset_versions={},
        canonical_input_version="v1",
        corpus_size=len(rows),
        corpus_by_truth={},
        dry_run=False,
        selected_targets=len(rows),
        rows=rows,
    )

    assert set(report.tls_summary) == {reason.value for reason in TLSFailureReason}
    assert "not_offered" in report.tls_summary


# --- refusals are recorded as refusals ---------------------------------------


@asyncio_test
async def test_a_local_refusal_is_recorded_as_one_and_never_as_a_status() -> None:
    """ADR 0013: capacity is not a fact about an address."""
    from emailcheck.application.verification import VerificationRefused

    refusing = ScriptedSMTPVerification(
        reply_lines=("250 2.1.5 ok",), raises=VerificationRefused("an abuse control")
    )
    authorized = BetaAuthorization(
        corpus=corpus(("ok@example.test", ControlledTruth.OWNED_MAILBOX)),
        external_probing_authorized=True,
    )
    runner, _ = harness(authorized, smtp=refusing)

    report = await runner.run(dry_run=False)
    row = report.rows[0]

    assert row.execution_state == BetaExecutionState.REFUSED.value
    assert row.status is None
    assert row.refused == "VerificationRefused"
    assert row.agreement == Agreement.NOT_APPLICABLE.value
    assert report.status_summary == {}


def _verdict_with(status: Status):  # type: ignore[no-untyped-def]
    """A real `Verdict` in the requested status, built by the real aggregator."""
    reason = {
        Status.LIKELY_DELIVERABLE: ReasonCode.RCPT_ACCEPTED,
        Status.INVALID: ReasonCode.RCPT_REJECTED_ADDRESS,
        Status.TEMPORARY_UNKNOWN: ReasonCode.SMTP_TEMPORARY_FAILURE,
        Status.UNKNOWN: ReasonCode.RCPT_UNVERIFIABLE,
    }[status]
    evidence = [
        Evidence(
            layer=EvidenceLayer.SMTP,
            reason=reason,
            strength=EvidenceStrength.MODERATE,
            observed_at=__import__("tests.phase6_fixtures", fromlist=["OBSERVED_AT"]).OBSERVED_AT,
            temporary=status is Status.TEMPORARY_UNKNOWN,
        )
    ]
    if status is Status.LIKELY_DELIVERABLE:
        evidence.append(
            Evidence(
                layer=EvidenceLayer.DNS,
                reason=ReasonCode.MX_AVAILABLE,
                strength=EvidenceStrength.WEAK,
                observed_at=evidence[0].observed_at,
            )
        )
    verdict = aggregate_evidence(tuple(evidence))
    assert verdict.status is status, (status, verdict.status)
    return verdict
