"""The limited-beta harness: bounded, allowlisted, and off unless told otherwise.

`prompts/08-limited-beta.md` work items 4 and 5 — *a controlled manual
integration test harness disabled by default*, and *an explicit allowlist or
authorization record for beta targets*. This is both, and the two are one object
because a harness whose allowlist is optional is a harness with no allowlist.

**It probes through the production service and nothing else.** `verification` is
the same `AddressVerificationService` an API request goes through, so admission,
the Phase 4 limiter, the Phase 7 quota layers, the destination policy, the
one-`RCPT TO` bound, the total deadline, and the kill switch all apply exactly as
they do in production. There is no parameter here that disables any of them,
because a measurement taken with the safety controls off measures a system
nobody will run.

**Four independent things must all be true before a socket opens:**

| Gate | Where |
|---|---|
| the operator authorized external probing | `BetaAuthorization.external_probing_authorized` |
| the corpus is non-empty | `BetaCorpus` |
| *this* address is in the corpus | `BetaCorpus.entry_for` |
| every production control permits it | the verification service |

The first is `False` by default and nothing infers it.
`prompts/08-limited-beta.md`'s exit criteria require a **human** to verify every
deployment gate in `docs/operations.md` before a beta starts, and this field is
where that decision is recorded rather than assumed.

**Nothing here decides a status.** A run records the `Verdict` the Phase 5
aggregator produced and the controlled-truth class an operator arranged, side by
side, and compares them nowhere except in a named `agreement` field whose
vocabulary says what it is. `if reply == 250: correct += 1` is exactly the
re-derivation Phase 5 stop condition 1 forbids, and a beta script is not exempt
from it.

**A result row carries no address.** The target appears as the Phase 7 versioned
HMAC and nothing else, so a result file is analysable without being a list of
who was probed. `docs/requirements.md` section 16 forbids a full address in an
ordinary log and a beta output file is ordinary.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from emailcheck.application.verification import (
    AddressVerificationService,
    SubmittedInputTooLong,
    VerificationRefused,
)
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.beta import (
    ARRANGED_ABSENT,
    ARRANGED_RECEIVING,
    BetaAuthorization,
    BetaExecutionState,
    BetaTarget,
    ControlledTruth,
)
from emailcheck.domain.principal import Principal
from emailcheck.domain.verdict import Status, Verdict
from emailcheck.ports.clock import Clock
from emailcheck.security.identifiers import (
    CANONICAL_INPUT_VERSION,
    check_correlation_key,
    correlation_digest,
)

#: The two closed vocabularies a row is checked against, resolved once.
_EXECUTION_VALUES: Final[frozenset[str]] = frozenset(state.value for state in BetaExecutionState)
_STATUS_VALUES: Final[frozenset[str]] = frozenset(status.value for status in Status)

#: The detail keys a beta row may read out of `Evidence.details`.
#:
#: An allowlist rather than a copy: `docs/status-model.md` bounds what a detail
#: may hold, but a beta export that took the whole mapping would ship whatever a
#: producer adds later. These four are what `prompts/08-limited-beta.md`'s
#: metrics and ADR 0009's measurement obligation actually need.
EXPORTED_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {"tls_negotiated", "tls_reason", "elapsed_milliseconds", "stage_reached"}
)


class BetaRefused(Exception):
    """This beta run, or this target, may not proceed.

    Not a `TimeoutError` and not an `OSError`, on the precedent every other
    refusal in this project sets: a harness refusing to start is not a fact
    about anybody's mailbox.
    """


class Agreement(StrEnum):
    """How a `Verdict` sat beside what an operator arranged.

    Deliberately **not** `correct` / `incorrect`. `docs/requirements.md` section
    1 says this project does not prove mailbox existence, so a `250` agreeing
    with an arranged mailbox is two observations pointing the same way rather
    than a proof that either was right. The names say what was measured.
    """

    #: The verdict pointed the same way as the arrangement.
    CONSISTENT = "consistent"
    #: The verdict pointed the other way. The row an audit reads first.
    CONTRADICTS = "contradicts"
    #: The verdict was `unknown` or `temporary_unknown`; nothing to compare.
    INCONCLUSIVE = "inconclusive"
    #: The arrangement makes no prediction about a recipient answer — an
    #: accept-all domain says `250` to everyone, and a Null MX domain never
    #: reaches a recipient at all.
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class BetaRow:
    """One selected target's outcome, in fields that may be written to a file.

    **Two vocabularies, and keeping them apart is the point.**
    `execution_state` says what the harness did; `status` is the published
    deliverability answer and exists **only** when a verification completed.
    An earlier build wrote `"not_run"` and `"refused"` into `status`, so a
    beta's status distribution mixed mailbox answers with harness bookkeeping —
    which is how "unknown rate" quietly becomes wrong.
    """

    target_digest: str
    truth: str
    #: One of `BetaExecutionState`. Every selected target has exactly one.
    execution_state: str
    #: A published `Status` value, or `None` when no verdict exists. Never a
    #: sentinel: `__post_init__` refuses one.
    status: str | None
    confidence: str | None
    primary_reason: str | None
    agreement: str
    attempted_active: bool
    #: `tls_negotiated`, `tls_reason`, `stage_reached`, `elapsed_milliseconds`.
    #: ADR 0009's measurement obligation needs the first two by name.
    tls_negotiated: bool | None = None
    tls_reason: str | None = None
    stage_reached: str | None = None
    elapsed_milliseconds: int | None = None
    #: The refusal category, when `execution_state` is `refused`. A bounded
    #: local vocabulary — an exception's *type name*, never its message, which
    #: could carry a path, a host, or an address.
    refused: str | None = None

    def __post_init__(self) -> None:
        if self.execution_state not in _EXECUTION_VALUES:
            raise BetaRefused(f"unknown beta execution state {self.execution_state!r}")
        if self.status is not None and self.status not in _STATUS_VALUES:
            # The barrier that keeps the two vocabularies apart. A sentinel
            # reaching this field is the defect, not the report that prints it.
            raise BetaRefused(f"{self.status!r} is not a published deliverability status")
        if (self.status is None) != (self.execution_state != BetaExecutionState.COMPLETED.value):
            raise BetaRefused("a status exists exactly when a verification completed")

    def as_json_object(self) -> dict[str, object]:
        return {
            "target_digest": self.target_digest,
            "truth": self.truth,
            "execution_state": self.execution_state,
            "status": self.status,
            "confidence": self.confidence,
            "primary_reason": self.primary_reason,
            "agreement": self.agreement,
            "attempted_active": self.attempted_active,
            "tls_negotiated": self.tls_negotiated,
            "tls_reason": self.tls_reason,
            "stage_reached": self.stage_reached,
            "elapsed_milliseconds": self.elapsed_milliseconds,
            "refused": self.refused,
        }


@dataclass(frozen=True, slots=True)
class BetaReport:
    """One run, with the reproducibility metadata a result needs to mean anything.

    `prompts/08-limited-beta.md` work item 6 asks for ruleset and dataset version
    reporting; a measurement whose ruleset nobody recorded cannot be compared
    with a later one. The sender identity and every credential are deliberately
    **absent** — a report is shared and those are not.
    """

    started_at: datetime
    finished_at: datetime
    ruleset: str
    dataset_versions: dict[str, str]
    canonical_input_version: str
    corpus_size: int
    corpus_by_truth: dict[str, int]
    dry_run: bool
    #: How many targets this run selected — `min(corpus, limits.max_targets)`.
    #: The denominator of every count below, and the number the accounting
    #: invariant balances against.
    selected_targets: int = 0
    rows: tuple[BetaRow, ...] = ()

    def __post_init__(self) -> None:
        if len(self.rows) != self.selected_targets:
            # Every selected target leaves exactly one row. An independent
            # review measured the earlier build starting a verification, being
            # cut off by the runtime bound, and reporting nothing at all about
            # it — an address contacted with no trace in the record.
            raise BetaRefused(
                f"{self.selected_targets} targets were selected and {len(self.rows)} rows exist"
            )

    @property
    def tls_summary(self) -> dict[str, int]:
        """The `tls_reason` distribution ADR 0009's obligation asks for.

        **Counted from the rows, whose values come from `Evidence.details`.**
        That is the whole path: `application/smtp_evidence.py` copies the
        `TLSFailureReason` onto the evidence it produces, and a row reads it
        through `EXPORTED_DETAIL_KEYS`. `SessionReport.summary` carries the same
        fact one layer lower and is **not** what this reads — an earlier
        docstring said it was, which an independent review caught. No second
        instrumentation path was added, and ADR 0009 asks for none.

        The keys are `TLSFailureReason`'s own values plus `negotiated`. Nothing
        is bucketed: `not_offered` in particular is its own key, because a
        server that advertises no `STARTTLS` has not failed at anything.
        """
        counts: dict[str, int] = {}
        for row in self.rows:
            if row.tls_negotiated:
                key = "negotiated"
            elif row.tls_reason is not None:
                key = row.tls_reason
            else:
                continue
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def status_summary(self) -> dict[str, int]:
        """The deliverability distribution, over completed rows only.

        `prompts/08-limited-beta.md`'s "unknown distribution" is a distribution
        of *mailbox answers*. A target the harness never ran has no answer, and
        counting it here would put harness bookkeeping into a product metric.
        """
        counts: dict[str, int] = {}
        for row in self.rows:
            if row.status is not None:
                counts[row.status] = counts.get(row.status, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def execution_summary(self) -> dict[str, int]:
        """Where every selected target ended up. Sums to `selected_targets`."""
        counts = {state.value: 0 for state in BetaExecutionState}
        for row in self.rows:
            counts[row.execution_state] += 1
        return counts

    @property
    def truncated(self) -> bool:
        """Whether the runtime bound stopped this run short.

        Published rather than left to be inferred from a row count, so a reader
        cannot mistake a truncated run for a complete one.
        """
        summary = self.execution_summary
        return bool(summary[BetaExecutionState.TIMED_OUT.value]) or (
            not self.dry_run and bool(summary[BetaExecutionState.NOT_RUN.value])
        )

    @property
    def contradictions(self) -> tuple[BetaRow, ...]:
        """The rows an evaluation audits first."""
        return tuple(row for row in self.rows if row.agreement == Agreement.CONTRADICTS.value)

    def as_json_object(self) -> dict[str, object]:
        return {
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "ruleset": self.ruleset,
            "dataset_versions": dict(self.dataset_versions),
            "canonical_input_version": self.canonical_input_version,
            "corpus_size": self.corpus_size,
            "corpus_by_truth": dict(self.corpus_by_truth),
            "dry_run": self.dry_run,
            "selected_targets": self.selected_targets,
            "truncated": self.truncated,
            "tls_summary": self.tls_summary,
            "status_summary": self.status_summary,
            "execution_summary": self.execution_summary,
            "rows": [row.as_json_object() for row in self.rows],
        }


@dataclass(frozen=True, slots=True)
class BetaHarness:
    """One bounded run over an authorized corpus.

    Every collaborator is the production one. There is no transport parameter,
    no limiter parameter, and no way to widen a bound from here.
    """

    verification: AddressVerificationService
    principal: Principal
    clock: Clock
    authorization: BetaAuthorization
    #: The operator secret target digests are taken under — the same key the
    #: cache, the job registry, and the abuse guard use, so one address has one
    #: digest across a beta report and the service that produced it.
    #: **Required, with no default.** An earlier build defaulted this to `b""`,
    #: which `check_correlation_key` always refuses, so the advertised-safe
    #: `run()` raised out of `security/identifiers.py` instead of producing a
    #: dry-run report. `SMTPProbeService` takes its `RateLimiter` with no
    #: default for the same reason: a value that can never work is a footgun,
    #: not a default, and composition is where a secret comes from.
    correlation_key: bytes = field(repr=False)
    #: Reported so a result can be compared with a later one.
    ruleset: str = "unknown"
    dataset_versions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Fail at construction rather than part way through a run: a harness
        # that cannot digest a target can never write a row, and discovering
        # that after the third probe would be discovering it too late.
        check_correlation_key(self.correlation_key)

    async def run(self, *, dry_run: bool = True) -> BetaReport:
        """Probe the authorized corpus, or explain why nothing was probed.

        `dry_run` defaults to **`True`**, so the reflex invocation is the one
        that opens no socket. A real run is a deliberate argument on top of a
        deliberate authorization flag on top of a non-empty corpus.
        """
        started = self.clock.now()
        limits = self.authorization.limits
        corpus = self.authorization.corpus

        if not dry_run and not self.authorization.may_probe:
            # The one place this is decided. `may_probe` is false when the
            # operator has not authorized probing *or* the corpus is empty, and
            # neither is a condition this harness may work around.
            raise BetaRefused(
                "a live beta run needs an authorized corpus; "
                "see prompts/08-limited-beta.md and docs/operations.md section 1"
            )

        selected = corpus.targets[: limits.max_targets]
        # The deadline is read once, from the loop's own clock, and every
        # target is measured against it. Wrapping the whole loop in one
        # `asyncio.timeout` was the earlier shape and it lost the in-flight
        # target's row entirely: a verification that had already reached the
        # SMTP layer left no trace in the record.
        deadline = asyncio.get_running_loop().time() + limits.max_runtime_seconds

        rows: list[BetaRow] = []
        for target in selected:
            digest = self._digest(target.address)
            if dry_run:
                rows.append(self._not_run(target, digest))
                continue
            if asyncio.get_running_loop().time() >= deadline:
                # Never started. Distinguished from a timeout on purpose: no
                # remote host was contacted for this one.
                rows.append(self._not_run(target, digest))
                continue
            try:
                async with asyncio.timeout_at(deadline):
                    rows.append(await self._one(target, digest))
            except TimeoutError:
                # Started, contacted, cut off. The row records the execution
                # fact and **no status**: there is no verdict to report, and
                # inventing `unknown` here would be a deliberate answer about a
                # mailbox this project never got an answer about.
                rows.append(
                    BetaRow(
                        target_digest=digest,
                        truth=target.truth.value,
                        execution_state=BetaExecutionState.TIMED_OUT.value,
                        status=None,
                        confidence=None,
                        primary_reason=None,
                        agreement=Agreement.NOT_APPLICABLE.value,
                        attempted_active=True,
                    )
                )

        return BetaReport(
            started_at=started,
            finished_at=self.clock.now(),
            ruleset=self.ruleset,
            dataset_versions=dict(self.dataset_versions),
            canonical_input_version=CANONICAL_INPUT_VERSION,
            corpus_size=len(corpus),
            corpus_by_truth=corpus.counts_by_truth(),
            dry_run=dry_run,
            selected_targets=len(selected),
            rows=tuple(rows),
        )

    def _not_run(self, target: BetaTarget, digest: str) -> BetaRow:
        """A selected target the harness never started."""
        return BetaRow(
            target_digest=digest,
            truth=target.truth.value,
            execution_state=BetaExecutionState.NOT_RUN.value,
            status=None,
            confidence=None,
            primary_reason=None,
            agreement=Agreement.NOT_APPLICABLE.value,
            attempted_active=False,
        )

    async def _one(self, target: BetaTarget, digest: str) -> BetaRow:
        """One target, through the production service.

        The corpus membership check is re-asserted here rather than trusted from
        the loop above, because this is the function that would be called by
        anything added later.
        """
        if self.authorization.corpus.entry_for(target.address) is None:
            raise BetaRefused("this address is not in the authorized beta corpus")

        try:
            outcome = await self.verification.verify(
                target.address, principal=self.principal, active=True
            )
        except (VerificationRefused, SubmittedInputTooLong) as refusal:
            # A local operational refusal is recorded as one. It is not a
            # verdict and it is not a measurement of the address, so it never
            # becomes a status — ADR 0013.
            return BetaRow(
                target_digest=digest,
                truth=target.truth.value,
                execution_state=BetaExecutionState.REFUSED.value,
                status=None,
                confidence=None,
                primary_reason=None,
                agreement=Agreement.NOT_APPLICABLE.value,
                attempted_active=False,
                refused=type(refusal).__name__,
            )

        details = self._details(outcome.verdict)
        return BetaRow(
            target_digest=digest,
            truth=target.truth.value,
            execution_state=BetaExecutionState.COMPLETED.value,
            status=outcome.verdict.status.value,
            confidence=outcome.verdict.confidence.level.value,
            primary_reason=(
                None
                if outcome.verdict.primary_reason is None
                else outcome.verdict.primary_reason.value
            ),
            agreement=classify_agreement(target.truth, outcome.verdict).value,
            attempted_active=outcome.active,
            tls_negotiated=_as_bool(details.get("tls_negotiated")),
            tls_reason=_as_str(details.get("tls_reason")),
            stage_reached=_as_str(details.get("stage_reached")),
            elapsed_milliseconds=_as_int(details.get("elapsed_milliseconds")),
        )

    def _details(self, verdict: Verdict) -> dict[str, object]:
        """The four allowlisted detail values, from the SMTP evidence if any.

        Read through `EXPORTED_DETAIL_KEYS` rather than copied, so a detail a
        producer adds later does not silently join a beta export.

        **The first attempt's values win, and one verification can have
        several.** Phase 4E falls through to the next exchanger on a failure
        *before* the recipient stage, so a verification that ends in a recipient
        answer may carry evidence from two or three attempts. `setdefault` takes
        the earliest, which is the preferred exchanger — the host the MX
        preference order names first and the one a receiving site's operator
        would recognise as the one approached.

        Neither this repository nor ADR 0009 specifies which attempt a
        per-verification TLS figure should describe, so this records the choice
        rather than leaving it to be discovered: **`tls_reason` on a row is the
        preferred reachable exchanger's, not the last one tried.** A
        representative TLS analysis must state that, because a domain whose
        primary exchanger offers no `STARTTLS` and whose secondary does is
        counted here as `not_offered`.
        """
        collected: dict[str, object] = {}
        for evidence in verdict.evidence:
            for key, value in evidence.details.items():
                if key in EXPORTED_DETAIL_KEYS and value is not None:
                    collected.setdefault(key, value)
        return collected

    def _digest(self, address: str) -> str:
        """The Phase 7 versioned HMAC of the normalized target.

        Through the ordinary parser, so a beta row's identity is the same digest
        the cache and the abuse guard use. An address that does not parse has no
        normalized form, and its raw text is deliberately not substituted.
        """
        parsed = parse_address(RawAddressInput(address))
        if not isinstance(parsed, AddressAccepted):
            return "unparseable"
        return correlation_digest(self.correlation_key, parsed.address.hmac_material)


def classify_agreement(truth: ControlledTruth, verdict: Verdict) -> Agreement:
    """How one verdict sat beside one arrangement.

    A pure function, and the only place a truth class and a status meet. It
    computes no status, changes no verdict, and produces no accuracy figure:
    `prompts/08-limited-beta.md` asks for "hard-invalid precision on controlled
    labels", which is counted from these outcomes by whoever reads the report.

    **The unknown statuses are `INCONCLUSIVE`, never a failure.** A beta that
    scored `unknown` as wrong would create pressure to widen the statuses, and
    `docs/requirements.md` section 17 makes conservatism the requirement rather
    than the cost.
    """
    if verdict.status in {Status.UNKNOWN, Status.TEMPORARY_UNKNOWN}:
        return Agreement.INCONCLUSIVE
    if truth in ARRANGED_RECEIVING:
        return (
            Agreement.CONSISTENT
            if verdict.status is Status.LIKELY_DELIVERABLE
            else Agreement.CONTRADICTS
        )
    if truth in ARRANGED_ABSENT:
        return Agreement.CONSISTENT if verdict.status is Status.INVALID else Agreement.CONTRADICTS
    if truth is ControlledTruth.OWNED_NULL_MX:
        # Phase 2 answers this without reaching a recipient, so `invalid` is the
        # arrangement being observed correctly at the DNS layer.
        return Agreement.CONSISTENT if verdict.status is Status.INVALID else Agreement.CONTRADICTS
    # An accept-all domain and an authorized third-party tenant make no
    # prediction about a recipient answer.
    return Agreement.NOT_APPLICABLE


def _as_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
