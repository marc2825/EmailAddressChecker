"""The Phase 5 decision table, against `docs/status-model.md` section 4.

Arranged as a matrix rather than as prose, so a row that stops being
implemented fails on the row. The sections follow the specification: the
precedence, then each gate on its own, then the properties that would be silent
if they broke — determinism, order independence, duplicate insensitivity, and
the separation of risk from status.

Evidence is built here rather than driven through a producer, because the
aggregator's contract is *evidence in, verdict out* and it must not assume its
input is coherent. Several rows below are evidence sets no pipeline can produce
today; the point is that the aggregator answers them conservatively instead of
assuming they cannot happen.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from itertools import permutations

import pytest

from emailcheck.application.aggregate import (
    AGGREGATION_RULESET,
    NON_BLOCKING_REASONS,
    REASON_PRIORITY,
    TARGET_SPECIFIC_REASONS,
    UNSUPPORTED_REASONS,
    USABLE_ROUTE_REASONS,
    aggregate_evidence,
    is_about_the_target,
    supports_invalid,
    supports_likely_deliverable,
)
from emailcheck.application.smtp_evidence import (
    NON_TARGET_SMTP_REASONS,
    POSITIVE_RECIPIENT_REASONS,
)
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import (
    HARD_INVALID_REASONS,
    PERMITTED_PRIMARY_REASONS,
    ConfidenceLevel,
    RiskFlag,
    Status,
    Verdict,
)

OBSERVED_AT = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def ev(
    reason: ReasonCode,
    *,
    layer: EvidenceLayer = EvidenceLayer.SMTP,
    strength: EvidenceStrength = EvidenceStrength.WEAK,
    temporary: bool = False,
    about_the_target: bool | None = None,
    observed_at: datetime | None = None,
) -> Evidence:
    """One observation, with only the fields a rule may read."""
    details: dict[str, str | int | bool | None] = {"no_message_data_sent": True}
    if about_the_target is not None:
        details["about_the_target"] = about_the_target
    return Evidence(
        layer=layer,
        reason=reason,
        strength=strength,
        observed_at=observed_at or OBSERVED_AT,
        temporary=temporary,
        details=details,
    )


# The observations the matrix is built from, named as the specification names
# them so a row reads as the document does.

SYNTAX_INVALID = ev(
    ReasonCode.INVALID_SYNTAX,
    layer=EvidenceLayer.SYNTAX,
    strength=EvidenceStrength.STRONG,
    about_the_target=True,
)
SYNTAX_UNSUPPORTED = ev(
    ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART, layer=EvidenceLayer.SYNTAX, about_the_target=True
)
SYNTAX_SMTPUTF8 = ev(
    ReasonCode.UNSUPPORTED_SMTPUTF8, layer=EvidenceLayer.SYNTAX, about_the_target=True
)
NXDOMAIN = ev(ReasonCode.DOMAIN_NXDOMAIN, layer=EvidenceLayer.DNS, strength=EvidenceStrength.STRONG)
NULL_MX = ev(ReasonCode.NULL_MX, layer=EvidenceLayer.DNS, strength=EvidenceStrength.STRONG)
NO_ROUTE = ev(ReasonCode.NO_MAIL_ROUTE, layer=EvidenceLayer.DNS, strength=EvidenceStrength.STRONG)
MX_ROUTE = ev(ReasonCode.MX_AVAILABLE, layer=EvidenceLayer.DNS)
IMPLICIT_ROUTE = ev(ReasonCode.IMPLICIT_MX_AVAILABLE, layer=EvidenceLayer.DNS)
DNS_TEMPORARY = ev(ReasonCode.DNS_TEMPORARY_FAILURE, layer=EvidenceLayer.DNS, temporary=True)
UNSAFE_DESTINATION = ev(ReasonCode.UNSAFE_DESTINATION, layer=EvidenceLayer.DNS)
ROUTE_ANOMALY = ev(ReasonCode.MX_CONFIGURATION_ANOMALY, layer=EvidenceLayer.DNS)

ROLE = ev(ReasonCode.ROLE_ACCOUNT, layer=EvidenceLayer.PASSIVE_CLASSIFICATION)
DISPOSABLE = ev(ReasonCode.DISPOSABLE_DOMAIN, layer=EvidenceLayer.PASSIVE_CLASSIFICATION)
FREE_MAIL = ev(ReasonCode.FREE_MAIL, layer=EvidenceLayer.PASSIVE_CLASSIFICATION)
PROVIDER_OPAQUE = ev(ReasonCode.PROVIDER_OPAQUE, layer=EvidenceLayer.PASSIVE_CLASSIFICATION)

ACCEPTED_250 = ev(
    ReasonCode.RCPT_ACCEPTED, strength=EvidenceStrength.MODERATE, about_the_target=True
)
FORWARDED_251 = ev(
    ReasonCode.RCPT_FORWARDED, strength=EvidenceStrength.MODERATE, about_the_target=True
)
UNVERIFIABLE_252 = ev(ReasonCode.RCPT_UNVERIFIABLE, about_the_target=True)
TEMPORARY_4XX = ev(
    ReasonCode.SMTP_TEMPORARY_FAILURE,
    strength=EvidenceStrength.MODERATE,
    temporary=True,
    about_the_target=True,
)
MAILBOX_FULL = ev(
    ReasonCode.MAILBOX_FULL,
    strength=EvidenceStrength.MODERATE,
    temporary=True,
    about_the_target=True,
)
REJECTED_511 = ev(
    ReasonCode.RCPT_REJECTED_ADDRESS, strength=EvidenceStrength.STRONG, about_the_target=True
)
REJECTED_POLICY_571 = ev(ReasonCode.RCPT_REJECTED_POLICY, about_the_target=True)
BARE_550 = ev(ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE, about_the_target=True)

BANNER_INVALID = ev(ReasonCode.SMTP_BANNER_INVALID, about_the_target=False)
POLICY_BLOCKED = ev(ReasonCode.SMTP_POLICY_BLOCKED, about_the_target=False)
TLS_FAILURE = ev(ReasonCode.SMTP_TLS_FAILURE, about_the_target=False)
MAIL_FROM_REJECTED = ev(ReasonCode.MAIL_FROM_REJECTED, about_the_target=False)
CONNECT_TIMEOUT = ev(ReasonCode.SMTP_CONNECTION_TIMEOUT, temporary=True, about_the_target=False)
CONNECT_REFUSED = ev(ReasonCode.SMTP_CONNECTION_REFUSED, temporary=True, about_the_target=False)
PROTOCOL_ERROR = ev(ReasonCode.SMTP_PROTOCOL_ERROR, about_the_target=False)
INTERNAL_ERROR = ev(ReasonCode.INTERNAL_ERROR, layer=EvidenceLayer.INTERNAL, about_the_target=False)


def status_of(*items: Evidence) -> Status:
    return aggregate_evidence(items).status


# --- syntax and route -------------------------------------------------------


SYNTAX_AND_ROUTE_MATRIX: tuple[tuple[str, tuple[Evidence, ...], Status, ReasonCode], ...] = (
    ("invalid syntax", (SYNTAX_INVALID,), Status.INVALID, ReasonCode.INVALID_SYNTAX),
    (
        "unsupported syntax",
        (SYNTAX_UNSUPPORTED,),
        Status.UNKNOWN,
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ),
    ("NXDOMAIN", (NXDOMAIN,), Status.INVALID, ReasonCode.DOMAIN_NXDOMAIN),
    ("Null MX", (NULL_MX,), Status.INVALID, ReasonCode.NULL_MX),
    ("authoritative no mail route", (NO_ROUTE,), Status.INVALID, ReasonCode.NO_MAIL_ROUTE),
    ("MX available only", (MX_ROUTE,), Status.UNKNOWN, ReasonCode.MX_AVAILABLE),
    (
        "implicit MX available only",
        (IMPLICIT_ROUTE,),
        Status.UNKNOWN,
        ReasonCode.IMPLICIT_MX_AVAILABLE,
    ),
    (
        "DNS temporary",
        (DNS_TEMPORARY,),
        Status.TEMPORARY_UNKNOWN,
        ReasonCode.DNS_TEMPORARY_FAILURE,
    ),
    ("unsafe destination", (UNSAFE_DESTINATION,), Status.UNKNOWN, ReasonCode.UNSAFE_DESTINATION),
    (
        "configuration anomaly",
        (ROUTE_ANOMALY,),
        Status.UNKNOWN,
        ReasonCode.MX_CONFIGURATION_ANOMALY,
    ),
)


@pytest.mark.parametrize(
    ("name", "items", "status", "primary"),
    SYNTAX_AND_ROUTE_MATRIX,
    ids=[row[0] for row in SYNTAX_AND_ROUTE_MATRIX],
)
def test_the_syntax_and_route_matrix(
    name: str, items: tuple[Evidence, ...], status: Status, primary: ReasonCode
) -> None:
    verdict = aggregate_evidence(items)
    assert verdict.status is status, name
    assert verdict.primary_reason is primary, name


def test_valid_syntax_produces_no_evidence_and_therefore_no_positive_verdict() -> None:
    """There is no reason code meaning "the syntax was fine", by design.

    `docs/requirements.md` section 3 publishes no positive syntax status, and
    `docs/status-model.md` section 5 publishes no positive syntax reason, so an
    address that parsed contributes nothing at all. A row that could say "syntax
    valid" is the first thing an aggregation would mistake for delivery
    evidence.
    """
    assert not any(reason.value.endswith("_syntax_valid") for reason in ReasonCode)
    assert aggregate_evidence(()).status is Status.UNKNOWN


# --- passive ----------------------------------------------------------------


PASSIVE_MATRIX: tuple[tuple[str, tuple[Evidence, ...], frozenset[RiskFlag]], ...] = (
    ("role only", (ROLE,), frozenset({RiskFlag.ROLE_ACCOUNT})),
    ("disposable only", (DISPOSABLE,), frozenset({RiskFlag.DISPOSABLE})),
    ("free mail only", (FREE_MAIL,), frozenset({RiskFlag.FREE_MAIL})),
    (
        "several risk flags",
        (ROLE, DISPOSABLE, FREE_MAIL),
        frozenset({RiskFlag.ROLE_ACCOUNT, RiskFlag.DISPOSABLE, RiskFlag.FREE_MAIL}),
    ),
    ("route anomaly", (ROUTE_ANOMALY,), frozenset({RiskFlag.DOMAIN_CONFIGURATION_ANOMALY})),
    (
        "internationalized local part",
        (SYNTAX_SMTPUTF8,),
        frozenset({RiskFlag.INTERNATIONALIZED_LOCAL_PART}),
    ),
)


@pytest.mark.parametrize(
    ("name", "items", "flags"), PASSIVE_MATRIX, ids=[row[0] for row in PASSIVE_MATRIX]
)
def test_passive_evidence_raises_flags_and_never_a_deliverability_answer(
    name: str, items: tuple[Evidence, ...], flags: frozenset[RiskFlag]
) -> None:
    """`docs/requirements.md` section 4: risk is orthogonal to deliverability.

    A disposable address may be likely deliverable and a role address may be
    invalid, so none of these may decide anything on its own.
    """
    verdict = aggregate_evidence(items)
    assert verdict.risk_flags == flags, name
    assert verdict.status in {Status.UNKNOWN, Status.TEMPORARY_UNKNOWN}, name


def test_a_provider_family_raises_no_flag_and_decides_nothing() -> None:
    """Provider family is metadata. `provider_opaque` is the one that is not.

    `docs/status-model.md` section 2 lists "remote server hides recipient
    validity" under `unknown`, so `provider_opaque` blocks a positive verdict —
    while still not being able to produce one, or an `invalid`.
    """
    assert status_of(PROVIDER_OPAQUE) is Status.UNKNOWN
    assert status_of(MX_ROUTE, ACCEPTED_250, PROVIDER_OPAQUE) is Status.UNKNOWN
    assert aggregate_evidence((PROVIDER_OPAQUE,)).risk_flags == frozenset(
        {RiskFlag.PROVIDER_OPAQUE}
    )


# --- SMTP recipient ---------------------------------------------------------


RECIPIENT_MATRIX: tuple[tuple[str, Evidence, Status, ReasonCode, ConfidenceLevel], ...] = (
    (
        "250 accepted",
        ACCEPTED_250,
        Status.LIKELY_DELIVERABLE,
        ReasonCode.RCPT_ACCEPTED,
        ConfidenceLevel.MEDIUM,
    ),
    (
        "251 forwarded",
        FORWARDED_251,
        Status.LIKELY_DELIVERABLE,
        ReasonCode.RCPT_FORWARDED,
        ConfidenceLevel.MEDIUM,
    ),
    (
        "252 unverifiable",
        UNVERIFIABLE_252,
        Status.UNKNOWN,
        ReasonCode.RCPT_UNVERIFIABLE,
        ConfidenceLevel.LOW,
    ),
    (
        "4xx temporary",
        TEMPORARY_4XX,
        Status.TEMPORARY_UNKNOWN,
        ReasonCode.SMTP_TEMPORARY_FAILURE,
        ConfidenceLevel.MEDIUM,
    ),
    (
        "mailbox full",
        MAILBOX_FULL,
        Status.TEMPORARY_UNKNOWN,
        ReasonCode.MAILBOX_FULL,
        ConfidenceLevel.MEDIUM,
    ),
    (
        "550 5.1.1",
        REJECTED_511,
        Status.INVALID,
        ReasonCode.RCPT_REJECTED_ADDRESS,
        ConfidenceLevel.MEDIUM,
    ),
    (
        "550 5.7.1 policy",
        REJECTED_POLICY_571,
        Status.UNKNOWN,
        ReasonCode.RCPT_REJECTED_POLICY,
        ConfidenceLevel.LOW,
    ),
    (
        "bare 550",
        BARE_550,
        Status.UNKNOWN,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ConfidenceLevel.LOW,
    ),
)


@pytest.mark.parametrize(
    ("name", "item", "status", "primary", "confidence"),
    RECIPIENT_MATRIX,
    ids=[row[0] for row in RECIPIENT_MATRIX],
)
def test_the_recipient_matrix_with_a_usable_route(
    name: str,
    item: Evidence,
    status: Status,
    primary: ReasonCode,
    confidence: ConfidenceLevel,
) -> None:
    """Each recipient answer, beside the route that made asking possible."""
    verdict = aggregate_evidence((MX_ROUTE, item))
    assert verdict.status is status, name
    assert verdict.primary_reason is primary, name
    assert verdict.confidence.level is confidence, name


# --- SMTP non-target --------------------------------------------------------


NON_TARGET_MATRIX: tuple[tuple[str, Evidence, Status], ...] = (
    ("banner invalid", BANNER_INVALID, Status.UNKNOWN),
    ("EHLO blocked", POLICY_BLOCKED, Status.UNKNOWN),
    ("TLS failure", TLS_FAILURE, Status.UNKNOWN),
    ("MAIL FROM rejected", MAIL_FROM_REJECTED, Status.UNKNOWN),
    ("protocol error", PROTOCOL_ERROR, Status.UNKNOWN),
    ("connection timeout", CONNECT_TIMEOUT, Status.TEMPORARY_UNKNOWN),
    ("connection refused", CONNECT_REFUSED, Status.TEMPORARY_UNKNOWN),
    ("unsafe destination", UNSAFE_DESTINATION, Status.UNKNOWN),
    ("internal error", INTERNAL_ERROR, Status.UNKNOWN),
)


@pytest.mark.parametrize(
    ("name", "item", "status"), NON_TARGET_MATRIX, ids=[row[0] for row in NON_TARGET_MATRIX]
)
def test_the_non_target_matrix_never_reaches_invalid(
    name: str, item: Evidence, status: Status
) -> None:
    """None of these is a target rejection, whatever it carries.

    `docs/requirements.md` section 9: connection, sender, reputation, and policy
    failures are not target-address invalidity.
    """
    verdict = aggregate_evidence((MX_ROUTE, item))
    assert verdict.status is status, name
    assert verdict.status is not Status.INVALID, name


@pytest.mark.parametrize("reason", sorted(NON_TARGET_SMTP_REASONS))
def test_no_non_target_reason_produces_invalid_at_any_strength(reason: ReasonCode) -> None:
    """Exhaustive over the published set, and over every strength.

    Section 7.6 stop condition B by name: `STRONG` is evidence weight and never
    final truth, and a non-target reason never supports target invalidity
    whatever its strength.
    """
    for strength in EvidenceStrength:
        for temporary in (False, True):
            item = ev(reason, strength=strength, temporary=temporary, about_the_target=False)
            assert aggregate_evidence((item,)).status is not Status.INVALID
            assert supports_invalid(item) is False


def test_a_failure_of_our_own_never_becomes_a_statement_about_the_address() -> None:
    """`internal_error` is `unknown`, and it does not hide behind a remote answer.

    Two properties, and the second is the one that needed a decision. It must
    not produce `invalid`; and when it arrives beside a remote policy rejection
    it is the reason the verdict names, because sending an operator to look at
    someone else's mail server for a bug in this one wastes the only signal the
    bug produced. It does **not** outrank a hard invalid or an explicit
    temporary condition, because those are still true.
    """
    assert status_of(INTERNAL_ERROR) is Status.UNKNOWN
    assert aggregate_evidence((POLICY_BLOCKED, INTERNAL_ERROR)).primary_reason is (
        ReasonCode.INTERNAL_ERROR
    )
    assert aggregate_evidence((NULL_MX, INTERNAL_ERROR)).primary_reason is ReasonCode.NULL_MX
    assert aggregate_evidence((DNS_TEMPORARY, INTERNAL_ERROR)).primary_reason is (
        ReasonCode.DNS_TEMPORARY_FAILURE
    )


# --- conflicts --------------------------------------------------------------


CONFLICT_MATRIX: tuple[tuple[str, tuple[Evidence, ...], Status, ReasonCode], ...] = (
    (
        "hard invalid + 250",
        (NULL_MX, MX_ROUTE, ACCEPTED_250),
        Status.INVALID,
        ReasonCode.NULL_MX,
    ),
    (
        "hard invalid + 251",
        (NXDOMAIN, MX_ROUTE, FORWARDED_251),
        Status.INVALID,
        ReasonCode.DOMAIN_NXDOMAIN,
    ),
    (
        "temporary DNS + 250",
        (DNS_TEMPORARY, MX_ROUTE, ACCEPTED_250),
        Status.TEMPORARY_UNKNOWN,
        ReasonCode.DNS_TEMPORARY_FAILURE,
    ),
    (
        "unsupported + 250",
        (SYNTAX_UNSUPPORTED, MX_ROUTE, ACCEPTED_250),
        Status.UNKNOWN,
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ),
    (
        "policy rejection + 250",
        (REJECTED_POLICY_571, MX_ROUTE, ACCEPTED_250),
        Status.UNKNOWN,
        ReasonCode.RCPT_REJECTED_POLICY,
    ),
    (
        "250 + 550 5.1.1",
        (MX_ROUTE, ACCEPTED_250, REJECTED_511),
        Status.INVALID,
        ReasonCode.RCPT_REJECTED_ADDRESS,
    ),
    (
        "250 + 252",
        (MX_ROUTE, ACCEPTED_250, UNVERIFIABLE_252),
        Status.UNKNOWN,
        ReasonCode.RCPT_UNVERIFIABLE,
    ),
    (
        "strong non-target + positive recipient",
        (
            MX_ROUTE,
            ev(
                ReasonCode.SMTP_TLS_FAILURE,
                strength=EvidenceStrength.STRONG,
                about_the_target=False,
            ),
            ACCEPTED_250,
        ),
        Status.UNKNOWN,
        ReasonCode.SMTP_TLS_FAILURE,
    ),
    (
        "internal error + positive recipient",
        (MX_ROUTE, INTERNAL_ERROR, ACCEPTED_250),
        Status.UNKNOWN,
        ReasonCode.INTERNAL_ERROR,
    ),
    (
        "hard invalid + temporary",
        (NULL_MX, DNS_TEMPORARY),
        Status.INVALID,
        ReasonCode.NULL_MX,
    ),
)


@pytest.mark.parametrize(
    ("name", "items", "status", "primary"),
    CONFLICT_MATRIX,
    ids=[row[0] for row in CONFLICT_MATRIX],
)
def test_the_conflict_matrix(
    name: str, items: tuple[Evidence, ...], status: Status, primary: ReasonCode
) -> None:
    """Contradictory evidence, resolved by the precedence rather than by luck.

    "A later network error must not erase a hard passive invalid result because
    the network probe should never have occurred" is section 4's closing rule,
    and the first two rows are it: a probe that reached a `250` on a domain
    publishing a Null MX is a probe that should not have happened, and the
    hard-invalid answer survives it.
    """
    verdict = aggregate_evidence(items)
    assert verdict.status is status, name
    assert verdict.primary_reason is primary, name


@pytest.mark.parametrize(
    ("name", "items", "status", "primary"),
    CONFLICT_MATRIX,
    ids=[row[0] for row in CONFLICT_MATRIX],
)
def test_every_conflict_resolves_the_same_way_in_every_order(
    name: str, items: tuple[Evidence, ...], status: Status, primary: ReasonCode
) -> None:
    """Full permutations of each conflicting set.

    Aggregation reads a multiset. Anything that depended on arrival order — a
    first-match loop, a `dict` built in input order, a set iterated — would pass
    the row above and fail here.
    """
    for ordering in permutations(items):
        verdict = aggregate_evidence(ordering)
        assert verdict.status is status, (name, ordering)
        assert verdict.primary_reason is primary, (name, ordering)
        assert verdict.confidence == aggregate_evidence(items).confidence
        assert verdict.risk_flags == aggregate_evidence(items).risk_flags
        assert verdict.reason_codes == aggregate_evidence(items).reason_codes


# --- the INVALID gate -------------------------------------------------------


def test_only_five_reasons_can_ever_produce_invalid() -> None:
    """Exhaustive over the whole published vocabulary.

    Every reason code, at every strength, in both permanence states, alone and
    beside a route: exactly the five `docs/status-model.md` section 2 lists may
    reach `invalid`.
    """
    reached: set[ReasonCode] = set()
    for reason in ReasonCode:
        for strength in EvidenceStrength:
            for temporary in (False, True):
                item = ev(reason, strength=strength, temporary=temporary, about_the_target=True)
                if aggregate_evidence((item,)).status is Status.INVALID:
                    reached.add(reason)
                if aggregate_evidence((MX_ROUTE, item)).status is Status.INVALID:
                    reached.add(reason)
    assert reached == set(HARD_INVALID_REASONS)


def test_the_invalid_gate_refuses_a_temporary_hard_invalid_reason() -> None:
    """The permanence barrier, pinned where the other two conditions pass.

    A `rcpt_rejected_address` marked temporary is target-specific, carries an
    approved reason, and is the strongest evidence this project produces.
    Removing the `temporary` check alone turns it into `invalid`, which is
    exactly what `docs/requirements.md` section 17 forbids.
    """
    item = ev(
        ReasonCode.RCPT_REJECTED_ADDRESS,
        strength=EvidenceStrength.STRONG,
        temporary=True,
        about_the_target=True,
    )
    assert supports_invalid(item) is False
    assert aggregate_evidence((MX_ROUTE, item)).status is Status.TEMPORARY_UNKNOWN


def test_the_invalid_gate_refuses_evidence_whose_producer_denied_targetness() -> None:
    """The targetness barrier, pinned where the other two conditions pass.

    Gate 4D publishes `about_the_target` on every piece of SMTP evidence, and it
    knows things this module does not — the stage the dialogue reached, and how
    many recipients were attempted. A `550 5.1.1` from a session that never
    reached the recipient stage arrives exactly like this, and only the
    producer's own statement separates it from a real rejection.
    """
    item = ev(
        ReasonCode.RCPT_REJECTED_ADDRESS,
        strength=EvidenceStrength.STRONG,
        about_the_target=False,
    )
    assert is_about_the_target(item) is False
    assert supports_invalid(item) is False
    assert aggregate_evidence((MX_ROUTE, item)).status is Status.UNKNOWN


def test_the_invalid_gate_refuses_a_reason_that_is_not_hard_invalid() -> None:
    """The semantics barrier, pinned where the other two conditions pass.

    A policy rejection and a bare `550` are both permanent, both about the
    target, and neither says the recipient does not exist.
    """
    for item in (REJECTED_POLICY_571, BARE_550, UNVERIFIABLE_252):
        assert is_about_the_target(item) is True
        assert item.temporary is False
        assert supports_invalid(item) is False


def test_strength_alone_never_reaches_the_invalid_gate() -> None:
    """Section 7.6 stop condition B, asserted directly on the gate.

    Every reason at `STRONG`, and only the five approved ones pass.
    """
    passing = {
        reason
        for reason in ReasonCode
        if supports_invalid(ev(reason, strength=EvidenceStrength.STRONG, about_the_target=True))
    }
    assert passing == set(HARD_INVALID_REASONS)


# --- the LIKELY_DELIVERABLE gate --------------------------------------------


def test_a_recipient_acceptance_alone_is_not_likely_deliverable() -> None:
    """The row `docs/adr/0012-evidence-aggregation-and-final-status.md` records as the ADR 0012
    decision.

    A `250` with no route evidence beside it is not an evidence set this project
    can produce — a probe cannot accept a recipient without having resolved and
    connected to an exchanger — and the aggregator does not assume that. It
    answers `unknown`, which is the conservative direction and the one that
    makes "a bare SMTP `250` is not automatically `likely_deliverable`" true of
    this function rather than only true in practice.
    """
    assert supports_likely_deliverable((ACCEPTED_250,)) is False
    assert status_of(ACCEPTED_250) is Status.UNKNOWN
    assert status_of(FORWARDED_251) is Status.UNKNOWN


def test_a_usable_route_alone_is_not_likely_deliverable() -> None:
    """A domain that receives mail is not a mailbox that exists."""
    assert status_of(MX_ROUTE) is Status.UNKNOWN
    assert status_of(IMPLICIT_ROUTE) is Status.UNKNOWN
    assert status_of(MX_ROUTE, IMPLICIT_ROUTE) is Status.UNKNOWN


def test_a_route_and_an_acceptance_together_are_likely_deliverable() -> None:
    """Both routes qualify, and both acceptances do."""
    for route in (MX_ROUTE, IMPLICIT_ROUTE):
        for acceptance in (ACCEPTED_250, FORWARDED_251):
            assert status_of(route, acceptance) is Status.LIKELY_DELIVERABLE


def test_252_can_never_reach_likely_deliverable() -> None:
    """The most important regression in this Phase.

    `252` is `RecipientStageOutcome.ACCEPTED` at the protocol layer and
    `is_about_the_target` is true for it, so the two properties an aggregation
    would naturally branch on both say "positive". Only the reason separates it,
    and `docs/status-model.md` section 7.4 is unambiguous: the server is saying
    it will not tell you.
    """
    assert UNVERIFIABLE_252.reason not in POSITIVE_RECIPIENT_REASONS
    assert is_about_the_target(UNVERIFIABLE_252) is True
    assert status_of(MX_ROUTE, UNVERIFIABLE_252) is Status.UNKNOWN
    assert supports_likely_deliverable((MX_ROUTE, UNVERIFIABLE_252)) is False


@pytest.mark.parametrize(
    "blocker",
    [NULL_MX, SYNTAX_UNSUPPORTED, DNS_TEMPORARY, TLS_FAILURE, REJECTED_POLICY_571, INTERNAL_ERROR],
    ids=["hard invalid", "unsupported", "temporary", "TLS", "policy", "internal"],
)
def test_every_higher_precedence_tier_blocks_likely_deliverable(blocker: Evidence) -> None:
    """One blocker from each of tiers 1 to 4, each one enough on its own."""
    assert supports_likely_deliverable((MX_ROUTE, ACCEPTED_250)) is True
    assert supports_likely_deliverable((MX_ROUTE, ACCEPTED_250, blocker)) is False
    assert status_of(MX_ROUTE, ACCEPTED_250, blocker) is not Status.LIKELY_DELIVERABLE


def test_membership_of_the_positive_set_is_not_the_answer() -> None:
    """Section 7.6 stop condition A, asserted behaviourally.

    Both members of `POSITIVE_RECIPIENT_REASONS` are shown reaching `unknown`,
    so an implementation that returned `LIKELY_DELIVERABLE` on membership would
    fail here even though every row of the recipient matrix still passed.
    """
    for reason in POSITIVE_RECIPIENT_REASONS:
        item = ev(reason, strength=EvidenceStrength.MODERATE, about_the_target=True)
        assert status_of(item) is Status.UNKNOWN
        assert status_of(MX_ROUTE, item, TLS_FAILURE) is Status.UNKNOWN


def test_a_positive_recipient_answer_that_is_not_about_the_target_is_refused() -> None:
    """The targetness barrier on the positive gate as well as the negative one."""
    item = ev(ReasonCode.RCPT_ACCEPTED, strength=EvidenceStrength.MODERATE, about_the_target=False)
    assert supports_likely_deliverable((MX_ROUTE, item)) is False
    assert status_of(MX_ROUTE, item) is Status.UNKNOWN


def test_a_temporary_acceptance_is_a_temporary_condition() -> None:
    """Permanence is read on the positive gate too, not only on the negative."""
    item = ev(
        ReasonCode.RCPT_ACCEPTED,
        strength=EvidenceStrength.MODERATE,
        temporary=True,
        about_the_target=True,
    )
    assert supports_likely_deliverable((MX_ROUTE, item)) is False
    assert status_of(MX_ROUTE, item) is Status.TEMPORARY_UNKNOWN


# --- temporary and unknown --------------------------------------------------


def test_every_temporary_observation_produces_temporary_unknown_on_its_own() -> None:
    """The `temporary` flag is the tier, and it outranks tiers 4 and 5.

    Exhaustive over the vocabulary rather than over a hand-picked list, because
    the property is about the flag rather than about which reasons carry it.
    """
    for reason in ReasonCode:
        if reason in HARD_INVALID_REASONS or reason in UNSUPPORTED_REASONS:
            # Tiers 1 and 2 are the two that outrank it, and each has its own
            # row: a temporary hard-invalid reason is refused by the gate and
            # lands here anyway, which the invalid-gate tests assert.
            continue
        item = ev(reason, temporary=True, about_the_target=True)
        assert aggregate_evidence((item,)).status is Status.TEMPORARY_UNKNOWN, reason


def test_a_temporary_observation_alone_never_becomes_permanently_invalid() -> None:
    """`docs/requirements.md` section 17, as an exhaustive assertion."""
    for reason in ReasonCode:
        item = ev(reason, strength=EvidenceStrength.STRONG, temporary=True, about_the_target=True)
        assert aggregate_evidence((item,)).status is not Status.INVALID, reason


def test_a_hard_invalid_observation_outranks_a_temporary_one() -> None:
    """The one direction the temporary tier does not win.

    Section 4 puts hard invalid first, and it means it: a domain that publishes
    a Null MX has not become deliverable because a nameserver timed out.
    """
    assert status_of(NULL_MX, DNS_TEMPORARY, CONNECT_TIMEOUT) is Status.INVALID


def test_unsupported_input_is_unknown_and_never_invalid() -> None:
    """`docs/requirements.md` section 6, over all three unsupported reasons.

    Unsupported is this project's limitation. Reporting it as invalid would be
    our gap presented as the user's mistake.
    """
    for reason in UNSUPPORTED_REASONS:
        item = ev(reason, layer=EvidenceLayer.SYNTAX, about_the_target=True)
        verdict = aggregate_evidence((item,))
        assert verdict.status is Status.UNKNOWN, reason
        assert verdict.primary_reason is reason, reason
    assert status_of(SYNTAX_UNSUPPORTED, NULL_MX) is Status.INVALID


def test_empty_evidence_is_unknown_with_no_reason_at_all() -> None:
    """`aggregate_evidence(())`, stated rather than left to be discovered."""
    verdict = aggregate_evidence(())

    assert verdict.status is Status.UNKNOWN
    assert verdict.primary_reason is None
    assert verdict.reason_codes == ()
    assert verdict.risk_flags == frozenset()
    assert verdict.confidence.level is ConfidenceLevel.LOW
    assert verdict.confidence.calibrated is False
    assert verdict.confidence.score is None
    assert verdict.evidence == ()
    assert verdict.ruleset == AGGREGATION_RULESET


# --- duplicates and independence --------------------------------------------


DUPLICATED = (
    ACCEPTED_250,
    REJECTED_511,
    UNVERIFIABLE_252,
    CONNECT_TIMEOUT,
    TLS_FAILURE,
    DNS_TEMPORARY,
    ROLE,
)


@pytest.mark.parametrize("item", DUPLICATED, ids=[item.reason.value for item in DUPLICATED])
@pytest.mark.parametrize("copies", [1, 2, 3, 10])
def test_repeating_one_observation_changes_nothing(item: Evidence, copies: int) -> None:
    """Count-weighting is forbidden, so counting must be impossible.

    Gate 4E can legitimately produce three pre-recipient failures for one
    address: three attempts at one question, not three independent answers to
    it. Nothing here may read the number.
    """
    once = aggregate_evidence((MX_ROUTE, item))
    many = aggregate_evidence((MX_ROUTE,) + (item,) * copies)

    assert many.status is once.status
    assert many.confidence == once.confidence
    assert many.primary_reason is once.primary_reason
    assert many.reason_codes == once.reason_codes
    assert many.risk_flags == once.risk_flags


def test_three_pre_recipient_failures_decide_what_one_decides() -> None:
    """The gate 4E shape, with three distinct failures rather than three copies."""
    one = aggregate_evidence((CONNECT_TIMEOUT,))
    three = aggregate_evidence((CONNECT_TIMEOUT, CONNECT_REFUSED, TLS_FAILURE))

    assert three.status is one.status is Status.TEMPORARY_UNKNOWN
    assert three.confidence.level is one.confidence.level


def test_duplicated_evidence_is_retained_in_full_even_though_it_decides_once() -> None:
    """Decision-time deduplication and audit-time retention are separate.

    The decision reads one entry per reason; the result keeps every observation
    that was handed in, in the order it was handed in. Collapsing the record
    would lose which attempt saw what.
    """
    items = (MX_ROUTE, CONNECT_TIMEOUT, CONNECT_TIMEOUT, CONNECT_TIMEOUT)
    verdict = aggregate_evidence(items)

    assert verdict.evidence == items
    assert verdict.reason_codes == (ReasonCode.SMTP_CONNECTION_TIMEOUT, ReasonCode.MX_AVAILABLE)


def test_evidence_from_several_layers_is_not_treated_as_independent() -> None:
    """No arithmetic, so no accidental Bayes.

    Syntax, DNS, SMTP, and passive observations of one address are correlated in
    ways nobody has measured. Adding a second layer that agrees changes nothing:
    the verdict is the deciding tier's, not a combination.
    """
    alone = aggregate_evidence((MX_ROUTE, ACCEPTED_250))
    with_more = aggregate_evidence((MX_ROUTE, ACCEPTED_250, ROLE, FREE_MAIL, DISPOSABLE))

    assert with_more.status is alone.status
    assert with_more.confidence == alone.confidence
    assert with_more.primary_reason is alone.primary_reason


# --- risk flags are separate from status ------------------------------------


ANY_VERDICT = (
    (MX_ROUTE, ACCEPTED_250),
    (NULL_MX,),
    (DNS_TEMPORARY,),
    (MX_ROUTE, BARE_550),
)

#: The passive risk signals, and only those.
#:
#: `mx_configuration_anomaly` is deliberately absent even though it raises a
#: flag. `docs/architecture.md` records a configuration anomaly as an outcome
#: that resolves to `unknown` — it is a DNS observation that happens to raise a
#: flag, not a risk signal that happens to be about DNS — and the test below
#: asserts that it does both.
FLAG_RAISING = (ROLE, DISPOSABLE, FREE_MAIL)


@pytest.mark.parametrize("base", ANY_VERDICT, ids=[str(len(row)) + "-item" for row in ANY_VERDICT])
def test_adding_a_risk_flag_never_changes_the_deliverability_answer(
    base: tuple[Evidence, ...],
) -> None:
    """`docs/test-strategy.md` names this property; here it is, over every status.

    The flags appear in the result and change nothing else. That is the whole
    content of "risk is orthogonal to deliverability".
    """
    before = aggregate_evidence(base)
    after = aggregate_evidence(base + FLAG_RAISING)

    assert after.status is before.status
    assert after.confidence == before.confidence
    assert after.primary_reason is before.primary_reason
    assert after.risk_flags > before.risk_flags


def test_adding_a_risk_flag_to_nothing_still_reaches_no_deliverability_answer() -> None:
    """The empty base, where a primary reason must appear rather than persist."""
    verdict = aggregate_evidence(FLAG_RAISING)

    assert verdict.status is Status.UNKNOWN
    assert verdict.confidence == aggregate_evidence(()).confidence
    assert verdict.primary_reason is ReasonCode.DISPOSABLE_DOMAIN


def test_a_configuration_anomaly_raises_a_flag_and_also_blocks() -> None:
    """The one reason that does both, and the reason it is not in `FLAG_RAISING`.

    `docs/architecture.md` maps "MX records exist, none usable" to `unknown`,
    and Phase 3 separately maps it to a risk flag. Both are true at once: it
    raises `domain_configuration_anomaly`, and it blocks a positive verdict
    because a route nobody can use is not a route.
    """
    verdict = aggregate_evidence((MX_ROUTE, ACCEPTED_250, ROUTE_ANOMALY))

    assert verdict.risk_flags == frozenset({RiskFlag.DOMAIN_CONFIGURATION_ANOMALY})
    assert verdict.status is Status.UNKNOWN
    assert verdict.status is not Status.INVALID


def test_risk_flags_are_deduplicated_and_stable() -> None:
    """A set, so repetition cannot show, and equal across orderings."""
    items = (ROLE, ROLE, DISPOSABLE, ROLE, DISPOSABLE)
    flags = aggregate_evidence(items).risk_flags

    assert flags == frozenset({RiskFlag.ROLE_ACCOUNT, RiskFlag.DISPOSABLE})
    for ordering in permutations(items):
        assert aggregate_evidence(ordering).risk_flags == flags


def test_a_risk_flag_alone_can_never_produce_a_deliverability_verdict() -> None:
    """No flag, and no combination of them, reaches `invalid` or positive."""
    verdict = aggregate_evidence(FLAG_RAISING)
    assert verdict.status is Status.UNKNOWN
    assert verdict.risk_flags
    assert verdict.status is not Status.INVALID
    assert verdict.status is not Status.LIKELY_DELIVERABLE


# --- determinism ------------------------------------------------------------


def test_the_same_evidence_twice_produces_the_same_verdict() -> None:
    items = (MX_ROUTE, ACCEPTED_250, ROLE)
    assert aggregate_evidence(items) == aggregate_evidence(items)


def test_a_verdict_reports_every_distinct_reason_primary_first() -> None:
    """`reason_codes` is the supporting evidence, ordered by the precedence.

    Reading only `primary_reason` loses ordering, never information.
    """
    verdict = aggregate_evidence((ROLE, MX_ROUTE, BARE_550, CONNECT_TIMEOUT))

    assert verdict.reason_codes[0] is verdict.primary_reason
    assert set(verdict.reason_codes) == {
        ReasonCode.ROLE_ACCOUNT,
        ReasonCode.MX_AVAILABLE,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ReasonCode.SMTP_CONNECTION_TIMEOUT,
    }
    assert verdict.reason_codes == (
        ReasonCode.SMTP_CONNECTION_TIMEOUT,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ReasonCode.MX_AVAILABLE,
        ReasonCode.ROLE_ACCOUNT,
    )


def test_the_priority_table_covers_the_vocabulary_exactly() -> None:
    """A new reason code cannot be added without ranking it.

    Without this, a code missing from `REASON_PRIORITY` raises `KeyError` the
    first time evidence carries it — at aggregation time, in production, rather
    than here.
    """
    assert len(REASON_PRIORITY) == len(set(REASON_PRIORITY))
    assert set(REASON_PRIORITY) == set(ReasonCode)


def test_the_published_sets_are_consistent_with_each_other() -> None:
    """The partitions the rules rest on, asserted rather than assumed."""
    assert HARD_INVALID_REASONS <= TARGET_SPECIFIC_REASONS
    assert POSITIVE_RECIPIENT_REASONS <= TARGET_SPECIFIC_REASONS
    assert not TARGET_SPECIFIC_REASONS & NON_TARGET_SMTP_REASONS
    assert not HARD_INVALID_REASONS & NON_BLOCKING_REASONS
    assert not POSITIVE_RECIPIENT_REASONS & NON_BLOCKING_REASONS
    assert USABLE_ROUTE_REASONS <= NON_BLOCKING_REASONS
    assert not USABLE_ROUTE_REASONS & TARGET_SPECIFIC_REASONS


def test_an_unclassified_reason_is_not_target_evidence() -> None:
    """Fail closed, on the gate 4D precedent.

    Every reason outside `TARGET_SPECIFIC_REASONS` is non-target, so a code
    added in a later Phase and forgotten here cannot support `invalid`.
    """
    for reason in ReasonCode:
        item = ev(reason, strength=EvidenceStrength.STRONG)
        expected = reason in TARGET_SPECIFIC_REASONS
        assert is_about_the_target(item) is expected, reason


# --- time and retention -----------------------------------------------------


def test_an_older_observation_is_not_weaker_than_a_newer_one() -> None:
    """No staleness policy exists in any document, so none is implemented.

    Silently discounting old evidence would weaken exactly the observations this
    project spends a rate-limited SMTP session to collect.
    """
    old = ev(
        ReasonCode.RCPT_REJECTED_ADDRESS,
        strength=EvidenceStrength.STRONG,
        about_the_target=True,
        observed_at=OBSERVED_AT - timedelta(days=3650),
    )
    fresh = ev(
        ReasonCode.RCPT_REJECTED_ADDRESS,
        strength=EvidenceStrength.STRONG,
        about_the_target=True,
        observed_at=OBSERVED_AT,
    )

    assert aggregate_evidence((MX_ROUTE, old)).status is Status.INVALID
    assert aggregate_evidence((MX_ROUTE, old)).status is (
        aggregate_evidence((MX_ROUTE, fresh)).status
    )
    assert aggregate_evidence((MX_ROUTE, old)).confidence == (
        aggregate_evidence((MX_ROUTE, fresh)).confidence
    )


def test_the_input_evidence_is_retained_unchanged_and_in_order() -> None:
    """Aggregation reads; it does not edit."""
    items = (ROLE, MX_ROUTE, ACCEPTED_250)
    verdict = aggregate_evidence(items)

    assert verdict.evidence == items
    assert [id(item) for item in verdict.evidence] == [id(item) for item in items]


def test_the_layer_summaries_name_each_layer_that_contributed() -> None:
    """`docs/status-model.md` section 6, in its layer-agnostic form."""
    verdict = aggregate_evidence((ROLE, MX_ROUTE, ACCEPTED_250))

    assert set(verdict.checks) == {"dns", "passive_classification", "smtp"}
    assert verdict.checks["smtp"] == {
        "result": ReasonCode.RCPT_ACCEPTED.value,
        "reason_count": 1,
        "evidence_count": 1,
    }


def test_the_promise_that_no_message_content_was_sent_is_carried_through() -> None:
    """Reported from the evidence rather than restated unconditionally."""
    assert aggregate_evidence((MX_ROUTE, ACCEPTED_250)).no_message_data_sent is True

    contradicted = Evidence(
        layer=EvidenceLayer.SMTP,
        reason=ReasonCode.RCPT_ACCEPTED,
        strength=EvidenceStrength.MODERATE,
        observed_at=OBSERVED_AT,
        details={"no_message_data_sent": False},
    )
    assert aggregate_evidence((MX_ROUTE, contradicted)).no_message_data_sent is False


# --- input handling ---------------------------------------------------------


def test_anything_that_is_not_evidence_is_refused_at_the_boundary() -> None:
    with pytest.raises(ValueError, match="Evidence"):
        aggregate_evidence(({"reason": "invalid_syntax"},))  # type: ignore[arg-type]


def test_a_list_and_a_generator_of_the_same_evidence_agree() -> None:
    """The parameter is a sequence; the result must not depend on which one."""
    items = [MX_ROUTE, ACCEPTED_250]
    as_sequence: Sequence[Evidence] = items
    assert aggregate_evidence(as_sequence) == aggregate_evidence(tuple(items))


def test_every_verdict_the_matrix_produces_is_a_legal_verdict() -> None:
    """`Verdict` validates itself, so this asserts the rules never fight it."""
    for _, items, _, _ in SYNTAX_AND_ROUTE_MATRIX + CONFLICT_MATRIX:
        assert isinstance(aggregate_evidence(items), Verdict)


# --- the independent review's findings, pinned ------------------------------
#
# Each of these is a property the code already had and nothing asserted. They are
# grouped so a reader can see what the review found rather than having to
# reconstruct it from where the assertions landed.


#: A set whose `REASON_PRIORITY` order is the *reverse* of the enum's.
#:
#: `internal_error` is declared last in `ReasonCode` and ranks first inside tier
#: 4; `smtp_tls_failure` is the other way round. A fixture where the two
#: orderings agree — and most do — proves nothing about which one is used, which
#: is exactly how the mutation below escaped the first time.
ORDERING_SENSITIVE = (INTERNAL_ERROR, POLICY_BLOCKED, TLS_FAILURE)


def test_reason_codes_are_ranked_by_the_priority_table_and_not_by_the_enum() -> None:
    """F1. The complete expected ordering, on a set that can tell them apart.

    Ordering `_ranked_reasons` by `list(ReasonCode).index` instead of
    `_REASON_RANK` leaves `primary_reason` correct — it is computed separately —
    and reverses this list, so `reason_codes[0]` stops being the primary reason.
    The whole suite passed with that mutation applied.
    """
    verdict = aggregate_evidence(ORDERING_SENSITIVE)

    assert verdict.reason_codes == (
        ReasonCode.INTERNAL_ERROR,
        ReasonCode.SMTP_POLICY_BLOCKED,
        ReasonCode.SMTP_TLS_FAILURE,
    )
    assert verdict.reason_codes[0] is verdict.primary_reason
    assert verdict.primary_reason is ReasonCode.INTERNAL_ERROR

    # The enum's own order, shown to differ, so the fixture cannot quietly
    # become one where both mechanisms agree.
    by_declaration = tuple(sorted(verdict.reason_codes, key=list(ReasonCode).index))
    assert by_declaration != verdict.reason_codes


@pytest.mark.parametrize(
    ("name", "items"),
    [
        ("tier 4 reversed", ORDERING_SENSITIVE),
        ("across tiers", (ROLE, MX_ROUTE, BARE_550, CONNECT_TIMEOUT, INTERNAL_ERROR)),
        ("hard invalid leading", (NULL_MX, MX_ROUTE, ACCEPTED_250, ROLE)),
        ("positive verdict", (MX_ROUTE, ACCEPTED_250, ROLE, DISPOSABLE)),
    ],
)
def test_the_primary_reason_always_leads_the_reported_reasons(
    name: str, items: tuple[Evidence, ...]
) -> None:
    """F1, as the invariant rather than as one fixture.

    `Verdict` refuses the inconsistent shape outright, so this also shows the
    aggregator never has to be trusted to keep the two orderings in step.
    """
    verdict = aggregate_evidence(items)
    assert verdict.reason_codes[0] is verdict.primary_reason, name


# --- F2: unsupported input outranks an explicit temporary condition ----------


UNSUPPORTED_OVER_TEMPORARY: tuple[tuple[str, tuple[Evidence, ...], ReasonCode], ...] = (
    (
        "quoted local part + DNS temporary",
        (SYNTAX_UNSUPPORTED, DNS_TEMPORARY),
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ),
    (
        "Unicode local part + SMTP temporary",
        (SYNTAX_SMTPUTF8, TEMPORARY_4XX),
        ReasonCode.UNSUPPORTED_SMTPUTF8,
    ),
    (
        "quoted local part + mailbox full",
        (SYNTAX_UNSUPPORTED, MAILBOX_FULL),
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ),
    (
        "domain literal + connection timeout",
        (
            ev(ReasonCode.UNSUPPORTED_DOMAIN_LITERAL, layer=EvidenceLayer.SYNTAX),
            CONNECT_TIMEOUT,
        ),
        ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
    ),
)


@pytest.mark.parametrize(
    ("name", "items", "primary"),
    UNSUPPORTED_OVER_TEMPORARY,
    ids=[row[0] for row in UNSUPPORTED_OVER_TEMPORARY],
)
def test_unsupported_input_outranks_a_temporary_condition(
    name: str, items: tuple[Evidence, ...], primary: ReasonCode
) -> None:
    """F2. The only combination that can tell tier 2 from tier 4.

    Both tiers produce `unknown`, and `REASON_PRIORITY` already ranks the three
    unsupported codes above every tier-4 reason — so deleting the tier-2 branch
    from `_base_tier` changed nothing anywhere *except* here, and the whole suite
    passed. With the branch gone these sets become `temporary_unknown` and name
    the temporary reason instead.

    The semantics matter more than the tier number: **retrying a temporarily
    failing network cannot make an address form this product does not support
    become supported**, so a bounded retry is the wrong advice to give a caller
    about an address nothing will ever parse.
    """
    verdict = aggregate_evidence(items)

    assert verdict.status is Status.UNKNOWN, name
    assert verdict.primary_reason is primary, name
    assert verdict.confidence.level is ConfidenceLevel.MEDIUM, name
    assert verdict.reason_codes[0] is primary, name
    assert len(verdict.reason_codes) == 2, name

    for ordering in permutations(items):
        assert aggregate_evidence(ordering).primary_reason is primary, (name, ordering)


def test_a_hard_invalid_still_outranks_an_unsupported_input() -> None:
    """The tier above tier 2 is unaffected by the row set above."""
    assert status_of(SYNTAX_UNSUPPORTED, DNS_TEMPORARY, NULL_MX) is Status.INVALID


# --- F3: the confidence table covers everything that can be primary ----------


def test_the_confidence_table_covers_every_reason_that_can_be_primary() -> None:
    """F3. Coverage, over the domain the lookup is actually performed on.

    The primary reason is drawn from `REASON_PRIORITY`, and
    `PERMITTED_PRIMARY_REASONS` leaves both unknown statuses open to every
    published code — so every reason can be a primary reason, and every reason
    needs a row. A code added to `REASON_PRIORITY` (which has its own test) but
    forgotten here would otherwise raise `KeyError` the first time a verdict
    named it.
    """
    from emailcheck.application.aggregate import _CONFIDENCE_BY_REASON

    assert set(_CONFIDENCE_BY_REASON) == set(REASON_PRIORITY)
    assert set(_CONFIDENCE_BY_REASON) == set(ReasonCode)

    reachable = set()
    for status, permitted in PERMITTED_PRIMARY_REASONS.items():
        del status
        reachable |= permitted
    assert reachable <= set(_CONFIDENCE_BY_REASON)


# --- F4: internal_error leads tier 4 ----------------------------------------


def test_internal_error_leads_every_other_tier_four_reason() -> None:
    """F4. The ordering that Phase 6 stop condition E rests on.

    Pinned as a position rather than as one pairing: the earlier test asserted
    only `internal_error` against `smtp_policy_blocked`, so swapping it with the
    reason immediately below it in `REASON_PRIORITY` escaped.
    """
    tier_four = [
        reason
        for reason in REASON_PRIORITY
        if reason
        not in (
            HARD_INVALID_REASONS
            | UNSUPPORTED_REASONS
            | NON_BLOCKING_REASONS
            | POSITIVE_RECIPIENT_REASONS
            | {
                ReasonCode.DNS_TEMPORARY_FAILURE,
                ReasonCode.SMTP_TEMPORARY_FAILURE,
                ReasonCode.MAILBOX_FULL,
                ReasonCode.SMTP_CONNECTION_TIMEOUT,
                ReasonCode.SMTP_CONNECTION_REFUSED,
            }
        )
    ]
    assert tier_four[0] is ReasonCode.INTERNAL_ERROR

    other = ev(ReasonCode.UNSAFE_DESTINATION, layer=EvidenceLayer.DNS, about_the_target=False)
    assert aggregate_evidence((INTERNAL_ERROR, other)).primary_reason is ReasonCode.INTERNAL_ERROR


@pytest.mark.parametrize(
    "companion",
    [
        UNSAFE_DESTINATION,
        REJECTED_POLICY_571,
        POLICY_BLOCKED,
        MAIL_FROM_REJECTED,
        TLS_FAILURE,
        BANNER_INVALID,
        PROTOCOL_ERROR,
        BARE_550,
        UNVERIFIABLE_252,
        PROVIDER_OPAQUE,
        ROUTE_ANOMALY,
    ],
    ids=lambda item: item.reason.value,
)
def test_internal_error_is_named_beside_every_same_tier_reason(companion: Evidence) -> None:
    """A bug in this project is never hidden behind a remote answer, pairwise."""
    verdict = aggregate_evidence((companion, INTERNAL_ERROR))

    assert verdict.status is Status.UNKNOWN
    assert verdict.primary_reason is ReasonCode.INTERNAL_ERROR
    assert companion.reason in verdict.reason_codes


# --- F9: the exported helper's own contract ---------------------------------


HELPER_CONTRACT: tuple[tuple[str, tuple[Evidence, ...], bool], ...] = (
    ("route only", (MX_ROUTE,), False),
    ("implicit route only", (IMPLICIT_ROUTE,), False),
    ("acceptance only", (ACCEPTED_250,), False),
    ("forward only", (FORWARDED_251,), False),
    ("route + acceptance", (MX_ROUTE, ACCEPTED_250), True),
    ("route + forward", (MX_ROUTE, FORWARDED_251), True),
    ("route + 252", (MX_ROUTE, UNVERIFIABLE_252), False),
    ("route + acceptance + blocker", (MX_ROUTE, ACCEPTED_250, TLS_FAILURE), False),
    ("nothing", (), False),
)


@pytest.mark.parametrize(
    ("name", "items", "expected"), HELPER_CONTRACT, ids=[row[0] for row in HELPER_CONTRACT]
)
def test_the_likely_deliverable_helper_answers_for_itself(
    name: str, items: tuple[Evidence, ...], expected: bool
) -> None:
    """F9. The helper is exported, so its contract is pinned on its own.

    Inside the aggregator the acceptance clause is redundant — `_base_tier`
    routes only a qualifying acceptance to tier 5, so the gate is never consulted
    without one, and replacing that clause with `return True` changed no verdict.
    The review recorded that as a redundancy rather than a defect, and the answer
    is to test the helper directly: `supports_likely_deliverable((route,))` must
    be `False` whatever the caller's own routing does.
    """
    assert supports_likely_deliverable(items) is expected, name
