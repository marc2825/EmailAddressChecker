"""Which outcomes earn the one automatic retry `docs/requirements.md` §14 allows.

**Two conditions, and the second one is Remediation A's.** A reason code in the
table is *necessary*; a first attempt that provably did not reach the recipient
stage is what makes it *sufficient*. `docs/threat-model.md` bounds one active
operation at one `RCPT TO` in total, and the final system audit measured the
previous rule breaking it: a `450` at `RCPT TO` is an "explicit temporary SMTP
response", §14 retried those, and the second verification issued a second
recipient command for one submitted address.

So every assertion here names a `RecipientTouch`. The reason table is unchanged
and still pinned row by row — that half of the policy was never wrong — and the
gate is tested as its own dimension, including the case the audit found: every
reply class that reaches this table at all reaches it *through* the recipient
stage, so in practice the recipient-stage rows are eligible by reason and
refused by touch.

The set is **closed and explicit**. There is no `if temporary: retry` shortcut,
so a reason code added to the vocabulary later is not retryable until somebody
adds it here on purpose — which is what the exhaustiveness test below is for.

Two decisions are pinned as decisions rather than inferred from rows:

- `mailbox_full` is in the table. It arises from `452 4.2.2` and from
  `552 5.2.2`, and §9 calls the latter a temporary storage condition, so §14's
  "explicit temporary SMTP response" covers both. An earlier build retried
  `450`/`451` but not `452`, a split §14 does not draw;
- `smtp_connection_timeout` is **not** in it. §14 permits that one only "if
  service health is otherwise normal", and this project does not model service
  health. A mutation adding it to the table fails here.

The verdicts are built by the real aggregator from evidence the real Phase 4D
mapper produced, so no row can assert a reason the pipeline would not emit.
"""

from __future__ import annotations

import pytest
from tests.phase6_fixtures import OBSERVED_AT, recipient_evidence

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.retry import (
    JITTER_FRACTION,
    RETRY_AFTER_SECONDS,
    jitter_span_seconds,
    retry_delay_seconds,
)
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.verdict import Verdict

_MINUTE = 60

#: The only value under which a reason code may produce a delay at all.
UNTOUCHED = RecipientTouch.NOT_TOUCHED
TOUCHED = RecipientTouch.MAYBE_TOUCHED

#: The whole policy, written out so a change to the table is a change here too.
EXPECTED_RETRYABLE: dict[ReasonCode, int] = {
    ReasonCode.SMTP_TEMPORARY_FAILURE: 20 * _MINUTE,
    ReasonCode.MAILBOX_FULL: 20 * _MINUTE,
    ReasonCode.DNS_TEMPORARY_FAILURE: 3 * _MINUTE,
}

#: Named individually rather than as "everything else", because §14's exclusions
#: are the part a later edit is most likely to erode.
EXPECTED_NOT_RETRYABLE = (
    ReasonCode.SMTP_CONNECTION_TIMEOUT,
    ReasonCode.RCPT_ACCEPTED,
    ReasonCode.RCPT_FORWARDED,
    ReasonCode.RCPT_UNVERIFIABLE,
    ReasonCode.RCPT_REJECTED_ADDRESS,
    ReasonCode.RCPT_REJECTED_POLICY,
    ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
    ReasonCode.SMTP_POLICY_BLOCKED,
    ReasonCode.SMTP_TLS_FAILURE,
    ReasonCode.SMTP_CONNECTION_REFUSED,
    ReasonCode.SMTP_BANNER_INVALID,
    ReasonCode.SMTP_PROTOCOL_ERROR,
    ReasonCode.MAIL_FROM_REJECTED,
    ReasonCode.INTERNAL_ERROR,
    ReasonCode.INVALID_SYNTAX,
    ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
    ReasonCode.UNSUPPORTED_SMTPUTF8,
    ReasonCode.DOMAIN_NXDOMAIN,
    ReasonCode.NULL_MX,
    ReasonCode.NO_MAIL_ROUTE,
    ReasonCode.MX_CONFIGURATION_ANOMALY,
    ReasonCode.MX_AVAILABLE,
    ReasonCode.IMPLICIT_MX_AVAILABLE,
    ReasonCode.UNSAFE_DESTINATION,
    ReasonCode.DISPOSABLE_DOMAIN,
    ReasonCode.ROLE_ACCOUNT,
    ReasonCode.FREE_MAIL,
    ReasonCode.PROVIDER_OPAQUE,
    ReasonCode.ACCEPT_ALL_SUSPECTED,
)


def verdict_for(reason: ReasonCode, *, layer: EvidenceLayer = EvidenceLayer.SMTP) -> Verdict:
    return aggregate_evidence(
        (
            Evidence(
                layer=layer,
                reason=reason,
                strength=EvidenceStrength.MODERATE,
                observed_at=OBSERVED_AT,
                temporary=reason in EXPECTED_RETRYABLE,
            ),
        )
    )


# --- the table matches section 14 -------------------------------------------


def test_the_retry_table_is_exactly_the_three_named_conditions() -> None:
    assert RETRY_AFTER_SECONDS == EXPECTED_RETRYABLE


def test_the_delays_are_section_14s() -> None:
    """ "approximately 20 minutes plus jitter" and "a few minutes"."""
    assert RETRY_AFTER_SECONDS[ReasonCode.SMTP_TEMPORARY_FAILURE] == 20 * _MINUTE
    assert RETRY_AFTER_SECONDS[ReasonCode.MAILBOX_FULL] == 20 * _MINUTE
    assert RETRY_AFTER_SECONDS[ReasonCode.DNS_TEMPORARY_FAILURE] == 3 * _MINUTE


# --- the closed set ---------------------------------------------------------


def test_every_published_reason_is_classified_one_way_or_the_other() -> None:
    """Exhaustive over the vocabulary, so a new `ReasonCode` fails this test
    until somebody decides which side it belongs on."""
    classified = set(EXPECTED_RETRYABLE) | set(EXPECTED_NOT_RETRYABLE)
    unclassified = set(ReasonCode) - classified
    assert unclassified == set(), f"undecided reason codes: {sorted(r.value for r in unclassified)}"


@pytest.mark.parametrize("reason", sorted(EXPECTED_RETRYABLE, key=lambda r: r.value))
def test_a_retryable_reason_schedules_one_later_attempt(reason: ReasonCode) -> None:
    """Eligible **and** untouched. The positive control for both conditions."""
    delay = retry_delay_seconds(verdict_for(reason), recipient_touch=UNTOUCHED)
    assert delay == float(EXPECTED_RETRYABLE[reason])


@pytest.mark.parametrize("reason", EXPECTED_NOT_RETRYABLE, ids=lambda r: r.value)
def test_a_non_retryable_reason_schedules_nothing(reason: ReasonCode) -> None:
    assert retry_delay_seconds(verdict_for(reason), recipient_touch=UNTOUCHED) is None
    assert jitter_span_seconds(verdict_for(reason), recipient_touch=UNTOUCHED) == 0.0


# --- the recipient-touch gate ------------------------------------------------
#
# The half the final system audit added. Each of these fails if the gate is
# removed from `retry_delay_seconds`, and none of them depends on which reason
# code is involved — which is the point: no reason may outrank the bound.


@pytest.mark.parametrize("reason", sorted(EXPECTED_RETRYABLE, key=lambda r: r.value))
def test_a_touched_recipient_refuses_every_eligible_reason(reason: ReasonCode) -> None:
    """The exact defect: `450`-class reasons are eligible and still not retried.

    Same verdict, same table, same delay — and `None`, because the first attempt
    may already have put this recipient in front of a mail server. A second one
    twenty minutes later is a second `RCPT TO` for one submitted address, which
    is the enumeration pattern `docs/threat-model.md` lists first.
    """
    verdict = verdict_for(reason)
    assert retry_delay_seconds(verdict, recipient_touch=UNTOUCHED) is not None
    assert retry_delay_seconds(verdict, recipient_touch=TOUCHED) is None
    assert jitter_span_seconds(verdict, recipient_touch=TOUCHED) == 0.0


def test_the_gate_is_not_a_default_a_caller_can_omit() -> None:
    """`recipient_touch` is required, and a non-answer is refused rather than
    read as "safe". A call site that forgets it must not compile, and a caller
    that passes something else must not be given a delay."""
    with pytest.raises(TypeError):
        retry_delay_seconds(verdict_for(ReasonCode.DNS_TEMPORARY_FAILURE))  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        retry_delay_seconds(
            verdict_for(ReasonCode.DNS_TEMPORARY_FAILURE),
            recipient_touch="not_touched",  # type: ignore[arg-type]
        )


def test_replay_safety_is_a_property_of_the_value_rather_than_a_comparison() -> None:
    """One member answers yes and one answers no, with nothing in between."""
    assert UNTOUCHED.replay_is_safe is True
    assert TOUCHED.replay_is_safe is False
    assert len(list(RecipientTouch)) == 2


def test_a_connection_timeout_is_not_retried_and_no_health_signal_is_invented() -> None:
    """§14 permits that retry only "if service health is otherwise normal".

    This project does not model service health, so retrying anyway would be
    implementing half a rule and calling it the rule. ADR 0014 records the
    decision; this is what fails when somebody adds the row.
    """
    assert ReasonCode.SMTP_CONNECTION_TIMEOUT not in RETRY_AFTER_SECONDS
    assert (
        retry_delay_seconds(
            verdict_for(ReasonCode.SMTP_CONNECTION_TIMEOUT), recipient_touch=UNTOUCHED
        )
        is None
    )


def test_there_is_no_temporary_shortcut() -> None:
    """A reason marked temporary is not retryable by that fact alone.

    `rcpt_unverifiable` and a refused connection are both non-permanent in
    ordinary language, and neither is one of §14's three conditions.
    """
    for reason in (ReasonCode.RCPT_UNVERIFIABLE, ReasonCode.SMTP_CONNECTION_REFUSED):
        temporary = aggregate_evidence(
            (
                Evidence(
                    layer=EvidenceLayer.SMTP,
                    reason=reason,
                    strength=EvidenceStrength.MODERATE,
                    observed_at=OBSERVED_AT,
                    temporary=True,
                ),
            )
        )
        assert retry_delay_seconds(temporary, recipient_touch=UNTOUCHED) is None, reason.value


# --- the reply classes, through the real mapper -----------------------------


@pytest.mark.parametrize(
    ("lines", "expected_reason", "retried"),
    [
        (("450 4.2.1 mailbox busy",), ReasonCode.SMTP_TEMPORARY_FAILURE, True),
        (("451 4.3.0 local error",), ReasonCode.SMTP_TEMPORARY_FAILURE, True),
        (("452 4.2.2 over quota",), ReasonCode.MAILBOX_FULL, True),
        (("552 5.2.2 mailbox full",), ReasonCode.MAILBOX_FULL, True),
        (("250 2.1.5 ok",), ReasonCode.RCPT_ACCEPTED, False),
        (("251 will forward",), ReasonCode.RCPT_FORWARDED, False),
        (("252 cannot verify",), ReasonCode.RCPT_UNVERIFIABLE, False),
        (("550 5.1.1 user unknown",), ReasonCode.RCPT_REJECTED_ADDRESS, False),
        (("550 rejected",), ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE, False),
        (("550 5.7.1 not permitted",), ReasonCode.RCPT_REJECTED_POLICY, False),
    ],
    ids=[
        "450",
        "451",
        "452",
        "552 5.2.2",
        "250",
        "251",
        "252",
        "550 5.1.1",
        "bare 550",
        "550 5.7.1",
    ],
)
def test_each_recipient_class_through_the_real_mapper(
    lines: tuple[str, ...], expected_reason: ReasonCode, retried: bool
) -> None:
    """The classification is the reason code's, never the reply's first digit.

    `552 5.2.2` is a 5xx whose *reason* is eligible and `550 5.7.1` is a 5xx
    whose reason is not, which is only expressible by branching on the semantic
    reason. `retried` is that reason-level eligibility, asserted under
    `NOT_TOUCHED` so it measures the table alone.

    What actually happens to these replies is the next test: every one of them
    arrives through the recipient stage, so none of them is retried at all.
    """
    verdict = aggregate_evidence(recipient_evidence(lines))
    assert verdict.primary_reason is expected_reason
    assert (retry_delay_seconds(verdict, recipient_touch=UNTOUCHED) is not None) is retried


@pytest.mark.parametrize(
    "lines",
    [
        ("450 4.2.1 mailbox busy",),
        ("451 4.3.0 local error",),
        ("452 4.2.2 over quota",),
        ("552 5.2.2 mailbox full",),
        ("250 2.1.5 ok",),
        ("550 5.1.1 user unknown",),
    ],
    ids=["450", "451", "452", "552 5.2.2", "250", "550 5.1.1"],
)
def test_no_reply_to_a_recipient_command_is_ever_replayed(lines: tuple[str, ...]) -> None:
    """The defect, stated as the property that now holds.

    A reply to `RCPT TO` — of any class — is by construction a reply the
    recipient stage produced, so the operation's touch is `MAYBE_TOUCHED` and no
    delay exists for it. The four temporary rows are the ones that used to
    schedule a second verification.
    """
    verdict = aggregate_evidence(recipient_evidence(lines))
    assert retry_delay_seconds(verdict, recipient_touch=TOUCHED) is None, lines


def test_a_5xx_that_is_not_mailbox_full_is_never_retried() -> None:
    for lines in (("550 5.1.1 unknown",), ("550 rejected",), ("550 5.7.1 policy",), ("553 bad",)):
        verdict = aggregate_evidence(recipient_evidence(lines))
        assert retry_delay_seconds(verdict, recipient_touch=UNTOUCHED) is None, lines


# --- jitter -----------------------------------------------------------------


def test_jitter_is_bounded_by_a_fraction_of_the_delay() -> None:
    verdict = verdict_for(ReasonCode.SMTP_TEMPORARY_FAILURE)
    base = float(RETRY_AFTER_SECONDS[ReasonCode.SMTP_TEMPORARY_FAILURE])
    assert jitter_span_seconds(verdict, recipient_touch=UNTOUCHED) == base * JITTER_FRACTION
    # An over-large jitter is clamped rather than trusted.
    assert (
        retry_delay_seconds(verdict, recipient_touch=UNTOUCHED, jitter_seconds=1e9)
        == base + base * JITTER_FRACTION
    )


def test_a_negative_or_wrongly_typed_jitter_is_refused() -> None:
    verdict = verdict_for(ReasonCode.SMTP_TEMPORARY_FAILURE)
    for bad in (-1.0, True, "20"):
        with pytest.raises(ValueError):
            retry_delay_seconds(verdict, recipient_touch=UNTOUCHED, jitter_seconds=bad)  # type: ignore[arg-type]


def test_a_verdict_with_no_primary_reason_is_not_retried() -> None:
    assert retry_delay_seconds(aggregate_evidence(()), recipient_touch=UNTOUCHED) is None
