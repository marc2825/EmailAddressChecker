"""One SMTP session, expressed as evidence — and still not as a status.

`docs/status-model.md` section 7 is the specification, written in gate 4C before
this code existed. This module implements it and nothing more: a `SessionReport`
becomes `Evidence` carrying a published `ReasonCode`, and what that evidence
*means* for deliverability is decided in Phase 5 with the syntax, DNS, and
passive evidence in front of it.

Three properties are worth reading the code for.

**Nothing here reads one field.** The classification uses the outcome, the stage
reached, the basic code, the enhanced code, the deadline flag, and the TLS
detail together. A `550` to `MAIL FROM` and a lost connection at the banner are
both `CONNECTION_ERROR`, because `RecipientStageOutcome` describes the recipient
stage and neither session reached it; only `stage_reached` separates them.
`is_about_the_target` is a filter, not a classifier — it is true for every 2xx,
including `252`.

**`252` is separated first.** Before any generic handling of a 2xx reply, because
gate 4C records it as `ACCEPTED` — at that layer `ACCEPTED` means only "answered
in the 2xx class" — and a mapping written as `if outcome is ACCEPTED` turns a
server's refusal to verify into an acceptance. That is the Phase 4D entry
condition in `plans/phase-04-smtp.md`, and it is the first branch below.

**This is a pure function.** No socket, no clock, no resolver, no limiter, no
storage, and no retry. Even the timestamp is a parameter: `Evidence.observed_at`
is the one thing a mapper would otherwise need a clock for, and a mapper that
took a clock would be a mapper whose output depended on when it ran.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, assert_never

from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.smtp_protocol import STAGE_ORDER, DialogueStage, SessionReport
from emailcheck.domain.smtp_reply import EnhancedStatusCode, SMTPReply
from emailcheck.domain.smtp_result import RecipientStageOutcome
from emailcheck.domain.smtp_transport import TransportFailure

#: The version of these rules, recorded on every piece of evidence they produce.
#: `docs/status-model.md` section 5 requires a reason vocabulary change to be a
#: versioned event; this is what lets a stored result say which rules produced
#: it.
SMTP_EVIDENCE_RULESET: Final = "smtp-evidence-2026-08-08"

#: `252`. Named rather than written inline, because the branch that reads it is
#: the one the whole mapping is arranged around.
UNVERIFIABLE_CODE: Final = 252

#: `251`, accepted for forwarding.
FORWARDED_CODE: Final = 251

#: Reason codes this mapper produces that say nothing about the target address.
#:
#: Published as a set rather than left implicit in prose, so Phase 5 can filter
#: on it instead of re-deriving it, and so a test can assert that a sender
#: rejection, a TLS failure, and a deadline never leave it.
NON_TARGET_SMTP_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.SMTP_CONNECTION_TIMEOUT,
        ReasonCode.SMTP_CONNECTION_REFUSED,
        ReasonCode.SMTP_BANNER_INVALID,
        ReasonCode.SMTP_PROTOCOL_ERROR,
        ReasonCode.SMTP_TLS_FAILURE,
        ReasonCode.SMTP_POLICY_BLOCKED,
        ReasonCode.MAIL_FROM_REJECTED,
        ReasonCode.UNSAFE_DESTINATION,
        ReasonCode.INTERNAL_ERROR,
    }
)

#: Reason codes that describe what the server said about the recipient. Only a
#: session that issued `RCPT TO` and read its reply can produce one.
RECIPIENT_STAGE_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.RCPT_ACCEPTED,
        ReasonCode.RCPT_FORWARDED,
        ReasonCode.RCPT_UNVERIFIABLE,
        ReasonCode.RCPT_REJECTED_ADDRESS,
        ReasonCode.RCPT_REJECTED_POLICY,
        ReasonCode.SMTP_TEMPORARY_FAILURE,
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
        ReasonCode.MAILBOX_FULL,
    }
)

#: The only reasons that are *positive* recipient evidence.
#:
#: `RCPT_UNVERIFIABLE` is deliberately absent. It is a recipient-stage reason —
#: the server was asked about the recipient and answered — and it is not
#: evidence that the recipient exists, because the answer was "I will not tell
#: you". A test asserts the absence, because the two sets differing by exactly
#: that member is the whole point of section 7.4.
#:
#: **This is a semantic category, not an aggregation rule.** Membership says the
#: server answered positively about the recipient at that stage; it does not say
#: the address is deliverable. Phase 5 may not write
#: `if reason in POSITIVE_RECIPIENT_REASONS: return LIKELY_DELIVERABLE` — the
#: precedence in `docs/status-model.md` section 4 puts hard-invalid, unsupported,
#: temporary, and policy evidence in front of an accepted recipient, and an
#: accept-all server says `250` to everyone.
POSITIVE_RECIPIENT_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.RCPT_ACCEPTED,
        ReasonCode.RCPT_FORWARDED,
    }
)

#: Outcomes that mean the recipient stage produced an answer. A pre-recipient
#: rejection is `CONNECTION_ERROR` and can never be any of these, which is the
#: first of two barriers between a `MAIL FROM 550` and a recipient rejection.
_RECIPIENT_ANSWERS: Final[frozenset[RecipientStageOutcome]] = frozenset(
    {
        RecipientStageOutcome.ACCEPTED,
        RecipientStageOutcome.REJECTED,
        RecipientStageOutcome.TEMPORARY_FAILURE,
    }
)

#: Stages at or past the recipient stage. The second barrier.
#:
#: Derived from `STAGE_ORDER` rather than written out, so a stage added after
#: `RCPT_TO` in a later gate is included automatically. A hardcoded pair would
#: silently treat a new post-recipient stage as pre-recipient, and a real
#: recipient answer would then vanish into `smtp_policy_blocked`.
#:
#: Today this is `{rcpt_to, cleanup}`, and **`cleanup` is the one every real
#: session reports**: `application/smtp_dialogue.py` records the recipient reply
#: with `stage=CLEANUP`, because `RCPT_TO` is the stage a dialogue is *in* while
#: the command is outstanding. `docs/status-model.md` section 7.3 says so, and a
#: Phase 5 filter written as `stage_reached == "rcpt_to"` would discard every
#: recipient answer this project produces.
_AT_OR_PAST_RECIPIENT: Final[frozenset[DialogueStage]] = frozenset(
    STAGE_ORDER[STAGE_ORDER.index(DialogueStage.RCPT_TO) :]
)

#: RFC 3463 subject/detail pairs this mapping reads. Nothing else is branched on;
#: every other enhanced code is carried as metadata and decides nothing.
_MAILBOX_STORAGE: Final = (2, 2)
_RECIPIENT_DOES_NOT_EXIST: Final = (1, 1)
_SECURITY_OR_POLICY_SUBJECT: Final = 7
#: RFC 3463 classes that can carry a failure, and the permanent one on its own.
_FAILURE_CLASSES: Final[frozenset[int]] = frozenset({4, 5})
_PERMANENT_CLASS: Final = 5


@dataclass(frozen=True, slots=True)
class _Finding:
    """One classification, before it is dressed up as `Evidence`."""

    reason: ReasonCode
    strength: EvidenceStrength
    temporary: bool


# --- the public mapping ----------------------------------------------------


def map_session_evidence(report: SessionReport, *, observed_at: datetime) -> tuple[Evidence, ...]:
    """Turn one completed session into evidence.

    Returns a tuple so the shape is stable for Phase 5 and for a later gate that
    may add a second item. Today it holds **exactly one** piece of evidence: the
    primary observation, with the TLS detail, the deadline flag, and the cleanup
    status carried as details on it rather than as evidence of their own.

    That is deliberate, and it is the answer to two requirements at once. A
    cleanup failure must never overwrite the recipient's answer, and cleanup must
    never reach a verdict on its own — so it is metadata on the one piece of
    evidence, which makes both impossible rather than merely discouraged.

    Deterministic: the same report always produces the same tuple, in the same
    order, with the same detail keys in the same order. Nothing iterates a set.
    """
    _check_observed_at(observed_at)
    finding = _classify(report)
    return (
        Evidence(
            layer=_layer_for(finding.reason),
            reason=finding.reason,
            strength=finding.strength,
            observed_at=observed_at,
            temporary=finding.temporary,
            source_version=SMTP_EVIDENCE_RULESET,
            details=_session_details(report, finding),
        ),
    )


def map_connect_failure(
    failure: TransportFailure,
    *,
    observed_at: datetime,
    deadline_exhausted: bool = False,
    elapsed_milliseconds: int | None = None,
) -> tuple[Evidence, ...]:
    """Turn a probe that never produced a session into evidence.

    `SMTPProbeService` answers with a `ProbeRefused` when the connection was
    refused, timed out, or was closed before a byte went out; a caller passes its
    transport failure and its deadline flag here. The primitives are taken rather
    than the refusal object, so this module imports nothing that imports
    `asyncio`, and the purity inspection has something narrow to check.

    `deadline_exhausted` wins over the transport's own failure, because the flag
    exists precisely to distinguish this project's bound from the network's, and
    both otherwise report the same reason.

    **A refusal at `approve_destination` is not mapped here.** That happens
    before any transport failure exists, and it is a DNS-layer fact the Phase 2
    route already reported as `unsafe_destination`. Handing it to an SMTP mapper
    would produce a second, weaker copy of evidence that already exists.

    This entry point takes raw primitives rather than validated domain values,
    which the session path does not: there, `RecipientObservation` has already
    refused a negative elapsed time and `SessionReport` has already checked the
    transcript. So the checking happens here, and the two entry points answer to
    the same contract rather than to whichever one the caller happened to use.
    """
    _check_observed_at(observed_at)
    _check_arguments(
        failure, deadline_exhausted=deadline_exhausted, elapsed_milliseconds=elapsed_milliseconds
    )
    finding = _connect_finding(failure, deadline_exhausted=deadline_exhausted)
    return (
        Evidence(
            layer=_layer_for(finding.reason),
            reason=finding.reason,
            strength=finding.strength,
            observed_at=observed_at,
            temporary=finding.temporary,
            source_version=SMTP_EVIDENCE_RULESET,
            details=_connect_details(
                failure,
                finding,
                deadline_exhausted=deadline_exhausted,
                elapsed_milliseconds=elapsed_milliseconds,
            ),
        ),
    )


# --- what a caller may hand this module ------------------------------------


def _check_observed_at(observed_at: datetime) -> None:
    """The timestamp must be a real, aware datetime.

    `Evidence` refuses the same thing, deliberately: this check gives the caller
    the error at the boundary it crossed, and the value type keeps the guarantee
    for every other producer. Both are tested, so neither is load-bearing alone.
    """
    if not isinstance(observed_at, datetime):
        raise ValueError("observed_at must be a datetime")
    if observed_at.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")


def _check_arguments(
    failure: TransportFailure,
    *,
    deadline_exhausted: bool,
    elapsed_milliseconds: int | None,
) -> None:
    """Refuse a primitive the session path would already have refused.

    `elapsed_milliseconds` carries no maximum, because `RecipientObservation`
    carries none either and the two contracts must agree. A boolean is refused
    even though `bool` is an `int`, because `True` would be recorded as one
    millisecond.
    """
    if not isinstance(failure, TransportFailure):
        raise ValueError("a connect failure must be a TransportFailure")
    if not isinstance(deadline_exhausted, bool):
        raise ValueError("deadline_exhausted must be a boolean")
    if elapsed_milliseconds is None:
        return
    if isinstance(elapsed_milliseconds, bool) or not isinstance(elapsed_milliseconds, int):
        raise ValueError("elapsed time must be a whole number of milliseconds")
    if elapsed_milliseconds < 0:
        raise ValueError("elapsed time cannot be negative")


# --- classification --------------------------------------------------------


def _require_known_outcome(outcome: RecipientStageOutcome) -> None:
    """Refuse an outcome this classifier was not written against.

    **Phase 5 stop condition, closed here.** The branches below were written
    against exactly seven members. A member added to `RecipientStageOutcome`
    without revisiting them would satisfy none of the named branches, fall
    through `_recipient_reply` — whose first barrier is membership of
    `_RECIPIENT_ANSWERS` — and be reported as `smtp_connection_timeout`: a
    temporary, non-target reason, invented for it silently. Phase 5 then weighs
    that as a real timeout. `TransportFailure` already fails loudly through the
    `_CONNECT_REASONS` subscript and `DialogueStage` is derived from
    `STAGE_ORDER`; this was the one enum left with neither.

    It fails twice over. `assert_never` narrows to `Never`, so **mypy** rejects a
    new member at this line, and reaching it at run time raises `AssertionError`
    rather than returning a default — the same "loud beats plausible" choice as
    the `_CONNECT_REASONS` subscript.

    **This is a guard and deliberately not the dispatch.** Turning it into the
    dispatch would be tidier and would quietly delete a reviewed barrier: the
    `outcome not in _RECIPIENT_ANSWERS` check in `_recipient_reply` is one of the
    three that stand between a `MAIL FROM 550` and a recipient rejection, and it
    is pinned by a test that fails when that check alone is removed. A `match`
    that routed `CONNECTION_ERROR` straight to `_pre_recipient_finding` would
    make that check unreachable, and its test would pass with the check deleted.
    Exhaustiveness is worth having; it is not worth paying for with a barrier.
    """
    match outcome:
        case (
            RecipientStageOutcome.ACCEPTED
            | RecipientStageOutcome.REJECTED
            | RecipientStageOutcome.TEMPORARY_FAILURE
            | RecipientStageOutcome.PROTOCOL_ERROR
            | RecipientStageOutcome.TLS_ERROR
            | RecipientStageOutcome.CONNECTION_ERROR
            | RecipientStageOutcome.INTERNAL_ERROR
        ):
            return
        case _ as unreachable:  # pragma: no cover - unreachable while the enum is closed
            assert_never(unreachable)


def _classify(report: SessionReport) -> _Finding:
    """Which reason one session produced. The branch order is the specification.

    1. this project's own failure, which is never about anything remote;
    2. TLS, before anything reply-shaped — a TLS failure ends the dialogue, and
       whatever reply it carried answered `STARTTLS` rather than the recipient;
    3. the recipient stage, and only when the recipient actually answered;
    4. everything else, which happened before the recipient stage.

    Every member of `RecipientStageOutcome` is accounted for before any of that,
    so a member added later fails rather than becoming a silent timeout.
    """
    observation = report.observation
    _require_known_outcome(observation.outcome)

    if observation.outcome is RecipientStageOutcome.INTERNAL_ERROR:
        return _Finding(ReasonCode.INTERNAL_ERROR, EvidenceStrength.WEAK, temporary=False)

    if observation.outcome is RecipientStageOutcome.TLS_ERROR:
        # Every TLS reason collapses here on purpose, including the refusal to
        # upgrade over a non-empty read buffer. `docs/status-model.md` section
        # 7.2: different diagnostics, one decision, and none of them is mailbox
        # invalidity.
        return _Finding(ReasonCode.SMTP_TLS_FAILURE, EvidenceStrength.WEAK, temporary=False)

    recipient_reply = _recipient_reply(report)
    if recipient_reply is not None:
        return _recipient_finding(recipient_reply)

    return _pre_recipient_finding(report)


def _recipient_reply(report: SessionReport) -> SMTPReply | None:
    """The reply the recipient stage produced, or `None` if it never got one.

    **Three independent barriers, and each is load-bearing on input a caller can
    construct.** "A `MAIL FROM 550` becomes a recipient rejection" is the single
    worst mistake this mapping could make, so no one of these carries it alone:

    - the outcome must be one a recipient answer produces. It alone refuses a
      `connection_error` at `cleanup` carrying a `550 5.1.1`, with one recipient
      attempted;
    - exactly one recipient must have been attempted. It alone refuses a
      `rejected` at `cleanup` carrying a `550 5.1.1`, with none attempted;
    - the session must have reached the recipient stage. It alone refuses a
      `rejected` at `mail_from` carrying a `550 5.1.1`, with one attempted.

    Every one of those constructs — `SessionReport` and `RecipientObservation`
    permit them all — so the review's rule applies: *two barriers are only two
    barriers if each is pinned by its own test*. Each row above has one, and each
    fails when that barrier alone is removed.
    """
    observation = report.observation
    if observation.outcome not in _RECIPIENT_ANSWERS:
        return None
    if observation.recipients_attempted != 1:
        return None
    if report.stage_reached not in _AT_OR_PAST_RECIPIENT:
        return None
    return observation.reply


def _recipient_finding(reply: SMTPReply) -> _Finding:
    """Classify the reply to the one `RCPT TO`. Never a status.

    `250` is not mailbox existence — an accept-all server says it to everyone —
    and a bare `550` is not mailbox absence, because policy rejections share the
    code. What this decides is which *observation* was made.
    """
    # `252` first, before any generic handling of a 2xx reply. The server
    # declined to verify the recipient: that is unverifiable evidence, and it is
    # not an acceptance. See `docs/status-model.md` section 7.4.
    if reply.code == UNVERIFIABLE_CODE:
        return _Finding(ReasonCode.RCPT_UNVERIFIABLE, EvidenceStrength.WEAK, temporary=False)

    if _is_mailbox_storage_condition(reply.enhanced):
        # `X.2.2` is a storage condition whichever class carries it.
        # `docs/requirements.md` section 9 names `552` with an explicit `X.2.2`
        # as a *temporary* mailbox condition, so the enhanced code outranks the
        # basic class here — the one place in this mapping where it does.
        return _Finding(ReasonCode.MAILBOX_FULL, EvidenceStrength.MODERATE, temporary=True)

    if reply.code == FORWARDED_CODE:
        return _Finding(ReasonCode.RCPT_FORWARDED, EvidenceStrength.MODERATE, temporary=False)

    if reply.code // 100 == 2:
        # Moderate, never strong: `docs/status-model.md` section 3 caps an
        # accepted recipient at medium confidence for exactly this reason.
        return _Finding(ReasonCode.RCPT_ACCEPTED, EvidenceStrength.MODERATE, temporary=False)

    if reply.is_transient:
        # No greylisting is asserted. A `4.7.1` is carried as metadata and read
        # by nothing here: deciding that a temporary policy refusal *is*
        # greylisting would be a guess dressed as an observation.
        return _Finding(
            ReasonCode.SMTP_TEMPORARY_FAILURE, EvidenceStrength.MODERATE, temporary=True
        )

    if _identifies_the_recipient(reply.enhanced):
        # The strongest evidence this project produces, and still not a verdict:
        # Phase 5 weighs it against everything else.
        return _Finding(ReasonCode.RCPT_REJECTED_ADDRESS, EvidenceStrength.STRONG, temporary=False)

    if _is_policy_refusal(reply.enhanced):
        return _Finding(ReasonCode.RCPT_REJECTED_POLICY, EvidenceStrength.WEAK, temporary=False)

    # A permanent rejection nothing disambiguates. Weak on purpose: policy,
    # reputation, and a badly expressed greylisting all arrive here.
    return _Finding(
        ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE, EvidenceStrength.WEAK, temporary=False
    )


def _pre_recipient_finding(report: SessionReport) -> _Finding:
    """Classify a session that never got an answer about the recipient.

    None of these is target evidence, and every reason produced here is in
    `NON_TARGET_SMTP_REASONS`.
    """
    observation = report.observation
    reply = observation.reply

    if observation.outcome is RecipientStageOutcome.PROTOCOL_ERROR:
        if report.stage_reached is DialogueStage.BANNER:
            return _Finding(ReasonCode.SMTP_BANNER_INVALID, EvidenceStrength.WEAK, temporary=False)
        return _Finding(ReasonCode.SMTP_PROTOCOL_ERROR, EvidenceStrength.WEAK, temporary=False)

    if report.deadline_exhausted:
        # This project's own bound. Named before the network's, because the flag
        # exists to tell the two apart, and `details` records which it was.
        return _Finding(ReasonCode.SMTP_CONNECTION_TIMEOUT, EvidenceStrength.WEAK, temporary=True)

    if reply is not None:
        if report.stage_reached is DialogueStage.MAIL_FROM:
            # The envelope sender was refused. `docs/requirements.md` section 9
            # puts sender, connection, reputation, and policy failures outside
            # target-address invalidity, and this is the one that most looks
            # like a recipient rejection while being nothing of the kind.
            return _Finding(
                ReasonCode.MAIL_FROM_REJECTED, EvidenceStrength.WEAK, temporary=reply.is_transient
            )
        return _Finding(
            ReasonCode.SMTP_POLICY_BLOCKED, EvidenceStrength.WEAK, temporary=reply.is_transient
        )

    # No reply at all: the connection was lost, reset, or closed mid-dialogue.
    # `SessionReport` carries no `TransportFailure`, so which of those it was is
    # not recoverable here; `docs/status-model.md` section 7.2 fixes the answer.
    return _Finding(ReasonCode.SMTP_CONNECTION_TIMEOUT, EvidenceStrength.WEAK, temporary=True)


#: Every transport failure, and the reason it becomes.
#:
#: **The subscript below is the mechanism, and it is pinned rather than trusted.**
#: A new `TransportFailure` member raises `KeyError` here, which is loud; a
#: `.get(failure, SMTP_CONNECTION_TIMEOUT)` would quietly call it a timeout, and
#: an earlier test only asserted the result was *a* reason code, which is true
#: either way. Two tests now hold it: one that the keys are exactly the enum, and
#: one that an unmapped failure raises rather than defaulting.
_CONNECT_REASONS: Final[Mapping[TransportFailure, ReasonCode]] = {
    TransportFailure.CONNECT_TIMEOUT: ReasonCode.SMTP_CONNECTION_TIMEOUT,
    TransportFailure.CONNECTION_REFUSED: ReasonCode.SMTP_CONNECTION_REFUSED,
    TransportFailure.NETWORK_UNREACHABLE: ReasonCode.SMTP_CONNECTION_REFUSED,
    TransportFailure.PEER_DENIED_BY_POLICY: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.PEER_ADDRESS_MISMATCH: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.PEER_PORT_MISMATCH: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.PEER_MALFORMED: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.PEER_UNEXPECTED_FAMILY: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.DESTINATION_DENIED_BY_POLICY: ReasonCode.UNSAFE_DESTINATION,
    TransportFailure.READ_TIMEOUT: ReasonCode.SMTP_CONNECTION_TIMEOUT,
    TransportFailure.WRITE_TIMEOUT: ReasonCode.SMTP_CONNECTION_TIMEOUT,
    TransportFailure.CONNECTION_RESET: ReasonCode.SMTP_CONNECTION_TIMEOUT,
    TransportFailure.CONNECTION_CLOSED: ReasonCode.SMTP_CONNECTION_TIMEOUT,
    TransportFailure.LINE_TOO_LONG: ReasonCode.SMTP_PROTOCOL_ERROR,
    TransportFailure.TOTAL_LIMIT_EXCEEDED: ReasonCode.SMTP_PROTOCOL_ERROR,
    TransportFailure.TLS_HANDSHAKE_FAILED: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.TLS_CERTIFICATE_INVALID: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.TLS_HOSTNAME_MISMATCH: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.TLS_TIMEOUT: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.TLS_PEER_CHANGED: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.TLS_ALREADY_ACTIVE: ReasonCode.SMTP_TLS_FAILURE,
    TransportFailure.INTERNAL_ERROR: ReasonCode.INTERNAL_ERROR,
}

#: Reasons from the table above that are worth one bounded retry.
#: `docs/requirements.md` section 14 allows one for a timeout and for an
#: explicitly temporary condition, and for nothing else.
_TEMPORARY_CONNECT_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {ReasonCode.SMTP_CONNECTION_TIMEOUT, ReasonCode.SMTP_CONNECTION_REFUSED}
)


def _connect_finding(failure: TransportFailure, *, deadline_exhausted: bool) -> _Finding:
    if deadline_exhausted:
        return _Finding(ReasonCode.SMTP_CONNECTION_TIMEOUT, EvidenceStrength.WEAK, temporary=True)
    reason = _CONNECT_REASONS[failure]
    return _Finding(reason, EvidenceStrength.WEAK, temporary=reason in _TEMPORARY_CONNECT_REASONS)


# --- enhanced status codes, read narrowly ----------------------------------


def _is_mailbox_storage_condition(enhanced: EnhancedStatusCode | None) -> bool:
    """Whether this is `X.2.2`, on a class that can carry a failure.

    A class-2 code is a success code, so `250 2.2.2` is not a storage failure
    however it reads; only `4.2.2` and `5.2.2` are.
    """
    if enhanced is None:
        return False
    if enhanced.status_class not in _FAILURE_CLASSES:
        return False
    return (enhanced.subject, enhanced.detail) == _MAILBOX_STORAGE


def _identifies_the_recipient(enhanced: EnhancedStatusCode | None) -> bool:
    """Whether this is exactly `5.1.1`, and nothing that merely resembles it.

    `5.1.0` is "other address status" and `5.1.6` is a moved mailbox. Neither
    says the recipient does not exist, so neither becomes the strongest evidence
    this project produces.

    **The class is checked here rather than assumed from the call site.** Three
    things already keep a `4.1.1` away from this branch — the 4A parser drops an
    enhanced code whose class contradicts the basic one, `SMTPReply` refuses to
    be constructed carrying the contradiction, and `_recipient_finding` reads
    `is_transient` first — and none of them is a property of *this* function. A
    helper that turns `4.1.1` into the strongest evidence this project produces
    is one bad edit away from being reachable, so it refuses on its own.
    """
    if enhanced is None:
        return False
    if enhanced.status_class != _PERMANENT_CLASS:
        return False
    return (enhanced.subject, enhanced.detail) == _RECIPIENT_DOES_NOT_EXIST


def _is_policy_refusal(enhanced: EnhancedStatusCode | None) -> bool:
    """Whether this is a permanent RFC 3463 security-or-policy refusal.

    Class-checked for the same reason as `_identifies_the_recipient`: a `4.7.1`
    is greylisting far more often than it is a policy refusal, and the mapping
    keeps it a temporary failure rather than guessing.
    """
    if enhanced is None:
        return False
    return (
        enhanced.status_class == _PERMANENT_CLASS
        and enhanced.subject == _SECURITY_OR_POLICY_SUBJECT
    )


# --- shaping the evidence --------------------------------------------------


def _is_about_the_target(reason: ReasonCode) -> bool:
    """Whether this evidence says anything about the address itself.

    **Derived from what is known to be target evidence, never from what is known
    not to be.** The obvious form, `reason not in NON_TARGET_SMTP_REASONS`, fails
    *open*: a reason added later and forgotten from both published sets would be
    labelled target evidence, which is the direction `AGENTS.md` says this
    project must never be wrong in. This form fails closed — an unclassified
    reason is non-target, and section 4 resolves it to `unknown`.

    The two sets partition every reason this mapper emits, and a test fixes that,
    so the two forms agree today. They stop agreeing exactly when someone forgets,
    which is the case worth choosing for.
    """
    return reason in RECIPIENT_STAGE_REASONS


def _layer_for(reason: ReasonCode) -> EvidenceLayer:
    """Which layer this evidence is attributed to.

    Almost always `SMTP`. Two exceptions, and both are honest rather than tidy:
    a failure of this project's own belongs to `INTERNAL`, and a destination the
    policy refuses is a `DNS`-layer fact that the transport happened to catch on
    its re-check. `docs/status-model.md` section 5 lists `unsafe_destination`
    under `dns`, and reporting it under `smtp` would put one reason code under
    two layers depending on which component noticed.
    """
    if reason is ReasonCode.INTERNAL_ERROR:
        return EvidenceLayer.INTERNAL
    if reason is ReasonCode.UNSAFE_DESTINATION:
        return EvidenceLayer.DNS
    return EvidenceLayer.SMTP


def _session_details(
    report: SessionReport, finding: _Finding
) -> Mapping[str, str | int | bool | None]:
    """The safe structured detail of one session.

    Everything here is either a code, an enum value, a bounded sanitized
    diagnostic, or a flag. No raw reply, no wire command, no transcript, no
    certificate, no library text, and no address: `docs/requirements.md` section
    11 forbids all of those in a public response, and this is what reaches one.

    The key order is fixed, so two equal reports produce two equal mappings.
    """
    observation = report.observation
    reply = observation.reply
    return {
        "stage_reached": report.stage_reached.value,
        "recipient_stage": finding.reason in RECIPIENT_STAGE_REASONS,
        "about_the_target": _is_about_the_target(finding.reason),
        "basic_code": observation.basic_code,
        "enhanced_code": observation.enhanced_code,
        "diagnostic": reply.diagnostic if reply is not None and reply.diagnostic else None,
        "defect": observation.defect.value if observation.defect is not None else None,
        "tls_negotiated": report.tls.negotiated,
        "tls_reason": report.tls.reason.value if report.tls.reason is not None else None,
        "deadline_exhausted": report.deadline_exhausted,
        "cleanup": report.cleanup.value,
        "recipients_attempted": observation.recipients_attempted,
        "no_message_data_sent": observation.no_message_data_sent,
        "elapsed_milliseconds": observation.elapsed_milliseconds,
    }


def _connect_details(
    failure: TransportFailure,
    finding: _Finding,
    *,
    deadline_exhausted: bool,
    elapsed_milliseconds: int | None,
) -> Mapping[str, str | int | bool | None]:
    """The safe structured detail of a probe that never opened a dialogue.

    The same shape as a session's, with `transport_failure` added and every
    protocol field absent, because none of it happened.
    """
    return {
        "stage_reached": DialogueStage.CONNECTED.value,
        "recipient_stage": False,
        "about_the_target": _is_about_the_target(finding.reason),
        "transport_failure": failure.value,
        "basic_code": None,
        "enhanced_code": None,
        "diagnostic": None,
        "defect": None,
        "tls_negotiated": False,
        "tls_reason": None,
        "deadline_exhausted": deadline_exhausted,
        "cleanup": None,
        "recipients_attempted": 0,
        "no_message_data_sent": True,
        "elapsed_milliseconds": elapsed_milliseconds,
    }
