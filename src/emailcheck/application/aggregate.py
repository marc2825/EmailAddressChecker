"""Evidence in, one conservative verdict out. Phase 5.

`docs/status-model.md` section 4 is the specification and this module is its
only implementation:

```text
1. supported hard invalid
2. unsupported input
3. explicit temporary condition
4. policy / opaque failure
5. accepted recipient
6. passive-only unknown
```

Six tiers, examined in that order, and the **lowest non-empty tier decides**.
Everything else here — the confidence table, the primary reason, the risk flags
— follows from which tier decided and never from a count, a strength, or the
order the evidence arrived in.

**No single field is a shortcut.** Not `strength`, which is evidence weight and
never a verdict; not membership of `POSITIVE_RECIPIENT_REASONS`, which says the
server answered positively *at that stage* and nothing about an accept-all
server; not a basic code, which this module never sees. `docs/status-model.md`
section 7.6 forbids the first two by name, and the two gates below are the only
places in this project that can produce `INVALID` or `LIKELY_DELIVERABLE`.

**Pure, and deterministic on the multiset.** No clock, no socket, no resolver,
no limiter, no probe, no retry. `Evidence.observed_at` is read by nothing: there
is no staleness policy in any document, so inventing one would silently weaken
evidence this project went to some trouble to collect. Two calls with the same
evidence in different orders produce the same status, the same confidence, the
same primary reason, and the same risk flags; only the retained `evidence` tuple
keeps the caller's order.

**Duplicates do not accumulate.** Ten copies of one observation decide exactly
what one copy decides. `application/smtp_verification.py` can legitimately
produce three pre-recipient failures for one address, and those are three
attempts at one question rather than three independent answers to it — so
nothing here counts evidence, weights it by count, or multiplies anything by
anything. See ADR 0012.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from emailcheck.domain.evidence import Evidence, EvidenceLayer
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import (
    HARD_INVALID_REASONS,
    POSITIVE_DELIVERY_REASONS,
    Confidence,
    ConfidenceLevel,
    RiskFlag,
    Status,
    Verdict,
)

#: The version of these rules, recorded on every verdict they produce, so a
#: stored result says which aggregation decided it. `docs/status-model.md`
#: section 5 makes a reason-vocabulary change a versioned event; this is the
#: same discipline applied to the rules that read the vocabulary.
AGGREGATION_RULESET: Final = "aggregation-2026-08-09"


# --- the precedence -------------------------------------------------------


#: Reasons that say something about the submitted address or its domain, as
#: opposed to something about the probe, the transport, the sender, or us.
#:
#: **Derived from what is known to be target evidence, never from the absence of
#: a non-target marker.** Gate 4D chose that direction for the same reason: the
#: positive form fails closed, so a reason added later and forgotten here is
#: non-target and cannot support `invalid`, while `reason not in
#: NON_TARGET_SMTP_REASONS` would silently promote it.
TARGET_SPECIFIC_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.INVALID_SYNTAX,
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ReasonCode.UNSUPPORTED_SMTPUTF8,
        ReasonCode.DOMAIN_NXDOMAIN,
        ReasonCode.NULL_MX,
        ReasonCode.NO_MAIL_ROUTE,
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

#: Input this Phase does not support, which is not the same as invalid.
#: `docs/requirements.md` section 6: unsupported syntax produces `unknown` with
#: a specific reason. A quoted local part is a legal address this project
#: declines to parse, and calling it invalid would be this project's limitation
#: reported as the user's mistake.
UNSUPPORTED_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
        ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
        ReasonCode.UNSUPPORTED_SMTPUTF8,
    }
)

#: A usable delivery path exists. A route, never a mailbox: a domain that
#: accepts mail says nothing about whether this recipient is one of its
#: mailboxes, which is why these appear only in the `likely_deliverable` gate as
#: a *necessary* condition and never as a sufficient one.
USABLE_ROUTE_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.MX_AVAILABLE,
        ReasonCode.IMPLICIT_MX_AVAILABLE,
    }
)

#: Reasons known to block nothing.
#:
#: The complement of this set — together with the tiers above it — is what lands
#: in tier 4, so an unrecognised reason **blocks** `likely_deliverable` rather
#: than being ignored. That direction is the whole design of this constant: a
#: reason code added in a later Phase and forgotten here resolves to `unknown`,
#: which is what `AGENTS.md` requires ambiguity to do.
#:
#: `provider_opaque` is deliberately absent. `docs/status-model.md` section 2
#: lists "remote server hides recipient validity" under `unknown`, so a provider
#: known to hide it blocks a positive verdict rather than decorating one.
NON_BLOCKING_REASONS: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.MX_AVAILABLE,
        ReasonCode.IMPLICIT_MX_AVAILABLE,
        ReasonCode.DISPOSABLE_DOMAIN,
        ReasonCode.ROLE_ACCOUNT,
        ReasonCode.FREE_MAIL,
    }
)


#: The total order over every published reason code, used for the primary reason
#: and for the reported ordering.
#:
#: Written out rather than taken from the enum's declaration order or from a
#: set, because both are accidents: reordering the enum for readability would
#: silently change which reason a verdict reports, and a set has no order at all.
#: A test asserts this is exactly `ReasonCode`, with nothing missing and nothing
#: repeated, so a new code cannot be added without choosing where it ranks.
REASON_PRIORITY: Final[tuple[ReasonCode, ...]] = (
    # Tier 1, hard invalid. Syntax before DNS before SMTP: the cheapest and most
    # certain observation names the verdict.
    ReasonCode.INVALID_SYNTAX,
    ReasonCode.DOMAIN_NXDOMAIN,
    ReasonCode.NULL_MX,
    ReasonCode.NO_MAIL_ROUTE,
    ReasonCode.RCPT_REJECTED_ADDRESS,
    # Tier 2, unsupported input.
    ReasonCode.UNSUPPORTED_SMTPUTF8,
    ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART,
    ReasonCode.UNSUPPORTED_DOMAIN_LITERAL,
    # Tier 3, explicit temporary conditions. The explicitly reported ones first,
    # because "the server told us" outranks "we stopped waiting".
    ReasonCode.DNS_TEMPORARY_FAILURE,
    ReasonCode.SMTP_TEMPORARY_FAILURE,
    ReasonCode.MAILBOX_FULL,
    ReasonCode.SMTP_CONNECTION_TIMEOUT,
    ReasonCode.SMTP_CONNECTION_REFUSED,
    # Tier 4, policy and opaque failure.
    #
    # `internal_error` leads it deliberately. A failure of this project's own
    # must not hide behind a remote server's answer: the verdict is `unknown`
    # either way, and reporting the remote rejection as the reason would send an
    # operator to look at the wrong system. It does not outrank a hard invalid
    # or an explicit temporary condition, because those are still true.
    ReasonCode.INTERNAL_ERROR,
    ReasonCode.UNSAFE_DESTINATION,
    ReasonCode.RCPT_REJECTED_POLICY,
    ReasonCode.SMTP_POLICY_BLOCKED,
    ReasonCode.MAIL_FROM_REJECTED,
    ReasonCode.SMTP_TLS_FAILURE,
    ReasonCode.SMTP_BANNER_INVALID,
    ReasonCode.SMTP_PROTOCOL_ERROR,
    ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE,
    ReasonCode.RCPT_UNVERIFIABLE,
    ReasonCode.ACCEPT_ALL_SUSPECTED,
    ReasonCode.PROVIDER_OPAQUE,
    ReasonCode.MX_CONFIGURATION_ANOMALY,
    # Tier 5, an accepted recipient.
    ReasonCode.RCPT_ACCEPTED,
    ReasonCode.RCPT_FORWARDED,
    # Tier 6, route and passive metadata. Never a verdict on their own.
    ReasonCode.MX_AVAILABLE,
    ReasonCode.IMPLICIT_MX_AVAILABLE,
    ReasonCode.DISPOSABLE_DOMAIN,
    ReasonCode.ROLE_ACCOUNT,
    ReasonCode.FREE_MAIL,
)

_REASON_RANK: Final[Mapping[ReasonCode, int]] = {
    reason: index for index, reason in enumerate(REASON_PRIORITY)
}

#: Tier indices, named so the code below reads as the specification does.
_TIER_HARD_INVALID: Final = 1
_TIER_UNSUPPORTED: Final = 2
_TIER_TEMPORARY: Final = 3
_TIER_OPAQUE: Final = 4
_TIER_ACCEPTED: Final = 5
_TIER_PASSIVE: Final = 6

#: Which status each tier produces when it is the one that decides.
_TIER_STATUS: Final[Mapping[int, Status]] = {
    _TIER_HARD_INVALID: Status.INVALID,
    _TIER_UNSUPPORTED: Status.UNKNOWN,
    _TIER_TEMPORARY: Status.TEMPORARY_UNKNOWN,
    _TIER_OPAQUE: Status.UNKNOWN,
    _TIER_ACCEPTED: Status.LIKELY_DELIVERABLE,
    _TIER_PASSIVE: Status.UNKNOWN,
}


# --- confidence -----------------------------------------------------------


#: The confidence level of a verdict, as a function of its primary reason alone.
#:
#: A table rather than arithmetic, and that is the decision rather than an
#: implementation detail. `docs/requirements.md` section 17 permits a
#: probability only after a calibration study, and no such study exists — so
#: there is no evidence for *any* arithmetic, and anything that added, averaged,
#: or multiplied levels would be inventing a number and dressing it as a
#: measurement. A table also makes three properties structural: duplicate
#: evidence cannot move confidence, input order cannot move it, and adding an
#: unrelated observation cannot move it.
#:
#: The rows `docs/status-model.md` section 3 states are taken from it verbatim.
#: Where it gives a range, the lower level is used: `medium or high` for an
#: explicit `5.1.1` is read as **medium**, because the higher reading would
#: claim more about a `550 5.1.1` than section 7.3 permits, and `low or medium`
#: for a timeout is read as **low**. Where it is silent, the level follows the
#: nearest row it does state. ADR 0012 records each choice.
_CONFIDENCE_BY_REASON: Final[Mapping[ReasonCode, ConfidenceLevel]] = {
    # "Syntax violates supported grammar | high"
    ReasonCode.INVALID_SYNTAX: ConfidenceLevel.HIGH,
    # "NXDOMAIN / Null MX | high". `no_mail_route` is the same kind of
    # observation: an authoritative absence on both address families.
    ReasonCode.DOMAIN_NXDOMAIN: ConfidenceLevel.HIGH,
    ReasonCode.NULL_MX: ConfidenceLevel.HIGH,
    ReasonCode.NO_MAIL_ROUTE: ConfidenceLevel.HIGH,
    # "Explicit RCPT 5.1.1 | medium or high" — the lower reading.
    ReasonCode.RCPT_REJECTED_ADDRESS: ConfidenceLevel.MEDIUM,
    # Unsupported input: what is certain is that this project cannot answer, and
    # the status says exactly that. Medium rather than high, because the reason
    # a caller reads is about our limits and not about their address.
    ReasonCode.UNSUPPORTED_SMTPUTF8: ConfidenceLevel.MEDIUM,
    ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART: ConfidenceLevel.MEDIUM,
    ReasonCode.UNSUPPORTED_DOMAIN_LITERAL: ConfidenceLevel.MEDIUM,
    # An explicitly reported temporary condition is a statement by the remote
    # side; a timeout is a statement by us. "Timeout | low or medium" — the
    # lower reading, and the explicit conditions sit one level above it.
    ReasonCode.DNS_TEMPORARY_FAILURE: ConfidenceLevel.MEDIUM,
    ReasonCode.SMTP_TEMPORARY_FAILURE: ConfidenceLevel.MEDIUM,
    ReasonCode.MAILBOX_FULL: ConfidenceLevel.MEDIUM,
    ReasonCode.SMTP_CONNECTION_TIMEOUT: ConfidenceLevel.LOW,
    ReasonCode.SMTP_CONNECTION_REFUSED: ConfidenceLevel.LOW,
    # "Policy block | low", and everything else that resolves to `unknown`
    # because nothing was learned about the address.
    ReasonCode.INTERNAL_ERROR: ConfidenceLevel.LOW,
    ReasonCode.UNSAFE_DESTINATION: ConfidenceLevel.LOW,
    ReasonCode.RCPT_REJECTED_POLICY: ConfidenceLevel.LOW,
    ReasonCode.SMTP_POLICY_BLOCKED: ConfidenceLevel.LOW,
    ReasonCode.MAIL_FROM_REJECTED: ConfidenceLevel.LOW,
    ReasonCode.SMTP_TLS_FAILURE: ConfidenceLevel.LOW,
    ReasonCode.SMTP_BANNER_INVALID: ConfidenceLevel.LOW,
    ReasonCode.SMTP_PROTOCOL_ERROR: ConfidenceLevel.LOW,
    # "Bare 550 | low".
    ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE: ConfidenceLevel.LOW,
    ReasonCode.RCPT_UNVERIFIABLE: ConfidenceLevel.LOW,
    ReasonCode.ACCEPT_ALL_SUSPECTED: ConfidenceLevel.LOW,
    ReasonCode.PROVIDER_OPAQUE: ConfidenceLevel.LOW,
    ReasonCode.MX_CONFIGURATION_ANOMALY: ConfidenceLevel.LOW,
    # "RCPT 250 | medium", and section 7.3: never high, because an accept-all
    # server says `250` to everyone. `251` is the same answer about a forwarding
    # arrangement and gets the same level.
    ReasonCode.RCPT_ACCEPTED: ConfidenceLevel.MEDIUM,
    ReasonCode.RCPT_FORWARDED: ConfidenceLevel.MEDIUM,
    # A route or a risk list on its own. "Passive risk list | not confidence
    # evidence", so the level records that nothing was established.
    ReasonCode.MX_AVAILABLE: ConfidenceLevel.LOW,
    ReasonCode.IMPLICIT_MX_AVAILABLE: ConfidenceLevel.LOW,
    ReasonCode.DISPOSABLE_DOMAIN: ConfidenceLevel.LOW,
    ReasonCode.ROLE_ACCOUNT: ConfidenceLevel.LOW,
    ReasonCode.FREE_MAIL: ConfidenceLevel.LOW,
}


# --- risk flags -----------------------------------------------------------


#: Which published reason raises which published risk flag.
#:
#: **Risk is orthogonal to deliverability** (`docs/requirements.md` section 4),
#: so this table is read once, after the status has already been decided, and no
#: branch below consults a risk flag. A disposable address may be likely
#: deliverable; a role address may be invalid.
#:
#: Every flag here is derived from a reason a producer already published. None
#: is derived from an SMTP reply: nothing a server says about one recipient is a
#: property of the address, and `accept_all_suspected` stays Phase 9's to emit.
_RISK_FLAG_BY_REASON: Final[Mapping[ReasonCode, RiskFlag]] = {
    ReasonCode.DISPOSABLE_DOMAIN: RiskFlag.DISPOSABLE,
    ReasonCode.ROLE_ACCOUNT: RiskFlag.ROLE_ACCOUNT,
    ReasonCode.FREE_MAIL: RiskFlag.FREE_MAIL,
    ReasonCode.PROVIDER_OPAQUE: RiskFlag.PROVIDER_OPAQUE,
    ReasonCode.ACCEPT_ALL_SUSPECTED: RiskFlag.ACCEPT_ALL_SUSPECTED,
    ReasonCode.MX_CONFIGURATION_ANOMALY: RiskFlag.DOMAIN_CONFIGURATION_ANOMALY,
    # The one flag with no other producer. `docs/requirements.md` section 4
    # publishes it, and `unsupported_smtputf8` is precisely "the local part
    # requires SMTPUTF8" — so the flag is derivable from published vocabulary
    # rather than needing a new signal. It changes no status: the reason already
    # decides tier 2 on its own, and this adds the flag beside it.
    ReasonCode.UNSUPPORTED_SMTPUTF8: RiskFlag.INTERNATIONALIZED_LOCAL_PART,
}


# --- the public entry point -----------------------------------------------


def aggregate_evidence(evidence: Sequence[Evidence]) -> Verdict:
    """Aggregate evidence into one conservative verdict.

    The result is a function of the *multiset* of evidence. Re-ordering the
    input changes the retained `evidence` tuple and nothing else — not the
    status, not the confidence, not the primary reason, not the risk flags.

    An empty sequence is `unknown` with no primary reason. It is not
    `likely_deliverable`: nothing was observed, and the absence of contradictory
    evidence is not positive evidence.
    """
    items = tuple(evidence)
    _check_evidence(items)

    tiers = _tiers_by_reason(items)
    deciding_tier = min(tiers.values(), default=None)

    if deciding_tier is None:
        return Verdict(
            status=Status.UNKNOWN,
            confidence=Confidence(level=ConfidenceLevel.LOW),
            primary_reason=None,
            reason_codes=(),
            risk_flags=frozenset(),
            checks=_checks(items),
            evidence=items,
            ruleset=AGGREGATION_RULESET,
            no_message_data_sent=_no_message_data_sent(items),
        )

    status = _TIER_STATUS[deciding_tier]
    ranked = _ranked_reasons(tiers)
    primary = _primary_reason(tiers, deciding_tier)

    return Verdict(
        status=status,
        confidence=Confidence(level=_CONFIDENCE_BY_REASON[primary]),
        primary_reason=primary,
        reason_codes=ranked,
        risk_flags=_risk_flags(items),
        checks=_checks(items),
        evidence=items,
        ruleset=AGGREGATION_RULESET,
        no_message_data_sent=_no_message_data_sent(items),
    )


def _check_evidence(items: tuple[Evidence, ...]) -> None:
    """Refuse anything that is not `Evidence`.

    `Evidence` validates itself, so there is nothing else to check here — but a
    caller handing this function a tuple of dictionaries would otherwise get an
    `AttributeError` from somewhere inside the precedence, which is a bug report
    about the wrong module.
    """
    for item in items:
        if not isinstance(item, Evidence):
            raise ValueError("aggregation takes Evidence and nothing else")


# --- the two gates --------------------------------------------------------


def is_about_the_target(item: Evidence) -> bool:
    """Whether this observation says anything about the address itself.

    **Two independent barriers, and each refuses something the other admits.**

    A producer may state the answer, and gate 4D's mapper does: every piece of
    SMTP evidence carries `about_the_target` in its details, computed there from
    `RECIPIENT_STAGE_REASONS`. When a producer says an observation is not about
    the target, that is believed — it knows things this module does not, such as
    the stage the dialogue reached and how many recipients were attempted. A
    `550 5.1.1` carried by a session that never reached the recipient stage is
    exactly that case.

    Absent such a statement, membership of `TARGET_SPECIFIC_REASONS` decides,
    and an unclassified reason is **not** target evidence.

    Each barrier is pinned by its own test, on the precedent gates 4A, 4D, and
    4E set: a `rcpt_rejected_address` whose producer denied targetness is
    refused by the first alone, and a non-target SMTP reason is refused by the
    second alone.
    """
    stated = item.details.get("about_the_target")
    if stated is False:
        return False
    return item.reason in TARGET_SPECIFIC_REASONS


def supports_invalid(item: Evidence) -> bool:
    """Whether one observation may produce `INVALID`. The only gate that can.

    Three conditions, all required, none of them `strength`:

    - **the reason must mean the address cannot be delivered to.**
      `docs/status-model.md` section 2 lists the five that do. A policy
      rejection, a bare `550`, and a `252` are all permanent, target-specific
      answers about the recipient, and none of them says the recipient does not
      exist;
    - **it must be about the target.** A refused sender, a TLS failure, a
      refused greeting, and a failure of this project's own never support
      invalidity, whatever they carry;
    - **it must not be temporary.** A condition expected to change cannot be a
      permanent verdict, and `docs/requirements.md` section 17 makes "temporary
      failures are not converted to invalid" a quality target.

    `EvidenceStrength.STRONG` appears nowhere in this function. Section 7.6 stop
    condition B forbids mapping strength to a status, and the reason it gives is
    the one that matters: a non-target reason never supports target invalidity
    however strong it is.
    """
    if not is_about_the_target(item):
        return False
    if item.temporary:
        return False
    return item.reason in HARD_INVALID_REASONS


def supports_likely_deliverable(items: tuple[Evidence, ...]) -> bool:
    """Whether this evidence set may produce `LIKELY_DELIVERABLE`.

    The only gate that can, and it takes the whole set rather than one item —
    because every condition is about what is *absent* as much as what is
    present. Three of them:

    - **no higher-precedence blocker.** Sections 4's first four tiers, all of
      them, so a hard invalid, an unsupported input, an explicit temporary
      condition, and a policy or opaque failure each refuse this on their own;
    - **a usable delivery path.** `mx_available` or `implicit_mx_available`.
      This is not stated as a separate condition in section 2, and it is
      implied by the pipeline — an SMTP acceptance cannot happen without a route
      having been resolved and connected to. It is required explicitly because
      an aggregator must not assume its input is coherent, and because it is
      what makes "a bare `250` is not automatically `likely_deliverable`"
      literally true of this function rather than true only in practice.
      ADR 0012 records it;
    - **a qualifying recipient acceptance**: `rcpt_accepted` or
      `rcpt_forwarded`, about the target, and not temporary.

    **Membership of the positive set is a condition, never the answer.** Section
    7.6 stop condition A forbids `if reason in POSITIVE_RECIPIENT_REASONS:
    return LIKELY_DELIVERABLE`, because an accept-all server says `250` to
    everyone; here it is one term of three, evaluated after the precedence has
    already declined to decide.
    """
    if any(_base_tier(item) < _TIER_ACCEPTED for item in items):
        return False
    if not any(item.reason in USABLE_ROUTE_REASONS for item in items):
        return False
    return any(
        item.reason in POSITIVE_DELIVERY_REASONS
        and not item.temporary
        and is_about_the_target(item)
        for item in items
    )


# --- tiers ----------------------------------------------------------------


def _base_tier(item: Evidence) -> int:
    """Which precedence tier one observation belongs to, on its own.

    Read the branches in order; they are `docs/status-model.md` section 4.

    The temporary check comes before the opaque one and after the unsupported
    one, exactly as the document orders them, so a temporary policy refusal is a
    temporary condition rather than a policy block — `4.7.1` is greylisting far
    more often than it is a refusal, and the retryable reading is the
    conservative one.

    "On its own" is the whole reason this function exists separately from
    `_tier_of`. Tier 5 is the one tier that depends on the *rest* of the set,
    and a single function computing both would have to ask
    `supports_likely_deliverable`, which asks every item for its tier: mutual
    recursion, and no obvious base case. So this answers the question that needs
    no context, the gate is built on it, and `_tier_of` applies the gate.
    """
    if supports_invalid(item):
        return _TIER_HARD_INVALID
    if item.reason in UNSUPPORTED_REASONS and not item.temporary:
        return _TIER_UNSUPPORTED
    if item.temporary:
        return _TIER_TEMPORARY
    if item.reason in POSITIVE_DELIVERY_REASONS and is_about_the_target(item):
        return _TIER_ACCEPTED
    if item.reason in NON_BLOCKING_REASONS:
        return _TIER_PASSIVE
    # Everything else, including any reason this module does not recognise.
    # Tier 4 is `unknown` and it blocks a positive verdict, which is where an
    # unclassified observation belongs.
    return _TIER_OPAQUE


def _tier_of(item: Evidence, items: tuple[Evidence, ...]) -> int:
    """`_base_tier`, with the one gate that needs the whole set applied.

    An acceptance that does not clear `supports_likely_deliverable` is not
    promoted to tier 4 as a punishment: it lands there because tier 4 is
    `unknown`, and an acceptance the precedence declined to act on is exactly a
    case where nothing reliable was determined. That is what makes a lone `250`
    — with no route evidence beside it — `unknown` rather than positive.
    """
    base = _base_tier(item)
    if base == _TIER_ACCEPTED and not supports_likely_deliverable(items):
        return _TIER_OPAQUE
    return base


def _tiers_by_reason(items: tuple[Evidence, ...]) -> Mapping[ReasonCode, int]:
    """The tier of each distinct reason present.

    **This is where duplicates stop mattering.** Ten copies of one reason become
    one entry before anything else looks at the evidence, so nothing downstream
    can count them, weight them, or notice that there were ten. When two
    observations share a reason but disagree — one temporary and one not, which
    two attempts against two exchangers can legitimately produce — the lower
    tier wins, so the more decisive reading is kept rather than whichever
    happened to arrive last.
    """
    tiers: dict[ReasonCode, int] = {}
    for item in items:
        tier = _tier_of(item, items)
        held = tiers.get(item.reason)
        if held is None or tier < held:
            tiers[item.reason] = tier
    return tiers


def _sorted_reasons(reasons: Iterable[ReasonCode]) -> tuple[ReasonCode, ...]:
    """Published reason order. Never enum declaration order, never a set's."""
    return tuple(sorted(reasons, key=lambda reason: _REASON_RANK[reason]))


def _ranked_reasons(tiers: Mapping[ReasonCode, int]) -> tuple[ReasonCode, ...]:
    """Every distinct reason, most decisive first.

    Sorted by tier and then by published priority, so the primary reason is
    always the first element and a caller reading the whole list sees the
    precedence that produced the verdict.
    """
    ordered = sorted(tiers.items(), key=lambda pair: (pair[1], _REASON_RANK[pair[0]]))
    return tuple(reason for reason, _ in ordered)


def _primary_reason(tiers: Mapping[ReasonCode, int], deciding_tier: int) -> ReasonCode:
    """The one reason that names the verdict.

    Chosen from the deciding tier alone and by an explicit priority table, so
    the same evidence multiset always names the same reason. Nothing here reads
    a set's iteration order, a dictionary's insertion order, or the order the
    caller supplied.
    """
    return _sorted_reasons(reason for reason, tier in tiers.items() if tier == deciding_tier)[0]


# --- the rest of the verdict ----------------------------------------------


def _risk_flags(items: tuple[Evidence, ...]) -> frozenset[RiskFlag]:
    """Risk flags, deduplicated by the set and derived only from reasons.

    Computed after the status and never consulted by it. A test asserts that
    adding any flag-raising evidence to any decided verdict leaves the status,
    the confidence, and the primary reason unchanged.
    """
    return frozenset(
        _RISK_FLAG_BY_REASON[item.reason] for item in items if item.reason in _RISK_FLAG_BY_REASON
    )


def _checks(items: tuple[Evidence, ...]) -> Mapping[str, object]:
    """A safe per-layer summary, in a fixed layer order.

    `docs/status-model.md` section 6 asks each layer for a summary. This is the
    layer-agnostic form of it: which reason that layer's most decisive
    observation carried, and how many observations it made. No remote text, no
    address, no transcript — the values that could carry any of those live in
    `Evidence.details`, which section 7.5 already bounds and which gate 4D
    already tests for privacy.
    """
    summary: dict[str, object] = {}
    for layer in EvidenceLayer:
        of_layer = tuple(item for item in items if item.layer is layer)
        if not of_layer:
            continue
        reasons = _sorted_reasons({item.reason for item in of_layer})
        summary[layer.value] = {
            "result": reasons[0].value,
            "reason_count": len(reasons),
            "evidence_count": len(of_layer),
        }
    return summary


def _no_message_data_sent(items: tuple[Evidence, ...]) -> bool:
    """The product promise, carried through rather than asserted.

    Every producer publishes `no_message_data_sent` as a derived, always-true
    detail. This reports it as `False` if any observation ever said so, rather
    than restating `True` unconditionally — a verdict that repeated the promise
    while its own evidence contradicted it would be the one output nobody would
    check.
    """
    return not any(item.details.get("no_message_data_sent") is False for item in items)
