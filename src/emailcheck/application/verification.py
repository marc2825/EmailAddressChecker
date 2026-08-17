"""The one entry point an external caller reaches. Phase 6.

Everything below is wiring. There is no deliverability rule here, no branch on a
`ReasonCode`, and no status this module decides: it collects the `Evidence` that
Phases 1 to 4 produce, hands the whole set to `aggregate_evidence`, and returns
what came back.

```text
raw text + Principal
  → parse_address                      Phase 1
  → syntax Evidence (on a rejection)   Phase 5's producer
  → mail route                         Phase 2
  → passive classification             Phase 3
  → SMTP verification                  Phase 4, only when a route offers one
  → aggregate_evidence                 Phase 5
  → Verdict
```

Four properties are what a review should check.

**Nothing reaches the network that does not have to.** A rejected address stops
before DNS, so an invalid or unsupported input costs zero lookups and zero
sockets. `docs/requirements.md` section 6 makes unsupported syntax `unknown`
rather than invalid, and neither answer needs a resolver to reach it.

**Phase 2 decides whether there is anywhere to connect, and Phase 6 does not
re-decide it.** The SMTP step runs only when `MailRoute.connectable_candidates`
is non-empty, which is empty for every outcome except the two route outcomes —
so a Null MX, an NXDOMAIN, an authoritative no-mail-route, a temporary failure,
a configuration anomaly, and an unsafe destination all stop here without a
second opinion being formed about them. No candidate is built from a DNS answer
in this module.

**The account the limiter partitions by comes from the authenticated
principal.** `principal.rate_limit_account` and nothing else — not a request
field, not the target's domain, not the local part. That is Phase 4 stop
condition 2, and an inspection test refuses the alternatives.

**One deadline covers the whole verification, admission included.** Phase 4
bounds a rate-limit wait and an SMTP session per candidate; three candidates is
three of each, plus DNS, plus the wait for an admission permit. This is the
bound on that sum, and it is a *local operational* refusal: exceeding it is a
fact about this service and never about the address.

The ordering matters and was got wrong once. `asyncio.timeout` is **outside**
`admission.admit`, so a caller queued behind a full gate is bounded by the same
clock as a caller inside it. With the two the other way round, the queue was
bounded in depth and not in time, and a document claiming the deadline covered
admission was claiming more than the code did.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Final

from emailcheck.application.abuse import AbuseGuard, AbuseRefused
from emailcheck.application.admission import AdmissionControl, AdmissionRefused
from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.mail_route import MailRouteService
from emailcheck.application.passive import PassiveClassifier
from emailcheck.application.smtp_verification import (
    AttemptOutcome,
    SMTPVerificationService,
    VerificationReport,
)
from emailcheck.application.syntax_evidence import SyntaxEvidenceProducer
from emailcheck.domain.address import (
    AddressAccepted,
    AddressRejected,
    NormalizedAddress,
    RawAddressInput,
    parse_address,
)
from emailcheck.domain.dns import DestinationAllowlist
from emailcheck.domain.evidence import Evidence
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.principal import Principal
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.recipient_touch import RecipientTouch
from emailcheck.domain.source import SourceIdentity
from emailcheck.domain.verdict import Verdict
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink

#: The longest a whole verification may take, and the ceiling on that.
#:
#: `docs/requirements.md` fixes no number, and `plans/phase-04-smtp.md` measured
#: the configured worst case of the Phase 4 loop alone at
#: `max_attempts x (rate-limit wait + session budget)` — 120 seconds at the
#: Phase 4 defaults. This is deliberately *below* that sum rather than above it:
#: a total deadline equal to the sum of its parts bounds nothing that was not
#: already bounded, and a caller waiting two minutes for `unknown` is a caller
#: whose request should have been refused a minute earlier.
DEFAULT_TOTAL_DEADLINE_SECONDS: Final = 30.0

#: A deadline above this is not a deadline. It is above the Phase 4 configured
#: worst case, so nothing inside can be waiting on this rather than on its own
#: bound.
MAX_TOTAL_DEADLINE_SECONDS: Final = 120.0

#: The longest submitted text this service will parse.
#:
#: `parse_address` has no early size guard — Phase 1 recorded that as a known
#: constraint and named an input bound as the right place for it. This is that
#: place. The value is far above any legal address (`docs/requirements.md`
#: section 6 enforces the real component limits) and far below anything that
#: costs measurable time to scan.
MAX_SUBMITTED_LENGTH: Final = 320


class VerificationRefused(Exception):
    """This service refused the request. Nothing was observed about the address.

    Deliberately not a `TimeoutError`, not an `OSError`, and not an SMTP type,
    on the precedent `RateLimitTimeout` and `AdmissionRefused` set: a handler
    written for a remote condition must not catch this project's own capacity or
    scheduling, and neither may become evidence.
    """

    def __init__(self, scope: str) -> None:
        super().__init__(f"verification refused: {scope}")
        self.scope = scope


class SubmittedInputTooLong(ValueError):
    """The submitted text is longer than anything this service will parse."""


@dataclass(frozen=True, slots=True)
class VerificationLimits:
    """The bounds this layer owns, validated the way every other bound is."""

    total_deadline_seconds: float = DEFAULT_TOTAL_DEADLINE_SECONDS
    max_submitted_length: int = MAX_SUBMITTED_LENGTH

    def __post_init__(self) -> None:
        value = self.total_deadline_seconds
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError("a total deadline must be a real number, not a boolean")
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("a total deadline must be finite")
        if value <= 0:
            raise ValueError("a total deadline must be positive")
        if value > MAX_TOTAL_DEADLINE_SECONDS:
            raise ValueError(f"a total deadline above {MAX_TOTAL_DEADLINE_SECONDS}s is not a bound")
        length = self.max_submitted_length
        if isinstance(length, bool) or not isinstance(length, int):
            raise ValueError("an input bound must be a whole number, not a boolean")
        if length <= 0:
            raise ValueError("an input bound must be positive")


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """What one verification produced.

    The verdict is `aggregate_evidence`'s, unmodified. `active` records whether
    SMTP was permitted for this request, which is operational metadata a caller
    may be told and which decides nothing.
    """

    verdict: Verdict
    #: Whether an SMTP dialogue was actually attempted for this request — not
    #: whether one was *permitted*. A caller reading this wants to know what the
    #: answer cost, and "we were allowed to probe but there was nowhere to
    #: connect" is the same as not probing.
    active: bool
    target: NormalizedAddress | None
    #: `MailRoute.ttl.applied_seconds` when DNS was consulted, and `None` when
    #: it was not. Carried so that `application/verdict_cache.py` can bound a
    #: cached verdict by the record it rests on — Phase 2 already applied
    #: `docs/requirements.md` section 13's caps, and re-deriving them in a
    #: second place is how two policies drift apart. It decides nothing: no
    #: status, confidence, reason, or flag reads it.
    route_ttl_seconds: int | None = None
    #: The canonical host of the exchanger this route would be approached
    #: through first, and `None` when there is nowhere to connect.
    #:
    #: **Scheduling metadata, on the `route_ttl_seconds` precedent.** It decides
    #: nothing — no status, confidence, reason, or flag reads it — and it exists
    #: so that a caller ordering many verifications can group them by the
    #: destination they will actually reach, without resolving DNS a second time
    #: through a path that has none of Phase 2's caching, ordering, or
    #: destination policy. `prompts/10-batch.md` asks for *fair scheduling by
    #: target domain and MX*, and this is the only honest way for anything above
    #: `AddressVerificationService` to learn the second half.
    #:
    #: It is the same host `application/abuse.py` is already charged for, taken
    #: from `connectable_candidates[0]`: a public DNS record, and the vocabulary
    #: `docs/requirements.md` section 16 already permits aggregating by.
    scheduling_key: str | None = None
    #: Whether this verification may already have put the recipient on a wire.
    #:
    #: **The one fact an automatic retry may be decided on.** `docs/threat-model.md`
    #: bounds one active operation at one `RCPT TO` in total, and the status this
    #: outcome carries cannot express that bound: `temporary_unknown` arises from
    #: a DNS SERVFAIL that opened no socket *and* from a `451` at `RCPT TO`, so a
    #: caller branching on the verdict retried both and contacted one recipient
    #: twice. Carried from `VerificationReport.recipient_touch`, which is the
    #: protocol fact, and never re-derived from a reason code here.
    #:
    #: The default is the conservative member on purpose. A producer that adds a
    #: path returning a `VerificationOutcome` without answering this question
    #: gets "an automatic retry is not allowed", which costs one retry; the other
    #: default costs a second recipient contact.
    recipient_touch: RecipientTouch = RecipientTouch.MAYBE_TOUCHED


@dataclass(frozen=True, slots=True)
class _RecipientStep:
    """What the SMTP step produced: evidence, whether it ran, and what it touched.

    A value rather than a tuple because the three disagree often enough that
    positional unpacking stopped being readable, and because adding the touch to
    a two-tuple is exactly the edit that gets made in the wrong order.
    """

    evidence: tuple[Evidence, ...]
    attempted: bool
    recipient_touch: RecipientTouch


#: The SMTP step that did not happen. There is nowhere to connect, this
#: deployment does not probe, or this request is passive — and none of the three
#: puts a recipient on a wire.
_NO_RECIPIENT_STEP: Final = _RecipientStep(
    evidence=(), attempted=False, recipient_touch=RecipientTouch.NOT_TOUCHED
)


@dataclass(frozen=True, slots=True)
class AddressVerificationService:
    """The high-level service every external entry point goes through.

    Phase 4 stop condition 1: an API or a CLI reaching `SMTPProbeService`,
    `SMTPConnector`, or `SMTPTransport` directly would be probing without the
    one-`RCPT TO` bound, the attempt cap, and the candidate ordering, because all
    three live in `SMTPVerificationService` one layer up. This is the only door,
    and an inspection test asserts `apps/` imports none of those.

    `smtp` is optional because `docs/requirements.md` section 15 defines a
    local-passive profile with no active probes at all. `None` is that profile:
    the SMTP step is skipped, not merely unused.
    """

    syntax: SyntaxEvidenceProducer
    routes: MailRouteService
    passive: PassiveClassifier
    admission: AdmissionControl
    operator: OperatorSink
    smtp: SMTPVerificationService | None = None
    limits: VerificationLimits = field(default_factory=VerificationLimits)
    #: Phase 7's abuse controls. `None` is a deployment with none configured —
    #: the local-passive profile — and every call site checks, so an absent
    #: guard is visibly absent rather than a silently permissive one.
    guard: AbuseGuard | None = None
    #: Which sender identity this deployment probes from, as the budget and the
    #: kill switch name it. Operator configuration, never a request field.
    sender_identity: str = "none"
    #: The exchangers this deployment may contact at all, or `None` for a
    #: deployment with no such restriction.
    #:
    #: `None` and an *empty* allowlist are deliberately different: `None` is the
    #: service-active profile, which is bounded by quotas and blocks rather than
    #: by an inventory of owned machines, and an empty `DestinationAllowlist`
    #: permits nothing. Reading a missing allowlist as "allow everything" is the
    #: failure mode this distinction exists to make unspellable, and
    #: `composition.py` refuses to build a probing lab-active deployment that
    #: has one.
    #:
    #: **Operator configuration, never a request field.** There is no parameter
    #: on `verify`, no key in the request schema, and no CLI flag through which a
    #: caller could supply, extend, or bypass it.
    destination_allowlist: DestinationAllowlist | None = None

    async def verify(
        self,
        submitted: str,
        *,
        principal: Principal,
        active: bool = True,
        source: SourceIdentity | None = None,
    ) -> VerificationOutcome:
        """Run the whole pipeline for one address, bounded and admitted.

        Raises `VerificationRefused` when capacity or the total deadline refuses
        the request. That is deliberately not a `Verdict`: a partial answer
        computed from whatever happened to arrive before the clock ran out would
        present this service's own limits as a statement about the address, and
        `unknown` is exactly the status a caller retries — which would add load
        at the moment the service is already short of it. ADR 0013 records the
        decision.
        """
        self._check_length(submitted)
        account = principal.rate_limit_account
        try:
            # The deadline is outside admission on purpose: a caller waiting for
            # a permit is waiting on this service, and a queue bounded only in
            # depth leaves that wait unbounded in time.
            async with asyncio.timeout(self.limits.total_deadline_seconds):
                async with self.admission.admit(account):
                    return await self._run(
                        submitted,
                        principal=principal,
                        account=account,
                        active=active,
                        source=source,
                    )
        except AdmissionRefused as refusal:
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.ADMISSION_REFUSED, detail=refusal.scope)
            )
            raise VerificationRefused(refusal.scope) from None
        except TimeoutError:
            # `asyncio.timeout` raises `TimeoutError` on expiry. It is converted
            # here rather than propagated, so nothing upstream can mistake this
            # project's own deadline for a remote one.
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.DEADLINE_EXCEEDED, detail="verification total deadline"
                )
            )
            raise VerificationRefused("the verification deadline") from None
        except AbuseRefused as refusal:
            # An abuse control refused. Local and operational, exactly like
            # capacity: no `Evidence`, no `Verdict`, and a category the operator
            # sees rather than the caller — which of nine budgets was reached is
            # information about this deployment, not about the address.
            self.operator.record(
                OperatorEvent(kind=OperatorEventKind.RATE_LIMITED, detail=refusal.category)
            )
            raise VerificationRefused("an abuse control") from None

    def _check_length(self, submitted: str) -> None:
        if not isinstance(submitted, str):
            raise SubmittedInputTooLong("submitted input must be text")
        if len(submitted) > self.limits.max_submitted_length:
            # Refused before parsing, and the message carries no input.
            raise SubmittedInputTooLong(
                f"submitted input exceeds {self.limits.max_submitted_length} characters"
            )

    async def _run(
        self,
        submitted: str,
        *,
        principal: Principal,
        account: str,
        active: bool,
        source: SourceIdentity | None,
    ) -> VerificationOutcome:
        """The pipeline itself, inside admission and inside the deadline.

        `account` is passed in rather than re-read from `principal`, so the
        value the limiter partitions by is derived in exactly one place — the
        property an inspection test counts.
        """
        parsed = parse_address(RawAddressInput(submitted))
        if isinstance(parsed, AddressRejected):
            # **Stops here.** No resolver, no socket. A broken grammar and an
            # unsupported form are both answerable from the input alone, and
            # `aggregate_evidence` separates them: `invalid` for one, `unknown`
            # for the other.
            return self._finish(
                self.syntax.evidence(parsed),
                active=False,
                target=None,
                route_ttl=None,
                scheduling_key=None,
                recipient_touch=RecipientTouch.NOT_TOUCHED,
            )

        assert isinstance(parsed, AddressAccepted)
        target = parsed.address
        if self.guard is not None:
            # After parsing, so the target layer is keyed by a normalized
            # address, and **before** DNS, so a refused caller costs no lookup.
            # A rejected address never reaches here, which is why a syntax error
            # is not chargeable: there is no target to charge it against, and
            # charging one caller's budget for another's typo would be a way to
            # spend somebody else's allowance.
            await self.guard.authorize_submission(
                principal=principal, target=target, source=source, active=active
            )
        route = await self.routes.resolve(target)
        route_evidence = self.routes.evidence(route)

        classification = self.passive.classify(target, route)
        passive_evidence = self.passive.evidence(classification)

        step = await self._verify_recipient(target, route, account=account, active=active)

        # `docs/status-model.md` section 4 makes the decision order-independent,
        # so this order is a retention decision rather than a semantic one:
        # cheapest layer first, then the network layers in the order they ran,
        # with SMTP evidence already in attempt order from Phase 4E.
        evidence = (*passive_evidence, route_evidence, *step.evidence)
        return self._finish(
            evidence,
            active=step.attempted,
            target=target,
            route_ttl=None if route.ttl is None else route.ttl.applied_seconds,
            scheduling_key=scheduled_exchanger(route, self.guard, self.destination_allowlist),
            recipient_touch=step.recipient_touch,
        )

    async def _verify_recipient(
        self, target: NormalizedAddress, route: MailRoute, *, account: str, active: bool
    ) -> _RecipientStep:
        """The SMTP step, when there is one, and whether it ran.

        The flag is returned separately from the evidence because the two can
        disagree: a verification refused by this project's own pacing reaches
        the SMTP layer and produces no evidence at all, and reporting that as
        "no probe was attempted" would be the wrong operational answer.

        The recipient-touch fact is returned as a third thing rather than being
        folded into either, because it disagrees with both: a paced-out
        verification attempted no probe and touched no recipient, while a
        verification that reached `RCPT TO` and got no reply attempted a probe,
        produced evidence about nothing, and touched the recipient.

        Three conditions, and none of them is a judgement about the address:
        active checks must be permitted for this request, this deployment must
        have an SMTP service configured, and **Phase 2 must have left somewhere
        to connect**. The third is read from `connectable_candidates`, which is
        empty for every non-route outcome, so nothing here re-reads a DNS answer
        to decide whether a Null MX means what Phase 2 already said it means.
        """
        if not active or self.smtp is None:
            return _NO_RECIPIENT_STEP
        if not route.connectable_candidates:
            return _NO_RECIPIENT_STEP
        if self.destination_allowlist is not None:
            # **Before the guard, and before any candidate can be approved.**
            # `docs/requirements.md` section 15 gives the lab-active profile a
            # destination allowlist, and this is where "eligible to be contacted
            # at all" is decided — earliest, so nothing downstream has to
            # remember it. It composes rather than replaces: a surviving
            # candidate still passes the operator's blocks below, the
            # destination policy, the peer check, and TLS verification.
            #
            # **Every candidate, not the preferred one.** Phase 4E falls through
            # to the next exchanger on a pre-recipient failure, so an allowlist
            # consulted for `connectable_candidates[0]` alone would let a
            # fallback reach a host the operator never authorized — the exact
            # shape the exchanger switch was already fixed for once.
            route = replace(
                route,
                candidates=tuple(
                    candidate
                    for candidate in route.candidates
                    if self.destination_allowlist.permits(candidate.host.value)
                ),
            )
            if not route.connectable_candidates:
                # No exchanger this domain publishes is one this deployment may
                # contact. Nothing is probed and no destination budget is spent.
                return _NO_RECIPIENT_STEP
        if self.guard is not None:
            # **The domain and sender switches first**, because they refuse the
            # whole verification rather than one host.
            self.guard.check_destination(
                domain=target.domain.ascii_form, sender_identity=self.sender_identity
            )

            # **Then every blocked exchanger is removed before Phase 4E plans.**
            # An independent review measured the earlier build consulting the
            # switch for the preferred candidate alone, so a blocked second
            # exchanger was still reached whenever the first failed before the
            # recipient stage. Filtering the route is the least invasive fix:
            # `plan_attempts` reads `connectable_candidates`, Phase 4E's
            # ordering, cap, de-duplication, and one-`RCPT TO` bound are
            # untouched, and no destination-safety logic is duplicated — this
            # removes candidates, it never adds or approves one.
            route = replace(
                route,
                candidates=tuple(
                    candidate
                    for candidate in route.candidates
                    if not self.guard.exchanger_blocked(candidate.host.value)
                ),
            )
            if not route.connectable_candidates:
                # Every exchanger this domain publishes is blocked. There is
                # nowhere to connect, so nothing is probed and no destination
                # budget is spent — the answer Phase 2 already gives a domain
                # with no usable route.
                return _NO_RECIPIENT_STEP

            # The destination layers, charged once per verification that will
            # actually connect. The exchanger *charged* is the preferred one
            # among those that survived, which is the one Phase 4E approaches
            # first and — unless it fails before the recipient stage — the only
            # one. A request that does fall through has under-charged the second
            # exchanger by at most `max_attempts - 1`, and the domain budget
            # above it covers the total either way. That approximation is the
            # **budget's** alone: the block above is exact for every candidate.
            await self.guard.authorize_destination(
                domain=target.domain.ascii_form,
                mx_host=route.connectable_candidates[0].host.value,
                sender_identity=self.sender_identity,
            )
        report = await self.smtp.verify(target, route, account=account)
        self._report_pacing(report, target)
        return _RecipientStep(
            evidence=report.evidence,
            attempted=True,
            recipient_touch=report.recipient_touch,
        )

    def _report_pacing(self, report: VerificationReport, target: NormalizedAddress) -> None:
        """Tell the operator when this project's own pacing refused an attempt.

        Read from the `AttemptRecord`s the Phase 4E loop actually produces, not
        from an exception. `RateLimitTimeout` never reaches this layer —
        `application/smtp_verification.py` catches it and records
        `AttemptOutcome.RATE_LIMITED` — so a handler for it here would be dead
        code that only a fake could exercise, which is what an earlier build had.

        This reads an operational fact and produces no `Evidence`. Phase 4's
        rule stands: a refused verification observed nothing, so there is
        nothing to aggregate, and the verdict is unchanged by this call.
        """
        paced = sum(
            1 for attempt in report.attempts if attempt.outcome is AttemptOutcome.RATE_LIMITED
        )
        if not paced:
            return
        self.operator.record(
            OperatorEvent(
                kind=OperatorEventKind.RATE_LIMITED,
                domain=target.domain.ascii_form,
                detail=report.stopped_because.value,
            )
        )

    def _finish(
        self,
        evidence: tuple[Evidence, ...],
        *,
        active: bool,
        target: NormalizedAddress | None,
        route_ttl: int | None,
        scheduling_key: str | None,
        recipient_touch: RecipientTouch,
    ) -> VerificationOutcome:
        """Aggregate, report an internal failure to the operator, and return.

        The verdict is not inspected for anything else. `internal_error` is
        looked for because Phase 5 stop condition 5 requires it to reach an
        operator rather than disappearing into the `unknown` a caller sees
        constantly — and looking for it changes nothing about the verdict.
        """
        verdict = aggregate_evidence(evidence)
        if ReasonCode.INTERNAL_ERROR in verdict.reason_codes:
            self.operator.record(
                OperatorEvent(
                    kind=OperatorEventKind.INTERNAL_ERROR,
                    reason=ReasonCode.INTERNAL_ERROR,
                    domain=None if target is None else target.domain.ascii_form,
                )
            )
        return VerificationOutcome(
            verdict=verdict,
            active=active,
            target=target,
            route_ttl_seconds=route_ttl,
            scheduling_key=scheduling_key,
            recipient_touch=recipient_touch,
        )


def scheduled_exchanger(
    route: MailRoute,
    guard: AbuseGuard | None,
    allowlist: DestinationAllowlist | None = None,
) -> str | None:
    """The exchanger this verification would approach **first**, or `None`.

    Read from `connectable_candidates`, so it is empty for exactly the outcomes
    Phase 2 already decided have nowhere to connect — a Null MX, an
    authoritative absence, a temporary failure — and no DNS answer is
    re-interpreted here. The host is the validated canonical form a
    `RouteCandidate` carries; nothing is parsed and nothing is normalized again.

    **The administrator's blocked-exchanger switch is applied.** An earlier
    revision returned `connectable_candidates[0]` unfiltered, which named a host
    this verification would then skip: `_verify_recipient` removes every blocked
    exchanger before Phase 4E plans, so the preferred candidate and the first
    one actually approached are different values whenever the preferred one is
    blocked. A scheduling key that named the blocked host would be accounting
    one destination's work against another — and a caller ordering work by it
    would be spreading load across a host nothing ever contacts.

    This is the *same read* of the same switch, in one function both callers
    use, rather than a second policy: it removes nothing from the plan and
    approves nothing. `_verify_recipient` still does the filtering that decides
    what is attempted.

    **It names the first exchanger, not every one.** Phase 4E falls through to a
    later candidate when an attempt fails before the recipient stage, and no
    value computed before the verification runs can know whether that will
    happen. See `docs/architecture.md` for the exact scope of what a caller may
    conclude from this.
    """
    for candidate in route.connectable_candidates:
        if allowlist is not None and not allowlist.permits(candidate.host.value):
            # A host this deployment may not contact is not the host this
            # verification will approach first, so naming it as the scheduling
            # key would account one destination's work against another — the
            # same reasoning the blocked-exchanger filter above already applies.
            continue
        if guard is not None and guard.exchanger_blocked(candidate.host.value):
            continue
        return candidate.host.value
    return None
