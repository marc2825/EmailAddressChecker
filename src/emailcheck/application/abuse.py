"""The one place a request is asked whether it may proceed.

`prompts/07-hardening.md`'s layered budgets, its administrative switches, and
its sequence indicators, composed. Everything below is a **refusal**: nothing
here can permit something another control refused, there is no exemption list,
and there is no path that widens a budget.

## Where the prompt's nine layers live

| Layer | Enforced by |
|---|---|
| API key | here, `BudgetLayer.API_KEY` |
| account | here, `BudgetLayer.ACCOUNT` |
| source IP | here, when a transport boundary supplied one |
| target address HMAC | here, `BudgetLayer.TARGET` |
| target domain | here, plus Phase 4's per-domain *pacing* |
| target MX | here, plus Phase 4's per-MX validation |
| sender identity | here |
| global concurrency | `application/admission.py`, since Phase 6 |
| daily total | here, `BudgetLayer.DAILY_TOTAL` |

Global concurrency is deliberately *not* re-implemented: a reviewed bound with a
second implementation is two bounds that will disagree. A test asserts this
table covers every layer the prompt names.

## What costs what

**Every verification charges the caller's layers**, and **every verification
that will actually probe also charges the destination layers.** One rule, no
exceptions, and the consequences are the ones the prompt asks for rather than
side effects of them:

- a **cache hit is not free**. It is a verification: it parses, resolves, and
  answers, and it charges the key, the account, the source, the target, and the
  daily total. Making it free would leave a caller enumerating a set of already
  cached addresses entirely unbudgeted — the enumeration
  `docs/threat-model.md` lists first, arriving through the one door nobody was
  counting;
- a **retry is not free**. `docs/requirements.md` section 14's one automatic
  retry is a whole new verification, so it charges everything a first attempt
  charges. The remote site experiences it as a second connection whatever this
  project calls it, and `MAX_RETRIES` is what bounds the total;
- a **passive check charges the caller's layers and no destination layer**,
  because there is no destination: it opens no socket and spends nobody's
  reputation.

So one active job that retries costs three caller charges — the submission's
passive pass and two active verifications — and two destination charges. That is
an amplification of three, bounded by `MAX_RETRIES` rather than by anything
here, and a test pins the arithmetic.

## Failing closed

`prompts/07-hardening.md` requires that a rate-storage failure fails closed for
active checks. It does, and it does **not** refuse a passive one:
`docs/architecture.md` section 5 requires the API to keep serving passive checks
when a dependency is unavailable, and a passive check opens no socket, touches
no remote host, and spends no reputation.

## What is never counted

No budget key, indicator input, metric label, or operator event built here
carries a local part, a complete address, an API key, an idempotency key, or a
job identifier. Targets are keyed digests, sources and domains are canonical,
and credentials appear only as the opaque `key_id`
`adapters/auth/api_keys.py` issues.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Final

from emailcheck.domain.abuse import (
    BudgetKey,
    BudgetLayer,
    QuotaSettings,
)
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.admin import AdminState, ControlDecision
from emailcheck.domain.indicators import (
    MAX_WINDOW,
    AttemptShape,
    Indicator,
    evaluate,
    local_part_shape,
)
from emailcheck.domain.principal import Principal
from emailcheck.domain.source import SourceIdentity
from emailcheck.ports.clock import Clock
from emailcheck.ports.metrics import MetricLabels, MetricName, MetricsSink, Outcome
from emailcheck.ports.observability import OperatorEvent, OperatorEventKind, OperatorSink
from emailcheck.ports.quota import BudgetRequest, QuotaStore, QuotaStoreUnavailable
from emailcheck.security.identifiers import correlation_digest

#: How many accounts keep an indicator window. Bounded for the reason every
#: per-caller table in this project is: a map keyed by an identity an attacker
#: can vary is a memory leak with a remote trigger.
DEFAULT_MAX_TRACKED_CALLERS: Final = 4_096

#: How many distinct credentials one source address is remembered as having
#: presented. Bounded for the same reason, and small because the indicator
#: threshold is small.
MAX_KEYS_PER_SOURCE: Final = 16


class AbuseRefused(Exception):
    """This request may not proceed. Nothing was observed and nothing was sent.

    Not a `TimeoutError`, not an `OSError`, and not an SMTP type — the treatment
    `AdmissionRefused` and `RateLimitTimeout` already get, for the same reason:
    a handler written for a remote condition must not catch this project's own
    refusal, and none of this is a fact about anybody's mailbox.
    """

    def __init__(
        self,
        *,
        decision: ControlDecision | None = None,
        layer: BudgetLayer | None = None,
        unavailable: bool = False,
    ) -> None:
        super().__init__("this request was refused by an abuse control")
        self.decision = decision
        self.layer = layer
        self.unavailable = unavailable

    @property
    def category(self) -> str:
        """A bounded operator category. Never shown to the caller."""
        if self.unavailable:
            return "quota_unavailable"
        if self.decision is not None:
            return self.decision.value
        return "budget_exhausted" if self.layer is None else self.layer.value


@dataclass(slots=True)
class _CallerWindow:
    """One caller's recent attempt shapes, bounded by construction."""

    attempts: deque[AttemptShape]


@dataclass(slots=True)
class AbuseGuard:
    """Every abuse control, asked once per unit of work.

    One instance per process, built by the composition root and shared. A guard
    constructed per request has empty windows and zero-valued counters, which
    permits everything — the reason the limiter and the admission gate are
    shared too.

    `state` is replaced wholesale by `application/admin.py` rather than mutated,
    so every decision is made against one coherent snapshot and a suspension
    cannot be half-applied.
    """

    quota: QuotaStore
    clock: Clock
    metrics: MetricsSink
    operator: OperatorSink
    #: The operator secret targets are digested under. The same key the cache
    #: and the job registry use, so one address has one digest everywhere.
    correlation_key: bytes = field(repr=False)
    settings: QuotaSettings = field(default_factory=QuotaSettings)
    state: AdminState = field(default_factory=AdminState)
    #: Local parts an operator considers dictionary-style. Empty by default:
    #: `prompts/07-hardening.md` says "when configured", and inventing a list
    #: would make this project's abuse policy depend on a dataset nobody
    #: licensed or reviewed.
    common_names: frozenset[str] = frozenset()
    max_tracked_callers: int = DEFAULT_MAX_TRACKED_CALLERS
    #: `repr=False`: these are bounded but large, and a `repr` that dumped
    #: thousands of windows is one nobody reads and one that carries every
    #: source address a deployment has seen into whatever printed it.
    _windows: OrderedDict[str, _CallerWindow] = field(default_factory=OrderedDict, repr=False)
    _keys_by_source: OrderedDict[str, set[str]] = field(default_factory=OrderedDict, repr=False)

    # --- the three authorization points --------------------------------------

    def check_caller(self, *, principal: Principal, active: bool) -> None:
        """The administrative half alone, with nothing charged.

        Called by `application/jobs.py` before a submission does any work, so a
        deployment whose kill switch is off refuses immediately instead of
        resolving DNS and then discovering it may not probe. The charging path
        below runs the same check again — this is an early exit, not the barrier
        itself, and removing it changes latency rather than authorization.
        """
        decision = self.state.decide_caller(
            account_id=principal.account_id, key_id=principal.key_id, active=active
        )
        if decision is not ControlDecision.PERMITTED:
            self._record_admin_refusal(decision)
            raise AbuseRefused(decision=decision)

    async def authorize_submission(
        self,
        *,
        principal: Principal,
        target: NormalizedAddress | None,
        source: SourceIdentity | None = None,
        active: bool,
    ) -> None:
        """May this caller submit this request at all?

        Raises `AbuseRefused`. Called before the cache is consulted and before
        anything is enqueued, so a refusal costs a parse and a DNS lookup and
        nothing else.
        """
        decision = self.state.decide_caller(
            account_id=principal.account_id, key_id=principal.key_id, active=active
        )
        if decision is not ControlDecision.PERMITTED:
            self._record_admin_refusal(decision)
            raise AbuseRefused(decision=decision)

        await self._spend(self._caller_requests(principal, target, source), active=active)
        self._observe(principal, target, source)

    def check_destination(self, *, domain: str, sender_identity: str) -> None:
        """The domain and sender-identity switches, before a candidate is chosen.

        Separate from `authorize_destination` because these two are **whole
        verification** controls while the exchanger switch is a *per-host* one.
        `docs/operations.md` section 2 lists "one target domain" and "one target
        MX" as different kill switches, so blocking a domain must refuse even
        when every one of its exchangers is also blocked — a case the combined
        check answered as "nowhere to connect" instead.
        """
        for decision in (
            self.state.decide_destination(domain=domain),
            self.state.decide_sender(sender_identity=sender_identity),
        ):
            if decision is not ControlDecision.PERMITTED:
                self._record_admin_refusal(decision)
                raise AbuseRefused(decision=decision)

    def exchanger_blocked(self, mx_host: str) -> bool:
        """Whether this exchanger may not be approached at all.

        **Asked for every candidate a verification may reach, not only the
        preferred one.** An independent review measured the earlier build
        consulting the switch for `connectable_candidates[0]` alone: Phase 4E
        falls through to the next exchanger on any pre-recipient failure, so a
        blocked second exchanger was still connected to and the kill switch
        `docs/threat-model.md` section 4 requires did nothing.

        The volume *budget* keeps its documented preferred-exchanger
        approximation; an administrative block does not, because an operator
        throwing a switch is entitled to an exact answer. ADR 0016 states the
        two separately.
        """
        decision = self.state.decide_exchanger(mx_host=mx_host)
        if decision is ControlDecision.PERMITTED:
            return False
        self._record_admin_refusal(decision)
        return True

    async def authorize_destination(
        self,
        *,
        domain: str,
        mx_host: str | None,
        sender_identity: str,
    ) -> None:
        """May an outbound attempt be made to this destination?

        Charged per attempt, so section 14's one retry charges it again. Raises
        `AbuseRefused`, which the caller treats as a local operational refusal
        exactly as it treats `AdmissionRefused`.
        """
        for decision in (
            self.state.decide_destination(domain=domain),
            self.state.decide_sender(sender_identity=sender_identity),
            ControlDecision.PERMITTED
            if mx_host is None
            else self.state.decide_exchanger(mx_host=mx_host),
        ):
            if decision is not ControlDecision.PERMITTED:
                self._record_admin_refusal(decision)
                raise AbuseRefused(decision=decision)

        requests = self._destination_requests(domain, mx_host, sender_identity)
        await self._spend(requests, active=True)

    # --- budgets -------------------------------------------------------------

    def _caller_requests(
        self,
        principal: Principal,
        target: NormalizedAddress | None,
        source: SourceIdentity | None,
    ) -> list[BudgetRequest]:
        values: list[tuple[BudgetLayer, str | None]] = [
            (BudgetLayer.API_KEY, principal.key_id),
            (BudgetLayer.ACCOUNT, principal.account_id),
            (BudgetLayer.SOURCE_IP, None if source is None else source.budget_value),
            (
                BudgetLayer.TARGET,
                None if target is None else self._digest(target.hmac_material),
            ),
            (BudgetLayer.DAILY_TOTAL, "all"),
        ]
        return self._requests(values)

    def _destination_requests(
        self, domain: str, mx_host: str | None, sender_identity: str
    ) -> list[BudgetRequest]:
        values: list[tuple[BudgetLayer, str | None]] = [
            (BudgetLayer.TARGET_DOMAIN, domain),
            (BudgetLayer.TARGET_MX, mx_host),
            (BudgetLayer.SENDER_IDENTITY, self._digest(sender_identity)),
        ]
        return self._requests(values)

    def _requests(self, values: list[tuple[BudgetLayer, str | None]]) -> list[BudgetRequest]:
        """Turn layer/value pairs into the requests a store can spend.

        A layer with no value is **skipped**, not defaulted: an absent source
        address must not collapse every anonymous-at-the-transport caller onto
        one shared counter, which would be a budget that any two callers can
        exhaust for each other. A layer whose limit is `None` is skipped too,
        because `None` means "not enforced here" rather than "unlimited by
        accident".
        """
        requests: list[BudgetRequest] = []
        for layer, value in values:
            if value is None:
                continue
            limit = self.settings.limit_for(layer)
            if limit is None:
                continue
            requests.append(
                BudgetRequest(
                    key=BudgetKey(layer=layer, value=value),
                    limit=limit,
                    window_seconds=self.settings.window_for(layer),
                )
            )
        return requests

    async def _spend(self, requests: list[BudgetRequest], *, active: bool) -> None:
        if not requests:
            return
        try:
            decision = await self.quota.consume(requests, now=self._now())
        except QuotaStoreUnavailable:
            # `prompts/07-hardening.md`: rate storage failure fails closed for
            # active checks. A passive check opens no socket and spends no
            # reputation, and `docs/architecture.md` section 5 requires it to
            # keep working when a dependency is down.
            return self._unreachable(active)
        except Exception:
            # **Any other failure of the backend, treated identically.**
            # `ports/quota.py` asks an implementation to raise
            # `QuotaStoreUnavailable`, and an independent review pointed out
            # that trusting it is the wrong posture for the one dependency with
            # a documented fail-closed contract — a Redis client raises
            # `redis.ConnectionError`, not ours. The earlier build let that
            # propagate: a `500` carrying a library message rather than a
            # refusal, and no fail-closed behaviour at all.
            #
            # `Exception`, never `BaseException`: a `CancelledError`, a
            # `KeyboardInterrupt`, and a `SystemExit` must still propagate, and
            # the exception is not named anywhere — a backend message can carry
            # a path, a query, or a value.
            return self._unreachable(active)

        if decision.permitted:
            self._count(
                MetricName.RATE_LIMIT_DECISION, labels=MetricLabels(outcome=Outcome.PERMITTED)
            )
            return

        layer = decision.refused_layer
        self._count(
            MetricName.RATE_LIMIT_DECISION,
            labels=MetricLabels(
                subject=None if layer is None else layer.value, outcome=Outcome.REFUSED
            ),
        )
        self._tell(
            OperatorEvent(
                kind=OperatorEventKind.RATE_LIMITED,
                detail=None if layer is None else layer.value,
            )
        )
        raise AbuseRefused(layer=layer)

    def _unreachable(self, active: bool) -> None:
        """The one answer for a budget backend that could not be reached.

        Active work fails **closed** — `prompts/07-hardening.md` requires it —
        and a passive check is left alone, because it opens no socket, touches
        no remote host, and spends nobody's reputation;
        `docs/architecture.md` section 5 requires the API to keep serving one
        when a dependency is down.

        The operator gets the bounded category `quota_unavailable` and never the
        backend's own message.
        """
        self._count(MetricName.RATE_LIMIT_DECISION, labels=MetricLabels(outcome=Outcome.FAILED))
        self._tell(OperatorEvent(kind=OperatorEventKind.RATE_LIMITED, detail="quota_unavailable"))
        if active:
            raise AbuseRefused(unavailable=True) from None
        return None

    # --- indicators ----------------------------------------------------------

    def _observe(
        self,
        principal: Principal,
        target: NormalizedAddress | None,
        source: SourceIdentity | None,
    ) -> None:
        """Record the shape of this attempt and report what it raises.

        Nothing here refuses. `prompts/07-hardening.md` says indicators "may
        suspend or require manual review", and both of those are an operator's
        decision through `application/admin.py` — an automatic suspension driven
        by a blunt heuristic is a denial of service somebody else can trigger on
        a caller's behalf.
        """
        if source is not None and principal.key_id is not None:
            self._remember_key(source.budget_value, principal.key_id)
        if target is None:
            return

        stem, ordinal = local_part_shape(target.local_part.value)
        # The dictionary comparison happens **here**, on the plaintext stem,
        # and only the answer is retained. Digesting first would make the
        # comparison impossible; retaining the stem would make the window a
        # store of local parts, which is what the corpus caught.
        shape = AttemptShape(
            domain=target.domain.ascii_form,
            target_digest=self._digest(target.hmac_material),
            stem_digest="" if not stem else self._digest(stem),
            ordinal=ordinal,
            dictionary_hit=stem.lower() in self.common_names,
            key_id=principal.key_id,
        )
        window = self._window_for(principal.account_id)
        window.attempts.append(shape)

        distinct = 0
        if source is not None:
            distinct = len(self._keys_by_source.get(source.budget_value, set()))
        for indicator in sorted(
            evaluate(tuple(window.attempts), distinct_keys_from_source=distinct)
        ):
            self._report(indicator)

    def record_acceptance(self, *, principal: Principal, target: NormalizedAddress) -> None:
        """Mark this caller's most recent attempt at this target as accepted.

        Fed by the job worker after a verification completes, so the
        "exploration near positive results" indicator has the one fact it needs.
        Only the digest is compared, so nothing new is retained.
        """
        window = self._windows.get(principal.account_id)
        if window is None:
            return
        digest = self._digest(target.hmac_material)
        for index, attempt in enumerate(window.attempts):
            if attempt.target_digest == digest:
                window.attempts[index] = AttemptShape(
                    domain=attempt.domain,
                    target_digest=attempt.target_digest,
                    stem_digest=attempt.stem_digest,
                    ordinal=attempt.ordinal,
                    dictionary_hit=attempt.dictionary_hit,
                    accepted=True,
                    key_id=attempt.key_id,
                )

    def _report(self, indicator: Indicator) -> None:
        self._count(MetricName.ABUSE_INDICATOR, labels=MetricLabels(subject=indicator.value))
        self._tell(OperatorEvent(kind=OperatorEventKind.RATE_LIMITED, detail=indicator.value))

    def _window_for(self, account_id: str) -> _CallerWindow:
        window = self._windows.get(account_id)
        if window is not None:
            self._windows.move_to_end(account_id)
            return window
        while len(self._windows) >= self.max_tracked_callers:
            # Least recently seen. Evicting an indicator window loses history
            # rather than resetting a budget, so unlike the quota table there is
            # nothing here that eviction can be used to bypass.
            self._windows.popitem(last=False)
        window = _CallerWindow(attempts=deque(maxlen=MAX_WINDOW))
        self._windows[account_id] = window
        return window

    def _remember_key(self, source_value: str, key_id: str) -> None:
        keys = self._keys_by_source.get(source_value)
        if keys is None:
            while len(self._keys_by_source) >= self.max_tracked_callers:
                self._keys_by_source.popitem(last=False)
            keys = set()
            self._keys_by_source[source_value] = keys
        else:
            self._keys_by_source.move_to_end(source_value)
        if len(keys) < MAX_KEYS_PER_SOURCE:
            keys.add(key_id)

    # --- helpers -------------------------------------------------------------

    def _record_admin_refusal(self, decision: ControlDecision) -> None:
        self._count(MetricName.ADMIN_REFUSAL, labels=MetricLabels(subject=decision.value))
        self._tell(OperatorEvent(kind=OperatorEventKind.RATE_LIMITED, detail=decision.value))

    def _count(self, name: MetricName, labels: MetricLabels | None = None) -> None:
        """Record one measurement, and never let it become a refusal.

        `ports/metrics.py` says a sink must not raise, and this does not trust
        it. A metrics failure is an observability problem; letting it propagate
        would turn it into a verification failure, which is the inversion
        `docs/architecture.md` section 5 exists to prevent — and it would do so
        on the *refusal* paths, converting "this budget is exhausted" into "the
        service is broken".

        **`Exception`, not `BaseException`.** A cancellation must still
        propagate: a worker told to stop must not be kept alive by a `try` around
        a counter. That is the same distinction the Phase 4E limiter draws, in
        the opposite direction and for the same reason.
        """
        try:
            self.metrics.increment(name, labels=labels)
        except Exception:
            return

    def _tell(self, event: OperatorEvent) -> None:
        """Report one operator event, under the same rule."""
        try:
            self.operator.record(event)
        except Exception:
            return

    def _digest(self, value: str) -> str:
        return correlation_digest(self.correlation_key, value)

    def _now(self) -> float:
        return self.clock.now().timestamp()

    @property
    def tracked_callers(self) -> int:
        return len(self._windows)
