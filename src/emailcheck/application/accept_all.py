"""The accept-all experiment: one control probe, behind five separate gates.

`prompts/09-accept-all.md`. This is a **separate high-level operation**, not a
step inside `verify()`. Nothing about an ordinary check changes because this
module exists, and an ordinary check never reaches it: `application/verification.py`
neither imports this module nor is imported by it, and an inspection test holds
that both ways.

**Why separate rather than folded in.** One verification issues at most one
`RCPT TO`, in total — `docs/threat-model.md`'s first enumeration control, and
the invariant gates 4A and 4E each pin with two barriers. A control recipient is
a *different* recipient, so probing it inside the caller's verification would
make that verification issue two, and no amount of care about which one is
"real" changes what the receiving site sees: one identity asking about two
recipients in one session, seconds apart. So the experiment is its own
verification, with its own one-`RCPT TO` bound, and the two never share a
session.

**Five gates, and all of them must open.** Every one of these is `False` or
absent by default, and each refuses on its own:

| Gate | Where it is decided |
|---|---|
| the operator enabled the feature | `AcceptAllSettings.enabled` |
| the operator authorized *this domain* | `AcceptAllAuthorization` |
| the administrative controls permit it | Phase 7's `AbuseGuard` |
| the separate accept-all domain budget has room | `BudgetLayer.ACCEPT_ALL_DOMAIN` |
| no unexpired cached answer exists | `ports/accept_all_cache.py` |

`prompts/09-accept-all.md`'s acceptance criterion is that **no public caller can
enable the feature without authorization and budget**, and the shape of that
here is that a caller has no parameter at all: `run` takes a domain and a
principal, and every gate above is read from the deployment or from the
operator's authorization record.

**Enabling is not authorizing.** Phase 8 drew that line for the beta harness and
this Phase inherits it: a deployment may build this service and still probe
nothing, because the domains it may experiment on are a separate operator
record. External accept-all probing additionally inherits Phase 8's human
deployment gate — `docs/operations.md` section 1 — which nothing here can satisfy
or bypass.

**One control probe. Exactly one, and never adaptively.** `AcceptAllSettings`
refuses any other count, the loop that would try a second recipient does not
exist, and no branch anywhere reads the reply to decide what to ask next: the
experiment's shape is fixed before the first byte moves. A second random
recipient would be a dictionary attack with a better random-number generator.

**The generated address is never published.** It appears in `RCPT TO` and
nowhere else — not in the evidence, not in the cache, not in a metric, not in an
operator event. A caller learns that a domain is *suspected*, never which
control was used, because a published control address is one a domain operator
could allowlist to defeat the experiment and one that says which of this
project's probes was which.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from emailcheck.application.smtp_evidence import (
    POSITIVE_RECIPIENT_REASONS,
    RECIPIENT_STAGE_REASONS,
)
from emailcheck.application.smtp_verification import SMTPVerificationService
from emailcheck.domain.accept_all import (
    CACHEABLE_OUTCOMES,
    CONTROL_ALPHABET,
    CONTROL_LOCAL_PART_LENGTH,
    EXPERIMENT_VERSION,
    MAX_COLLISION_RETRIES,
    AcceptAllError,
    AcceptAllOutcome,
    AcceptAllSettings,
    ControlLocalPart,
    control_local_part,
)
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.evidence import Evidence, EvidenceLayer, EvidenceStrength
from emailcheck.domain.mail_route import MailRoute
from emailcheck.domain.principal import Principal
from emailcheck.domain.reasons import ReasonCode
from emailcheck.ports.accept_all_cache import AcceptAllCache, AcceptAllCacheKey, CachedAcceptAll
from emailcheck.ports.clock import Clock
from emailcheck.ports.random_source import RandomSource
from emailcheck.security.identifiers import correlation_digest

__all__ = [
    "AcceptAllAuthorization",
    "AcceptAllExperiment",
    "AcceptAllRefused",
    "AcceptAllResult",
    "generate_control_local_part",
]


class AcceptAllRefused(Exception):
    """This experiment may not run.

    Not a `TimeoutError` and not an `OSError`, on the precedent every refusal in
    this project sets — and never a `Verdict`: an experiment that did not run is
    not a fact about anybody's mailbox.
    """


def generate_control_local_part(
    random_source: RandomSource,
    *,
    forbidden: frozenset[str] = frozenset(),
) -> ControlLocalPart:
    """A cryptographically random, non-dictionary control local part.

    `prompts/09-accept-all.md`: "generate a cryptographically random
    non-dictionary ASCII local part" and "no personal names, roles, or
    sequential strings".

    **Non-dictionary by construction, not by filtering.** There is no list of
    words to avoid here, because a blocklist is only as good as its vocabulary
    and this project already refuses to keep one. Twenty characters drawn
    uniformly from thirty-six symbols is not a word in any language, is not a
    name, is not a role, and is not sequential — and the property holds for
    languages nobody thought of, which a list cannot promise.

    The entropy comes from `RandomSource.token`, the port `docs/architecture.md`
    section 2 lists for exactly this: a module calling `secrets` directly can
    only be tested against real entropy, and a review cannot see where
    unpredictability came from.

    `forbidden` is the collision set — the caller's own target, and anything
    already drawn. Retries are **finite**: `MAX_COLLISION_RETRIES` draws and
    then a refusal, because a generator that kept going until something was
    acceptable is the first step of the adaptive probing this Phase forbids.
    """
    permitted = set(CONTROL_ALPHABET)
    for _ in range(MAX_COLLISION_RETRIES):
        # `token` answers a URL-safe string, which is a superset of the
        # alphabet; the filter narrows it rather than mapping it, because a
        # mapping would fold several tokens onto one output and quietly reduce
        # the entropy this is here to provide.
        drawn = "".join(
            character
            for character in random_source.token(CONTROL_LOCAL_PART_LENGTH * 2).lower()
            if character in permitted
        )
        if len(drawn) < CONTROL_LOCAL_PART_LENGTH:
            continue
        candidate = drawn[:CONTROL_LOCAL_PART_LENGTH]
        if candidate in forbidden:
            continue
        return control_local_part(candidate)
    raise AcceptAllRefused("a control local part could not be generated within the retry bound")


@dataclass(frozen=True, slots=True)
class AcceptAllAuthorization:
    """Which domains an operator has authorized an experiment on.

    **Membership is the authorization**, on the precedent `BetaCorpus` set. A
    domain absent from this record is one nobody said yes to, and the experiment
    refuses it rather than treating the caller's ordinary verification
    authorization as covering it.

    Saying that separately matters: a Phase 8 beta corpus authorizes *specific
    mailboxes* on a domain. It does not authorize sending a made-up recipient to
    that domain, which is a different act with a different footprint on the
    receiving side. `docs/requirements.md` section 10's "prefer verified domains"
    is the same instinct, stated as a preference; this is the mechanism.
    """

    domains: frozenset[str] = frozenset()
    #: The operator's explicit statement that control probing is permitted.
    #: `False` by default, and nothing infers it — Phase 8's human deployment
    #: gate in `docs/operations.md` section 1 still applies on top.
    external_probing_authorized: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.external_probing_authorized, bool):
            raise AcceptAllError("external authorization is a boolean an operator sets")
        if not isinstance(self.domains, frozenset):
            raise AcceptAllError("authorized domains are a fixed set")
        for domain in self.domains:
            if not isinstance(domain, str) or not domain or "@" in domain:
                raise AcceptAllError("an authorized entry is a domain, never a mailbox")

    def permits(self, domain: str) -> bool:
        """Both conditions. Either alone is a way to be wrong."""
        return self.external_probing_authorized and domain in self.domains


@dataclass(frozen=True, slots=True)
class AcceptAllResult:
    """What one experiment produced. **No `Status`, and no mailbox claim.**

    `evidence` is empty for every outcome except `SUSPECTED`, because
    `prompts/09-accept-all.md`'s Result section says the experiment may add only
    the `accept_all_suspected` risk flag and this project publishes no reason
    code meaning "not accept-all".
    """

    outcome: AcceptAllOutcome
    #: Why it did not run, when it did not. A bounded local category, never an
    #: exception's message.
    refused: str | None = None
    from_cache: bool = False
    checked_at: datetime | None = None
    expires_at: datetime | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.evidence and self.outcome is not AcceptAllOutcome.SUSPECTED:
            raise AcceptAllError("only a suspected outcome produces evidence")


#: Which recipient reason a control answer maps to which outcome.
#:
#: **Read from the structured evidence, never from the basic code.**
#: `prompts/09-accept-all.md` says "compare structured evidence, not only the
#: basic code", and the reason codes are Phase 4D's — this table adds no
#: vocabulary and re-derives nothing. A bare `550` arrives here as
#: `smtp_ambiguous_permanent_failure` and lands in `INCONCLUSIVE`, which is
#: `docs/requirements.md` section 10's "do not declare catch-all from one
#: ambiguous response" expressed as data.
OUTCOME_BY_REASON: Final[dict[ReasonCode, AcceptAllOutcome]] = {
    # A recipient nobody created was accepted. Suspicion.
    ReasonCode.RCPT_ACCEPTED: AcceptAllOutcome.SUSPECTED,
    ReasonCode.RCPT_FORWARDED: AcceptAllOutcome.SUSPECTED,
    # An address-specific rejection of an address that does not exist is the
    # exchanger behaving as a non-accept-all exchanger should.
    ReasonCode.RCPT_REJECTED_ADDRESS: AcceptAllOutcome.NOT_SUSPECTED,
    # Answered, but not about whether every recipient is accepted.
    ReasonCode.RCPT_UNVERIFIABLE: AcceptAllOutcome.INCONCLUSIVE,
    ReasonCode.RCPT_REJECTED_POLICY: AcceptAllOutcome.INCONCLUSIVE,
    ReasonCode.SMTP_AMBIGUOUS_PERMANENT_FAILURE: AcceptAllOutcome.INCONCLUSIVE,
    # Transient. Never cached, never definitive.
    ReasonCode.SMTP_TEMPORARY_FAILURE: AcceptAllOutcome.TEMPORARY,
    ReasonCode.MAILBOX_FULL: AcceptAllOutcome.TEMPORARY,
}

#: The mapping is **exhaustive over the recipient stage, and closed**.
#:
#: Checked at import on the precedent `LIMIT_FIELDS` and `_CONNECT_REASONS` set:
#: a reason Phase 4D can emit at the recipient stage but this table does not
#: name would otherwise fall through `_read` and be read as `TEMPORARY` —
#: silently, and in the direction that looks safe. An independent review found
#: the correspondence true and unpinned, which is the state in which it stops
#: being true without anybody noticing.
if set(OUTCOME_BY_REASON) != RECIPIENT_STAGE_REASONS:  # pragma: no cover - definition error
    raise AcceptAllError(
        "OUTCOME_BY_REASON must name exactly the recipient-stage reasons: "
        f"missing {sorted(r.value for r in RECIPIENT_STAGE_REASONS - set(OUTCOME_BY_REASON))}, "
        f"stray {sorted(r.value for r in set(OUTCOME_BY_REASON) - RECIPIENT_STAGE_REASONS)}"
    )

#: Suspicion is exactly Phase 5's positive recipient set, and that is not a
#: coincidence to be rediscovered later.
#:
#: `POSITIVE_RECIPIENT_REASONS` is what Phase 5 calls an acceptance, and an
#: acceptance of a recipient nobody created is what this experiment measures.
#: Two lists that mean the same thing drift; this makes the drift an import
#: error rather than a difference somebody has to notice.
if {
    reason for reason, outcome in OUTCOME_BY_REASON.items() if outcome is AcceptAllOutcome.SUSPECTED
} != POSITIVE_RECIPIENT_REASONS:  # pragma: no cover - definition error
    raise AcceptAllError(
        "the suspected reasons must be exactly Phase 5's positive recipient reasons"
    )


@dataclass(frozen=True, slots=True)
class AcceptAllExperiment:
    """One bounded control probe against one authorized domain."""

    #: The **production** verification service. Not a probe, not a transport:
    #: the experiment inherits admission, the Phase 4 limiter, the destination
    #: policy, TLS, the sender identity, the total deadline, and the
    #: one-`RCPT TO` bound because it goes through the same door an ordinary
    #: verification does.
    #: The collaborators are `repr=False` on Phase 7's precedent. A generated
    #: `repr` walks whatever it is handed, so what it prints is a property of
    #: the object graph rather than of this class — an independent review found
    #: it reaching a test transport's recorded wire bytes, including the control
    #: local part. Production transports record nothing, so that was not a
    #: production leak; hiding the collaborators makes it not a leak whatever is
    #: wired in. The *configuration* stays visible, because an operator reading
    #: a `repr` needs to see which settings and which authorized domains are in
    #: force.
    verification: SMTPVerificationService = field(repr=False)
    guard: object = field(repr=False)
    cache: AcceptAllCache = field(repr=False)
    clock: Clock = field(repr=False)
    random_source: RandomSource = field(repr=False)
    settings: AcceptAllSettings
    authorization: AcceptAllAuthorization
    correlation_key: bytes = field(repr=False)
    sender_identity: str = "none"

    async def run(self, route: MailRoute, *, domain: str, principal: Principal) -> AcceptAllResult:
        """Experiment on one domain, or explain why nothing was probed.

        Every refusal below returns rather than raises, and returns
        `REFUSED` — an experiment that did not happen is operational, and
        `application/verification.py` must be able to call this without an
        optional experiment being able to fail an ordinary check. ADR 0013's
        rule, applied to a subsystem that is optional by construction.
        """
        if not self.settings.enabled:
            return AcceptAllResult(outcome=AcceptAllOutcome.REFUSED, refused="feature_disabled")
        if not self.authorization.permits(domain):
            return AcceptAllResult(outcome=AcceptAllOutcome.REFUSED, refused="not_authorized")

        now = self.clock.now()
        key = self._key(domain)
        cached = await self.cache.get(key, now=now)
        if cached is not None:
            # A cache hit probes nothing. The seven-day window exists so that a
            # domain's configuration is asked about once, not once per caller.
            return AcceptAllResult(
                outcome=cached.outcome,
                from_cache=True,
                checked_at=cached.checked_at,
                expires_at=cached.expires_at,
                evidence=self._evidence(cached.outcome, cached.checked_at),
            )

        if not route.connectable_candidates:
            # Phase 2 already decided there is nowhere to connect. Read rather
            # than re-derived, exactly as `application/verification.py` reads it.
            return AcceptAllResult(outcome=AcceptAllOutcome.REFUSED, refused="no_route")

        try:
            # The caller-level controls first, and **the global kill switch with
            # them**: `decide_caller` is where `active_probing_enabled` is read,
            # so an experiment that skipped it would keep probing after an
            # operator threw the switch — the one moment `docs/operations.md`
            # section 2 says a switch most needs to have worked.
            self.guard.check_caller(principal=principal, active=True)  # type: ignore[attr-defined]
            await self._authorize_destination(domain, route)
        except Exception:
            # An administrative block, a kill switch, or the separate accept-all
            # budget. Which one is operator information and is already audited
            # by Phase 7; the experiment records that it did not run.
            return AcceptAllResult(outcome=AcceptAllOutcome.REFUSED, refused="controls_refused")

        control = generate_control_local_part(self.random_source)
        parsed = parse_address(RawAddressInput(f"{control.value}@{domain}"))
        if not isinstance(parsed, AddressAccepted):
            # The generated form must satisfy the ordinary Phase 1 grammar. If
            # it does not, that is this project's defect and not a fact about
            # the domain.
            return AcceptAllResult(outcome=AcceptAllOutcome.REFUSED, refused="control_unparseable")

        report = await self.verification.verify(
            parsed.address, route, account=principal.rate_limit_account
        )
        outcome = self._read(report.evidence)
        checked_at = self.clock.now()

        if outcome in CACHEABLE_OUTCOMES:
            expires_at = checked_at + timedelta(seconds=self.settings.cache_seconds)
            await self.cache.put(
                key, CachedAcceptAll(outcome=outcome, checked_at=checked_at, expires_at=expires_at)
            )
            return AcceptAllResult(
                outcome=outcome,
                checked_at=checked_at,
                expires_at=expires_at,
                evidence=self._evidence(outcome, checked_at),
            )
        # Temporary, inconclusive, or refused: nothing is stored, so the next
        # caller asks again rather than inheriting one bad minute for a week.
        return AcceptAllResult(outcome=outcome, checked_at=checked_at)

    async def _authorize_destination(self, domain: str, route: MailRoute) -> None:
        """The Phase 7 controls, plus the separate accept-all domain budget."""
        guard = self.guard
        guard.check_destination(domain=domain, sender_identity=self.sender_identity)  # type: ignore[attr-defined]
        preferred = route.connectable_candidates[0].host.value
        if guard.exchanger_blocked(preferred):  # type: ignore[attr-defined]
            raise AcceptAllRefused("the preferred exchanger is administratively blocked")
        await guard.authorize_accept_all(  # type: ignore[attr-defined]
            domain=domain, mx_host=preferred, sender_identity=self.sender_identity
        )

    def _read(self, evidence: tuple[Evidence, ...]) -> AcceptAllOutcome:
        """Map the control's structured evidence onto one outcome.

        The first recipient-stage reason decides, and a verification produces at
        most one because it issues at most one `RCPT TO`. Anything else — a TLS
        failure, a refused banner, a connect timeout — is non-target evidence
        about the *transport*, which says nothing about the domain's recipient
        policy and is therefore `TEMPORARY` rather than a conclusion.

        **An unmapped recipient-stage reason raises**, rather than defaulting.
        The import guard above makes that unreachable, and this is the second
        barrier: `.get` returning `None` for a recipient answer would read as
        "transient" — the direction that looks safe and is wrong, because a
        reason the mapper emitted about the recipient is exactly the thing this
        experiment exists to classify.
        """
        for item in evidence:
            if item.reason in RECIPIENT_STAGE_REASONS:
                outcome = OUTCOME_BY_REASON.get(item.reason)
                if outcome is None:  # pragma: no cover - the import guard forbids it
                    raise AcceptAllError(
                        f"no accept-all outcome is defined for {item.reason.value!r}"
                    )
                return outcome
        return AcceptAllOutcome.TEMPORARY

    def _evidence(self, outcome: AcceptAllOutcome, checked_at: datetime) -> tuple[Evidence, ...]:
        """`accept_all_suspected`, and nothing else, and only when suspected.

        `WEAK` and non-temporary, the strength every risk observation in this
        project carries. Phase 5 places `accept_all_suspected` in tier 4, which
        is `unknown` and which blocks a positive verdict — so an accepted target
        beside a suspected accept-all aggregates to `unknown` without this
        module knowing that a status exists.
        """
        if outcome is not AcceptAllOutcome.SUSPECTED:
            return ()
        return (
            Evidence(
                layer=EvidenceLayer.ACCEPT_ALL,
                reason=ReasonCode.ACCEPT_ALL_SUSPECTED,
                strength=EvidenceStrength.WEAK,
                observed_at=checked_at,
                temporary=False,
                source_version=EXPERIMENT_VERSION,
                details={"experiment_version": EXPERIMENT_VERSION},
            ),
        )

    def _key(self, domain: str) -> AcceptAllCacheKey:
        """A domain, an identity, and a version. **No local part, ever.**

        Accept-all is a property of the domain's configuration, so keying on the
        caller's mailbox would file one domain's answer under every address
        anybody asked about — and would put a target in a store that outlives
        the request by a week.
        """
        return AcceptAllCacheKey(
            domain_digest=correlation_digest(self.correlation_key, domain),
            sender_digest=correlation_digest(self.correlation_key, self.sender_identity),
            experiment_version=EXPERIMENT_VERSION,
        )
