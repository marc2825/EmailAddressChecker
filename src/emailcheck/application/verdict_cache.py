"""The result cache: what may be reused, keyed by what produced it.

`prompts/06-api-cli.md` requires a cache lookup before an enqueue;
`docs/architecture.md` section 6 fixes the rule that repeated requests inside
the cache window return the existing result. ADR 0015 decides the two things
those documents leave open: how long an aggregated `Verdict` lives, and what the
key is.

**The key is every input that could change the answer.** The normalized target,
the sender identity the answer was obtained through, the aggregation ruleset,
and the account — four HMACs under the operator's correlation key, all of them
in the `WHERE` clause. A verdict obtained from one envelope sender is not
evidence about another, and a verdict produced by rules that no longer exist is
a result nothing produced.

**The lifetime is `domain/cache_policy.py`'s**, which is pure and table-driven
and answers `None` for anything `docs/requirements.md` section 13 does not
price. This module never supplies a default for that `None`: an unpriced verdict
is not stored, because a default would be a duration nobody wrote down.

**Only an active verification is cached.** A passive verdict and an active one
for the same address are different evidence, and serving the first for an active
request would answer without probing while reporting a status derived from a
probe that never happened.

Nothing here decides a status. Every published value is copied from the verdict
that `aggregate_evidence` produced, or read back out of the row that copy wrote.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from emailcheck.application.public_result import PublicCheck, PublicResult, public_result
from emailcheck.domain.address import NormalizedAddress
from emailcheck.domain.cache_policy import verdict_ttl_seconds
from emailcheck.domain.verdict import Verdict
from emailcheck.ports.clock import Clock
from emailcheck.ports.random_source import RandomSource
from emailcheck.ports.verdict_store import StoredVerdict, VerdictStore
from emailcheck.security.identifiers import correlation_digest

#: The sender identity a deployment with no active probing is keyed under.
#:
#: A fixed operator-side constant rather than an absent component: leaving the
#: column empty would let a passive row and an active row collide, and the two
#: are different evidence.
NO_SENDER_IDENTITY = "sender:none"

#: Bytes of entropy in a stored record's identifier. `StoredVerdict` calls it
#: unguessable so that a stored result cannot be enumerated.
_RECORD_ID_BYTES = 32


@dataclass(frozen=True, slots=True)
class VerdictCache:
    """Reads and writes the result cache. Holds the key material and nothing else."""

    store: VerdictStore
    clock: Clock
    random: RandomSource
    #: The operator's HMAC secret. Never logged, never returned, never stored.
    #: `repr=False`, for the reason every other holder of this secret carries
    #: it: the key is what makes a stored digest irreversible, and this object
    #: is reachable from `VerificationStack.cache`, so a `repr` of the stack
    #: printed the operator secret in full beside the database it protects. An
    #: independent review measured it. Every other holder was redacted in Phase
    #: 7 and this one was missed, because the privacy corpus built a stack with
    #: no store and therefore no cache at all.
    correlation_key: bytes = field(repr=False)
    #: A stable description of the envelope sender and EHLO name this deployment
    #: probes from, taken from operator configuration.
    sender_identity: str = NO_SENDER_IDENTITY

    async def find(
        self, target: NormalizedAddress, *, account: str, ruleset: str
    ) -> PublicResult | None:
        """The live cached result for this caller and target, or `None`."""
        record = await self.store.find(
            account_digest=self._digest(account),
            target_digest=self._digest(target.hmac_material),
            sender_identity_digest=self._digest(self.sender_identity),
            aggregation_ruleset=ruleset,
            now=self.clock.now(),
        )
        if record is None:
            return None
        return _result_of(record)

    async def save(
        self,
        target: NormalizedAddress,
        *,
        account: str,
        verdict: Verdict,
        route_ttl: int | None,
    ) -> bool:
        """Store this verdict if section 13 prices every reason that decided it.

        `route_ttl` is `MailRoute.ttl.applied_seconds` when DNS was consulted
        and `None` when it was not; `application/jobs.py` is the only caller and
        reads it off the verification outcome.
        """
        if not verdict.no_message_data_sent:
            # Unreachable: this project never sends message content, and the
            # flag is set by the aggregator. Refused anyway rather than
            # persisted, because a stored `False` would outlive the bug.
            return False
        lifetime = verdict_ttl_seconds(verdict, route_ttl_seconds=route_ttl)
        if lifetime is None:
            return False
        published = public_result(verdict)
        now = self.clock.now()
        await self.store.save(
            StoredVerdict(
                record_id=self.random.token(_RECORD_ID_BYTES),
                account_digest=self._digest(account),
                target_digest=self._digest(target.hmac_material),
                sender_identity_digest=self._digest(self.sender_identity),
                status=verdict.status,
                confidence=published.confidence,
                primary_reason=published.primary_reason,
                reasons=published.reasons,
                risk_flags=published.risk_flags,
                checks=tuple((name, check.result) for name, check in published.checks.items()),
                aggregation_ruleset=verdict.ruleset,
                created_at=now,
                expires_at=now + timedelta(seconds=lifetime),
            )
        )
        return True

    def _digest(self, value: str) -> str:
        return correlation_digest(self.correlation_key, value)


def _result_of(record: StoredVerdict) -> PublicResult:
    """Rebuild the published result from a row. A copy, field by field.

    Every value went into the row as a published string and comes back as one.
    `no_message_data_sent` is not stored because it is an invariant of this
    project rather than an observation, and `save` refuses to write a row that
    would contradict it.
    """
    return PublicResult(
        status=record.status.value,
        confidence=record.confidence,
        primary_reason=record.primary_reason,
        reasons=record.reasons,
        risk_flags=record.risk_flags,
        checks={name: PublicCheck(result=value) for name, value in record.checks},
        no_message_data_sent=True,
        ruleset=record.aggregation_ruleset,
    )
