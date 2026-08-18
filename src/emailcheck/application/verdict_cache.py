"""The result cache: what may be reused, keyed by what produced it.

`prompts/06-api-cli.md` requires a cache lookup before an enqueue;
`docs/architecture.md` section 6 fixes the rule that repeated requests inside
the cache window return the existing result. ADR 0015 decides the two things
those documents leave open: how long an aggregated `Verdict` lives, and what the
key is.

**The key is every input that could change the answer.** The normalized target,
the sender identity the answer was obtained through, the aggregation ruleset,
the passive dataset snapshot, and the account — all of them in the `WHERE`
clause. A verdict obtained from one envelope sender is not evidence about
another, and a verdict produced by rules that no longer exist is a result
nothing produced.

**The dataset fingerprint is the newest component and it was missing.** The key
held every input except the lists the answer partly came from, so a verdict
computed before an operator added a domain to the role-account dataset was
still served afterwards for as long as `docs/requirements.md` section 13 prices
it — a published risk flag that the current configuration would not produce. The
final system audit found it. `PassiveDatasets.fingerprint` is a bounded digest
of every dataset version and entry count, deterministic across processes, and it
now sits in the lookup beside the ruleset.

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
from emailcheck.classification.repository import PassiveDatasets
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

#: The fingerprint of a deployment that configures no passive datasets.
#:
#: Computed rather than written down, so it can never drift from what
#: `PassiveDatasets().fingerprint` actually produces — and so "no datasets" is
#: one concrete identity rather than a sentinel that could collide with a real
#: snapshot.
EMPTY_DATASET_FINGERPRINT = PassiveDatasets().fingerprint

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
    #: `PassiveDatasets.fingerprint` for the snapshot this process classifies
    #: with. Operator configuration, exactly like the sender identity: it comes
    #: from the datasets `composition.py` loaded, never from a request.
    #:
    #: The default is the fingerprint of an **empty** snapshot rather than a
    #: placeholder, so a deployment that configures no datasets still has one
    #: real identity and cannot collide with a populated one.
    passive_dataset_fingerprint: str = EMPTY_DATASET_FINGERPRINT

    async def find(
        self, target: NormalizedAddress, *, account: str, ruleset: str
    ) -> PublicResult | None:
        """The live cached result for this caller and target, or `None`."""
        record = await self.store.find(
            account_digest=self._digest(account),
            target_digest=self._digest(target.hmac_material),
            sender_identity_digest=self._digest(self.sender_identity),
            aggregation_ruleset=ruleset,
            passive_dataset_fingerprint=self.passive_dataset_fingerprint,
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
        expected_generation: int,
    ) -> bool:
        """Store this verdict if section 13 prices every reason that decided it.

        `route_ttl` is `MailRoute.ttl.applied_seconds` when DNS was consulted
        and `None` when it was not; `application/jobs.py` is the only caller and
        reads it off the verification outcome.

        `expected_generation` is that caller's admitted account generation and
        is passed to the store, which compares it with its own fence in the same
        transaction as the write. `False` therefore means either "not cacheable"
        or "this account is being erased", and neither is an error.
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
        return await self.store.save(
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
                passive_dataset_fingerprint=self.passive_dataset_fingerprint,
                created_at=now,
                expires_at=now + timedelta(seconds=lifetime),
            ),
            expected_generation=expected_generation,
        )

    async def forget_account(self, account: str) -> int:
        """Remove every cached verdict this account owns. Returns how many.

        **Every fingerprint and every ruleset.** The store is asked by
        `account_digest` alone, so a deletion is not scoped to whatever dataset
        snapshot or aggregation this process happens to be running — an entry
        written under an older snapshot is still the account's data, and a
        deletion that removed only the current one would leave exactly the rows
        an operator believed were gone.

        The digest is computed here because the store never sees an account
        identifier: it holds HMACs, so the only layer that can turn "delete
        account A" into a `WHERE` clause is the one holding the correlation key.
        """
        return await self.store.delete_account(account_digest=self._digest(account))

    async def fence_account(self, account: str, *, generation: int) -> int:
        """Raise the store's fence for this account, before its rows are deleted.

        Here rather than in the deletion service for `forget_account`'s reason:
        the store holds digests, so the only layer that can name an account to
        it is the one holding the correlation key.
        """
        return await self.store.fence(account_digest=self._digest(account), generation=generation)

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
