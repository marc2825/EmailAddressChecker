"""The operator's switches, as a value with no I/O in it.

`prompts/07-hardening.md`'s admin controls, `docs/operations.md` section 2's
kill switches, and `SECURITY.md`'s emergency response all name the same set:
disable active probing globally, suspend a key or an account, block a domain or
an MX, and disable a sender identity. This is that state and the decisions it
implies; `application/admin.py` is how it changes and who may change it.

**Every switch is a refusal, and refusals compose.** A caller is stopped by the
*first* thing that says no, and nothing here can say yes on behalf of something
else: there is no "allow" list, no exemption, and no override. A control that
could grant access is one an attacker can aim for.

**Suspension is immediate.** `prompts/07-hardening.md` tests for it by name, so
the state is read on every decision rather than cached anywhere — a snapshot
taken at request start would leave a suspended key working for the length of
whatever held the snapshot.

**A kill switch stops the enqueue *and* the worker.** Stopping only the API
leaves already-queued jobs connecting to remote hosts after an operator has
said stop, which is precisely the moment they most need it to have worked.

**Nothing here names a provider.** A block is on a domain an operator typed;
there is no rule keyed to a provider's identity, and an inspection test refuses
one — `docs/threat-model.md`'s provider-neutrality control applies to abuse
thresholds as much as to reply parsing.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

#: Bounded, because these are operator-supplied strings that reach a log line, a
#: metric label, and an audit event.
MAX_SUBJECT_LENGTH: Final = 255

#: How many subjects one deployment may suspend or block. An unbounded set is a
#: memory leak whose trigger is an admin API.
MAX_SUBJECTS: Final = 10_000

_PERMITTED: Final = frozenset(string.ascii_letters + string.digits + "-_.:")


class AdminStateError(ValueError):
    """An administrative subject that cannot be recorded."""


class ControlDecision(StrEnum):
    """Why a request was stopped, as operator vocabulary.

    **Never a `ReasonCode`.** `docs/architecture.md` keeps operational telemetry
    and mailbox semantics apart, and a caller being suspended says nothing at
    all about the address they asked about. `application/abuse.py` maps these to
    a single public service error.
    """

    PERMITTED = "permitted"
    ACTIVE_DISABLED = "active_disabled"
    KEY_SUSPENDED = "key_suspended"
    ACCOUNT_SUSPENDED = "account_suspended"
    DOMAIN_BLOCKED = "domain_blocked"
    MX_BLOCKED = "mx_blocked"
    SENDER_DISABLED = "sender_disabled"


#: Every decision that is a refusal. Derived from the enum rather than listed
#: twice, so a member added later is a refusal until somebody decides otherwise
#: — the fail-closed direction.
REFUSALS: Final[frozenset[ControlDecision]] = frozenset(
    decision for decision in ControlDecision if decision is not ControlDecision.PERMITTED
)


def check_subject(kind: str, value: str) -> str:
    """Validate one administrative subject, returning it unchanged.

    Refuses rather than normalizes, for the reason `SourceIdentity` does: the
    string an operator suspended and the string this project compares must be
    the same one, or a suspension can silently miss.
    """
    if not isinstance(value, str) or not value:
        raise AdminStateError(f"a {kind} must be non-empty text")
    if len(value) > MAX_SUBJECT_LENGTH:
        raise AdminStateError(f"a {kind} is too long")
    if not _PERMITTED.issuperset(value):
        # `@` is outside the set, so no switch can ever be keyed by a mailbox.
        raise AdminStateError(f"a {kind} carries an unpermitted character")
    return value


@dataclass(frozen=True, slots=True)
class AdminState:
    """A snapshot of every switch. Immutable; `application/admin.py` replaces it.

    Immutable rather than mutable because a decision must be made against one
    coherent state: a mutable set being read while another task edits it can
    answer from a half-applied change, and "suspension is immediate" is a
    guarantee about ordering as much as about latency.
    """

    #: `docs/operations.md` section 2's global switch. `False` stops every
    #: active check — the enqueue and the worker both.
    active_probing_enabled: bool = True
    suspended_keys: frozenset[str] = field(default_factory=frozenset)
    suspended_accounts: frozenset[str] = field(default_factory=frozenset)
    blocked_domains: frozenset[str] = field(default_factory=frozenset)
    blocked_mx_hosts: frozenset[str] = field(default_factory=frozenset)
    disabled_sender_identities: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.active_probing_enabled, bool):
            raise AdminStateError("the global switch must be a boolean")
        total = 0
        for kind, subjects in self._sets():
            if not isinstance(subjects, frozenset):
                raise AdminStateError(f"{kind} must be an immutable set")
            for subject in subjects:
                check_subject(kind, subject)
            total += len(subjects)
        if total > MAX_SUBJECTS:
            raise AdminStateError(f"more than {MAX_SUBJECTS} administrative subjects")

    def _sets(self) -> tuple[tuple[str, frozenset[str]], ...]:
        return (
            ("suspended key", self.suspended_keys),
            ("suspended account", self.suspended_accounts),
            ("blocked domain", self.blocked_domains),
            ("blocked exchanger", self.blocked_mx_hosts),
            ("disabled sender identity", self.disabled_sender_identities),
        )

    @property
    def subject_count(self) -> int:
        return sum(len(subjects) for _, subjects in self._sets())

    def decide_caller(
        self, *, account_id: str, key_id: str | None, active: bool
    ) -> ControlDecision:
        """Whether this caller may proceed at all.

        The global switch is checked **first and only for active work**: a
        deployment that has stopped probing still answers passive checks, which
        is `docs/architecture.md` section 5's failure-isolation rule stated as a
        deliberate operator action rather than as a failure.
        """
        if active and not self.active_probing_enabled:
            return ControlDecision.ACTIVE_DISABLED
        if key_id is not None and key_id in self.suspended_keys:
            return ControlDecision.KEY_SUSPENDED
        if account_id in self.suspended_accounts:
            return ControlDecision.ACCOUNT_SUSPENDED
        return ControlDecision.PERMITTED

    def decide_destination(self, *, domain: str) -> ControlDecision:
        """Whether this recipient domain may be approached.

        Exact comparison on the canonical domain the caller supplies. No suffix
        matching: blocking `example.test` must not silently also block
        `notexample.test`, and a parent domain that should block its children is
        a policy nobody has written down.
        """
        if domain in self.blocked_domains:
            return ControlDecision.DOMAIN_BLOCKED
        return ControlDecision.PERMITTED

    def decide_exchanger(self, *, mx_host: str) -> ControlDecision:
        if mx_host in self.blocked_mx_hosts:
            return ControlDecision.MX_BLOCKED
        return ControlDecision.PERMITTED

    def decide_sender(self, *, sender_identity: str) -> ControlDecision:
        if sender_identity in self.disabled_sender_identities:
            return ControlDecision.SENDER_DISABLED
        return ControlDecision.PERMITTED
