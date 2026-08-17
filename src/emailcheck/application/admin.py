"""The non-public interface `prompts/07-hardening.md` requires, and its audit.

Six operations, and no seventh:

| Operation | `prompts/07-hardening.md` | `docs/operations.md` §2 |
|---|---|---|
| `set_active_probing` | disable active globally | global active checks |
| `suspend_key` / `restore_key` | suspend key | one account/API key |
| `suspend_account` / `restore_account` | suspend account | one account/API key |
| `block_domain` / `unblock_domain` | block domain/MX | one target domain |
| `block_exchanger` / `unblock_exchanger` | block domain/MX | one target MX |
| `disable_sender` / `enable_sender` | disable sender identity | one sender identity |
| `audit_events` | inspect safe audit events | — |
| `run_deletion` | trigger deletion | raw evidence retention |

**This module holds no transport and publishes no route.** It is called by an
operator tool; binding it to an HTTP path would put an interface that can
disable a security control behind whatever authenticates the public API, and
`prompts/07-hardening.md` calls it a "non-public interface" precisely to keep
those apart. Which is a stop condition on the ASGI binding, not a gap here.

**Every change replaces the state.** `AdminState` is frozen, so a decision in
flight is made against one coherent snapshot rather than against a set somebody
is editing — which is what makes "suspension is immediate" a statement about
ordering rather than only about latency.

**An audit event carries no target and no credential.** `docs/privacy.md`
section 6 logs support access; `prompts/07-hardening.md` requires that
indicators do not leak guessed addresses in admin summaries. So an event holds
the operation, the *category* of subject, an opaque digest of the subject, the
outcome, and a timestamp — never a raw address, never an API key, never a local
part. The subjects an operator types here are already opaque handles and
canonical domains, and the digest means an audit trail that is stolen does not
become a list of who this deployment's customers are.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Final

from emailcheck.application.abuse import AbuseGuard
from emailcheck.domain.admin import AdminState, check_destination_subject, check_subject
from emailcheck.ports.clock import Clock
from emailcheck.ports.metrics import MetricLabels, MetricName, MetricsSink, Outcome
from emailcheck.security.identifiers import correlation_digest


def _is_hex(value: str) -> bool:
    return all(character in "0123456789abcdef" for character in value)


#: How many audit events are kept in memory. `docs/privacy.md` section 3 gives
#: audit data a policy-defined retention with deletion support, and this
#: development implementation's policy is a bounded ring — an unbounded list is
#: a memory leak whose trigger is an admin tool.
DEFAULT_AUDIT_CAPACITY: Final = 1_000


class AdminOperation(StrEnum):
    """What an operator did. A closed vocabulary, so an audit is queryable."""

    SET_ACTIVE_PROBING = "set_active_probing"
    SUSPEND_KEY = "suspend_key"
    RESTORE_KEY = "restore_key"
    SUSPEND_ACCOUNT = "suspend_account"
    RESTORE_ACCOUNT = "restore_account"
    BLOCK_DOMAIN = "block_domain"
    UNBLOCK_DOMAIN = "unblock_domain"
    BLOCK_EXCHANGER = "block_exchanger"
    UNBLOCK_EXCHANGER = "unblock_exchanger"
    DISABLE_SENDER = "disable_sender"
    ENABLE_SENDER = "enable_sender"
    RUN_DELETION = "run_deletion"


class SubjectKind(StrEnum):
    """What kind of thing an operation acted on."""

    NONE = "none"
    API_KEY = "api_key"
    ACCOUNT = "account"
    DOMAIN = "domain"
    EXCHANGER = "exchanger"
    SENDER_IDENTITY = "sender_identity"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One administrative action, in a form that is safe to keep and to show.

    `subject_digest` is an HMAC under the operator's correlation key, so two
    events about one account correlate without the account being named. An
    operator who needs to know *which* account can compute the digest from the
    identifier they already hold; somebody who steals the audit trail cannot go
    the other way.
    """

    operation: AdminOperation
    subject_kind: SubjectKind
    subject_digest: str | None
    at: datetime
    #: Whether the state actually changed. A repeated suspension is recorded and
    #: is visibly a no-op, which is what an incident timeline needs.
    changed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.operation, AdminOperation):
            raise ValueError("an audit event must name a published operation")
        if not isinstance(self.subject_kind, SubjectKind):
            raise ValueError("an audit event must name a published subject kind")
        if self.at.tzinfo is None:
            raise ValueError("an audit timestamp must be timezone-aware")
        digest = self.subject_digest
        if digest is None:
            return
        if not isinstance(digest, str) or len(digest) != 64 or not _is_hex(digest):
            # A full hexadecimal HMAC and nothing else. The check exists so
            # that a raw subject cannot reach an audit trail by somebody
            # passing the identifier where the digest belongs.
            raise ValueError("an audit subject digest must be a hexadecimal HMAC")

    def as_json_object(self) -> dict[str, object]:
        """The safe projection an admin summary may show."""
        return {
            "operation": self.operation.value,
            "subject_kind": self.subject_kind.value,
            "subject_digest": self.subject_digest,
            "at": self.at.isoformat(),
            "changed": self.changed,
        }


@dataclass(slots=True)
class AdminControl:
    """The operator's switches, with an audit trail behind each one.

    Holds the `AbuseGuard` because the guard is where the state is *read*: an
    administrative change that did not reach the thing making decisions is a
    change that did not happen. There is one guard per process and this replaces
    its state, so a suspension applies to the next decision rather than to the
    next request that happens to build something.
    """

    guard: AbuseGuard
    clock: Clock
    metrics: MetricsSink
    #: The same operator secret every other digest in this project uses.
    correlation_key: bytes = field(repr=False)
    audit_capacity: int = DEFAULT_AUDIT_CAPACITY
    _audit: deque[AuditEvent] = field(default_factory=deque)

    def __post_init__(self) -> None:
        if isinstance(self.audit_capacity, bool) or not isinstance(self.audit_capacity, int):
            raise ValueError("the audit capacity must be a whole number")
        if self.audit_capacity <= 0:
            raise ValueError("the audit capacity must be positive")
        self._audit = deque(self._audit, maxlen=self.audit_capacity)

    @property
    def state(self) -> AdminState:
        return self.guard.state

    # --- the global switch ---------------------------------------------------

    def set_active_probing(self, enabled: bool) -> bool:
        """Turn active probing on or off for the whole deployment.

        `docs/operations.md` section 2's first kill switch. Off stops the
        enqueue **and** the worker: `AbuseGuard.authorize_submission` refuses a
        new active check and `authorize_destination` refuses an attempt from a
        job that was already queued, which is the case that matters — a switch
        that only stopped new work would leave the queue connecting to remote
        hosts after an operator said stop.
        """
        if not isinstance(enabled, bool):
            raise ValueError("the global switch takes a boolean")
        changed = self.state.active_probing_enabled != enabled
        self._apply(replace(self.state, active_probing_enabled=enabled))
        self.metrics.increment(
            MetricName.KILL_SWITCH_STATE,
            labels=MetricLabels(outcome=Outcome.ENABLED if enabled else Outcome.DISABLED),
        )
        return self._record(AdminOperation.SET_ACTIVE_PROBING, SubjectKind.NONE, None, changed)

    # --- suspension ----------------------------------------------------------
    #
    # Ten explicit methods rather than one reflective helper taking a field
    # name. The helper was shorter and mypy could not check it: an attribute
    # addressed by string is one no type and no inspection test can follow, and
    # these are the methods that turn security controls off.

    def suspend_key(self, key_id: str) -> bool:
        value = check_subject(SubjectKind.API_KEY.value, key_id)
        changed = value not in self.state.suspended_keys
        self._apply(replace(self.state, suspended_keys=self.state.suspended_keys | {value}))
        return self._record(AdminOperation.SUSPEND_KEY, SubjectKind.API_KEY, value, changed)

    def restore_key(self, key_id: str) -> bool:
        value = check_subject(SubjectKind.API_KEY.value, key_id)
        changed = value in self.state.suspended_keys
        self._apply(replace(self.state, suspended_keys=self.state.suspended_keys - {value}))
        return self._record(AdminOperation.RESTORE_KEY, SubjectKind.API_KEY, value, changed)

    def suspend_account(self, account_id: str) -> bool:
        value = check_subject(SubjectKind.ACCOUNT.value, account_id)
        changed = value not in self.state.suspended_accounts
        self._apply(replace(self.state, suspended_accounts=self.state.suspended_accounts | {value}))
        return self._record(AdminOperation.SUSPEND_ACCOUNT, SubjectKind.ACCOUNT, value, changed)

    def restore_account(self, account_id: str) -> bool:
        value = check_subject(SubjectKind.ACCOUNT.value, account_id)
        changed = value in self.state.suspended_accounts
        self._apply(replace(self.state, suspended_accounts=self.state.suspended_accounts - {value}))
        return self._record(AdminOperation.RESTORE_ACCOUNT, SubjectKind.ACCOUNT, value, changed)

    # --- destinations --------------------------------------------------------

    def block_domain(self, domain: str) -> bool:
        value = check_destination_subject(SubjectKind.DOMAIN.value, domain)
        changed = value not in self.state.blocked_domains
        self._apply(replace(self.state, blocked_domains=self.state.blocked_domains | {value}))
        return self._record(AdminOperation.BLOCK_DOMAIN, SubjectKind.DOMAIN, value, changed)

    def unblock_domain(self, domain: str) -> bool:
        value = check_destination_subject(SubjectKind.DOMAIN.value, domain)
        changed = value in self.state.blocked_domains
        self._apply(replace(self.state, blocked_domains=self.state.blocked_domains - {value}))
        return self._record(AdminOperation.UNBLOCK_DOMAIN, SubjectKind.DOMAIN, value, changed)

    def block_exchanger(self, mx_host: str) -> bool:
        value = check_destination_subject(SubjectKind.EXCHANGER.value, mx_host)
        changed = value not in self.state.blocked_mx_hosts
        self._apply(replace(self.state, blocked_mx_hosts=self.state.blocked_mx_hosts | {value}))
        return self._record(AdminOperation.BLOCK_EXCHANGER, SubjectKind.EXCHANGER, value, changed)

    def unblock_exchanger(self, mx_host: str) -> bool:
        value = check_destination_subject(SubjectKind.EXCHANGER.value, mx_host)
        changed = value in self.state.blocked_mx_hosts
        self._apply(replace(self.state, blocked_mx_hosts=self.state.blocked_mx_hosts - {value}))
        return self._record(AdminOperation.UNBLOCK_EXCHANGER, SubjectKind.EXCHANGER, value, changed)

    # --- sender identity -----------------------------------------------------

    def disable_sender(self, sender_identity: str) -> bool:
        value = check_subject(SubjectKind.SENDER_IDENTITY.value, sender_identity)
        changed = value not in self.state.disabled_sender_identities
        self._apply(
            replace(
                self.state,
                disabled_sender_identities=self.state.disabled_sender_identities | {value},
            )
        )
        return self._record(
            AdminOperation.DISABLE_SENDER, SubjectKind.SENDER_IDENTITY, value, changed
        )

    def enable_sender(self, sender_identity: str) -> bool:
        value = check_subject(SubjectKind.SENDER_IDENTITY.value, sender_identity)
        changed = value in self.state.disabled_sender_identities
        self._apply(
            replace(
                self.state,
                disabled_sender_identities=self.state.disabled_sender_identities - {value},
            )
        )
        return self._record(
            AdminOperation.ENABLE_SENDER, SubjectKind.SENDER_IDENTITY, value, changed
        )

    # --- audit ---------------------------------------------------------------

    def audit_events(self, *, limit: int = 100) -> tuple[AuditEvent, ...]:
        """The most recent events, newest last.

        Bounded by construction and bounded again here, so an admin tool asking
        for everything gets a page rather than the whole ring.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("an audit page must be a positive whole number")
        events = tuple(self._audit)
        return events[-limit:]

    def record_deletion(self, *, removed: int, failed: bool) -> AuditEvent:
        """Record a retention run. Called by `application/retention.py`.

        `docs/operations.md` section 3 alerts on a deletion job failing, so the
        failure is a counter of its own rather than a zero in the success one —
        a run that removed nothing because there was nothing to remove and a run
        that removed nothing because it broke are different facts.
        """
        event = self._event(AdminOperation.RUN_DELETION, SubjectKind.NONE, None, not failed)
        self._audit.append(event)
        if failed:
            self.metrics.increment(
                MetricName.DELETION_FAILURE, labels=MetricLabels(outcome=Outcome.FAILED)
            )
            return event
        self.metrics.observe(MetricName.DELETION_REMOVED, float(removed))
        return event

    # --- the machinery -------------------------------------------------------

    def _apply(self, state: AdminState) -> None:
        self.guard.state = state

    def _record(
        self, operation: AdminOperation, kind: SubjectKind, subject: str | None, changed: bool
    ) -> bool:
        self._audit.append(self._event(operation, kind, subject, changed))
        return changed

    def _event(
        self, operation: AdminOperation, kind: SubjectKind, subject: str | None, changed: bool
    ) -> AuditEvent:
        return AuditEvent(
            operation=operation,
            subject_kind=kind,
            subject_digest=(
                None if subject is None else correlation_digest(self.correlation_key, subject)
            ),
            at=self.clock.now(),
            changed=changed,
        )
