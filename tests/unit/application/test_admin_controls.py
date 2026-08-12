"""The administrative interface, its audit trail, and immediacy.

`prompts/07-hardening.md` requires six controls and tests that suspension is
immediate and that indicators do not leak guessed addresses in admin summaries.
"""

from __future__ import annotations

import pytest
from tests.phase7_fixtures import (
    ACCOUNT,
    CORRELATION_KEY,
    KEY_ID,
    PRINCIPAL,
    SAME_ACCOUNT_OTHER_KEY,
    SOURCE,
    CountingQuotaStore,
    RecordingOperator,
    SteppableClock,
    quota_settings,
    target,
)

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.application.abuse import AbuseGuard, AbuseRefused
from emailcheck.application.admin import AdminControl, AdminOperation, SubjectKind
from emailcheck.domain.admin import AdminStateError, ControlDecision
from emailcheck.ports.metrics import MetricLabels, MetricName, Outcome

asyncio_test = pytest.mark.asyncio


def build() -> tuple[AbuseGuard, AdminControl, InMemoryMetrics]:
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=SteppableClock(),
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
        settings=quota_settings(per_api_key=1000, per_account=1000, daily_total=1000),
    )
    admin = AdminControl(
        guard=guard, clock=SteppableClock(), metrics=metrics, correlation_key=CORRELATION_KEY
    )
    return guard, admin, metrics


async def submit(guard: AbuseGuard, *, principal=PRINCIPAL, active: bool = True) -> None:
    await guard.authorize_submission(
        principal=principal, target=target(), source=SOURCE, active=active
    )


# --- the global kill switch --------------------------------------------------


@asyncio_test
async def test_disabling_active_probing_refuses_new_active_checks_at_once() -> None:
    """`docs/operations.md` section 2's first switch. No cache to invalidate and
    no restart: the state is read on every decision."""
    guard, admin, _ = build()
    await submit(guard)

    admin.set_active_probing(False)
    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard)
    assert refusal.value.decision is ControlDecision.ACTIVE_DISABLED

    admin.set_active_probing(True)
    await submit(guard)


@asyncio_test
async def test_the_kill_switch_also_stops_a_job_that_was_already_queued() -> None:
    """The case that matters. A switch that stopped only *new* work would leave
    the queue connecting to remote hosts after an operator said stop, which is
    the moment they most need it to have worked."""
    guard, admin, _ = build()
    await guard.authorize_destination(
        domain="example.test", mx_host="mx.example.test", sender_identity="probe.example"
    )

    admin.set_active_probing(False)
    guard.check_caller(principal=PRINCIPAL, active=False)  # passive is unaffected
    with pytest.raises(AbuseRefused):
        guard.check_caller(principal=PRINCIPAL, active=True)


@asyncio_test
async def test_a_disabled_deployment_still_answers_passive_checks() -> None:
    """`docs/architecture.md` section 5: a passive check opens no socket, so
    stopping active probing must not stop it."""
    guard, admin, _ = build()
    admin.set_active_probing(False)
    await submit(guard, active=False)


def test_the_switch_is_reported_as_a_metric() -> None:
    _, admin, metrics = build()
    admin.set_active_probing(False)
    assert (
        metrics.counter(MetricName.KILL_SWITCH_STATE, labels=MetricLabels(outcome=Outcome.DISABLED))
        == 1
    )


# --- suspension --------------------------------------------------------------


@asyncio_test
async def test_suspending_a_key_leaves_the_accounts_other_key_working() -> None:
    """The property that makes a per-key layer worth having: a leaked
    credential is containable without suspending the account that owns it."""
    guard, admin, _ = build()
    admin.suspend_key(KEY_ID)

    with pytest.raises(AbuseRefused) as refusal:
        await submit(guard, principal=PRINCIPAL)
    assert refusal.value.decision is ControlDecision.KEY_SUSPENDED

    await submit(guard, principal=SAME_ACCOUNT_OTHER_KEY)


@asyncio_test
async def test_suspending_an_account_refuses_every_one_of_its_keys() -> None:
    guard, admin, _ = build()
    admin.suspend_account(ACCOUNT)
    for principal in (PRINCIPAL, SAME_ACCOUNT_OTHER_KEY):
        with pytest.raises(AbuseRefused) as refusal:
            await submit(guard, principal=principal)
        assert refusal.value.decision is ControlDecision.ACCOUNT_SUSPENDED


@asyncio_test
async def test_suspension_applies_to_a_passive_check_too() -> None:
    """A suspended caller is suspended. Only the *global* switch is scoped to
    active work — suspension is about who is asking, not about what it costs."""
    guard, admin, _ = build()
    admin.suspend_account(ACCOUNT)
    with pytest.raises(AbuseRefused):
        await submit(guard, active=False)


@asyncio_test
async def test_restoring_is_immediate_too() -> None:
    guard, admin, _ = build()
    admin.suspend_account(ACCOUNT)
    admin.restore_account(ACCOUNT)
    await submit(guard)


# --- destinations and sender identity ----------------------------------------


@asyncio_test
async def test_a_blocked_domain_refuses_the_attempt() -> None:
    guard, admin, _ = build()
    admin.block_domain("example.test")
    with pytest.raises(AbuseRefused) as refusal:
        await guard.authorize_destination(
            domain="example.test", mx_host="mx.example.test", sender_identity="probe.example"
        )
    assert refusal.value.decision is ControlDecision.DOMAIN_BLOCKED


@asyncio_test
async def test_a_block_is_exact_and_never_a_suffix_match() -> None:
    """Blocking `example.test` must not also block `notexample.test`, and a
    parent blocking its children is a policy nobody has written down."""
    guard, admin, _ = build()
    admin.block_domain("example.test")
    await guard.authorize_destination(
        domain="notexample.test", mx_host="mx.other.test", sender_identity="probe.example"
    )
    await guard.authorize_destination(
        domain="sub.example.test", mx_host="mx.other.test", sender_identity="probe.example"
    )


@asyncio_test
async def test_a_blocked_exchanger_refuses_while_the_domain_stays_reachable() -> None:
    guard, admin, _ = build()
    admin.block_exchanger("mx.bad.test")
    with pytest.raises(AbuseRefused) as refusal:
        await guard.authorize_destination(
            domain="example.test", mx_host="mx.bad.test", sender_identity="probe.example"
        )
    assert refusal.value.decision is ControlDecision.MX_BLOCKED
    await guard.authorize_destination(
        domain="example.test", mx_host="mx.good.test", sender_identity="probe.example"
    )


@asyncio_test
async def test_a_disabled_sender_identity_refuses_every_attempt() -> None:
    guard, admin, _ = build()
    admin.disable_sender("probe.example")
    with pytest.raises(AbuseRefused) as refusal:
        await guard.authorize_destination(
            domain="example.test", mx_host="mx.example.test", sender_identity="probe.example"
        )
    assert refusal.value.decision is ControlDecision.SENDER_DISABLED


# --- the audit trail ---------------------------------------------------------


def test_every_operation_is_audited_with_its_outcome() -> None:
    _, admin, _ = build()
    admin.suspend_account(ACCOUNT)
    admin.suspend_account(ACCOUNT)
    events = admin.audit_events()

    assert [event.operation for event in events] == [
        AdminOperation.SUSPEND_ACCOUNT,
        AdminOperation.SUSPEND_ACCOUNT,
    ]
    # The repeat is recorded and is visibly a no-op, which is what an incident
    # timeline needs.
    assert [event.changed for event in events] == [True, False]
    assert events[0].subject_kind is SubjectKind.ACCOUNT


def test_an_audit_event_names_no_subject_in_the_clear() -> None:
    """`docs/privacy.md` section 6. An audit trail that is stolen must not
    become a list of who this deployment's customers are."""
    _, admin, _ = build()
    admin.suspend_account(ACCOUNT)
    admin.suspend_key(KEY_ID)
    admin.block_domain("example.test")

    rendered = " ".join(str(event.as_json_object()) for event in admin.audit_events())
    for subject in (ACCOUNT, KEY_ID, "example.test"):
        assert subject not in rendered
    assert all(len(event.subject_digest or "") == 64 for event in admin.audit_events())


def test_the_audit_trail_is_bounded_and_keeps_the_newest() -> None:
    """An unbounded list is a memory leak whose trigger is an admin tool."""
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=SteppableClock(),
        metrics=metrics,
        operator=RecordingOperator(),
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(
        guard=guard,
        clock=SteppableClock(),
        metrics=metrics,
        correlation_key=CORRELATION_KEY,
        audit_capacity=3,
    )
    for index in range(10):
        admin.block_domain(f"d{index}.test")

    events = admin.audit_events()
    assert len(events) == 3
    assert events[-1].subject_digest != events[0].subject_digest


def test_an_audit_page_is_bounded_too() -> None:
    _, admin, _ = build()
    for index in range(20):
        admin.block_domain(f"d{index}.test")
    assert len(admin.audit_events(limit=5)) == 5
    with pytest.raises(ValueError):
        admin.audit_events(limit=0)


# --- what an operator may name ------------------------------------------------


@pytest.mark.parametrize(
    "subject",
    ["alice@example.test", "with space", "with\nnewline", "", "x" * 300],
    ids=["address", "space", "newline", "empty", "long"],
)
def test_a_subject_that_could_not_be_an_identifier_is_refused(subject: str) -> None:
    """`@` is outside the permitted set, so no switch can ever be keyed by a
    mailbox — the shape check `rate_limit_key` and `Principal` already make."""
    _, admin, _ = build()
    with pytest.raises(AdminStateError):
        admin.block_domain(subject)


def test_the_state_is_replaced_rather_than_mutated() -> None:
    """A decision in flight is made against one coherent snapshot, which is what
    makes "suspension is immediate" a statement about ordering."""
    guard, admin, _ = build()
    before = guard.state
    admin.suspend_account(ACCOUNT)
    assert guard.state is not before
    assert before.suspended_accounts == frozenset()


# --- each barrier pinned on its own -------------------------------------------
#
# `check_destination` and `authorize_destination` both consult the domain and
# sender switches, and the redundancy is deliberate: the first refuses a whole
# verification before a candidate is chosen, the second charges an attempt. A
# Phase 8 mutation run found that the *first* one's sender check was unpinned —
# removing it left the entire suite green, because the second copy still
# refused. Two barriers are only two barriers when each has a test that fails
# when only it is removed.


def test_check_destination_refuses_a_blocked_domain_on_its_own() -> None:
    guard, admin, _ = build()
    admin.block_domain("example.test")

    with pytest.raises(AbuseRefused) as refusal:
        guard.check_destination(domain="example.test", sender_identity="probe.test")

    assert refusal.value.decision is ControlDecision.DOMAIN_BLOCKED


def test_check_destination_refuses_a_disabled_sender_on_its_own() -> None:
    """The barrier the mutation run found unpinned.

    It matters because this one runs **before** a candidate is chosen: a
    deployment whose sender identity is disabled must refuse the verification
    rather than discover it while charging an attempt.
    """
    guard, admin, _ = build()
    admin.disable_sender("probe.test")

    with pytest.raises(AbuseRefused) as refusal:
        guard.check_destination(domain="example.test", sender_identity="probe.test")

    assert refusal.value.decision is ControlDecision.SENDER_DISABLED


def test_check_destination_permits_when_neither_switch_is_thrown() -> None:
    """So the two above are about the switches rather than about refusing always."""
    guard, _, _ = build()

    guard.check_destination(domain="example.test", sender_identity="probe.test")
