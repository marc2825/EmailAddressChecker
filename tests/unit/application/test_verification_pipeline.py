"""The whole pipeline, end to end, against fakes.

These are the composition tests: one address in, one `Verdict` out, with every
layer wired the way `composition.py` wires it. The point is not to re-test the
aggregation — Phase 5 did that exhaustively — but to show that **the wiring
hands the aggregator the right evidence and returns what it answered**.

Two measurements recur and both are the reason these tests exist rather than
being a restatement of Phase 5: the resolver counts what it was asked, and the
scripted SMTP service counts whether it was called at all. "An invalid address
costs no DNS and no SMTP" is a claim about wiring, and it is only checkable
here.
"""

from __future__ import annotations

import pytest
from tests.phase6_fixtures import (
    PRINCIPAL,
    ScriptedSMTPVerification,
    build_service,
    internal_error_evidence,
    resolver_with_null_mx,
    resolver_with_route,
    resolver_with_temporary_failure,
)

from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import Status
from emailcheck.ports.observability import OperatorEventKind

pytestmark = pytest.mark.asyncio

VALID = "user@example.test"


# --- syntax short circuits before any network ------------------------------


@pytest.mark.parametrize(
    ("submitted", "status", "reason"),
    [
        ("", Status.INVALID, ReasonCode.INVALID_SYNTAX),
        ("no-at-sign", Status.INVALID, ReasonCode.INVALID_SYNTAX),
        ("a@@b.example", Status.INVALID, ReasonCode.INVALID_SYNTAX),
        ('"quoted"@example.test', Status.UNKNOWN, ReasonCode.UNSUPPORTED_QUOTED_LOCAL_PART),
        ("user@[192.0.2.1]", Status.UNKNOWN, ReasonCode.UNSUPPORTED_DOMAIN_LITERAL),
        ("ユーザー@example.test", Status.UNKNOWN, ReasonCode.UNSUPPORTED_SMTPUTF8),
    ],
    ids=["empty", "no at", "two ats", "quoted", "domain literal", "smtputf8"],
)
async def test_a_rejected_address_costs_no_dns_and_no_smtp(
    submitted: str, status: Status, reason: ReasonCode
) -> None:
    """Both rejection kinds stop before the network, and they differ in status.

    `docs/requirements.md` section 6 makes unsupported syntax `unknown` rather
    than invalid, and neither answer needs a resolver — so a caller submitting
    nonsense cannot make this project issue a lookup, let alone a connection.
    """
    smtp = ScriptedSMTPVerification()
    service, resolver, _ = build_service(smtp=smtp)

    outcome = await service.verify(submitted, principal=PRINCIPAL)

    assert outcome.verdict.status is status
    assert outcome.verdict.primary_reason is reason
    assert resolver.calls == []
    assert smtp.calls == []
    assert outcome.active is False


# --- the DNS to SMTP boundary ----------------------------------------------


async def test_a_null_mx_reaches_invalid_without_any_smtp() -> None:
    """Phase 2 said the domain accepts no mail, and Phase 6 does not re-decide.

    The SMTP step is skipped because `connectable_candidates` is empty, which is
    a property of the `MailRoute` rather than a rule written here — no branch in
    `application/verification.py` names `null_mx`.
    """
    smtp = ScriptedSMTPVerification()
    service, resolver, _ = build_service(resolver=resolver_with_null_mx(), smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is Status.INVALID
    assert outcome.verdict.primary_reason is ReasonCode.NULL_MX
    assert smtp.calls == []
    assert resolver.calls  # DNS did happen; SMTP did not


async def test_a_temporary_dns_failure_never_falls_through_to_smtp() -> None:
    """A resolver that could not answer is not a licence to start guessing."""
    smtp = ScriptedSMTPVerification()
    service, _, _ = build_service(resolver=resolver_with_temporary_failure(), smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is Status.TEMPORARY_UNKNOWN
    assert outcome.verdict.primary_reason is ReasonCode.DNS_TEMPORARY_FAILURE
    assert smtp.calls == []


async def test_an_unroutable_domain_reaches_invalid_without_smtp() -> None:
    """No MX and no A/AAAA: an authoritative absence on both families."""
    smtp = ScriptedSMTPVerification()
    service, _, _ = build_service(smtp=smtp)  # default fake answers nothing for the domain

    outcome = await service.verify("user@nowhere.test", principal=PRINCIPAL)

    assert outcome.verdict.status is Status.INVALID
    assert outcome.verdict.primary_reason is ReasonCode.NO_MAIL_ROUTE
    assert smtp.calls == []


# --- the recipient answers --------------------------------------------------


RECIPIENT_MATRIX = (
    ("250 accepted", ("250 2.1.5 Recipient ok",), Status.LIKELY_DELIVERABLE, "rcpt_accepted"),
    (
        "251 forwarded",
        ("251 User not local; will forward",),
        Status.LIKELY_DELIVERABLE,
        "rcpt_forwarded",
    ),
    ("252 unverifiable", ("252 Cannot VRFY user",), Status.UNKNOWN, "rcpt_unverifiable"),
    (
        "450 temporary",
        ("450 4.2.1 Mailbox busy",),
        Status.TEMPORARY_UNKNOWN,
        "smtp_temporary_failure",
    ),
    ("550 5.1.1", ("550 5.1.1 User unknown",), Status.INVALID, "rcpt_rejected_address"),
    ("bare 550", ("550 Rejected",), Status.UNKNOWN, "smtp_ambiguous_permanent_failure"),
    ("550 5.7.1 policy", ("550 5.7.1 Not permitted",), Status.UNKNOWN, "rcpt_rejected_policy"),
)


@pytest.mark.parametrize(
    ("name", "lines", "status", "reason"),
    RECIPIENT_MATRIX,
    ids=[row[0] for row in RECIPIENT_MATRIX],
)
async def test_a_route_and_a_recipient_answer_reach_the_documented_status(
    name: str, lines: tuple[str, ...], status: Status, reason: str
) -> None:
    """Each recipient class, through the whole pipeline rather than by hand.

    The evidence is built by the real Phase 4D mapper from a real parsed reply,
    so these rows exercise the same path production uses — and the status is
    whatever `aggregate_evidence` said, which is what makes them a wiring test.
    """
    smtp = ScriptedSMTPVerification(reply_lines=lines)
    service, _, _ = build_service(resolver=resolver_with_route(), smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is status, name
    assert outcome.verdict.primary_reason is not None
    assert outcome.verdict.primary_reason.value == reason, name
    assert smtp.calls == [("example.test", PRINCIPAL.account_id)]


async def test_the_rate_limit_account_is_the_authenticated_principal() -> None:
    """Phase 4 stop condition 2, measured on what the SMTP layer was handed.

    Not the target's domain, not its local part, and not anything a caller could
    supply: the value the limiter partitions by is the account the authenticator
    issued.
    """
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, _ = build_service(smtp=smtp)

    await service.verify(VALID, principal=PRINCIPAL)

    (_, account) = smtp.calls[0]
    assert account == PRINCIPAL.rate_limit_account
    assert account != "example.test"
    assert "@" not in account


# --- passive evidence does not steer the network ---------------------------


async def test_a_passive_risk_signal_changes_neither_the_probe_nor_the_status() -> None:
    """`docs/requirements.md` section 4: risk is orthogonal to deliverability.

    The shipped datasets are empty, so this asserts the wiring rather than a
    match: passive classification runs, contributes evidence, and the SMTP step
    is decided by the route alone.
    """
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, _ = build_service(smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is Status.LIKELY_DELIVERABLE
    assert len(smtp.calls) == 1


# --- the passive profile ----------------------------------------------------


async def test_a_deployment_without_an_smtp_service_never_probes() -> None:
    """`docs/requirements.md` section 15's local-passive profile.

    `smtp=None` is the profile, and it is an absent object rather than a flag:
    there is nothing to call even if a later edit forgot the condition.
    """
    service, _, _ = build_service(smtp=None)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is Status.UNKNOWN
    assert outcome.verdict.primary_reason is ReasonCode.MX_AVAILABLE
    assert outcome.active is False


async def test_a_caller_asking_for_a_passive_check_gets_no_smtp() -> None:
    """The same, chosen per request rather than per deployment."""
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, _ = build_service(smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL, active=False)

    assert smtp.calls == []
    assert outcome.verdict.status is Status.UNKNOWN


# --- internal_error reaches an operator -------------------------------------


async def test_an_internal_error_reaches_the_operator_sink() -> None:
    """Phase 5 stop condition 5.

    The verdict is `unknown` — which is what a caller sees constantly — so the
    only thing that distinguishes a bug in this project from an opaque server is
    that somebody was told. This is that somebody.
    """
    smtp = ScriptedSMTPVerification(evidence=internal_error_evidence())
    service, _, sink = build_service(smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)

    assert outcome.verdict.status is Status.UNKNOWN
    assert ReasonCode.INTERNAL_ERROR in outcome.verdict.reason_codes
    assert OperatorEventKind.INTERNAL_ERROR.value in sink.kinds()

    (event,) = [item for item in sink.events if item.kind is OperatorEventKind.INTERNAL_ERROR]
    assert event.reason is ReasonCode.INTERNAL_ERROR
    assert event.domain == "example.test"


async def test_an_ordinary_verdict_reports_nothing_to_the_operator() -> None:
    """A sink that fires on every request is a sink nobody reads."""
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, sink = build_service(smtp=smtp)

    await service.verify(VALID, principal=PRINCIPAL)

    assert sink.events == []


# --- evidence retention -----------------------------------------------------


async def test_the_verdict_retains_evidence_in_the_documented_order() -> None:
    """Passive, then the route, then SMTP in attempt order.

    The decision is order-independent — Phase 5 proves that over half a million
    permutations — so this is a *retention* contract: an auditor reading a
    stored verdict sees the layers in one order rather than in whichever order
    the pipeline happened to finish them.
    """
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, _ = build_service(smtp=smtp)

    outcome = await service.verify(VALID, principal=PRINCIPAL)
    layers = [item.layer.value for item in outcome.verdict.evidence]

    assert layers[-1] == "smtp"
    assert "dns" in layers
    assert layers.index("dns") == len(layers) - 2


async def test_the_same_input_and_the_same_fakes_produce_the_same_result() -> None:
    """Determinism, end to end."""
    smtp = ScriptedSMTPVerification(reply_lines=("250 ok",))
    service, _, _ = build_service(smtp=smtp)

    first = await service.verify(VALID, principal=PRINCIPAL)
    second = await service.verify(VALID, principal=PRINCIPAL)

    assert first.verdict.status is second.verdict.status
    assert first.verdict.primary_reason is second.verdict.primary_reason
    assert first.verdict.reason_codes == second.verdict.reason_codes
    assert first.verdict.risk_flags == second.verdict.risk_flags
