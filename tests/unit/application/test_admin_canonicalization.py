"""An operator's block matches the route however either one is spelled.

`application/admin.py` stored destination switches as the string an operator
typed, and `check_subject` explicitly *refused to normalize* — the right rule
for an account identifier, which has no canonical form, and the wrong one for a
host name, which this project canonicalizes everywhere else. So the block and
the route were compared as a raw string against a canonical one, and the final
system audit found three spellings that walked past a thrown switch:

- `EXAMPLE.TEST`, because the route says `example.test`;
- `mx1.example.test.`, because the trailing dot is presentation;
- `bücher.test`, because DNS says `xn--bcher-kva.test`.

Every one read as blocked and blocked nothing. The tests below drive the
comparison from both ends — an operator's spelling against a canonical route,
and a canonical spelling against a route that arrived some other way — because a
one-directional fix is the shape this defect had in the first place.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Final

import pytest
from tests.phase6_fixtures import (
    MX_ADDRESS,
    PRINCIPAL,
    FakeResolver,
    RecordingOperatorSink,
    ScriptedSMTPVerification,
    build_service,
)
from tests.phase7_fixtures import CORRELATION_KEY, CountingQuotaStore, SteppableClock

from emailcheck.adapters.observability.metrics import InMemoryMetrics
from emailcheck.application.abuse import AbuseGuard
from emailcheck.application.admin import AdminControl
from emailcheck.application.verification import VerificationRefused
from emailcheck.domain.admin import AdminStateError, check_destination_subject
from emailcheck.domain.dns import AddressLookup, MXLookup, MXRecord, apply_ttl_policy

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 5.0
DOMAIN: Final = "example.test"
ADDRESS: Final = f"user@{DOMAIN}"
MX_HOST: Final = "mx1.example.test"
UNICODE_DOMAIN: Final = "bücher.test"
PUNYCODE_DOMAIN: Final = "xn--bcher-kva.test"


def controls() -> tuple[AdminControl, AbuseGuard]:
    clock = SteppableClock()
    metrics = InMemoryMetrics()
    guard = AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=metrics,
        operator=RecordingOperatorSink(),
        correlation_key=CORRELATION_KEY,
    )
    admin = AdminControl(guard=guard, clock=clock, metrics=metrics, correlation_key=CORRELATION_KEY)
    return admin, guard


def resolver(domain: str = DOMAIN, exchanger: str = MX_HOST) -> FakeResolver:
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={domain: MXLookup(records=(MXRecord(preference=10, exchange=exchanger),), ttl=ttl)},
        a={exchanger: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl)},
    )


async def probe(
    guard: AbuseGuard, *, address: str, route: FakeResolver
) -> ScriptedSMTPVerification:
    """Run one verification and return the SMTP fake, so calls can be counted.

    A `VerificationRefused` is absorbed because the two destination switches
    refuse at different levels and both are correct: a **domain** block refuses
    the whole verification — `docs/operations.md` section 2 makes it a separate
    kill switch precisely so it fires even when every exchanger is also blocked
    — while an **exchanger** block removes candidates and leaves nothing to
    connect to. What every test here asserts is the property both share: no
    SMTP dialogue happened.
    """
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=route, smtp=smtp, guard=guard)
    with contextlib.suppress(VerificationRefused):
        async with asyncio.timeout(OUTER_BOUND):
            await service.verify(address, principal=PRINCIPAL, active=True)
    return smtp


# --- the canonical identity itself -------------------------------------------


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        ("EXAMPLE.TEST", "example.test"),
        ("Example.Test", "example.test"),
        ("example.test.", "example.test"),
        ("  example.test.  ", "example.test"),
        ("MX1.Example.Test.", "mx1.example.test"),
        (UNICODE_DOMAIN, PUNYCODE_DOMAIN),
        ("BÜCHER.TEST", PUNYCODE_DOMAIN),
        (PUNYCODE_DOMAIN, PUNYCODE_DOMAIN),
    ],
)
def test_a_destination_subject_is_stored_canonically(spelling: str, canonical: str) -> None:
    """One function, one identity — and it is Phase 1's IDNA encoder rather than
    a second `.lower()` written here."""
    assert check_destination_subject("domain", spelling) == canonical


def test_an_unusable_destination_subject_is_refused_at_the_boundary() -> None:
    """A switch stored as an inert unmatched string is a control that looks
    thrown and is not, which is worse than a refusal because nobody rechecks."""
    admin, _ = controls()
    # The last three pass the character screen and are still not host names, so
    # they pin the *validity* barrier rather than the screen above it.
    for bad in (
        "not a host!!",
        "",
        " ",
        "a" * 300,
        "alice@example.test",
        "-leading-hyphen.test",
        "double..dot.test",
        "trailing-hyphen-.test",
    ):
        with pytest.raises(AdminStateError):
            admin.block_domain(bad)
        with pytest.raises(AdminStateError):
            admin.block_exchanger(bad)


def test_an_account_subject_is_still_refused_rather_than_normalized() -> None:
    """The canonicalization is for destinations only.

    An account identifier is opaque: two spellings really are two accounts, and
    lowercasing one would suspend an account nobody named.
    """
    admin, guard = controls()
    admin.suspend_account("Acct-Mixed-Case")

    assert "Acct-Mixed-Case" in guard.state.suspended_accounts
    assert "acct-mixed-case" not in guard.state.suspended_accounts


# --- the block reaches the route ---------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    ["EXAMPLE.TEST", "Example.Test.", "example.test.", "  example.test  "],
    ids=["upper", "mixed and dotted", "trailing dot", "spacing"],
)
@asyncio_test
async def test_a_domain_block_in_any_spelling_stops_the_verification(spelling: str) -> None:
    admin, guard = controls()
    admin.block_domain(spelling)

    smtp = await probe(guard, address=ADDRESS, route=resolver())

    assert smtp.calls == [], f"{spelling!r} read as blocked and blocked nothing"


@pytest.mark.parametrize(
    "spelling",
    ["MX1.EXAMPLE.TEST", "mx1.example.test.", "Mx1.Example.Test."],
    ids=["upper", "trailing dot", "mixed and dotted"],
)
@asyncio_test
async def test_an_exchanger_block_in_any_spelling_stops_the_verification(spelling: str) -> None:
    """Repeated independently of the domain namespace, because they are two
    switches — `docs/operations.md` section 2 lists them separately — and a
    domain test passing says nothing about the exchanger one."""
    admin, guard = controls()
    admin.block_exchanger(spelling)

    smtp = await probe(guard, address=ADDRESS, route=resolver())

    assert smtp.calls == [], f"{spelling!r} read as blocked and blocked nothing"


@asyncio_test
async def test_a_unicode_domain_block_stops_a_punycode_route() -> None:
    """The operator writes the U-label; DNS carries the A-label."""
    admin, guard = controls()
    admin.block_domain(UNICODE_DOMAIN)

    smtp = await probe(
        guard,
        address=f"user@{PUNYCODE_DOMAIN}",
        route=resolver(domain=PUNYCODE_DOMAIN),
    )

    assert smtp.calls == []


@asyncio_test
async def test_a_punycode_domain_block_stops_a_unicode_submission() -> None:
    """The other direction, because a one-directional fix is how this began."""
    admin, guard = controls()
    admin.block_domain(PUNYCODE_DOMAIN)

    smtp = await probe(
        guard,
        address=f"user@{UNICODE_DOMAIN}",
        route=resolver(domain=PUNYCODE_DOMAIN),
    )

    assert smtp.calls == []


@asyncio_test
async def test_a_unicode_exchanger_block_stops_a_punycode_exchanger() -> None:
    admin, guard = controls()
    admin.block_exchanger("mx.bücher.test")

    smtp = await probe(
        guard,
        address=ADDRESS,
        route=resolver(exchanger="mx.xn--bcher-kva.test"),
    )

    assert smtp.calls == []


# --- unblocking, and the absence of orphaned spellings -----------------------


def test_a_block_and_an_unblock_in_different_spellings_are_one_identity() -> None:
    """Otherwise an operator lifting a block leaves the original in place and
    believes they have lifted it."""
    admin, guard = controls()

    assert admin.block_domain("EXAMPLE.TEST") is True
    assert guard.state.blocked_domains == frozenset({DOMAIN})
    assert admin.unblock_domain("example.test.") is True
    assert guard.state.blocked_domains == frozenset()


def test_blocking_the_same_host_twice_in_two_spellings_stores_one_entry() -> None:
    """No orphaned duplicates, and the second call reports no change."""
    admin, guard = controls()

    first = admin.block_exchanger("MX1.EXAMPLE.TEST")
    second = admin.block_exchanger("mx1.example.test.")

    assert first is True
    assert second is False, "a second spelling was recorded as a new block"
    assert guard.state.blocked_mx_hosts == frozenset({MX_HOST})


def test_an_unblock_of_a_never_blocked_host_changes_nothing() -> None:
    admin, guard = controls()

    assert admin.unblock_domain("EXAMPLE.TEST") is False
    assert guard.state.blocked_domains == frozenset()


# --- live work ----------------------------------------------------------------


@asyncio_test
async def test_a_block_thrown_after_the_route_was_prepared_still_applies() -> None:
    """`docs/operations.md` section 2 wants a kill switch to be immediate.

    The route is resolved, the operator throws the switch in a noncanonical
    spelling, and only then does the verification reach the destination step —
    which reads the *live* admin state rather than a snapshot taken at request
    time.
    """
    admin, guard = controls()
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver(), smtp=smtp, guard=guard)

    # Nothing blocked yet: the same call would probe.
    async with asyncio.timeout(OUTER_BOUND):
        await service.verify(ADDRESS, principal=PRINCIPAL, active=True)
    assert len(smtp.calls) == 1

    admin.block_exchanger("MX1.Example.Test.")

    async with asyncio.timeout(OUTER_BOUND):
        await service.verify(ADDRESS, principal=PRINCIPAL, active=True)

    assert len(smtp.calls) == 1, "a live block in another spelling was not observed"


@asyncio_test
async def test_lifting_a_block_in_another_spelling_restores_probing() -> None:
    """The control is reversible, and reversing it uses the same identity."""
    admin, guard = controls()
    admin.block_domain("EXAMPLE.TEST")
    smtp = await probe(guard, address=ADDRESS, route=resolver())
    assert smtp.calls == []

    admin.unblock_domain("example.test.")

    resumed = await probe(guard, address=ADDRESS, route=resolver())
    assert len(resumed.calls) == 1
