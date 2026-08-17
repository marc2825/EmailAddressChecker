"""The lab-active destination allowlist, and everything it does not override.

`docs/requirements.md` section 15 gives the lab-active profile a *destination
allowlist* and `config/lab-active.toml.example` has listed one since Phase 0.
Nothing read it: `Deployment` had no such field, so a lab deployment probed
whatever DNS pointed it at, which is the opposite of "controlled SMTP server or
owned domain". The final system audit found it.

Two properties are what a review should check here, and they pull in opposite
directions.

**It restricts.** Every candidate a verification could reach — the preferred
exchanger and every fallback — must be on the list, because Phase 4E falls
through on a pre-recipient failure and an allowlist consulted for the first
candidate alone authorizes nothing about the second.

**It grants nothing.** A host on the list still passes the destination policy,
the operator's blocks, the peer check, and TLS verification. `allowlisted` means
*eligible to be contacted*, never *exempt*.

Nothing here opens a socket.
"""

from __future__ import annotations

import asyncio
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
from emailcheck.composition import Deployment, DeploymentProfile, build_verification_stack
from emailcheck.domain.admin import AdminState
from emailcheck.domain.dns import (
    AddressLookup,
    DestinationAllowlist,
    DNSContractError,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)

asyncio_test = pytest.mark.asyncio

OUTER_BOUND: Final = 5.0
DOMAIN: Final = "recipient.test.example"
ADDRESS: Final = f"probe.target@{DOMAIN}"
ALLOWED: Final = "mx1.test.example"
OTHER_ALLOWED: Final = "mx2.test.example"
FORBIDDEN: Final = "mx-elsewhere.example.test"
KEY: Final = "k" * 40
SENDER: Final = {
    "ehlo_hostname": "probe.example.test",
    "envelope_sender": "verify@probe.example.test",
}


def resolver_for(*exchangers: str) -> FakeResolver:
    """One domain publishing several exchangers, in preference order."""
    ttl = apply_ttl_policy(3600, positive=True)
    return FakeResolver(
        mx={
            DOMAIN: MXLookup(
                records=tuple(
                    MXRecord(preference=10 * (index + 1), exchange=host)
                    for index, host in enumerate(exchangers)
                ),
                ttl=ttl,
            )
        },
        a={host: AddressLookup(addresses=(MX_ADDRESS,), ttl=ttl) for host in exchangers},
    )


def guard_with(state: AdminState) -> AbuseGuard:
    clock = SteppableClock()
    return AbuseGuard(
        quota=CountingQuotaStore(),
        clock=clock,
        metrics=InMemoryMetrics(),
        operator=RecordingOperatorSink(),
        correlation_key=CORRELATION_KEY,
        state=state,
    )


async def verify(
    *,
    exchangers: tuple[str, ...],
    allowlist: DestinationAllowlist | None,
    state: AdminState | None = None,
) -> ScriptedSMTPVerification:
    """Run one verification and return the SMTP fake, so calls can be counted."""
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(
        resolver=resolver_for(*exchangers),
        smtp=smtp,
        guard=None if state is None else guard_with(state),
    )
    service = type(service)(  # rebuild with the allowlist; the type is frozen
        syntax=service.syntax,
        routes=service.routes,
        passive=service.passive,
        admission=service.admission,
        operator=service.operator,
        smtp=service.smtp,
        limits=service.limits,
        guard=service.guard,
        sender_identity=service.sender_identity,
        destination_allowlist=allowlist,
    )
    async with asyncio.timeout(OUTER_BOUND):
        await service.verify(ADDRESS, principal=PRINCIPAL, active=True)
    return smtp


# --- what the allowlist restricts --------------------------------------------


@asyncio_test
async def test_an_allowlisted_exchanger_may_be_contacted() -> None:
    """The positive control. Without it an over-strict build passes everything
    else in this file by contacting nothing at all."""
    smtp = await verify(exchangers=(ALLOWED,), allowlist=DestinationAllowlist.of([ALLOWED]))

    assert len(smtp.calls) == 1


@asyncio_test
async def test_an_exchanger_that_is_not_allowlisted_is_never_contacted() -> None:
    smtp = await verify(exchangers=(FORBIDDEN,), allowlist=DestinationAllowlist.of([ALLOWED]))

    assert smtp.calls == [], "a lab deployment contacted a host it does not own"


@asyncio_test
async def test_an_empty_allowlist_permits_nothing_rather_than_everything() -> None:
    """The direction a missing safety setting has to fail.

    An empty allowlist read as "allow every public MX" would make the
    safest-looking configuration the most dangerous one — and it is the shape a
    misconfiguration takes, which is why `composition.py` also refuses to build
    one.
    """
    smtp = await verify(exchangers=(ALLOWED,), allowlist=DestinationAllowlist())

    assert smtp.calls == []


@asyncio_test
async def test_a_deployment_with_no_allowlist_is_unrestricted_by_this_control() -> None:
    """`None` and empty are different, and this pins the difference.

    Service-active is bounded by quotas, blocks, and the destination policy
    rather than by an inventory of owned machines, so it has no allowlist at all
    — which must not silently become an empty one.
    """
    smtp = await verify(exchangers=(FORBIDDEN,), allowlist=None)

    assert len(smtp.calls) == 1


# --- every candidate, not the preferred one ----------------------------------


@asyncio_test
async def test_a_fallback_that_is_not_allowlisted_is_removed_before_planning() -> None:
    """The fallback case, which is the one an allowlist is most likely to miss.

    Phase 4E falls through to the next exchanger when the first fails before the
    recipient stage, so checking `connectable_candidates[0]` alone would let a
    fallback reach a host the operator never authorized. The forbidden host must
    not even be planned.
    """
    smtp = await verify(
        exchangers=(ALLOWED, FORBIDDEN), allowlist=DestinationAllowlist.of([ALLOWED])
    )

    assert len(smtp.calls) == 1
    # The route the SMTP layer was handed carries only the allowlisted host.
    assert smtp.routes and [
        candidate.host.value for candidate in smtp.routes[-1].connectable_candidates
    ] == [ALLOWED]


@asyncio_test
async def test_two_allowlisted_exchangers_both_survive_so_fallback_still_works() -> None:
    """The allowlist must restrict, not disable Phase 4E's fallback entirely."""
    smtp = await verify(
        exchangers=(ALLOWED, OTHER_ALLOWED),
        allowlist=DestinationAllowlist.of([ALLOWED, OTHER_ALLOWED]),
    )

    assert smtp.routes and [
        candidate.host.value for candidate in smtp.routes[-1].connectable_candidates
    ] == [ALLOWED, OTHER_ALLOWED]


@asyncio_test
async def test_a_preferred_host_that_is_not_allowlisted_does_not_block_an_allowed_one() -> None:
    """Removing candidates never promotes one that was already forbidden."""
    smtp = await verify(
        exchangers=(FORBIDDEN, ALLOWED), allowlist=DestinationAllowlist.of([ALLOWED])
    )

    assert smtp.routes and [
        candidate.host.value for candidate in smtp.routes[-1].connectable_candidates
    ] == [ALLOWED]


# --- one identity model, shared with the operator's blocks -------------------


@pytest.mark.parametrize(
    "configured",
    ["MX1.TEST.EXAMPLE", "mx1.test.example.", "  Mx1.Test.Example.  "],
    ids=["upper case", "trailing dot", "spacing and case"],
)
@asyncio_test
async def test_a_configured_spelling_matches_the_canonical_route_host(configured: str) -> None:
    """Case, trailing dot, and surrounding space are presentation.

    The allowlist compares the same canonical `HostName` the route holds, so an
    operator writing a configuration file does not have to guess the wire
    spelling — which is the mistake that made an operator's block do nothing.
    """
    smtp = await verify(exchangers=(ALLOWED,), allowlist=DestinationAllowlist.of([configured]))

    assert len(smtp.calls) == 1


@asyncio_test
async def test_a_unicode_configuration_entry_matches_its_punycode_route_host() -> None:
    """IDNA, through the repository's own UTS-46 encoder rather than a codec.

    DNS answers carry the A-label; a human writes the U-label. One identity.
    """
    unicode_host = "bücher.test.example"
    punycode_host = "xn--bcher-kva.test.example"
    assert DestinationAllowlist.of([unicode_host]).hosts == frozenset({punycode_host})

    smtp = await verify(
        exchangers=(punycode_host,), allowlist=DestinationAllowlist.of([unicode_host])
    )

    assert len(smtp.calls) == 1


def test_an_unusable_allowlist_entry_is_refused_rather_than_stored() -> None:
    """An entry that cannot be a host cannot be one this deployment owns, and
    storing it inert would be a control that looks configured and is not."""
    for bad in ("not a host!!", "", "  ", "@example.test"):
        with pytest.raises(DNSContractError):
            DestinationAllowlist.of([bad])


def test_the_allowlist_holds_canonical_identities_and_refuses_others() -> None:
    """The value type will not hold a raw spelling even if constructed directly."""
    assert DestinationAllowlist.of(["MX1.Test.Example."]).hosts == frozenset({ALLOWED})
    with pytest.raises(DNSContractError):
        DestinationAllowlist(hosts=frozenset({"MX1.TEST.EXAMPLE"}))
    assert DestinationAllowlist().is_empty is True
    assert DestinationAllowlist.of([ALLOWED]).permits("not a host!!") is False
    # `permits` canonicalizes its argument as well as its entries. The route
    # already supplies a canonical `HostName.value`, so this is defence in depth
    # for a caller added later — pinned here because a production-path test
    # cannot reach it.
    assert DestinationAllowlist.of([ALLOWED]).permits("MX1.Test.Example.") is True
    assert DestinationAllowlist.of([ALLOWED]).permits(ALLOWED.upper()) is True


# --- the allowlist grants nothing --------------------------------------------


@asyncio_test
async def test_an_operator_block_beats_the_allowlist() -> None:
    """An allowlist is deployment configuration; a block is a kill switch.

    An operator throwing a switch during an incident must not be overruled by a
    file written before it.
    """
    smtp = await verify(
        exchangers=(ALLOWED,),
        allowlist=DestinationAllowlist.of([ALLOWED]),
        state=AdminState(blocked_mx_hosts=frozenset({ALLOWED})),
    )

    assert smtp.calls == [], "an allowlist overrode an operator block"


@asyncio_test
async def test_an_operator_block_in_another_spelling_still_beats_the_allowlist() -> None:
    """B6 and B9 share one identity model, and this is where that is proven.

    The operator blocks `MX1.TEST.EXAMPLE.` through `AdminControl`, which
    canonicalizes; the allowlist holds the canonical form; the route publishes
    it. All three have to agree or the block silently loses.
    """
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
    admin.block_exchanger("MX1.TEST.EXAMPLE.")

    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver_for(ALLOWED), smtp=smtp, guard=guard)
    service = type(service)(
        syntax=service.syntax,
        routes=service.routes,
        passive=service.passive,
        admission=service.admission,
        operator=service.operator,
        smtp=service.smtp,
        limits=service.limits,
        guard=guard,
        sender_identity=service.sender_identity,
        destination_allowlist=DestinationAllowlist.of([ALLOWED]),
    )
    async with asyncio.timeout(OUTER_BOUND):
        await service.verify(ADDRESS, principal=PRINCIPAL, active=True)

    assert smtp.calls == [], "a noncanonical block lost to the allowlist"


@asyncio_test
async def test_an_allowlisted_host_on_an_unsafe_address_is_still_refused() -> None:
    """The allowlist does not bypass the SSRF destination policy.

    `192.0.2.0/24` is denied by `security/destination.py`, so the exchanger
    resolves to nothing usable and Phase 2 leaves no candidate — allowlisted or
    not.
    """
    ttl = apply_ttl_policy(3600, positive=True)
    resolver = FakeResolver(
        mx={DOMAIN: MXLookup(records=(MXRecord(preference=10, exchange=ALLOWED),), ttl=ttl)},
        a={ALLOWED: AddressLookup(addresses=("192.0.2.10",), ttl=ttl)},
    )
    smtp = ScriptedSMTPVerification(reply_lines=("250 2.1.5 ok",))
    service, _, _ = build_service(resolver=resolver, smtp=smtp)
    service = type(service)(
        syntax=service.syntax,
        routes=service.routes,
        passive=service.passive,
        admission=service.admission,
        operator=service.operator,
        smtp=service.smtp,
        limits=service.limits,
        guard=service.guard,
        sender_identity=service.sender_identity,
        destination_allowlist=DestinationAllowlist.of([ALLOWED]),
    )
    async with asyncio.timeout(OUTER_BOUND):
        await service.verify(ADDRESS, principal=PRINCIPAL, active=True)

    assert smtp.calls == [], "an allowlisted host reached a denied address"


# --- composition --------------------------------------------------------------


def lab(**kwargs: object) -> Deployment:
    return Deployment(
        api_keys={"acct-1": KEY},
        correlation_key=b"c" * 32,
        sender_identity=SENDER,
        active_probing=True,
        profile=DeploymentProfile.LAB_ACTIVE,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_probing_lab_deployment_without_an_allowlist_does_not_start() -> None:
    """Section 15's requirement as a refusal rather than as documentation."""
    with pytest.raises(ValueError, match="destination allowlist"):
        lab()


def test_an_unusable_allowlist_entry_fails_at_start_up() -> None:
    """With a sentence, rather than as a host that silently matches nothing."""
    with pytest.raises(ValueError):
        lab(lab_destination_allowlist=frozenset({"not a host!!"}))


def test_a_configured_lab_allowlist_reaches_the_verification_service() -> None:
    """Identity, not existence: a canonicalized value that the service holds."""
    stack = build_verification_stack(
        lab(lab_destination_allowlist=frozenset({"MX1.Test.Example."}))
    )

    allowlist = stack.verification.destination_allowlist
    assert allowlist is not None
    assert allowlist.hosts == frozenset({ALLOWED})


def test_a_non_lab_profile_may_not_configure_a_destination_allowlist() -> None:
    """A setting that cannot take effect is a misconfiguration, on this type's
    existing rule — the same one that refuses a local-passive job store."""
    with pytest.raises(ValueError, match="lab-active"):
        Deployment(
            api_keys={"acct-1": KEY},
            correlation_key=b"c" * 32,
            lab_destination_allowlist=frozenset({ALLOWED}),
        )


def test_the_local_passive_profile_is_unaffected() -> None:
    """It has no allowlist, no SMTP service, and no restriction to apply."""
    stack = build_verification_stack(
        Deployment(api_keys={"acct-1": KEY}, correlation_key=b"c" * 32)
    )

    assert stack.verification.destination_allowlist is None
    assert stack.verification.smtp is None


def test_no_caller_supplied_field_can_reach_the_allowlist() -> None:
    """Operator configuration, never a request field.

    Asserted structurally over the API's closed request schema and the CLI's
    arguments rather than by reading the handler: a key added to either later
    would have to appear here.
    """
    from emailcheck.apps.api import PERMITTED_REQUEST_KEYS
    from emailcheck.apps.cli import build_parser

    assert frozenset({"email"}) == PERMITTED_REQUEST_KEYS
    flags = {action.dest for action in build_parser()._actions}
    for forbidden in ("allowlist", "destination", "mx", "mx_host", "bypass", "override"):
        assert not any(forbidden in flag for flag in flags), forbidden
