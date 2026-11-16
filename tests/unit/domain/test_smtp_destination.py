"""The destination policy runs three times, and none of them can be skipped.

Phase 2 judged the DNS answer. `ApprovedDestination` judges again at the moment
of connecting, and `ConfirmedPeer` judges the address the socket actually
reached. The point of these being types is that the third cannot be forgotten:
a session requires a `ConfirmedPeer`, which requires an `ApprovedDestination`.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.dns import HostName
from emailcheck.domain.mail_route import CandidateStatus, RouteCandidate, RouteSource
from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_destination import (
    ALLOWED_SMTP_PORTS,
    DEFAULT_SMTP_PORT,
    ApprovedDestination,
    ConfirmedPeer,
    DestinationApproved,
    DestinationRefused,
    DestinationRejection,
    DestinationVerdict,
    PeerAccepted,
    PeerEndpoint,
    PeerRefused,
    PeerRejection,
    approve_destination,
    confirm_peer,
)
from emailcheck.domain.smtp_session import SMTPSession, begin_session
from emailcheck.security.destination import DestinationDecision, DestinationDenyReason
from fake_smtp_transport import unvalidated_peer

HOST = HostName("mx.example.com")
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def approved(address: str = PUBLIC_V4) -> ApprovedDestination:
    return ApprovedDestination(host=HOST, address=address)


# --- the pre-connect check -------------------------------------------------


@pytest.mark.parametrize("address", [PUBLIC_V4, PUBLIC_V6, "1.1.1.1", "8.8.8.8"])
def test_a_public_address_is_approved(address: str) -> None:
    destination = ApprovedDestination(host=HOST, address=address)
    assert destination.address == address
    assert destination.port == DEFAULT_SMTP_PORT


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 - an unspecified address is a destination, not a bind
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "not-an-address",
        "",
    ],
)
def test_a_forbidden_address_cannot_become_an_approved_destination(address: str) -> None:
    """Every one of these was resolvable by DNS. None may be connected to."""
    with pytest.raises(SMTPContractError, match="refused by policy"):
        ApprovedDestination(host=HOST, address=address)


def test_the_dns_layer_being_satisfied_is_not_enough() -> None:
    """A resolver can answer differently on the second lookup, so this re-runs."""
    destination = approved()
    assert destination.address == PUBLIC_V4
    with pytest.raises(SMTPContractError):
        ApprovedDestination(host=HOST, address="127.0.0.1")


@pytest.mark.parametrize("port", [0, 1, 22, 80, 465, 587, 2525, 8025, 65535])
def test_only_the_smtp_port_is_reachable(port: int) -> None:
    with pytest.raises(SMTPContractError, match="not an allowed SMTP destination port"):
        ApprovedDestination(host=HOST, address=PUBLIC_V4, port=port)


def test_the_allowed_port_set_is_exactly_smtp() -> None:
    """587 is submission and needs AUTH, which this project does not implement."""
    assert frozenset({25}) == ALLOWED_SMTP_PORTS


def test_a_destination_must_be_stored_canonically() -> None:
    """Two spellings of one address would defeat the peer comparison."""
    with pytest.raises(SMTPContractError, match="canonical form"):
        ApprovedDestination(host=HOST, address="2606:4700:4700:0000::1111")


# --- the post-connect check ------------------------------------------------


def test_a_matching_peer_is_confirmed() -> None:
    verdict = confirm_peer(approved(), PeerEndpoint(PUBLIC_V4, DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerAccepted)
    assert verdict.peer.peer_address == PUBLIC_V4
    assert verdict.peer.host == HOST
    assert verdict.peer.port == DEFAULT_SMTP_PORT


def test_a_peer_that_is_not_the_approved_address_is_refused() -> None:
    """The connection landed somewhere else. It is closed, not used."""
    # 8.8.8.8 is permitted by the policy, so the only thing wrong with it is
    # that it is not the address that was approved.
    verdict = confirm_peer(approved(), PeerEndpoint("8.8.8.8", DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.ADDRESS_MISMATCH
    assert verdict.deny_reason is None


@pytest.mark.parametrize(
    ("peer_address", "expected"),
    [
        ("127.0.0.1", DestinationDenyReason.LOOPBACK),
        ("169.254.169.254", DestinationDenyReason.METADATA),
        ("10.0.0.1", DestinationDenyReason.PRIVATE),
        ("::1", DestinationDenyReason.LOOPBACK),
    ],
)
def test_a_forbidden_peer_is_refused_even_though_dns_was_safe(
    peer_address: str, expected: DestinationDenyReason
) -> None:
    """This is the check that catches a connection redirected after approval."""
    verdict = confirm_peer(approved(), PeerEndpoint(peer_address, DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.DENIED_BY_POLICY
    assert verdict.deny_reason is expected


def test_a_confirmed_peer_cannot_be_built_around_a_forbidden_address() -> None:
    with pytest.raises(SMTPContractError, match="peer refused by policy"):
        ConfirmedPeer(approved=approved(), peer_address="127.0.0.1")


def test_a_confirmed_peer_cannot_be_built_around_a_different_address() -> None:
    with pytest.raises(SMTPContractError, match="not the approved destination"):
        ConfirmedPeer(approved=approved(), peer_address="8.8.8.8")


# --- the gate this exists for ----------------------------------------------


def test_a_session_cannot_be_opened_without_passing_every_check() -> None:
    """There is no order of operations that reaches a session by another route."""
    verdict = confirm_peer(approved(), PeerEndpoint(PUBLIC_V4, DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerAccepted)
    session = begin_session(verdict.peer)
    assert isinstance(session, SMTPSession)
    assert session.peer.peer_address == PUBLIC_V4


def test_the_session_type_names_the_peer_as_required() -> None:
    """`peer` has no default, so a session cannot be built without one."""
    import dataclasses

    field = SMTPSession.__dataclass_fields__["peer"]
    assert field.default is dataclasses.MISSING
    assert field.default_factory is dataclasses.MISSING
    with pytest.raises(TypeError):
        SMTPSession()  # type: ignore[call-arg]


def test_no_transport_port_accepts_a_bare_address() -> None:
    """The port takes an `ApprovedDestination`, so the policy has already run."""
    import inspect

    from emailcheck.ports.smtp import SMTPTransport

    signature = inspect.signature(SMTPTransport.connect)
    annotations = {
        name: parameter.annotation
        for name, parameter in signature.parameters.items()
        if name != "self"
    }
    assert annotations["destination"] == "ApprovedDestination"
    assert "host" not in annotations
    assert "address" not in annotations
    assert "port" not in annotations


# --- the only path from DNS to a connectable destination -------------------


def candidate(
    *addresses: str,
    status: CandidateStatus = CandidateStatus.USABLE,
    host: str = "mx.example.com",
) -> RouteCandidate:
    decisions = tuple(
        DestinationDecision(allowed=True, address=a, version=4, deny_reason=None) for a in addresses
    )
    return RouteCandidate(
        host=HostName(host),
        preference=10,
        source=RouteSource.MX,
        status=status,
        decisions=decisions,
    )


def approve(cand: RouteCandidate, address: str, **kw: object) -> DestinationVerdict:
    return approve_destination(cand, address, **kw)  # type: ignore[arg-type]


def test_an_address_the_candidate_resolved_to_is_approved() -> None:
    verdict = approve(candidate(PUBLIC_V4), PUBLIC_V4)
    assert isinstance(verdict, DestinationApproved)
    assert verdict.destination.address == PUBLIC_V4
    assert verdict.destination.port == DEFAULT_SMTP_PORT
    # The host comes from the candidate, not from a parameter.
    assert verdict.destination.host == HostName("mx.example.com")


def test_a_public_address_the_candidate_never_offered_is_refused() -> None:
    """The gap the review found: the policy allows 1.1.1.1, DNS never named it."""
    verdict = approve(candidate(PUBLIC_V4), "1.1.1.1")
    assert isinstance(verdict, DestinationRefused)
    assert verdict.reason is DestinationRejection.ADDRESS_NOT_IN_CANDIDATE


def test_a_denied_address_is_refused_even_if_the_candidate_named_it() -> None:
    verdict = approve(candidate(PUBLIC_V4), "127.0.0.1")
    assert isinstance(verdict, DestinationRefused)
    assert verdict.reason is DestinationRejection.DENIED_BY_POLICY
    assert verdict.deny_reason is DestinationDenyReason.LOOPBACK


@pytest.mark.parametrize("status", [CandidateStatus.NO_ADDRESSES, CandidateStatus.ADDRESSES_DENIED])
def test_a_candidate_that_is_not_usable_offers_no_destination(
    status: CandidateStatus,
) -> None:
    decisions = (
        ()
        if status is CandidateStatus.NO_ADDRESSES
        else (
            DestinationDecision(
                allowed=False,
                address="10.0.0.1",
                version=4,
                deny_reason=DestinationDenyReason.PRIVATE,
            ),
        )
    )
    unusable = RouteCandidate(
        host=HostName("mx.example.com"),
        preference=10,
        source=RouteSource.MX,
        status=status,
        decisions=decisions,
    )
    verdict = approve(unusable, PUBLIC_V4)
    assert isinstance(verdict, DestinationRefused)
    assert verdict.reason is DestinationRejection.CANDIDATE_NOT_USABLE


@pytest.mark.parametrize("port", [0, 22, 465, 587, 2525, 65535])
def test_the_factory_refuses_any_port_but_25(port: int) -> None:
    verdict = approve(candidate(PUBLIC_V4), PUBLIC_V4, port=port)
    assert isinstance(verdict, DestinationRefused)
    assert verdict.reason is DestinationRejection.PORT_NOT_ALLOWED


def test_the_factory_matches_on_the_canonical_form() -> None:
    """A candidate stores canonical addresses; a caller may not."""
    verdict = approve(candidate("2606:4700:4700::1111"), "2606:4700:4700:0:0:0:0:1111")
    assert isinstance(verdict, DestinationApproved)
    assert verdict.destination.address == "2606:4700:4700::1111"


def test_one_candidate_address_does_not_approve_a_sibling_it_lacks() -> None:
    multi = candidate(PUBLIC_V4, "8.8.8.8")
    assert isinstance(approve(multi, PUBLIC_V4), DestinationApproved)
    assert isinstance(approve(multi, "8.8.8.8"), DestinationApproved)
    assert isinstance(approve(multi, "1.1.1.1"), DestinationRefused)


@pytest.mark.inspection
def test_production_code_reaches_a_destination_only_through_the_factory() -> None:
    """Python has no private constructor, so this is fixed by inspection.

    The raw constructor stays validating as the second barrier, but nothing in
    `src/` may call it: the factory is what ties an address to DNS.
    """
    import ast
    from pathlib import Path

    source_root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    callers: list[str] = []
    for module in sorted(source_root.rglob("*.py")):
        if module.name == "smtp_destination.py":
            continue  # the factory itself
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ApprovedDestination"
            ):
                callers.append(f"{module.name}:{node.lineno}")
    assert callers == [], f"ApprovedDestination built outside the factory: {callers}"


# --- the peer endpoint carries a port, and the family is the transport's job -


def test_a_peer_on_the_wrong_port_is_refused() -> None:
    """`getpeername()` returns an address and a port. Both are checked."""
    verdict = confirm_peer(approved(), PeerEndpoint(PUBLIC_V4, 2525))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.PORT_MISMATCH


@pytest.mark.parametrize("port", [1, 24, 26, 587, 65535])
def test_only_the_approved_port_confirms(port: int) -> None:
    verdict = confirm_peer(approved(), PeerEndpoint(PUBLIC_V4, port))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.PORT_MISMATCH


def test_a_confirmed_peer_cannot_be_built_on_the_wrong_port() -> None:
    with pytest.raises(SMTPContractError, match="not the approved port"):
        ConfirmedPeer(approved=approved(), peer_address=PUBLIC_V4, peer_port=2525)


@pytest.mark.parametrize(
    ("approved_address", "peer_address", "accepted", "label"),
    [
        (PUBLIC_V4, PUBLIC_V4, True, "identical IPv4"),
        (PUBLIC_V6, PUBLIC_V6, True, "identical IPv6 compressed"),
        (PUBLIC_V6, "2606:4700:4700:0:0:0:0:1111", True, "IPv6 expanded"),
        (PUBLIC_V6, "2606:4700:4700:0000:0000:0000:0000:1111", True, "IPv6 fully padded"),
        (PUBLIC_V4, "::ffff:93.184.216.34", False, "IPv4-mapped IPv6"),
        (PUBLIC_V4, "::ffff:5db8:d822", False, "IPv4-mapped, hex form"),
        (PUBLIC_V4, "8.8.8.8", False, "an unrelated but permitted public peer"),
    ],
)
def test_peer_address_representations(
    approved_address: str, peer_address: str, accepted: bool, label: str
) -> None:
    """A mapped form is refused, never quietly unwrapped into a public IPv4."""
    destination = ApprovedDestination(host=HOST, address=approved_address)
    verdict = confirm_peer(destination, PeerEndpoint(peer_address, DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerAccepted) is accepted, label


@pytest.mark.parametrize(
    "mapped",
    ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1"],
)
def test_a_private_address_wearing_an_ipv6_form_is_never_approved(mapped: str) -> None:
    """The reason the policy refuses mapped forms at all."""
    verdict = confirm_peer(approved(), PeerEndpoint(mapped, DEFAULT_SMTP_PORT))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.DENIED_BY_POLICY
    with pytest.raises(SMTPContractError):
        ApprovedDestination(host=HOST, address=mapped)


def test_the_transport_port_reports_an_endpoint_not_a_bare_address() -> None:
    """So the implementation cannot pass the address and forget the port."""
    import inspect

    from emailcheck.ports.smtp import SMTPTransport

    signature = inspect.signature(SMTPTransport.connect)
    assert signature.return_annotation == "ConnectionOutcome"

    from emailcheck.ports.smtp import SMTPConnection

    peer_annotation = inspect.signature(SMTPConnection.peer.fget).return_annotation  # type: ignore[union-attr]
    assert peer_annotation == "PeerEndpoint"


# --- the peer endpoint guarantees its shape, and only its shape ------------
#
# Two layers, kept apart on purpose. `PeerEndpoint` fixes what an endpoint may
# look like — a numeric address, no CR/LF/NUL, a real port number — and says
# nothing about whether it may be reached. `confirm_peer` re-runs the
# destination policy and answers that. A value type that judged policy would let
# a caller acquire the permission by constructing the value.


@pytest.mark.parametrize(
    ("address", "label"),
    [
        ("", "empty"),
        ("nonsense", "a word"),
        ("mx.example.com", "a host name, which would mean something resolved"),
        ("93.184.216.34\r\n", "carrying CRLF"),
        ("93.184.216.34\n", "carrying LF"),
        ("93.184.216.34\x00", "carrying NUL"),
        ("93.184.216.34 QUIT", "carrying a second word"),
        (" 93.184.216.34 ", "surrounded by whitespace"),
        ("093.184.216.034", "with leading zeros, which are ambiguous"),
        ("1568553506", "written as an integer"),
        ("[93.184.216.34]", "bracketed"),
        ("93.184.216.34:25", "with a port glued on"),
        ("fe80::1%eth0", "carrying a scope identifier"),
    ],
)
def test_a_peer_address_must_be_a_plain_numeric_address(address: str, label: str) -> None:
    with pytest.raises(SMTPContractError):
        PeerEndpoint(address, DEFAULT_SMTP_PORT)


@pytest.mark.parametrize("address", [None, 25, b"93.184.216.34", ("93.184.216.34",), object()])
def test_a_peer_address_must_be_text(address: object) -> None:
    with pytest.raises(SMTPContractError):
        PeerEndpoint(address, DEFAULT_SMTP_PORT)  # type: ignore[arg-type]


@pytest.mark.parametrize("port", [0, -1, 65536, 70000, 2**31])
def test_a_peer_port_must_be_a_real_port_number(port: int) -> None:
    with pytest.raises(SMTPContractError):
        PeerEndpoint(PUBLIC_V4, port)


@pytest.mark.parametrize("port", [None, "25", 2.5, b"25", True, False])
def test_a_peer_port_must_be_a_whole_number(port: object) -> None:
    """`True` is `1` in Python, so a boolean would silently mean port one."""
    with pytest.raises(SMTPContractError):
        PeerEndpoint(PUBLIC_V4, port)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "address", [PUBLIC_V4, PUBLIC_V6, "8.8.8.8", "127.0.0.1", "10.0.0.1", "::1"]
)
def test_a_well_formed_endpoint_is_accepted_whatever_the_policy_thinks(address: str) -> None:
    """Loopback and RFC 1918 are well-formed. Being reachable is a separate question."""
    endpoint = PeerEndpoint(address, DEFAULT_SMTP_PORT)
    assert endpoint.address == address


@pytest.mark.parametrize("port", [1, 25, 587, 65535])
def test_every_real_port_number_is_a_well_formed_endpoint(port: int) -> None:
    assert PeerEndpoint(PUBLIC_V4, port).port == port


def test_the_policy_still_refuses_an_endpoint_that_skipped_its_own_checks() -> None:
    """The two barriers are independent, and this is what makes that testable.

    `unvalidated_peer` builds a `PeerEndpoint` without running `__post_init__`,
    which is the only way to reach `confirm_peer` with a malformed address now.
    If the value type were the only thing refusing these, tightening it would
    have quietly removed a check rather than added one.
    """
    for address in ("nonsense", "", "not an address at all"):
        verdict = confirm_peer(approved(), unvalidated_peer(address, DEFAULT_SMTP_PORT))
        assert isinstance(verdict, PeerRefused)
        assert verdict.reason is PeerRejection.DENIED_BY_POLICY
        assert verdict.deny_reason is DestinationDenyReason.MALFORMED


def test_the_policy_still_refuses_a_forbidden_address_that_skipped_its_own_checks() -> None:
    """Shape and permission answer different questions, and both are asked."""
    for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254"):
        verdict = confirm_peer(approved(), unvalidated_peer(address, DEFAULT_SMTP_PORT))
        assert isinstance(verdict, PeerRefused)
        assert verdict.reason is PeerRejection.DENIED_BY_POLICY


def test_a_port_the_value_type_would_refuse_is_still_a_port_mismatch() -> None:
    verdict = confirm_peer(approved(), unvalidated_peer(PUBLIC_V4, 0))
    assert isinstance(verdict, PeerRefused)
    assert verdict.reason is PeerRejection.PORT_MISMATCH
