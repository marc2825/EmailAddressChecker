"""The transport adapter's decisions, tested without opening a socket.

Three things this adapter does are safety-relevant and all three are pure enough
to test directly: which socket family it picks, whether it re-checks the policy
before creating a socket, and how it turns a `getpeername()` result into a
value. The socket-level behaviour is in `tests/integration/`.
"""

from __future__ import annotations

import socket

import pytest

from emailcheck.adapters.smtp.asyncio_transport import (
    AsyncioSMTPConnection,
    AsyncioSMTPTransport,
    _family_for,
    _peer_from_sockaddr,
)
from emailcheck.domain.dns import HostName
from emailcheck.domain.smtp_contract import SMTPContractError
from emailcheck.domain.smtp_destination import ApprovedDestination, PeerEndpoint
from emailcheck.domain.smtp_transport import (
    DEFAULT_MAX_TOTAL_BYTES,
    TransportFailure,
    TransportLimits,
    TransportTimeouts,
)
from emailcheck.ports.smtp import ConnectionFailed

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def destination(address: str) -> ApprovedDestination:
    return ApprovedDestination(host=HostName("mx.example.com"), address=address)


# --- the family is chosen, never inherited ---------------------------------


@pytest.mark.parametrize(
    ("address", "expected", "label"),
    [
        (PUBLIC_V4, socket.AF_INET, "IPv4 uses AF_INET"),
        ("1.1.1.1", socket.AF_INET, "IPv4 uses AF_INET"),
        (PUBLIC_V6, socket.AF_INET6, "IPv6 uses AF_INET6"),
        ("2001:4860:4860::8888", socket.AF_INET6, "IPv6 uses AF_INET6"),
    ],
)
def test_the_family_matches_the_destination(address: str, expected: int, label: str) -> None:
    """An IPv4 destination never goes out on a dual-stack AF_INET6 socket.

    That is the whole reason the peer arrives unmapped: a dual-stack socket
    would report `::ffff:…`, which the policy refuses on purpose.
    """
    assert _family_for(destination(address)) is expected, label


def test_no_destination_is_ever_given_af_unspec() -> None:
    for address in (PUBLIC_V4, PUBLIC_V6):
        assert _family_for(destination(address)) in {socket.AF_INET, socket.AF_INET6}


# --- what getpeername() may become -----------------------------------------


@pytest.mark.parametrize(
    ("sockaddr", "family", "expected"),
    [
        ((PUBLIC_V4, 25), socket.AF_INET, PeerEndpoint(PUBLIC_V4, 25)),
        ((PUBLIC_V6, 25, 0, 0), socket.AF_INET6, PeerEndpoint(PUBLIC_V6, 25)),
        # An expanded IPv6 form normalizes within its own family.
        (
            ("2606:4700:4700:0:0:0:0:1111", 25, 0, 0),
            socket.AF_INET6,
            PeerEndpoint(PUBLIC_V6, 25),
        ),
    ],
)
def test_a_usable_peer_becomes_an_endpoint(
    sockaddr: tuple[object, ...], family: int, expected: PeerEndpoint
) -> None:
    assert _peer_from_sockaddr(sockaddr, family) == expected


@pytest.mark.parametrize(
    ("sockaddr", "family", "expected", "label"),
    [
        (
            ("::ffff:93.184.216.34", 25, 0, 0),
            socket.AF_INET6,
            TransportFailure.PEER_UNEXPECTED_FAMILY,
            "a mapped IPv4 on an IPv6 socket",
        ),
        (
            ("2002:5db8:d822::1", 25, 0, 0),
            socket.AF_INET6,
            TransportFailure.PEER_UNEXPECTED_FAMILY,
            "a 6to4 form on an IPv6 socket",
        ),
        (
            (PUBLIC_V4, 25),
            socket.AF_INET6,
            TransportFailure.PEER_UNEXPECTED_FAMILY,
            "an IPv4 address on an IPv6 socket",
        ),
        (
            (PUBLIC_V6, 25, 0, 0),
            socket.AF_INET,
            TransportFailure.PEER_UNEXPECTED_FAMILY,
            "an IPv6 address on an IPv4 socket",
        ),
        (
            ("fe80::1%eth0", 25, 0, 2),
            socket.AF_INET6,
            TransportFailure.PEER_UNEXPECTED_FAMILY,
            "a scoped link-local peer",
        ),
        (
            ("not-an-address", 25),
            socket.AF_INET,
            TransportFailure.PEER_MALFORMED,
            "unparsable text",
        ),
        ((PUBLIC_V4,), socket.AF_INET, TransportFailure.PEER_MALFORMED, "a one-element sockaddr"),
        ((PUBLIC_V4, "25"), socket.AF_INET, TransportFailure.PEER_MALFORMED, "a string port"),
        ((PUBLIC_V4, True), socket.AF_INET, TransportFailure.PEER_MALFORMED, "a boolean port"),
        (
            (25, PUBLIC_V4),
            socket.AF_INET,
            TransportFailure.PEER_MALFORMED,
            "the fields the wrong way round",
        ),
        (
            "93.184.216.34:25",
            socket.AF_INET,
            TransportFailure.PEER_MALFORMED,
            "a string rather than a tuple",
        ),
        (None, socket.AF_INET, TransportFailure.PEER_MALFORMED, "nothing at all"),
    ],
)
def test_an_unusable_peer_is_refused_not_repaired(
    sockaddr: object, family: int, expected: TransportFailure, label: str
) -> None:
    """A mapped form is refused rather than unwrapped.

    Unwrapping is the fallback that would trust a mapped address as a public
    IPv4, which is exactly what the policy refuses mapped forms to prevent. It
    is reported as a family problem rather than a policy denial, because this
    transport never opens a dual-stack socket: seeing one means the family
    selection broke.
    """
    assert _peer_from_sockaddr(sockaddr, family) is expected, label


def test_the_mapped_form_is_never_silently_converted() -> None:
    """Stated as its own test because it is the tempting shortcut."""
    refused = _peer_from_sockaddr(("::ffff:93.184.216.34", 25, 0, 0), socket.AF_INET6)
    assert refused is TransportFailure.PEER_UNEXPECTED_FAMILY
    assert not isinstance(refused, PeerEndpoint)


# --- the policy runs once more, before a socket exists ---------------------


@pytest.mark.asyncio
async def test_a_destination_that_became_forbidden_opens_no_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: `ApprovedDestination` checked it, and it is checked again.

    The destination is built while the policy allows the address, and the policy
    is then changed underneath it, which is what a stale job looks like. No
    socket may be created.
    """
    approved = destination(PUBLIC_V4)

    created: list[object] = []
    real_socket = socket.socket

    def recording_socket(*args: object, **kwargs: object) -> object:
        created.append(args)
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "socket", recording_socket)
    monkeypatch.setattr(
        "emailcheck.adapters.smtp.asyncio_transport.evaluate_destination",
        lambda address: _denied(address),
    )

    outcome = await AsyncioSMTPTransport().connect(approved)

    assert isinstance(outcome, ConnectionFailed)
    assert outcome.failure is TransportFailure.DESTINATION_DENIED_BY_POLICY
    assert created == [], "a socket was created for a destination the policy refuses"


def _denied(address: str) -> object:
    from emailcheck.security.destination import DestinationDecision, DestinationDenyReason

    return DestinationDecision(
        allowed=False,
        address=address,
        version=4,
        deny_reason=DestinationDenyReason.LOOPBACK,
    )


@pytest.mark.asyncio
async def test_the_recheck_uses_the_shared_policy_not_a_private_list() -> None:
    """The adapter must reuse Phase 2's function, not keep its own allowlist."""
    import ast
    import inspect

    from emailcheck.adapters.smtp import asyncio_transport

    source = inspect.getsource(asyncio_transport)
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert "evaluate_destination" in imported
    for forbidden in ("ALLOWLIST", "allowlist", "TRUSTED", "trusted_addresses"):
        assert forbidden not in source


# --- what the adapter must not offer ---------------------------------------


def test_the_connection_has_no_public_write_method() -> None:
    """Gate 4B publishes no way to put a byte on the wire."""
    from emailcheck.adapters.smtp.asyncio_transport import AsyncioSMTPConnection

    public = {name for name in dir(AsyncioSMTPConnection) if not name.startswith("_")}
    for forbidden in ("write", "write_line", "sendall", "writeline", "send_line"):
        assert forbidden not in public


def test_the_port_protocol_declares_no_write_method() -> None:
    from emailcheck.ports.smtp import SMTPConnection

    public = {name for name in dir(SMTPConnection) if not name.startswith("_")}
    assert public <= {"peer", "read_line", "close"}


def test_the_adapter_imports_no_tls() -> None:
    """STARTTLS is gate 4C. No `ssl` reaches this module."""
    import ast
    import inspect

    from emailcheck.adapters.smtp import asyncio_transport

    tree = ast.parse(inspect.getsource(asyncio_transport))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "ssl"
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] != "ssl"


def test_the_transport_exposes_connect_and_nothing_else() -> None:
    """A `connect_raw(address, port)` would bypass the whole chain.

    A mutation check added exactly that and no test noticed, so the method
    surface is pinned rather than left to review attention.
    """
    import inspect

    public = {
        name
        for name, member in inspect.getmembers(AsyncioSMTPTransport)
        if not name.startswith("_") and inspect.isfunction(member)
    }
    assert public == {"connect"}


def test_connect_accepts_an_approved_destination_and_nothing_else() -> None:
    """No host, no address, no port parameter exists to pass one through."""
    import inspect

    signature = inspect.signature(AsyncioSMTPTransport.connect)
    parameters = {
        name: parameter.annotation
        for name, parameter in signature.parameters.items()
        if name != "self"
    }
    assert parameters == {"destination": "ApprovedDestination"}


def test_the_transport_matches_the_port_it_claims_to_implement() -> None:
    """The concrete adapter may not offer more than the protocol declares."""
    import inspect

    from emailcheck.ports.smtp import SMTPTransport

    declared = {
        name
        for name, member in inspect.getmembers(SMTPTransport)
        if not name.startswith("_") and inspect.isfunction(member)
    }
    implemented = {
        name
        for name, member in inspect.getmembers(AsyncioSMTPTransport)
        if not name.startswith("_") and inspect.isfunction(member)
    }
    assert implemented == declared


# --- connect checks its argument at run time -------------------------------


class _LooksApproved:
    """Everything `connect` reads, and none of the checks that produce it.

    A review built one of these pointing at a public address and it reached a
    real socket connect. The policy still applied, so only a public address was
    reachable — but that is precisely what `approve_destination` exists to stop:
    connecting to an address the domain never published.
    """

    def __init__(self, address: str, port: int = 25, version: int = 4) -> None:
        self.address = address
        self.port = port
        self.version = version


def _no_socket_may_be_created(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    created: list[object] = []
    real_socket = socket.socket

    def recording_socket(*args: object, **kwargs: object) -> object:
        created.append(args)
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "socket", recording_socket)
    return created


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("destination_value", "label"),
    [
        (_LooksApproved(PUBLIC_V4), "a duck-typed public destination"),
        (_LooksApproved("8.8.8.8"), "a duck-typed destination that is not the candidate's"),
        (PUBLIC_V4, "a bare address string"),
        ((PUBLIC_V4, 25), "a bare tuple"),
        (HostName("mx.example.com"), "a host name"),
        (None, "nothing at all"),
        (25, "a port"),
        (PeerEndpoint(PUBLIC_V4, 25), "an unconfirmed peer"),
    ],
)
async def test_connect_refuses_anything_that_is_not_an_approved_destination(
    destination_value: object, label: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The type is checked at run time, on the same reasoning as `SMTPSession`.

    mypy rejects every one of these and mypy runs on `src` only, so an `Any`
    from a caller it never sees launders the value straight into a socket.
    """
    created = _no_socket_may_be_created(monkeypatch)

    with pytest.raises(SMTPContractError, match="ApprovedDestination"):
        await AsyncioSMTPTransport().connect(destination_value)  # type: ignore[arg-type]

    assert created == [], f"a socket was created for {label}"


@pytest.mark.asyncio
async def test_a_wrong_type_never_surfaces_as_an_attribute_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before the check these raised bare `AttributeError` from library code.

    `docs/requirements.md` section 11 keeps library exception text out of a
    result, and an `AttributeError` naming an internal attribute is exactly the
    kind of leak this project answers in its own vocabulary instead.
    """
    _no_socket_may_be_created(monkeypatch)
    for value in (PUBLIC_V4, None, (PUBLIC_V4, 25)):
        with pytest.raises(SMTPContractError):
            await AsyncioSMTPTransport().connect(value)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_the_type_check_runs_before_the_policy_re_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lookalike must not even be evaluated, let alone connected to."""
    evaluated: list[str] = []
    monkeypatch.setattr(
        "emailcheck.adapters.smtp.asyncio_transport.evaluate_destination",
        lambda address: evaluated.append(address),
    )
    with pytest.raises(SMTPContractError):
        await AsyncioSMTPTransport().connect(_LooksApproved(PUBLIC_V4))  # type: ignore[arg-type]
    assert evaluated == []


# --- the connection's own invariants ---------------------------------------


def _connection_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "_socket": socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        "_peer": PeerEndpoint(PUBLIC_V4, 25),
        "_limits": TransportLimits(),
        "_timeouts": TransportTimeouts(),
        "_buffer": bytearray(),
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize(
    ("overrides", "label"),
    [
        ({"_peer": None}, "no peer at all"),
        ({"_peer": PUBLIC_V4}, "a bare address as the peer"),
        ({"_peer": (PUBLIC_V4, 25)}, "a bare tuple as the peer"),
        ({"_limits": None}, "unvalidated limits"),
        ({"_timeouts": None}, "unvalidated timeouts"),
        ({"_total_read": -1}, "a negative byte count"),
        ({"_total_read": True}, "a boolean byte count"),
        ({"_total_read": DEFAULT_MAX_TOTAL_BYTES + 1}, "beyond its own total limit"),
    ],
)
def test_a_connection_cannot_be_built_in_a_contradictory_state(
    overrides: dict[str, object], label: str
) -> None:
    """It is an I/O handle rather than a domain value, and `_peer` still matters.

    `_peer` is what the application puts through `confirm_peer`, so a connection
    carrying something else would carry it into the one check that decides
    whether a session may open.
    """
    fields = _connection_fields(**overrides)
    try:
        with pytest.raises(SMTPContractError):
            AsyncioSMTPConnection(**fields)  # type: ignore[arg-type]
    finally:
        held = fields["_socket"]
        assert isinstance(held, socket.socket)
        held.close()


def test_a_connection_cannot_claim_to_be_closed_while_holding_an_open_socket() -> None:
    fields = _connection_fields(_closed=True)
    try:
        with pytest.raises(SMTPContractError, match="reported as closed"):
            AsyncioSMTPConnection(**fields)  # type: ignore[arg-type]
    finally:
        held = fields["_socket"]
        assert isinstance(held, socket.socket)
        held.close()


def test_the_ordinary_construction_is_still_accepted() -> None:
    fields = _connection_fields()
    connection = AsyncioSMTPConnection(**fields)  # type: ignore[arg-type]
    try:
        assert connection.peer == PeerEndpoint(PUBLIC_V4, 25)
        assert connection.is_closed is False
    finally:
        held = fields["_socket"]
        assert isinstance(held, socket.socket)
        held.close()


# --- the socket-wrapping primitive is internal -----------------------------


def test_wrapping_a_socket_is_not_a_public_entry_point() -> None:
    """`connect` is the only public way in, and the wrapper is named privately.

    It is not a policy bypass — it takes no destination, so it grants no
    reachability a caller did not already have by holding a connected socket,
    and it returns a connection with no write method rather than a session. The
    naming is so it cannot be *read* as the way in.
    """
    import inspect

    public = {
        name for name, _ in inspect.getmembers(AsyncioSMTPConnection) if not name.startswith("_")
    }
    assert public == {"peer", "is_closed", "read_line", "close"}
    assert hasattr(AsyncioSMTPConnection, "_over_socket")
    assert not hasattr(AsyncioSMTPConnection, "over_socket")


def test_no_production_code_outside_the_adapter_wraps_a_socket() -> None:
    """The one production caller is `connect`, in the adapter's own module."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    adapter = root / "adapters" / "smtp" / "asyncio_transport.py"
    callers: list[str] = []
    for module in sorted(root.rglob("*.py")):
        if module == adapter:
            continue
        if "_over_socket" in module.read_text(encoding="utf-8"):
            callers.append(str(module.relative_to(root)))
    assert callers == [], f"a socket is wrapped outside the transport: {callers}"

    tree = ast.parse(adapter.read_text(encoding="utf-8"))
    wrapping = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_over_socket"
    ]
    assert len(wrapping) == 1, "connect is the only production caller"
