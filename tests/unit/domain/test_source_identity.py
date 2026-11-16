"""Where a request came from, and everywhere it may not come from.

`docs/threat-model.md` lists source IP among the layered budgets. ADR 0016
records why no header is trusted: without a trusted-proxy list, a spoofable
value in a budget key turns a per-source limit into a per-*claimed*-source
limit that an attacker resets by changing a string.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from emailcheck.domain.source import SourceFamily, SourceIdentity, SourceIdentityError

ROOT = pathlib.Path(__file__).resolve().parents[2].parent
SOURCE_MODULE = ROOT / "src/emailcheck/domain/source.py"


@pytest.mark.parametrize(
    ("address", "family"),
    [
        ("198.51.100.7", SourceFamily.IPV4),
        ("203.0.113.9", SourceFamily.IPV4),
        ("2001:db8::1", SourceFamily.IPV6),
        ("::1", SourceFamily.IPV6),
    ],
)
def test_a_canonical_address_is_accepted(address: str, family: SourceFamily) -> None:
    identity = SourceIdentity(address)
    assert identity.family is family
    assert identity.budget_value == address


@pytest.mark.parametrize(
    "address",
    [
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "::ffff:198.51.100.7",
        "2002:c633:6401::1",
        "198.51.100.007",
    ],
    ids=["upper", "expanded", "mapped", "6to4", "padded"],
)
def test_a_non_canonical_address_is_refused_rather_than_rewritten(address: str) -> None:
    """One client must be one budget: counting `2001:db8::1` and
    `2001:DB8:0:0:0:0:0:1` separately is a bypass costing nothing.

    Refused rather than normalized, so the caller's value and the budget key are
    the same string and nobody has to remember which form was counted. A mapped
    or 6to4 address is refused rather than unwrapped, which is the policy
    `security/destination.py` already applies to peers.
    """
    with pytest.raises(SourceIdentityError):
        SourceIdentity(address)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example.test",
        "localhost",
        "198.51.100.7:25",
        "[2001:db8::1]",
        "  198.51.100.7",
        None,
        7,
    ],
    ids=["empty", "name", "localhost", "port", "brackets", "space", "none", "number"],
)
def test_anything_that_is_not_a_numeric_address_is_refused(value: object) -> None:
    """No name resolution, ever: resolving here would make an inbound request
    cause an outbound lookup."""
    with pytest.raises(SourceIdentityError):
        SourceIdentity(value)  # type: ignore[arg-type]


def test_a_source_identity_is_usable_as_a_budget_key() -> None:
    from emailcheck.domain.abuse import BudgetKey, BudgetLayer

    for address in ("198.51.100.7", "2001:db8::1"):
        key = BudgetKey(layer=BudgetLayer.SOURCE_IP, value=SourceIdentity(address).budget_value)
        assert key.storage_key.startswith("source_ip:")


# --- provenance --------------------------------------------------------------


@pytest.mark.inspection
def test_the_module_reads_no_header_and_no_environment() -> None:
    """Read from the syntax tree with docstrings excluded, because this module
    explains at length which headers it does not trust and a text scan fails on
    its own prose — the mistake this repository has now made five times."""
    tree = ast.parse(SOURCE_MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            continue  # docstrings and string constants are not behaviour
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "getenv", "headers"}, node.attr
        if isinstance(node, ast.Name):
            assert node.id not in {"os", "requests", "socket"}, node.id


def code_without_docstrings(path: pathlib.Path) -> str:
    """One module's source with every docstring removed.

    The distinction this needs to draw: `domain/source.py` *explains* at length
    that it does not trust `X-Forwarded-For`, and a raw text scan would flag
    that explanation. Reading the tree with docstrings dropped is the difference
    between a module naming a header and a module using one — a mistake this
    repository has now made in five separate gates, including in the first
    version of this test.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


@pytest.mark.inspection
def test_no_forwarding_header_is_used_anywhere_in_production() -> None:
    """A header this project never *reads* is one no future edit trusts by
    accident. `docs/architecture.md` carries proxy policy as a stop condition on
    the ASGI binding instead."""
    offenders: list[str] = []
    for path in (ROOT / "src").rglob("*.py"):
        code = code_without_docstrings(path).lower()
        for header in ("x-forwarded-for", "x_forwarded_for", "x-real-ip", "forwarded="):
            if header in code:
                offenders.append(f"{path.name}: {header}")
    assert offenders == []


def test_no_request_body_field_could_supply_a_source() -> None:
    """`ApiRequest.body` accepts exactly one key, so a body carrying
    `source_ip` is refused as malformed rather than believed."""
    from emailcheck.apps.api import PERMITTED_REQUEST_KEYS

    assert frozenset({"email"}) == PERMITTED_REQUEST_KEYS


@pytest.mark.inspection
def test_the_constructor_is_not_reachable_from_apps_or_application() -> None:
    """The split `Principal` and `PeerEndpoint` already use: the value
    guarantees the shape, a transport boundary grants the provenance."""
    offenders: list[str] = []
    for package in ("apps", "application"):
        for path in (ROOT / "src/emailcheck" / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "SourceIdentity"
                ):
                    offenders.append(f"{package}/{path.name}:{node.lineno}")
    assert offenders == []
