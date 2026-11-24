"""Verification is not a policy, and these tests are what say so.

A context that skips verification turns STARTTLS into decoration: an active
attacker on the path completes the handshake with any certificate and reads the
`RCPT TO` the upgrade existed to protect. So the property being pinned is not
"the default is safe" but "there is no way to make it unsafe".
"""

from __future__ import annotations

import ast
import inspect
import ssl
from pathlib import Path

import pytest

from emailcheck.adapters.smtp.tls import (
    MINIMUM_TLS_VERSION,
    SYSTEM_TRUST,
    TLSTrust,
    build_client_context,
)

CA_FILE = str(Path(__file__).resolve().parents[2] / "fixtures" / "tls" / "ca.crt")


# --- what the context always is --------------------------------------------


@pytest.mark.parametrize("trust", [SYSTEM_TRUST, TLSTrust(), TLSTrust(ca_file=CA_FILE)])
def test_verification_is_on_whatever_the_trust_is(trust: TLSTrust) -> None:
    context = build_client_context(trust)
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.verify_mode is not ssl.CERT_NONE
    assert context.verify_mode is not ssl.CERT_OPTIONAL


@pytest.mark.parametrize("trust", [SYSTEM_TRUST, TLSTrust(ca_file=CA_FILE)])
def test_deprecated_protocol_versions_are_refused(trust: TLSTrust) -> None:
    """RFC 8996 deprecates TLS 1.0 and 1.1, and no mail server needs them."""
    context = build_client_context(trust)
    assert context.minimum_version is MINIMUM_TLS_VERSION
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_the_default_is_the_system_trust_store() -> None:
    assert SYSTEM_TRUST.ca_file is None
    assert SYSTEM_TRUST.uses_system_trust_only is True
    assert (
        build_client_context().get_ca_certs() == build_client_context(SYSTEM_TRUST).get_ca_certs()
    )


def test_an_extra_anchor_is_added_rather_than_replacing_the_defaults() -> None:
    """The seam can only widen trust by one CA. It cannot narrow or remove it."""
    system = build_client_context(SYSTEM_TRUST)
    widened = build_client_context(TLSTrust(ca_file=CA_FILE))
    assert len(widened.get_ca_certs()) >= len(system.get_ca_certs())
    subjects = [entry.get("subject") for entry in widened.get_ca_certs()]
    assert any("emailcheck test CA" in str(subject) for subject in subjects)


# --- what there is no way to do --------------------------------------------


def test_the_builder_takes_only_a_trust_anchor() -> None:
    """No context parameter, no verify mode, no hostname override."""
    signature = inspect.signature(build_client_context)
    assert list(signature.parameters) == ["trust"]
    assert signature.parameters["trust"].annotation == "TLSTrust"


def test_the_trust_value_carries_nothing_but_a_file() -> None:
    import dataclasses

    fields = {field.name for field in dataclasses.fields(TLSTrust)}
    assert fields == {"ca_file"}
    for forbidden in ("verify_mode", "check_hostname", "insecure", "verify", "context"):
        assert forbidden not in fields


@pytest.mark.inspection
def test_nothing_in_the_project_disables_verification() -> None:
    """Asserted over the whole tree, so a future module cannot add it quietly."""
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    offences: list[str] = []
    for module in sorted(root.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"CERT_NONE", "CERT_OPTIONAL"}:
                offences.append(f"{module.name}:{node.lineno} {node.attr}")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "check_hostname"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is False
                    ):
                        offences.append(f"{module.name}:{node.lineno} check_hostname = False")
    assert offences == [], f"certificate verification is disabled somewhere: {offences}"


@pytest.mark.inspection
def test_no_unverified_context_helper_is_used() -> None:
    """`ssl._create_unverified_context` is the one-line way to undo all of this."""
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    for module in sorted(root.rglob("*.py")):
        source = module.read_text(encoding="utf-8")
        assert "_create_unverified_context" not in source, module.name
        assert "_create_default_https_context" not in source, module.name


@pytest.mark.inspection
def test_a_trust_anchor_comes_from_operator_configuration_only() -> None:
    """Trust may be widened, and only by whoever runs the deployment.

    `TLSTrust` cannot disable verification — the tests above pin that — but it
    can add a certificate authority, and a Phase 6 request field that reached it
    would let a caller choose who signs the certificate this project trusts.
    There is no such field today, and this is what has to fail before one is
    added: no `TLSTrust` is constructed in `src/` outside the module that
    defines the system-trust default, and nothing in the tree reads the
    environment.

    `docs/adr/0009-smtp-dialogue-and-tls.md` records this as a stop condition for Phase 6.
    """
    root = Path(__file__).resolve().parents[3] / "src" / "emailcheck"
    definition = root / "adapters" / "smtp" / "tls.py"
    presentation = root / "apps" / "messages.py"

    constructions: list[str] = []
    environment: list[str] = []
    for module in sorted(root.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        if module == presentation:
            # The one exception: the CLI's language and colour. Its function
            # body is checked separately below and skipped here.
            tree.body = [
                node
                for node in tree.body
                if not (
                    isinstance(node, ast.FunctionDef) and node.name == "presentation_environment"
                )
            ]
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "TLSTrust"
                and module != definition
            ):
                constructions.append(f"{module.relative_to(root)}:{node.lineno}")
            if isinstance(node, ast.Attribute) and node.attr in {
                "environ",
                "getenv",
                "environb",
            }:
                environment.append(f"{module.relative_to(root)}:{node.lineno} {node.attr}")
    assert constructions == [], f"a trust anchor is built outside its module: {constructions}"
    assert environment == [], f"production reads the environment: {environment}"

    # The exception reads five named presentation variables and nothing else:
    # the list, the function's exact body, and who calls it are all pinned.
    from emailcheck.apps.messages import PRESENTATION_VARIABLES

    assert PRESENTATION_VARIABLES == ("LC_ALL", "LC_MESSAGES", "LANG", "NO_COLOR", "TERM")
    function = next(
        node
        for node in ast.parse(presentation.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "presentation_environment"
    )
    expected = ast.parse(
        'import os\nreturn {name: os.environ.get(name, "") for name in PRESENTATION_VARIABLES}\n'
    ).body
    body = function.body[1:]  # after the docstring
    assert [ast.dump(node) for node in body] == [ast.dump(node) for node in expected]
    callers = sorted(
        str(module.relative_to(root))
        for module in root.rglob("*.py")
        if "presentation_environment" in module.read_text(encoding="utf-8")
    )
    assert callers == ["apps/cli.py", "apps/commands.py", "apps/messages.py"]

    # The one seam is a keyword-only file path with a safe default. Nothing in
    # the signature could carry a PEM body, a context, or a verify mode.
    parameters = inspect.signature(TLSTrust).parameters
    assert list(parameters) == ["ca_file"]
    assert parameters["ca_file"].default is None


@pytest.mark.inspection
def test_the_transport_builds_its_context_through_this_function() -> None:
    """One builder, one call site: the adapter cannot be handed a context."""
    module = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "emailcheck"
        / "adapters"
        / "smtp"
        / "asyncio_transport.py"
    )
    tree = ast.parse(module.read_text(encoding="utf-8"))
    builders = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "build_client_context"
    ]
    assert len(builders) == 1

    contexts = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"create_default_context", "SSLContext", "wrap_socket"}
    ]
    assert contexts == [], "the transport builds or wraps a context of its own"
