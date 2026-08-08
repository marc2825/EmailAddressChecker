"""Where the sender comes from, and every way it may not come from the target.

`docs/threat-model.md` names the threat precisely: the envelope sender derived
from the address being probed, or from request input, so a probe presents a
forged return path. The port answers it by shape — `current_identity()` takes no
argument — and this implementation answers it by provenance: operator
configuration, validated, and nothing else.
"""

from __future__ import annotations

import inspect

import pytest

from dialogue_fixtures import address
from emailcheck.adapters.smtp.sender_identity import (
    ConfiguredSenderIdentityProvider,
    SenderIdentityError,
    load_sender_identity,
)
from emailcheck.domain.smtp_identity import EhloIdentity, EnvelopeSender
from emailcheck.ports.smtp_sender_identity import SenderIdentity

GOOD = {
    "ehlo_hostname": "probe.sender.test.example",
    "envelope_sender": "verify@sender.test.example",
}


# --- the shape it produces -------------------------------------------------


def test_a_configured_identity_supplies_both_halves() -> None:
    identity = load_sender_identity(GOOD)
    assert isinstance(identity, SenderIdentity)
    assert isinstance(identity.ehlo, EhloIdentity)
    assert isinstance(identity.envelope_sender, EnvelopeSender)
    assert identity.ehlo.value == "probe.sender.test.example"
    assert identity.envelope_sender.path == "verify@sender.test.example"


def test_the_provider_takes_no_argument() -> None:
    """A provider that received the target could return a sender derived from it."""
    signature = inspect.signature(ConfiguredSenderIdentityProvider.current_identity)
    assert [name for name in signature.parameters if name != "self"] == []


def test_the_provider_returns_the_same_identity_every_time() -> None:
    """One stable identity per deployment, never rotated to change an answer."""
    provider = ConfiguredSenderIdentityProvider(identity=load_sender_identity(GOOD))
    assert provider.current_identity() == provider.current_identity()


# --- provenance ------------------------------------------------------------


def test_nothing_about_the_probe_target_can_reach_the_loader() -> None:
    """The signature is the argument: a mapping of configuration, and no address."""
    signature = inspect.signature(load_sender_identity)
    assert list(signature.parameters) == ["configuration"]
    annotation = signature.parameters["configuration"].annotation
    assert "Mapping" in str(annotation)
    assert "Address" not in str(annotation)


def test_the_loader_reads_no_environment_variable() -> None:
    """Configuration is handed in deliberately, not picked up from the ambient shell."""
    import ast
    from pathlib import Path

    module = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "emailcheck"
        / "adapters"
        / "smtp"
        / "sender_identity.py"
    )
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "os" not in imported
    assert "dotenv" not in imported

    # Checked structurally rather than by substring: the module docstring says
    # "no environment variable", and a text search would find its own prose.
    reads = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} | {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    for forbidden in ("environ", "getenv", "getenvb"):
        assert forbidden not in reads


def test_a_target_address_is_not_accepted_as_a_sender_by_accident() -> None:
    """It would load — it is a valid mailbox — and the alignment check refuses it.

    This is the shape of the threat: the recipient's own address as the return
    path. The EHLO name belongs to this deployment and the recipient's domain
    does not, so the two cannot agree.
    """
    target = address("probe.target@recipient.test.example")
    with pytest.raises(SenderIdentityError, match="unrelated"):
        load_sender_identity(
            {"ehlo_hostname": "probe.sender.test.example", "envelope_sender": target.smtp_target}
        )


# --- refusals --------------------------------------------------------------


@pytest.mark.parametrize(
    ("configuration", "label"),
    [
        ({}, "nothing configured at all"),
        ({"envelope_sender": "verify@sender.test.example"}, "no EHLO name"),
        ({"ehlo_hostname": "probe.sender.test.example"}, "no envelope sender"),
    ],
)
def test_an_incomplete_configuration_is_refused(configuration: dict[str, str], label: str) -> None:
    """There is no default identity. An unconfigured deployment must not probe."""
    with pytest.raises(SenderIdentityError):
        load_sender_identity(configuration)


def test_an_unknown_key_is_refused_rather_than_ignored() -> None:
    """On the Phase 3 precedent: a silently ignored typo is a silent default."""
    with pytest.raises(SenderIdentityError, match="unknown sender configuration keys"):
        load_sender_identity({**GOOD, "ehlo_host": "typo.sender.test.example"})


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("localhost", "not fully qualified"),
        ("probe", "a bare label"),
        ("", "empty"),
        ("probe .sender.test.example", "carrying a space"),
        ("probe.sender.test.example\r\nRSET", "carrying CRLF"),
        ("-bad.sender.test.example", "an invalid label"),
    ],
)
def test_an_unusable_ehlo_name_is_refused(value: str, label: str) -> None:
    """A name that cannot resolve back to the connecting host reads as anonymous."""
    with pytest.raises(SenderIdentityError):
        load_sender_identity({**GOOD, "ehlo_hostname": value})


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("", "empty, which would be the null sender"),
        ("   ", "whitespace, which would be the null sender"),
        ("<>", "the null reverse path written out"),
        ("not an address", "not a mailbox"),
        ("verify@sender.test.example\r\nRCPT TO:<x@y.example>", "carrying a second command"),
        ("verify@", "no domain"),
        ("@sender.test.example", "no local part"),
    ],
)
def test_an_unusable_envelope_sender_is_refused(value: str, label: str) -> None:
    with pytest.raises(SenderIdentityError):
        load_sender_identity({**GOOD, "envelope_sender": value})


def test_the_null_reverse_path_is_not_configurable() -> None:
    """The decision, stated once and enforced here rather than chosen at run time.

    `EnvelopeSender.null()` stays a legal value — RFC 5321 has uses for `<>` —
    but a configured probing identity may not be one: `docs/requirements.md`
    section 9 requires SPF, a PTR, and monitored `postmaster` and `abuse`
    channels, none of which exists for the null sender.
    """
    assert EnvelopeSender.null().is_null_sender is True
    for empty in ("", "   "):
        with pytest.raises(SenderIdentityError, match="managed return path"):
            load_sender_identity({**GOOD, "envelope_sender": empty})


@pytest.mark.parametrize("value", [25, ["a"], {"a": 1}, 1.5, True])
def test_a_non_text_value_is_refused(value: object) -> None:
    with pytest.raises(SenderIdentityError, match="must be text"):
        load_sender_identity({**GOOD, "ehlo_hostname": value})  # type: ignore[dict-item]


# --- alignment -------------------------------------------------------------


@pytest.mark.parametrize(
    ("ehlo_hostname", "envelope_sender", "label"),
    [
        ("sender.test.example", "verify@sender.test.example", "the same name"),
        ("mx1.sender.test.example", "verify@sender.test.example", "EHLO is a subdomain"),
        ("sender.test.example", "verify@mx1.sender.test.example", "the sender is a subdomain"),
    ],
)
def test_an_aligned_pair_is_accepted(ehlo_hostname: str, envelope_sender: str, label: str) -> None:
    identity = load_sender_identity(
        {"ehlo_hostname": ehlo_hostname, "envelope_sender": envelope_sender}
    )
    assert identity.ehlo.value == ehlo_hostname


@pytest.mark.parametrize(
    ("ehlo_hostname", "envelope_sender", "label"),
    [
        ("mx.attacker.test.example", "verify@sender.test.example", "unrelated names"),
        ("sender.test.example", "verify@othersender.test.example", "a lookalike suffix"),
        ("notsender.test.example", "verify@sender.test.example", "a suffix without a dot"),
        ("sender.test.example.evil", "verify@sender.test.example", "a suffix attack"),
    ],
)
def test_an_unaligned_pair_is_refused(ehlo_hostname: str, envelope_sender: str, label: str) -> None:
    """The configuration mistake that gets a probe treated as forgery."""
    with pytest.raises(SenderIdentityError, match="unrelated"):
        load_sender_identity({"ehlo_hostname": ehlo_hostname, "envelope_sender": envelope_sender})


def test_alignment_is_checked_on_label_boundaries() -> None:
    """`notsender.test.example` does not end at a label of `sender.test.example`."""
    with pytest.raises(SenderIdentityError):
        load_sender_identity(
            {
                "ehlo_hostname": "notsender.test.example",
                "envelope_sender": "verify@sender.test.example",
            }
        )
