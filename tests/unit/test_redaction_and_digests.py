"""Redaction, and the versioned HMAC `docs/privacy.md` section 5 specifies."""

from __future__ import annotations

import pytest

from emailcheck.security.identifiers import (
    CANONICAL_INPUT_VERSION,
    CorrelationKeyError,
    correlation_digest,
)
from emailcheck.security.redaction import UNREDACTABLE, redact_address, redact_domain

KEY = b"correlation-secret-of-thirty-two"


# --- redaction ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("alice@example.com", "a***@example.com"),
        ("a@example.com", "*@example.com"),
        ("alice.smith+tag@example.com", "a***@example.com"),
        ("VeryLongLocalPart@example.com", "V***@example.com"),
    ],
    ids=["ordinary", "single", "tagged", "long"],
)
def test_the_documented_examples_hold(value: str, expected: str) -> None:
    """`docs/privacy.md` section 4's own examples, so the document and the code
    cannot drift apart."""
    assert redact_address(value) == expected


def test_the_mask_hides_the_length_of_the_local_part() -> None:
    """A fixed three asterisks whatever the length: the length of a local part
    is itself a distinguishing feature."""
    assert redact_address("ab@example.com") == redact_address("abcdefghijklmnop@example.com")


def test_nothing_of_the_tag_or_the_dots_survives() -> None:
    assert "+" not in redact_address("alice+newsletter@example.com")
    assert redact_address("a.l.i.c.e@example.com") == "a***@example.com"


@pytest.mark.parametrize(
    "value",
    ["", "not-an-address", "@example.com", "alice@", "a@b@c.com", None, 7, "alice@ example.com"],
    ids=["empty", "no-at", "no-local", "no-domain", "two-at", "none", "number", "space"],
)
def test_text_that_is_not_an_address_is_never_echoed(value: object) -> None:
    """A redaction function that echoed unparseable input would be a way to
    write arbitrary user input into a log."""
    assert redact_address(value) == UNREDACTABLE


def test_redaction_never_raises() -> None:
    """Called on the failure paths, where a traceback would carry the value the
    call was meant to hide."""
    for value in (object(), b"bytes", ["list"], {"a": 1}):
        assert redact_address(value) == UNREDACTABLE


@pytest.mark.parametrize(
    "value",
    ["example.com", "sub.example.co.uk", "xn--bcher-kva.example"],
)
def test_an_ordinary_domain_survives(value: str) -> None:
    """`docs/requirements.md` section 16 permits analytics aggregated by domain,
    and a domain is not a mailbox."""
    assert redact_domain(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "a@b.com", "with space", "with\nnewline", "x" * 300, None],
    ids=["empty", "address", "space", "newline", "long", "none"],
)
def test_a_domain_that_is_unsafe_to_log_is_not(value: object) -> None:
    assert redact_domain(value) == UNREDACTABLE


# --- the versioned digest ----------------------------------------------------


def test_the_digest_covers_the_canonicalization_version() -> None:
    """`docs/privacy.md` section 5:
    `HMAC-SHA-256(key, canonical_input_version || normalized_target)`."""
    assert correlation_digest(KEY, "a", version="v1") != correlation_digest(KEY, "a", version="v2")


def test_the_version_is_prefixed_so_no_value_can_forge_another_version() -> None:
    """Appended, `("v1", "xa")` and `("v1x", "a")` would produce one digest."""
    assert correlation_digest(KEY, "xa", version="v1") != correlation_digest(
        KEY, "a", version="v1x"
    )


def test_the_default_version_is_the_published_one() -> None:
    assert correlation_digest(KEY, "a") == correlation_digest(
        KEY, "a", version=CANONICAL_INPUT_VERSION
    )


def test_the_digest_is_stable_and_reveals_nothing() -> None:
    digest = correlation_digest(KEY, "1:alice@example.test")
    assert digest == correlation_digest(KEY, "1:alice@example.test")
    assert len(digest) == 64
    for secret in ("alice", "example.test", "@"):
        assert secret not in digest


def test_a_different_key_gives_a_different_digest() -> None:
    """The property that makes a stolen database useless without the key."""
    assert correlation_digest(KEY, "a") != correlation_digest(
        b"another-correlation-secret-32abc", "a"
    )


@pytest.mark.parametrize("version", ["", None, 7, "v\x001"], ids=["empty", "none", "number", "nul"])
def test_an_unusable_version_is_refused(version: object) -> None:
    with pytest.raises(CorrelationKeyError):
        correlation_digest(KEY, "a", version=version)  # type: ignore[arg-type]


def test_a_short_key_is_refused() -> None:
    with pytest.raises(CorrelationKeyError):
        correlation_digest(b"too-short", "a")


def test_the_store_version_moved_with_the_addressing() -> None:
    """Adding the canonicalization version changed every digest once, so every
    row in a version-2 file addresses something nothing will find again. A store
    of unreachable rows looks like a cache that never hits, which is a worse
    failure than refusing to open. ADR 0016.

    Version 4 is Remediation C: the passive dataset fingerprint joined the key.
    A version-3 row carries no fingerprint, and the one value a migration could
    assume for it — "whatever this process has configured now" — is exactly the
    assumption the column exists to prevent, so the file is refused instead.

    Version 5 is the C11 fencing follow-up: the account fence and the authority
    binding are in this file now, because a fence held in another database is
    one a second transaction can overtake. A version-4 file records neither, and
    adopting it under whichever deletion authority happens to be configured is
    the configuration mistake the binding exists to catch — so it is refused
    rather than migrated.
    """
    from emailcheck.adapters.storage.sqlite_store import SCHEMA_VERSION

    assert SCHEMA_VERSION == 5
