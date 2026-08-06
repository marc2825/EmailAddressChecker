"""Property checks over addresses that are built to be accepted.

The hostile fuzz corpus in `test_address_properties.py` almost never produces a
valid address, so it exercises the rejection paths. This module covers the other
half: a deterministic cross product of valid local parts and valid domains, so
the invariants that only hold for an accepted address get real coverage.

Expected values are written out here, not computed with the parser's own
helpers. Encoded domains are hard-coded literals rather than calls to `idna`, so
a change in encoding behavior fails a test instead of moving with it.
"""

from itertools import pairwise

import pytest

from emailcheck.domain.address import (
    ADDRESS_MAX_LENGTH,
    LOCAL_PART_MAX_LENGTH,
    AddressAccepted,
    AddressContractError,
    DomainName,
    NormalizedAddress,
    RawAddressInput,
    parse_address,
)

#: Atoms covering single characters, case, digits, and the RFC 5322 atext
#: symbols that a conservative validator is most likely to get wrong.
LOCAL_ATOMS = [
    "a",
    "Z",
    "7",
    "user",
    "User",
    "USER",
    "uSeR",
    "x-y",
    "x_y",
    "n1",
    "!#$%&",
    "'*/=?",
    "^`{|}~",
]

#: (submitted domain, expected ASCII form). The encoded forms are literals.
DOMAIN_CASES = [
    ("example.com", "example.com"),
    ("Example.COM", "example.com"),
    ("EXAMPLE.EXAMPLE", "example.example"),
    ("sub.domain.example.com", "sub.domain.example.com"),
    ("a.co", "a.co"),
    ("x1-y2.example", "x1-y2.example"),
    ("localhost", "localhost"),
    ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("MÜNCHEN.de", "xn--mnchen-3ya.de"),
    ("日本語.jp", "xn--wgv71a119e.jp"),
    ("straße.de", "xn--strae-oqa.de"),
    ("münchen.example.com", "xn--mnchen-3ya.example.com"),
    (f"{'a' * 63}.com", f"{'a' * 63}.com"),
]


def local_parts() -> list[str]:
    """Every local part shape the MVP accepts, built without the parser."""
    parts = list(LOCAL_ATOMS)
    parts += [f"{a}.{b}" for a, b in pairwise(LOCAL_ATOMS)]
    parts += [
        f"{a}.{b}.{c}"
        for a, b, c in zip(LOCAL_ATOMS, LOCAL_ATOMS[1:], LOCAL_ATOMS[2:], strict=False)
    ]
    parts += [f"{a}+tag" for a in LOCAL_ATOMS[:6]]
    parts += [f"{a}+Tag2026" for a in LOCAL_ATOMS[:4]]
    parts += [f"{a}.{b}+news" for a, b in pairwise(LOCAL_ATOMS[:5])]
    parts += ["a" * LOCAL_PART_MAX_LENGTH, "A" * (LOCAL_PART_MAX_LENGTH - 1) + "z"]
    return parts


VALID_CASES = [
    (local, submitted_domain, expected_ascii)
    for local in local_parts()
    for submitted_domain, expected_ascii in DOMAIN_CASES
]


def test_the_generated_corpus_is_large_and_varied() -> None:
    """Guard against a generator change that silently shrinks the corpus."""
    assert len(VALID_CASES) >= 500
    assert len({local for local, _, _ in VALID_CASES}) >= 40
    assert len({domain for _, domain, _ in VALID_CASES}) == len(DOMAIN_CASES)


def test_every_generated_address_is_accepted() -> None:
    for local, submitted_domain, _ in VALID_CASES:
        text = f"{local}@{submitted_domain}"
        assert isinstance(parse_address(RawAddressInput(text)), AddressAccepted), text


def accepted_addresses() -> list[tuple[str, str, str, NormalizedAddress]]:
    built: list[tuple[str, str, str, NormalizedAddress]] = []
    for local, submitted_domain, expected_ascii in VALID_CASES:
        text = f"{local}@{submitted_domain}"
        result = parse_address(RawAddressInput(text))
        assert isinstance(result, AddressAccepted), text
        built.append((local, submitted_domain, expected_ascii, result.address))
    return built


ACCEPTED = accepted_addresses()


def test_no_accepted_target_carries_cr_lf_or_nul() -> None:
    for local, submitted_domain, _, address in ACCEPTED:
        target = address.smtp_target
        for forbidden in ("\r", "\n", "\x00"):
            assert forbidden not in target, f"{local}@{submitted_domain}"


def test_local_part_case_dots_and_plus_tags_survive_verbatim() -> None:
    for local, submitted_domain, _, address in ACCEPTED:
        context = f"{local}@{submitted_domain}"
        assert address.local_part.value == local, context
        assert address.smtp_target.startswith(f"{local}@"), context
        assert address.local_part.value.count(".") == local.count("."), context
        assert address.local_part.value.count("+") == local.count("+"), context


def test_the_ascii_domain_matches_the_expected_normal_form() -> None:
    for local, submitted_domain, expected_ascii, address in ACCEPTED:
        context = f"{local}@{submitted_domain}"
        assert address.domain.ascii_form == expected_ascii, context
        assert address.domain.unicode_form == submitted_domain, context
        assert address.smtp_target == f"{local}@{expected_ascii}", context


def test_target_and_hmac_material_are_stable_across_reparsing() -> None:
    for local, submitted_domain, _, address in ACCEPTED:
        context = f"{local}@{submitted_domain}"
        again = parse_address(RawAddressInput(address.smtp_target))
        assert isinstance(again, AddressAccepted), context
        assert again.address.smtp_target == address.smtp_target, context
        assert again.address.hmac_material == address.hmac_material, context


def test_redaction_never_reveals_the_whole_local_part() -> None:
    for local, submitted_domain, expected_ascii, address in ACCEPTED:
        context = f"{local}@{submitted_domain}"
        redacted = address.redacted
        masked, separator, shown_domain = redacted.partition("@")
        assert separator == "@", context
        # The mask keeps at most the first character, and the domain is shown
        # only up to the bounded display length, so it is a prefix of the real
        # one rather than the whole value.
        assert masked in (f"{local[0]}***", "*"), context
        assert expected_ascii.startswith(shown_domain), context
        if len(local) > 1:
            assert local not in redacted, context


def test_no_accepted_address_exceeds_the_mailbox_limit() -> None:
    for local, submitted_domain, _, address in ACCEPTED:
        assert len(address.smtp_target) <= ADDRESS_MAX_LENGTH, f"{local}@{submitted_domain}"


def test_a_generated_address_cannot_be_rebuilt_into_an_inconsistent_value() -> None:
    """The accepted pieces still may not be recombined into a mismatched domain."""
    other_ascii = "victim.example"
    for local, submitted_domain, expected_ascii, address in ACCEPTED[:60]:
        context = f"{local}@{submitted_domain}"
        with pytest.raises(AddressContractError):
            DomainName(unicode_form=submitted_domain, ascii_form=other_ascii)
        rebuilt = NormalizedAddress(
            local_part=address.local_part,
            domain=DomainName(unicode_form=submitted_domain, ascii_form=expected_ascii),
        )
        assert rebuilt == address, context
