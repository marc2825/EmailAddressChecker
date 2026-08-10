"""The authenticated identity, and the shapes it refuses.

`Principal` is the value that closes Phase 4 stop condition 2, and the type
alone cannot carry that: nothing stops an API handler writing
`Principal(account_id=body["account"])`. So the type fixes the *shape* and the
inspection test in `tests/test_phase6_inspection.py` fixes the *provenance* —
the same split `PeerEndpoint` and `confirm_peer` use, and the same reason.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.principal import MAX_ACCOUNT_ID_LENGTH, Principal


def test_an_ordinary_account_identifier_is_accepted() -> None:
    principal = Principal(account_id="acct-42_test.a")
    assert principal.rate_limit_account == "acct-42_test.a"


@pytest.mark.parametrize(
    "account_id",
    [
        "",
        "a" * (MAX_ACCOUNT_ID_LENGTH + 1),
        "user@example.test",
        "acct 42",
        "acct\n42",
        "acct\x00",
        "acct/42",
        "アカウント",
    ],
    ids=["empty", "too long", "an address", "space", "newline", "NUL", "slash", "non-ASCII"],
)
def test_an_unusable_account_identifier_is_refused(account_id: str) -> None:
    """`@` most of all: an account identifier may never be a mailbox.

    `rate_limit_key` already refuses one, so this is the second barrier — and
    it fires before the value ever reaches a budget, a log line, or a store.
    """
    with pytest.raises(ValueError):
        Principal(account_id=account_id)


def test_a_non_string_identifier_is_refused() -> None:
    with pytest.raises(ValueError, match="must be a string"):
        Principal(account_id=42)  # type: ignore[arg-type]


def test_the_rate_limit_account_is_a_named_property_rather_than_the_raw_field() -> None:
    """Named so an inspection test has something specific to require.

    A call site reading `principal.rate_limit_account` is visibly reading an
    authenticated identity; one reading `request.body["account"]` is visibly
    not, and the difference is what the mutation in the inspection suite tests.
    """
    principal = Principal(account_id="acct-1")
    assert principal.rate_limit_account == principal.account_id
