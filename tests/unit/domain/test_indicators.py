"""The five sequence indicators. Conservative, explicit, and reporting-only.

`prompts/07-hardening.md` asks for conservative indicators and forbids opaque
ML. Every rule here is one sentence and every threshold is a small integer, so a
false positive costs an operator a review rather than costing a caller a refusal.
"""

from __future__ import annotations

import pytest

from emailcheck.domain.indicators import (
    DICTIONARY_THRESHOLD,
    DOMAIN_CONCENTRATION_THRESHOLD,
    EXPLORATION_THRESHOLD,
    MAX_WINDOW,
    MULTIPLE_KEY_THRESHOLD,
    NUMERIC_SEQUENCE_THRESHOLD,
    AttemptShape,
    Indicator,
    evaluate,
    local_part_shape,
)

DOMAIN = "example.test"


def attempt(index: int, **overrides: object) -> AttemptShape:
    fields: dict[str, object] = {
        "domain": DOMAIN,
        "target_digest": f"digest-{index}",
        "stem_digest": "stem-digest-user",
    }
    fields.update(overrides)
    return AttemptShape(**fields)  # type: ignore[arg-type]


# --- the shape of a local part ----------------------------------------------


@pytest.mark.parametrize(
    ("local_part", "expected"),
    [
        ("user117", ("user", 117)),
        ("user", ("user", None)),
        ("117", ("", 117)),
        ("", ("", None)),
        ("user007", ("user", 7)),
        ("a" * 40 + "9", ("a" * 32, 9)),
        ("user" + "9" * 12, ("user", None)),
    ],
    ids=["numbered", "plain", "digits-only", "empty", "leading-zero", "long-stem", "long-run"],
)
def test_a_local_part_is_reduced_to_a_bounded_shape(
    local_part: str, expected: tuple[str, int | None]
) -> None:
    """The stem exists for comparison, not for reconstruction, so it is
    truncated — and an over-long digit run is not an ordinal anybody is counting
    through, so it is not converted into an unbounded integer from user input."""
    assert local_part_shape(local_part) == expected


def test_the_shape_function_is_total() -> None:
    """Called on the failure paths, where raising would be worse than answering."""
    assert local_part_shape(None) == ("", None)  # type: ignore[arg-type]


# --- numeric sequences -------------------------------------------------------


def test_several_numbered_attempts_at_one_domain_raise_a_sequence() -> None:
    window = [attempt(i, ordinal=i) for i in range(NUMERIC_SEQUENCE_THRESHOLD)]
    assert Indicator.NUMERIC_SEQUENCE in evaluate(window)


def test_a_sequence_does_not_have_to_be_consecutive() -> None:
    """Requiring consecutive numbers would make the rule avoidable by counting
    in twos, which is not a defence."""
    window = [attempt(i, ordinal=value) for i, value in enumerate((1, 7, 92, 400))]
    assert Indicator.NUMERIC_SEQUENCE in evaluate(window)


def test_the_same_number_repeated_is_not_a_sequence() -> None:
    window = [attempt(i, ordinal=5) for i in range(10)]
    assert Indicator.NUMERIC_SEQUENCE not in evaluate(window)


def test_numbers_under_different_stems_are_not_one_sequence() -> None:
    window = [attempt(i, ordinal=i, stem_digest=f"name{i}") for i in range(10)]
    assert Indicator.NUMERIC_SEQUENCE not in evaluate(window)


def test_numbers_at_different_domains_are_not_one_sequence() -> None:
    window = [attempt(i, ordinal=i, domain=f"d{i}.test") for i in range(10)]
    assert Indicator.NUMERIC_SEQUENCE not in evaluate(window)


def test_one_short_of_the_threshold_raises_nothing() -> None:
    window = [attempt(i, ordinal=i) for i in range(NUMERIC_SEQUENCE_THRESHOLD - 1)]
    assert evaluate(window) == frozenset()


# --- concentration -----------------------------------------------------------


def test_many_distinct_targets_at_one_domain_raise_concentration() -> None:
    window = [attempt(i) for i in range(DOMAIN_CONCENTRATION_THRESHOLD)]
    assert Indicator.DOMAIN_CONCENTRATION in evaluate(window)


def test_repeatedly_checking_one_address_is_not_concentration() -> None:
    """That is a caller with a broken retry loop, not an enumeration."""
    window = [attempt(0) for _ in range(50)]
    assert Indicator.DOMAIN_CONCENTRATION not in evaluate(window)


def test_targets_spread_over_domains_are_not_concentration() -> None:
    window = [attempt(i, domain=f"d{i}.test") for i in range(50)]
    assert Indicator.DOMAIN_CONCENTRATION not in evaluate(window)


# --- dictionary --------------------------------------------------------------


def test_repeated_common_name_attempts_raise_the_dictionary_indicator() -> None:
    window = [attempt(i, dictionary_hit=True) for i in range(DICTIONARY_THRESHOLD)]
    assert Indicator.DICTIONARY_PATTERN in evaluate(window)


def test_nothing_is_a_dictionary_hit_unless_an_operator_configured_one() -> None:
    """This project licenses no name dataset, so the list is empty by default
    and the indicator simply never fires."""
    window = [attempt(i) for i in range(50)]
    assert Indicator.DICTIONARY_PATTERN not in evaluate(window)


# --- keys from one source ----------------------------------------------------


def test_several_credentials_from_one_source_raise_the_indicator() -> None:
    assert Indicator.MULTIPLE_KEYS_ONE_SOURCE in evaluate(
        [], distinct_keys_from_source=MULTIPLE_KEY_THRESHOLD
    )


def test_one_credential_from_one_source_raises_nothing() -> None:
    assert evaluate([], distinct_keys_from_source=1) == frozenset()


# --- exploration after a positive --------------------------------------------


def test_fresh_targets_after_an_acceptance_raise_exploration() -> None:
    window = [attempt(0, accepted=True)] + [attempt(i + 1) for i in range(EXPLORATION_THRESHOLD)]
    assert Indicator.EXPLORATION_AFTER_POSITIVE in evaluate(window)


def test_an_acceptance_that_comes_last_raises_nothing() -> None:
    """Counted only *after* the acceptance, so a caller who happens to check
    several addresses and finds a live one last is not flagged."""
    window = [attempt(i + 1) for i in range(EXPLORATION_THRESHOLD)] + [attempt(0, accepted=True)]
    assert Indicator.EXPLORATION_AFTER_POSITIVE not in evaluate(window)


def test_exploration_at_a_different_domain_is_not_counted() -> None:
    window = [attempt(0, accepted=True)] + [
        attempt(i + 1, domain="other.test") for i in range(EXPLORATION_THRESHOLD)
    ]
    assert Indicator.EXPLORATION_AFTER_POSITIVE not in evaluate(window)


# --- the window --------------------------------------------------------------


def test_only_the_most_recent_attempts_are_considered() -> None:
    """A per-caller history is a per-caller allocation, so the window is bounded
    and the oldest entries fall out of it."""
    old = [attempt(i, ordinal=i) for i in range(NUMERIC_SEQUENCE_THRESHOLD)]
    recent = [attempt(1000 + i, ordinal=5, stem_digest=f"z{i}") for i in range(MAX_WINDOW)]
    assert Indicator.NUMERIC_SEQUENCE not in evaluate(old + recent)


def test_an_empty_window_raises_nothing() -> None:
    assert evaluate([]) == frozenset()


def test_evaluation_is_deterministic() -> None:
    window = [attempt(i, ordinal=i) for i in range(NUMERIC_SEQUENCE_THRESHOLD)]
    assert evaluate(window) == evaluate(window) == evaluate(list(window))


# --- what an indicator is not ------------------------------------------------


def test_no_indicator_is_a_reason_code_or_a_status() -> None:
    """`docs/architecture.md` keeps operational telemetry and mailbox semantics
    apart: a caller's behaviour says nothing about whether an address exists."""
    from emailcheck.domain.reasons import ReasonCode
    from emailcheck.domain.verdict import Status

    published = {member.value for member in ReasonCode} | {member.value for member in Status}
    assert {indicator.value for indicator in Indicator}.isdisjoint(published)


def test_the_window_holds_no_local_part_or_address() -> None:
    """`AttemptShape` has no field for one, so this is structural rather than a
    convention: a stem is a local part with its trailing digits removed and
    truncated, and it is what a *caller* chose to pass rather than an address."""
    fields = set(AttemptShape.__dataclass_fields__)
    assert "local_part" not in fields
    assert "address" not in fields
    assert "target" not in fields
    # And not the stem either, in plaintext: the first version stored it, and
    # for `very.secret.localpart+tag7` that is very nearly the whole local part.
    assert "stem" not in fields
    assert "stem_digest" in fields
