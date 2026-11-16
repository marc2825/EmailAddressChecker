"""What behaviour cannot show about the aggregator.

Three properties need the syntax tree rather than a call: that the module
imports nothing that could reach a network, that each decisive status is
produced in exactly one place, and that no branch anywhere names a provider. A
behavioural test cannot enumerate the providers nobody thought of, cannot prove
the absence of an import, and cannot see that two `if`s both return
`LIKELY_DELIVERABLE` under conditions that have quietly drifted apart.

**Every scan reads the tree with docstrings excluded.** This module explains at
length why it contains no retry and no probe, so a scan over the raw text fails
on its own prose — which this repository has now done four times.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.inspection

SOURCES = {
    "aggregate": Path("src/emailcheck/application/aggregate.py"),
    "syntax_evidence": Path("src/emailcheck/application/syntax_evidence.py"),
    "verdict": Path("src/emailcheck/domain/verdict.py"),
}

AGGREGATOR = SOURCES["aggregate"]


def tree_of(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def code_without_docstrings(path: Path) -> str:
    """The module's source with every docstring replaced by a placeholder.

    Comments survive, deliberately: a comment naming a provider would be as much
    of a warning sign as a branch on one, and none of these modules needs to.
    """
    tree = tree_of(path)
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
            body[0].value.value = "<docstring>"
    return ast.unparse(tree)


def imported_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree_of(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


# --- purity -----------------------------------------------------------------


FORBIDDEN_IMPORTS = (
    "socket",
    "ssl",
    "asyncio",
    "smtplib",
    "dns",
    "requests",
    "httpx",
    "sqlalchemy",
    "redis",
    "random",
    "secrets",
    "os",
    "time",
    "subprocess",
)


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_the_aggregation_modules_import_nothing_that_can_reach_the_world(name: str) -> None:
    """Phase 5 is pure aggregation. There is nothing here to make it impure with."""
    for imported in imported_names(SOURCES[name]):
        root = imported.split(".")[0]
        assert root not in FORBIDDEN_IMPORTS, (name, imported)


FORBIDDEN_COLLABORATORS = (
    "SMTPTransport",
    "SMTPConnection",
    "SMTPProbeService",
    "SMTPVerificationService",
    "RateLimiter",
    "InProcessRateLimiter",
    "DNSResolver",
    "Cache",
    "Store",
    "Executor",
    "Clock",
    "MonotonicClock",
    "Sleeper",
)


def test_the_aggregator_names_no_collaborator_it_could_ask_for_more() -> None:
    """An aggregator that wanted more information would re-probe. This cannot.

    Not even a clock: `Evidence.observed_at` is input metadata, and a rule that
    read the current time would be a rule whose answer changed while nothing
    else did.
    """
    source = code_without_docstrings(AGGREGATOR)
    for collaborator in FORBIDDEN_COLLABORATORS:
        assert collaborator not in source, collaborator


def test_the_aggregator_defines_no_coroutine_and_awaits_nothing() -> None:
    """Nothing to await means nothing to wait for means no I/O."""
    tree = tree_of(AGGREGATOR)
    for node in ast.walk(tree):
        assert not isinstance(node, ast.AsyncFunctionDef)
        assert not isinstance(node, ast.Await)
        assert not isinstance(node, ast.AsyncFor)
        assert not isinstance(node, ast.AsyncWith)


def test_the_aggregator_reads_no_clock() -> None:
    """`observed_at` is metadata; there is no staleness policy to implement."""
    source = code_without_docstrings(AGGREGATOR)
    for forbidden in ("datetime.now", "utcnow", "time.time", "monotonic", "today"):
        assert forbidden not in source, forbidden


def test_the_aggregator_performs_no_arithmetic_on_confidence() -> None:
    """No calibration study exists, so there is no number to compute.

    `docs/requirements.md` section 17 permits a probability only after one.
    Anything that added, multiplied, or averaged would be inventing a
    measurement, and a Bayesian-looking expression over correlated layers would
    be inventing an independence assumption too.
    """
    tree = tree_of(AGGREGATOR)
    confidence_functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and "confidence" in node.name
    ]
    assert not confidence_functions, "confidence is a table lookup, not a computation"

    # Narrowed to the operators that could only be scoring. `|` is excluded
    # because it is set union and type-union syntax, and `%` because it is
    # nothing but a formatting operator here; a test that failed the day someone
    # wrote `ReasonCode | None` would be a test people learn to edit rather than
    # to read.
    scoring = (ast.Mult, ast.Div, ast.FloorDiv, ast.Pow, ast.Sub)
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, scoring), ast.dump(node)
        if isinstance(node, ast.AugAssign):
            assert not isinstance(node.op, scoring), ast.dump(node)


# --- the two gates are each in one place ------------------------------------


def status_producing_functions(name: str) -> set[str]:
    """Every function whose body mentions `Status.<name>`."""
    tree = tree_of(AGGREGATOR)
    found: set[str] = set()
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == name
                and isinstance(node.value, ast.Name)
                and node.value.id == "Status"
            ):
                found.add(function.name)
    return found


@pytest.mark.parametrize("status", ["LIKELY_DELIVERABLE", "INVALID"])
def test_no_function_returns_a_decisive_status_directly(status: str) -> None:
    """Sections 38 and 39 of the Phase 5 brief, as a structural property.

    Two `if`s that both produce `likely_deliverable` are two conditions that
    will drift, and the drift is invisible until one of them is wrong. Both
    decisive statuses are therefore named exactly once outside the tier tables:
    in the gate that owns them.
    """
    producers = status_producing_functions(status)
    assert producers == set(), (
        f"Status.{status} is named inside {producers}; it must appear only in "
        "the module-level tier table, which maps a decided tier to a status"
    )


def test_the_tier_table_is_the_only_thing_that_names_a_status() -> None:
    """The counterpart of the test above: the one place statuses are named.

    `_TIER_STATUS` maps a *decided tier* to a status, so a status cannot be
    produced without a tier having won the precedence first. That is what makes
    "no single field is a shortcut" structural rather than a convention.
    """
    tree = tree_of(AGGREGATOR)
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "_TIER_STATUS"
    ]
    assert len(assignments) == 1

    named = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "Status"
    }
    assert named == {"INVALID", "UNKNOWN", "TEMPORARY_UNKNOWN", "LIKELY_DELIVERABLE"}


def test_the_published_smtp_sets_are_not_used_as_status_shortcuts() -> None:
    """Section 7.6 stop condition A, as a structural check.

    Using `POSITIVE_RECIPIENT_REASONS` for semantic filtering is fine and is
    what it is published for. What is forbidden is membership *being* the
    answer, and since no function in this module names a status at all, no
    membership test can be one.
    """
    source = code_without_docstrings(AGGREGATOR)
    assert "POSITIVE_RECIPIENT_REASONS" not in source
    assert "EvidenceStrength" not in source


def test_strength_is_never_read_by_any_rule() -> None:
    """Stop condition B, as strongly as it can be stated.

    The aggregator does not import `EvidenceStrength` and never reads
    `.strength`. `if evidence.strength is STRONG: return INVALID` is not merely
    absent — the field is unreachable from every rule in the module.
    """
    tree = tree_of(AGGREGATOR)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr != "strength", ast.dump(node)


# --- no provider branch -----------------------------------------------------


PROVIDER_NAMES = (
    "google",
    "gmail",
    "microsoft",
    "outlook",
    "hotmail",
    "yahoo",
    "proton",
    "zoho",
    "fastmail",
    "icloud",
    "aol",
    "yandex",
    "mail.ru",
    "qq.com",
    "ProviderFamily",
)


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_no_aggregation_module_names_a_provider(name: str) -> None:
    """A behavioural test cannot enumerate the providers it did not think of.

    `docs/requirements.md` section 8: provider family is metadata, not proof,
    and a verdict must never come from provider identity. The aggregator does
    not even receive a provider family — it receives reason codes — and this
    keeps it that way.
    """
    source = code_without_docstrings(SOURCES[name]).lower()
    for provider in PROVIDER_NAMES:
        assert provider.lower() not in source, (name, provider)


# --- no retry, no probing ---------------------------------------------------


def test_the_aggregator_contains_no_retry_or_backoff() -> None:
    """`docs/requirements.md` section 14 schedules retries in minutes, elsewhere.

    An aggregator that could ask for another observation would be an aggregator
    that turned one request into several SMTP sessions.
    """
    source = code_without_docstrings(AGGREGATOR).lower()
    for forbidden in ("retry", "backoff", "jitter", "reprobe", "re_probe", "sleep"):
        assert forbidden not in source, forbidden


# --- the confidence lookup must fail loudly, not default --------------------


def test_the_confidence_lookup_is_a_subscript_and_never_a_defaulting_get() -> None:
    """F3. Coverage alone is insufficient; the mechanism has to be pinned.

    `_CONFIDENCE_BY_REASON[primary]` raises `KeyError` on a reason nobody gave a
    row, which is loud. `_CONFIDENCE_BY_REASON.get(primary, ConfidenceLevel.LOW)`
    silently calls it low — and because the table is complete today, *every*
    behavioural test passes with that change applied. Only the mechanism
    distinguishes them.

    This is the precedent gate 4D set for `_CONNECT_REASONS`, which had exactly
    this hole and closed it the same way.
    """
    tree = tree_of(AGGREGATOR)

    subscripts = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "_CONFIDENCE_BY_REASON"
    ]
    assert len(subscripts) == 1, "the confidence level is read by subscript, exactly once"

    defaulting = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"_CONFIDENCE_BY_REASON", "_REASON_RANK", "_TIER_STATUS"}
    ]
    assert defaulting == [], "a decision table is read by subscript so a gap raises"


def test_the_ranking_and_the_primary_reason_share_one_ranking_mechanism() -> None:
    """F1, from the other side: two orderings computed by two mechanisms drift.

    `Verdict` now refuses a list that does not lead with its primary reason, so
    the inconsistency cannot escape into a result. This adds the structural half:
    both orderings read `_REASON_RANK`, and neither reads the enum.
    """
    tree = tree_of(AGGREGATOR)

    for name in ("_ranked_reasons", "_sorted_reasons"):
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        read = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and node.id.startswith("_REASON")
        }
        assert "_REASON_RANK" in read, name

    source = code_without_docstrings(AGGREGATOR)
    assert "list(ReasonCode)" not in source
    assert "ReasonCode).index" not in source
