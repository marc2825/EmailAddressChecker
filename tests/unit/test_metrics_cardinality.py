"""Metrics carry no identity, and cannot be made to.

`docs/threat-model.md`: metrics must not include local parts. This project
goes further — every label is a value one of its published enumerations already
declares, so a target, a job identifier, a credential, and a source address are
*unrepresentable* rather than merely absent. ADR 0016 records the choice and
its cost.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from emailcheck.adapters.observability.metrics import InMemoryMetrics, NullMetrics
from emailcheck.ports.metrics import (
    INDICATOR_SUBJECTS,
    PERMITTED_SUBJECTS,
    MetricLabels,
    MetricName,
    Outcome,
)

ROOT = pathlib.Path(__file__).resolve().parents[1].parent


# --- the closed label set ----------------------------------------------------


@pytest.mark.parametrize(
    "subject",
    [
        "alice@example.test",
        "alice",
        "example.test",
        "mx.example.test",
        "job-abcdefghijklmnopqrstuv",
        "acct-1",
        "198.51.100.7",
        "order-4711-attempt-1",
        "k" * 40,
    ],
    ids=[
        "address",
        "local-part",
        "domain",
        "exchanger",
        "job-id",
        "account",
        "source-ip",
        "idempotency-key",
        "api-key",
    ],
)
def test_a_label_that_is_not_published_vocabulary_is_refused(subject: str) -> None:
    with pytest.raises(ValueError):
        MetricLabels(subject=subject)


def test_the_permitted_subjects_are_a_fixed_set_known_at_import() -> None:
    """The cardinality bound is on the *values*, not on their count — so a label
    cannot become high-cardinality by being fed something new, only by somebody
    adding an enum member on purpose."""
    assert len(PERMITTED_SUBJECTS) < 200
    assert all(isinstance(subject, str) and subject for subject in PERMITTED_SUBJECTS)
    assert not any("@" in subject for subject in PERMITTED_SUBJECTS | INDICATOR_SUBJECTS)


def test_a_published_status_and_job_state_are_usable_as_labels() -> None:
    from emailcheck.domain.job import JobState
    from emailcheck.domain.verdict import Status

    for member in (*JobState, *Status):
        MetricLabels(subject=member.value)


def test_there_is_no_field_that_could_hold_free_text() -> None:
    """A closed dataclass rather than a mapping: a caller cannot attach a domain
    or an identifier because there is no field that would hold one."""
    assert set(MetricLabels.__dataclass_fields__) == {"subject", "outcome"}


def test_an_outcome_must_be_a_published_outcome() -> None:
    with pytest.raises(ValueError):
        MetricLabels(outcome="refused")  # type: ignore[arg-type]


# --- the number of series is bounded -----------------------------------------


def test_ten_thousand_distinct_targets_create_no_new_series() -> None:
    """The property that matters: cardinality must not track traffic."""
    metrics = InMemoryMetrics()
    for index in range(10_000):
        # The only thing a caller can vary is which *published* value is used,
        # so ten thousand different addresses are ten thousand increments of
        # the same two series.
        metrics.increment(
            MetricName.RATE_LIMIT_DECISION,
            labels=MetricLabels(subject="target", outcome=Outcome.REFUSED),
        )
        metrics.observe(MetricName.SMTP_STAGE_LATENCY, float(index % 7))
    assert len(metrics.rendered_keys()) == 2


def test_no_rendered_series_carries_an_address_or_an_identifier() -> None:
    metrics = InMemoryMetrics()
    metrics.increment(MetricName.VERDICT_STATUS, labels=MetricLabels(subject="unknown"))
    metrics.increment(MetricName.ADMIN_REFUSAL, labels=MetricLabels(subject="account_suspended"))
    rendered = " ".join(metrics.rendered_keys())
    for forbidden in ("@", "alice", "acct-", "job-", "198.51"):
        assert forbidden not in rendered


# --- neither sink raises -----------------------------------------------------


def test_a_metrics_sink_never_raises_whatever_it_is_given() -> None:
    """A monitoring failure that propagated would turn an observability problem
    into a verification failure, which is the inversion
    `docs/architecture.md` section 5 exists to prevent."""
    for sink in (InMemoryMetrics(), NullMetrics()):
        sink.increment("not a metric")  # type: ignore[arg-type]
        sink.observe(MetricName.SMTP_STAGE_LATENCY, float("nan"))
        sink.observe(MetricName.SMTP_STAGE_LATENCY, "twelve")  # type: ignore[arg-type]
        sink.increment(MetricName.CACHE_LOOKUP, labels=None)


def test_a_not_a_number_observation_does_not_poison_a_summary() -> None:
    metrics = InMemoryMetrics()
    metrics.observe(MetricName.SMTP_STAGE_LATENCY, 10.0)
    metrics.observe(MetricName.SMTP_STAGE_LATENCY, float("nan"))
    metrics.observe(MetricName.SMTP_STAGE_LATENCY, 20.0)
    summary = metrics.observations[("smtp_stage_latency", None, None)]
    assert (summary.count, summary.total, summary.minimum, summary.maximum) == (2, 30.0, 10.0, 20.0)


def test_an_observation_keeps_a_summary_rather_than_every_sample() -> None:
    """Keeping every sample would make memory a function of traffic."""
    metrics = InMemoryMetrics()
    for index in range(1_000):
        metrics.observe(MetricName.SMTP_STAGE_LATENCY, float(index))
    summary = metrics.observations[("smtp_stage_latency", None, None)]
    assert summary.count == 1_000
    assert set(summary.__dataclass_fields__) == {"count", "total", "minimum", "maximum"}


# --- inspection --------------------------------------------------------------


@pytest.mark.inspection
def test_the_metrics_port_publishes_no_method_taking_free_text() -> None:
    """Behaviour cannot show the absence of an API, so this is read from the
    syntax tree — with docstrings excluded, because this module explains at
    length what it does not accept and a text scan fails on its own prose."""
    source = (ROOT / "src/emailcheck/ports/metrics.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for argument in node.args.args + node.args.kwonlyargs:
            annotation = argument.annotation
            if annotation is None:
                continue
            rendered = ast.unparse(annotation)
            assert rendered != "str", (node.name, argument.arg)
            assert "Mapping" not in rendered, (node.name, argument.arg)
            assert "dict" not in rendered, (node.name, argument.arg)
