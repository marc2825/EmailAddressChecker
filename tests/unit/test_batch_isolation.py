"""What the batch subsystem must be unable to do.

The risk in Phase 10 is not a wrong answer for one address — it is a *shortcut*
for ten thousand. A batch that reached past the job service, built its own
limiter, resolved DNS to learn an exchanger, kept a second result cache, or
enabled Phase 9's accept-all experiment on the way past would be short,
plausible code that no scenario test catches until the day it is wrong.

Every scan reads the **syntax tree with docstrings excluded**: these modules
explain at length what they do not do, and a raw text scan fails on their own
prose — a mistake this repository has now made in seven separate gates.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from typing import Final

import pytest

from emailcheck.application import batch as batch_application
from emailcheck.domain.batch import BatchRowState, BatchSettings
from emailcheck.domain.job import JobState
from emailcheck.domain.verdict import Status

ROOT: Final = pathlib.Path(__file__).resolve().parents[2]

PHASE_10_MODULES: Final = {
    "domain": "src/emailcheck/domain/batch.py",
    "csv": "src/emailcheck/application/batch_csv.py",
    "scheduler": "src/emailcheck/application/batch.py",
    "port": "src/emailcheck/ports/batch_store.py",
    "store": "src/emailcheck/adapters/storage/sqlite_batch_store.py",
}

#: The modules that hold policy. The SQLite adapter is excluded from the scans
#: that forbid a concrete dependency, because being one is its whole job.
PHASE_10_POLICY: Final = {name: path for name, path in PHASE_10_MODULES.items() if name != "store"}


def tree_of(relative: str) -> ast.Module:
    return ast.parse((ROOT / relative).read_text(encoding="utf-8"))


def code_without_docstrings(relative: str) -> str:
    tree = tree_of(relative)
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


def imported_names(relative: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree_of(relative)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


# --- batch owns no verification logic ---------------------------------------


def test_the_scheduler_reaches_no_lower_than_the_job_service() -> None:
    """Every control this project has is inherited through `JobService`.

    Reaching past it — to the verification service, the probe, a transport, or
    a resolver — would mean the destination policy, the limiter, the sender
    identity, TLS, and the one-`RCPT TO` bound were all things batch had to
    remember rather than inherit.
    """
    code = code_without_docstrings(PHASE_10_MODULES["scheduler"])

    for shortcut in (
        "AddressVerificationService",
        "SMTPVerificationService",
        "SMTPProbeService",
        "SMTPTransport",
        "AsyncioSMTPConnection",
        "ApprovedDestination",
        "DNSResolver",
        "MailRouteService",
        "RateLimiter",
        "AbuseGuard",
        "TLSPolicy",
        "EnvelopeSender",
    ):
        assert shortcut not in code, shortcut


@pytest.mark.parametrize("name", sorted(PHASE_10_MODULES))
def test_no_batch_module_imports_a_transport_or_resolver(name: str) -> None:
    imported = imported_names(PHASE_10_MODULES[name])

    for forbidden in (
        "socket",
        "ssl",
        "dns",
        "emailcheck.adapters.smtp.asyncio_transport",
        "emailcheck.adapters.dns.dnspython_resolver",
    ):
        assert forbidden not in imported, (name, forbidden)


def test_the_scheduler_learns_an_exchanger_and_never_resolves_one() -> None:
    """`prompts/10-batch.md` wants MX fairness; it does not want a second router.

    A batch calling a resolver to learn where a domain's mail goes would
    duplicate Phase 2's ordering, caching, and destination policy, and would
    open a gap between the host it scheduled against and the host the probe
    actually reaches. The key comes out of the ordinary pipeline instead —
    `SubmitOutcome.scheduling_key`, read and never derived.
    """
    code = code_without_docstrings(PHASE_10_MODULES["scheduler"])

    for derived in (
        "resolve(",
        "MXRecord",
        "MailRoute",
        "RouteCandidate",
        "connectable_candidates",
        "getaddrinfo",
    ):
        assert derived not in code, derived
    assert "scheduling_key" in code, "the scheduler learns nothing at all"


def test_batch_builds_no_limiter_quota_or_deployment_of_its_own() -> None:
    """One process-wide limiter, quota, and admin state. `composition.py`'s rule.

    A batch that constructed its own would start every counter at zero, which
    permits everything — the exact defect `composition.py` documents for a
    per-request limiter.
    """
    code = code_without_docstrings(PHASE_10_MODULES["scheduler"])

    for constructed in (
        "Deployment(",
        "build_verification_stack(",
        "TokenBucket(",
        "QuotaSettings(",
        "AdmissionControl(",
        "InProcessQuotaStore(",
    ):
        assert constructed not in code, constructed


def test_batch_keeps_no_result_cache_of_its_own() -> None:
    """`prompts/10-batch.md`: *one active result cache shared with single checks*.

    A batch-private `VerdictCache` would be a second answer to "is this address
    still deliverable" with its own lifetime, and `docs/requirements.md` section
    13's TTLs would be applied twice from two clocks. The artifact store is not
    a second cache: it is keyed by a batch identifier rather than by a target,
    is written after the work rather than consulted before it, and nothing reads
    it to decide a verdict.
    """
    for name in ("scheduler", "csv", "domain"):
        code = code_without_docstrings(PHASE_10_MODULES[name])
        for forbidden in ("VerdictCache", "StoredVerdict", "cache_ttl", "verdict_cache"):
            assert forbidden not in code, (name, forbidden)


# --- Phase 9 stays where it was ---------------------------------------------


@pytest.mark.parametrize("name", sorted(PHASE_10_MODULES))
def test_no_batch_module_touches_the_accept_all_experiment(name: str) -> None:
    """Phase 9 is deferred and unwired, and Phase 10 does not wire it.

    `prompts/10-batch.md` says nothing about accept-all, and a batch that
    opportunistically enabled it would spend a budget the operator never
    authorized — for every row.
    """
    code = code_without_docstrings(PHASE_10_MODULES[name])
    imported = imported_names(PHASE_10_MODULES[name])

    for forbidden in ("accept_all", "AcceptAll", "ACCEPT_ALL"):
        assert forbidden not in code, (name, forbidden)
    assert not any("accept_all" in module for module in imported), name


# --- nothing here decides a status ------------------------------------------


@pytest.mark.parametrize("name", sorted(PHASE_10_POLICY))
def test_no_batch_module_names_a_deliverability_status(name: str) -> None:
    """A row's answer is Phase 5's, read through the public allowlist."""
    code = code_without_docstrings(PHASE_10_POLICY[name])

    for status in Status:
        assert status.value not in code, (name, status.value)
    for forbidden in ("Status.", "aggregate_evidence", "EvidenceStrength", "Verdict("):
        assert forbidden not in code, (name, forbidden)


def test_row_states_are_not_job_states() -> None:
    """Two vocabularies that describe different things, kept apart.

    A row can be "not an address" and a job cannot; a job can be "running" and a
    row does not track that — it carries the `JobId` and the job's state is the
    job's. Overlapping names would invite one being read as the other.
    """
    rows = {state.value for state in BatchRowState}
    jobs = {state.value for state in JobState}
    statuses = {status.value for status in Status}

    # `cancelled` is shared on purpose and means the same thing in both: work
    # that will not happen because somebody asked it to stop. Every other name
    # is distinct, so no row state can be read as a job state — `queued` and
    # `claimed` are deliberately not `pending`, which `JobState` already has.
    assert rows & jobs == {"cancelled"}, rows & jobs

    # **No row state may reuse a deliverability status's word.** `invalid` was
    # the first draft of `rejected`, and it collided with `Status.INVALID` —
    # which claims a mailbox does not exist, while a rejected row only means the
    # text was not an address this project supports.
    assert rows & statuses == set(), rows & statuses
    assert rows == {
        "queued",
        "claimed",
        "submitted",
        "duplicate",
        "rejected",
        "refused",
        "cancelled",
    }


# --- the feature is an operator's ------------------------------------------


def test_batch_is_disabled_and_unapproved_by_default() -> None:
    settings = BatchSettings()

    assert settings.enabled is False
    assert settings.approval.accounts == frozenset()
    assert settings.permits("any-account") is False


def test_no_request_surface_names_the_batch_feature() -> None:
    """`prompts/10-batch.md`'s non-goals begin with public anonymous uploads.

    Nothing request-facing names batch at all, which is what stops a body key, a
    CLI flag, or an anonymous download route being added without somebody
    reading this test. The result is reachable through an application service
    that takes a `Principal`, and through nothing else.
    """
    for surface in (
        "src/emailcheck/apps/api.py",
        "src/emailcheck/apps/schema.py",
        "src/emailcheck/composition.py",
    ):
        code = code_without_docstrings(surface).lower()
        for name in ("batch", "bulk", "csv", "download"):
            assert name not in code, (surface, name)

    # ADR 0020 permits local passive orchestration, never the active job service.
    for surface in ("src/emailcheck/apps/cli.py", "src/emailcheck/apps/commands.py"):
        imported = imported_names(surface)
        assert "emailcheck.application.batch" not in imported
        assert "BatchService" not in code_without_docstrings(surface)


def test_no_batch_module_introduces_an_http_surface() -> None:
    """ASGI stays deferred. "Downloadable" is an application port, not a route.

    `docs/architecture.md` lists the stop conditions a binding must close first,
    and a CSV upload adds one that is load-bearing rather than theoretical:
    request body size must be enforced *while* the body is read, not after.
    """
    for relative in PHASE_10_MODULES.values():
        imported = imported_names(relative)
        for forbidden in ("fastapi", "starlette", "uvicorn", "http", "urllib", "aiohttp"):
            assert not any(
                module == forbidden or module.startswith(forbidden + ".") for module in imported
            ), (relative, forbidden)


def test_the_upload_body_limit_is_recorded_inside_the_existing_stop_condition() -> None:
    """Phase 10's contribution to the ASGI conditions is wording, not a count.

    `docs/architecture.md`'s **request body size** condition was already one of
    the seven Phase 7 approved. A CSV upload does not add a condition — it makes
    the existing one specific: `parse_batch_csv` bounds a value that is already
    in memory, so the bound that protects the process has to be applied while
    the body is read.

    An earlier Phase 10 revision made the canonical count eight instead, which
    rewrote a Phase 7 invariant to accommodate a later Phase. `tests/
    test_phase7_inspection.py` owns the count; this owns the wording, so neither
    can be satisfied by changing the other.
    """
    text = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    section = text.split("#### Stop conditions on the ASGI binding", 1)[1].split("###", 1)[0]
    flattened = " ".join(section.split()).lower()

    assert "request body limit must be enforced while the body is read" in flattened
    assert "not only after the complete upload has been buffered" in flattened
    # And it is *inside* the body-size bullet rather than a bullet of its own.
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert len(bullets) == 7, bullets
    body_size = section.split("- **request body size.**", 1)[1].split("\n- **", 1)[0]
    assert "while the body is read" in " ".join(body_size.split())


@pytest.mark.parametrize("method", ["submit", "resume", "report", "result", "cancel", "delete"])
def test_every_batch_operation_requires_a_principal(method: str) -> None:
    """No anonymous handle reaches any of them, including the download."""
    signature = inspect.signature(getattr(batch_application.BatchService, method))

    assert "principal" in signature.parameters, method
    assert signature.parameters["principal"].kind is inspect.Parameter.KEYWORD_ONLY


def test_submitting_takes_the_raw_input_and_a_principal() -> None:
    """Bytes, not a parsed input: the gate must come before the parser runs."""
    signature = inspect.signature(batch_application.BatchService.submit)

    assert set(signature.parameters) == {"self", "content", "principal"}


# --- privacy ----------------------------------------------------------------


def test_the_service_repr_hides_its_secret_and_its_cancellations() -> None:
    """A batch holds a list of addresses; nothing here may print one."""
    import dataclasses

    hidden = {
        field.name for field in dataclasses.fields(batch_application.BatchService) if not field.repr
    }

    assert {"correlation_key", "_cancelled"} <= hidden


def test_a_persisted_row_hides_its_plaintext_from_its_repr() -> None:
    """The store is the new privacy surface, and its `repr` is its first leak."""
    import dataclasses

    from emailcheck.ports.batch_store import BatchArtifact, StoredBatchRow

    row_hidden = {field.name for field in dataclasses.fields(StoredBatchRow) if not field.repr}
    artifact_hidden = {field.name for field in dataclasses.fields(BatchArtifact) if not field.repr}

    assert "submitted" in row_hidden
    # The artifact body is the whole report — every row of it.
    assert "content" in artifact_hidden


@pytest.mark.parametrize("name", sorted(PHASE_10_MODULES))
def test_no_batch_module_logs_or_counts_a_target(name: str) -> None:
    """No metric label, no operator event, and no logger in the batch path.

    `prompts/10-batch.md` needs none, and the surface it would create is a list
    of addresses. `ports/metrics.py`'s labels are a closed enumeration, so a
    domain or an address is unrepresentable — this keeps the question from
    arising at all.
    """
    code = code_without_docstrings(PHASE_10_MODULES[name])
    for forbidden in ("logging", "logger", "MetricName", "MetricLabels", "OperatorEvent"):
        assert forbidden not in code, (name, forbidden)


def test_the_store_builds_no_sql_at_a_call_site() -> None:
    """Every statement is a module constant, on the Phase 6 store's precedent.

    An f-string reaching a cursor is the shape an injection has; a literal
    cannot be one, and this reads the tree rather than trusting the convention.
    """
    tree = tree_of(PHASE_10_MODULES["store"])

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if not isinstance(target, ast.Attribute) or target.attr not in {
            "execute",
            "executemany",
            "executescript",
        }:
            continue
        first = node.args[0] if node.args else None
        assert isinstance(first, ast.Name), ast.unparse(node)
        assert first.id.isupper() or first.id.startswith("_"), first.id
