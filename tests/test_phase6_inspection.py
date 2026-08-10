"""What behaviour cannot show about the Phase 6 boundary.

Phase 6 is a *consumer*. Its central risk is not that it computes a wrong
answer — it computes none — but that somebody adds a shortcut: a serializer that
reads a reason code and picks a status, a handler that builds a `Principal` from
a request field, an entry point that reaches past the high-level service into
`SMTPProbeService`. Every one of those is short, plausible code, and none of
them fails a behavioural test until the day it is wrong.

So the twelve stop conditions — seven from `plans/phase-04-smtp.md`, five from
`plans/phase-05-aggregation.md` — are asserted here as properties of the source.

**Every scan reads the syntax tree with docstrings excluded.** These modules
explain at length why they contain no status rule, so a scan over the raw text
fails on its own prose. This repository has made that mistake four times.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "emailcheck"

#: Every module Phase 6 added. The boundary is only as good as its widest hole,
#: so the scans below run over all of them rather than over the API alone.
PHASE_6_MODULES = {
    "composition": SOURCE / "composition.py",
    "verification": SOURCE / "application" / "verification.py",
    "admission": SOURCE / "application" / "admission.py",
    "public_result": SOURCE / "application" / "public_result.py",
    "public_job": SOURCE / "application" / "public_job.py",
    "jobs": SOURCE / "application" / "jobs.py",
    "retry": SOURCE / "application" / "retry.py",
    "verdict_cache": SOURCE / "application" / "verdict_cache.py",
    "api": SOURCE / "apps" / "api.py",
    "cli": SOURCE / "apps" / "cli.py",
    "schema": SOURCE / "apps" / "schema.py",
    "principal": SOURCE / "domain" / "principal.py",
    "job": SOURCE / "domain" / "job.py",
    "cache_policy": SOURCE / "domain" / "cache_policy.py",
    "api_keys": SOURCE / "adapters" / "auth" / "api_keys.py",
    "logging_sink": SOURCE / "adapters" / "observability" / "logging_sink.py",
    "sqlite_store": SOURCE / "adapters" / "storage" / "sqlite_store.py",
    "memory_executor": SOURCE / "adapters" / "execution" / "memory_executor.py",
    "random_source": SOURCE / "adapters" / "system" / "random_source.py",
    "urllib_client": SOURCE / "adapters" / "http" / "urllib_client.py",
    "remote_url": SOURCE / "security" / "remote_url.py",
}

#: The layers a request may arrive through. The rules about provenance and about
#: reaching low-level components are strictest here.
#:
#: **`jobs` is one of them.** An independent review pointed out that a future
#: job worker was the one entry point this file did not cover, and that a worker
#: reaching `SMTPProbeService` directly would probe without the one-`RCPT TO`
#: bound, the attempt cap, or the candidate ordering — exactly what Phase 4 stop
#: condition 1 exists to prevent, arriving through the door nobody was watching.
ENTRY_POINTS = {name: PHASE_6_MODULES[name] for name in ("api", "cli", "jobs")}

#: `schema` documents that no numeric confidence exists, so it necessarily
#: contains the words the scan below refuses. It gets a stricter test instead:
#: its example bodies are built by the real projection and are asserted to hold
#: no number at all.
NUMERIC_SCANNED = {name: path for name, path in PHASE_6_MODULES.items() if name != "schema"}


def tree_of(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def code_without_docstrings(path: Path) -> str:
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


# --- Phase 5 stop condition 1: no re-derived status -------------------------


#: The vocabulary a re-derivation would need. Reading any of these to *pick* a
#: status is the duplication the two aggregation gates exist to prevent.
AGGREGATION_INTERNALS = (
    "HARD_INVALID_REASONS",
    "POSITIVE_DELIVERY_REASONS",
    "POSITIVE_RECIPIENT_REASONS",
    "NON_TARGET_SMTP_REASONS",
    "RECIPIENT_STAGE_REASONS",
    "TARGET_SPECIFIC_REASONS",
    "UNSUPPORTED_REASONS",
    "USABLE_ROUTE_REASONS",
    "NON_BLOCKING_REASONS",
    "REASON_PRIORITY",
    "EvidenceStrength",
    "supports_invalid",
    "supports_likely_deliverable",
)


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_reads_the_aggregation_vocabulary(name: str) -> None:
    """Phase 5 stop condition 1, as an absence.

    A serializer that wrote `if reason in POSITIVE_DELIVERY_REASONS: status =
    "likely_deliverable"` would be a second aggregation policy, and it would
    drift toward whatever an API consumer asked for. None of these modules can
    write it, because none of them has the sets.
    """
    source = code_without_docstrings(PHASE_6_MODULES[name])
    for symbol in AGGREGATION_INTERNALS:
        assert symbol not in source, (name, symbol)


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_names_a_status_member(name: str) -> None:
    """`Status.INVALID` written anywhere here would be a status being *chosen*.

    The public schema copies `verdict.status.value`; it never names a member.
    """
    tree = tree_of(PHASE_6_MODULES[name])
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "Status"
        ):
            raise AssertionError(f"{name} names Status.{node.attr}")


def test_the_public_schema_reads_the_verdict_and_branches_on_no_reason() -> None:
    """The projection is a copy, and its shape says so.

    Every field is read off the verdict. There is no comparison against a
    `ReasonCode` member anywhere in the module, so there is nothing for a status
    decision to hang off.
    """
    tree = tree_of(PHASE_6_MODULES["public_result"])
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "ReasonCode"
        ):
            raise AssertionError(f"the public schema branches on ReasonCode.{node.attr}")


# --- Phase 5 stop condition 2: no score, percentage, or rank ----------------


FORBIDDEN_NUMERIC = ("score", "percentage", "percent", "rank", "probability", "confidence_value")


@pytest.mark.parametrize("name", sorted(NUMERIC_SCANNED))
def test_no_phase_6_module_invents_a_numeric_confidence(name: str) -> None:
    """Phase 5 stop condition 2.

    `docs/requirements.md` section 17 permits a probability only after a
    calibration study, and Phase 5 leaves even the *range* of a calibrated score
    undefined — so there is nothing a response could carry meaningfully, and
    these modules carry nothing.
    """
    source = code_without_docstrings(NUMERIC_SCANNED[name]).lower()
    for word in FORBIDDEN_NUMERIC:
        assert word not in source, (name, word)


def test_the_published_schema_contains_no_number_in_any_example() -> None:
    """The `schema` module's version of the rule above.

    It is the one module that must *name* a score in order to say there is
    none, so the absence is asserted on the document it produces rather than on
    its source text.
    """
    from emailcheck.apps.schema import api_schema

    def numbers(value: object) -> list[object]:
        if isinstance(value, bool):
            return []
        if isinstance(value, float):
            return [value]
        if isinstance(value, dict):
            found: list[object] = []
            for key, item in value.items():
                # Status codes are integers and are part of the HTTP contract.
                if key in {"status_codes"}:
                    continue
                found.extend(numbers(item))
            return found
        if isinstance(value, list):
            return [found for item in value for found in numbers(item)]
        return []

    assert numbers(api_schema()) == []


def test_the_public_body_has_no_field_a_number_could_go_in() -> None:
    """Structural rather than behavioural: the serializer builds no float.

    `as_json_object` names every key it emits, so adding a numeric one is a
    visible edit to this method rather than a field appearing by inheritance.
    """
    tree = tree_of(PHASE_6_MODULES["public_result"])
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "as_json_object"
    )
    for node in ast.walk(method):
        assert not (isinstance(node, ast.Constant) and isinstance(node.value, float))


# --- Phase 5 stop condition 3: Evidence.details is not public ---------------


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_serializes_evidence_wholesale(name: str) -> None:
    """Phase 5 stop condition 3.

    `asdict(verdict)`, `dict(evidence.details)`, and `verdict.evidence` in a
    response body are each one line, and each publishes whatever a producer ever
    recorded. The public schema is an allowlist instead.
    """
    source = code_without_docstrings(PHASE_6_MODULES[name])
    for forbidden in ("asdict", ".details", "__dict__", "dataclasses.asdict"):
        assert forbidden not in source, (name, forbidden)


def test_the_public_schema_never_reads_the_retained_evidence() -> None:
    """`Verdict.evidence` is for audit. A response is built from the summary."""
    tree = tree_of(PHASE_6_MODULES["public_result"])
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "evidence":
            raise AssertionError("the public schema reads Verdict.evidence")


# --- Phase 5 stop condition 4: the ruleset is part of a lookup --------------


def test_the_store_matches_on_the_whole_cache_key() -> None:
    """Phase 5 stop condition 4 and `docs/requirements.md` section 13, together.

    A row written by rules that no longer exist is a result nothing produced; a
    row obtained through a different envelope sender is evidence about a
    different question; and an expired row is neither. All three are `WHERE`
    predicates, because filtering afterwards leaves a row reachable and
    filtering in the query does not.
    """
    source = code_without_docstrings(PHASE_6_MODULES["sqlite_store"])
    for predicate in (
        "account_digest = ?",
        "target_digest = ?",
        "sender_identity_digest = ?",
        "aggregation_ruleset = ?",
        "expires_at > ?",
    ):
        assert predicate in source, predicate

    tree = tree_of(PHASE_6_MODULES["sqlite_store"])
    find = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "find"
    )
    parameters = {argument.arg for argument in find.args.kwonlyargs}
    assert {
        "account_digest",
        "target_digest",
        "sender_identity_digest",
        "aggregation_ruleset",
        "now",
    } <= parameters


def test_every_sql_statement_is_parameterized() -> None:
    """No f-string and no concatenation reaches a cursor."""
    tree = tree_of(PHASE_6_MODULES["sqlite_store"])
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"execute", "executescript"}:
                continue
            statement = node.args[0] if node.args else None
            assert isinstance(statement, ast.Constant | ast.Name), ast.dump(node)


# --- Phase 5 stop condition 5: internal_error reaches an operator -----------


def test_the_service_reports_an_internal_error_to_the_operator_sink() -> None:
    """The call has to exist for the behavioural test to mean anything."""
    source = code_without_docstrings(PHASE_6_MODULES["verification"])
    assert "operator.record" in source
    assert "OperatorEventKind.INTERNAL_ERROR" in source


def test_no_internal_diagnostic_reaches_a_public_response() -> None:
    """The operator's copy and the caller's copy are different things.

    `internal` is absent from the public layer allowlist, so a caller is told
    `unknown` without being told which of our components failed.
    """
    source = code_without_docstrings(PHASE_6_MODULES["public_result"])
    assert "EvidenceLayer.INTERNAL" not in source


# --- Phase 4 stop condition 1: the high-level service is the only door ------


FORBIDDEN_LOW_LEVEL = (
    "SMTPProbeService",
    "SMTPConnector",
    "SMTPTransport",
    "AsyncioSMTPTransport",
    "SMTPSession",
    "SMTPConnection",
    "ApprovedDestination",
    "ConfirmedPeer",
    "smtp_probe",
    "smtp_connect",
    "smtp_dialogue",
    "asyncio_transport",
)


@pytest.mark.parametrize("name", sorted(ENTRY_POINTS))
def test_an_entry_point_cannot_reach_a_low_level_smtp_component(name: str) -> None:
    """Phase 4 stop condition 1.

    An API wired to `SMTPProbeService` is correct-looking code — it probes, it
    is rate limited, it closes its connection — and it has none of the
    one-`RCPT TO` bound, the attempt cap, or the candidate ordering, because all
    three live one layer up.
    """
    source = code_without_docstrings(ENTRY_POINTS[name])
    for symbol in FORBIDDEN_LOW_LEVEL:
        assert symbol not in source, (name, symbol)

    for imported in imported_names(ENTRY_POINTS[name]):
        assert "smtp" not in imported.lower(), (name, imported)


def test_only_the_composition_root_names_a_low_level_smtp_component() -> None:
    """It is the wiring, so it is the one place that may hold the parts.

    The check is that this is *one* place: the verification service names the
    high-level `SMTPVerificationService` and nothing below it.
    """
    verification = code_without_docstrings(PHASE_6_MODULES["verification"])
    for symbol in ("SMTPProbeService", "AsyncioSMTPTransport", "ApprovedDestination"):
        assert symbol not in verification, symbol
    assert "SMTPVerificationService" in verification

    composition = code_without_docstrings(PHASE_6_MODULES["composition"])
    assert "SMTPProbeService" in composition
    assert "AsyncioSMTPTransport" in composition


# --- Phase 4 stop condition 2: principal provenance ------------------------


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_only_an_authenticator_constructs_a_principal(name: str) -> None:
    """Phase 4 stop condition 2, as the provenance the type cannot carry.

    Nothing about a frozen dataclass stops a handler writing
    `Principal(account_id=body["account"])`. This does: the constructor appears
    only in the authenticator adapter and in the value's own module.
    """
    if name in {"principal", "api_keys"}:
        return
    tree = tree_of(PHASE_6_MODULES[name])
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "Principal", f"{name} constructs a Principal"


def test_the_rate_limit_account_comes_from_the_principal_and_nowhere_else() -> None:
    """The value the limiter partitions by, read from one named property.

    Not the target's domain, not its local part, not a request field. Reading
    `principal.rate_limit_account` is visibly an authenticated identity; the
    alternatives are visibly not.
    """
    tree = tree_of(PHASE_6_MODULES["verification"])
    reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "rate_limit_account"
    ]
    assert len(reads) == 1
    assert isinstance(reads[0].value, ast.Name)
    assert reads[0].value.id == "principal"

    source = code_without_docstrings(PHASE_6_MODULES["verification"])
    for forbidden in ("account = body", "account = request", '["account"]', ".get('account'"):
        assert forbidden not in source


# --- Phase 4 stop conditions 3, 4, 5, 6: the graph and its bounds ----------


def test_the_composition_root_builds_the_limiter_exactly_once() -> None:
    """Phase 4 stop condition 3.

    One construction site, and it is at the top of the builder rather than
    inside a per-request function.
    """
    tree = tree_of(PHASE_6_MODULES["composition"])
    built = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "InProcessRateLimiter"
    ]
    assert len(built) == 1


def test_the_composition_root_names_no_fake_or_test_double() -> None:
    """Phase 4 stop condition 4, from the other side.

    A production graph that could name a fake is one a mistaken import turns
    into an unpaced prober.
    """
    source = code_without_docstrings(PHASE_6_MODULES["composition"]).lower()
    for forbidden in ("fake", "stub", "mock", "dummy", "test_", "immediate", "noop"):
        assert forbidden not in source, forbidden


def test_the_service_holds_an_admission_gate_and_a_total_deadline() -> None:
    """Phase 4 stop conditions 5 and 6, as fields rather than as conventions."""
    fields = set(
        __import__(
            "emailcheck.application.verification", fromlist=["AddressVerificationService"]
        ).AddressVerificationService.__dataclass_fields__
    )
    assert "admission" in fields
    assert "limits" in fields

    source = code_without_docstrings(PHASE_6_MODULES["verification"])
    assert "admission.admit" in source
    assert "asyncio.timeout" in source


def test_a_refusal_is_not_a_remote_failure_type() -> None:
    """Phase 6's refusals join `RateLimitTimeout` in being uncatchable by accident.

    A handler written for a remote condition must not catch this project's own
    capacity, pacing, or deadline.
    """
    from emailcheck.application.admission import AdmissionRefused
    from emailcheck.application.verification import VerificationRefused

    for kind in (AdmissionRefused, VerificationRefused):
        assert not issubclass(kind, TimeoutError)
        assert not issubclass(kind, OSError)


# --- Phase 4 stop condition 7, and sender provenance -----------------------


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_constructs_a_trust_anchor_or_a_sender(name: str) -> None:
    """Phase 4 stop condition 7, and the sender-identity rule beside it.

    Request, user, and API input may never supply a CA file, a PEM body, a
    trust anchor, a verification override, an envelope sender, or an EHLO name.
    The composition root loads the sender from operator configuration; nothing
    else names either.
    """
    source = code_without_docstrings(PHASE_6_MODULES[name])
    for symbol in ("TLSTrust", "SSLContext", "ssl.", "CERT_NONE", "check_hostname"):
        assert symbol not in source, (name, symbol)
    if name != "composition":
        for symbol in ("EnvelopeSender", "EhloIdentity", "load_sender_identity"):
            assert symbol not in source, (name, symbol)


# --- privacy and purity across the boundary --------------------------------


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_names_a_provider(name: str) -> None:
    """A behavioural test cannot enumerate the providers nobody thought of."""
    providers = ("google", "gmail", "microsoft", "outlook", "yahoo", "proton", "zoho", "fastmail")
    source = code_without_docstrings(PHASE_6_MODULES[name]).lower()
    for provider in providers:
        assert provider not in source, (name, provider)


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_reads_the_environment(name: str) -> None:
    """Configuration is passed in. An environment read is a trust anchor
    configured by whoever can set a variable in the worker's environment."""
    source = code_without_docstrings(PHASE_6_MODULES[name])
    for forbidden in ("os.environ", "getenv", "environb"):
        assert forbidden not in source, (name, forbidden)


def test_no_background_task_outlives_a_request() -> None:
    """A verification that continued after the caller left would be an unpaced
    probe nobody is waiting for, and a permit nobody returns."""
    for name in ("verification", "api", "cli"):
        source = code_without_docstrings(PHASE_6_MODULES[name])
        for forbidden in ("create_task", "ensure_future", "TaskGroup", "run_in_background"):
            assert forbidden not in source, (name, forbidden)


def test_neither_entry_point_retries() -> None:
    """`docs/requirements.md` section 14 schedules a retry in minutes, elsewhere."""
    for name in ("verification", "api", "cli"):
        source = code_without_docstrings(PHASE_6_MODULES[name]).lower()
        for forbidden in ("retry", "backoff", "jitter"):
            assert forbidden not in source, (name, forbidden)


def test_the_api_imports_no_web_framework() -> None:
    """`docs/architecture.md` section 1: application policy knows no framework.

    The binding from an ASGI route to `handle` is the remaining step and holds
    no policy, which is exactly why this layer can be complete without it.
    """
    for imported in imported_names(PHASE_6_MODULES["api"]):
        root = imported.split(".")[0]
        assert root not in {"fastapi", "starlette", "flask", "django", "pydantic", "uvicorn"}


# --- the shortcut a set-based check does not see ---------------------------
#
# The scans above refuse the aggregation *vocabulary*: the published reason
# sets, `EvidenceStrength`, every `Status` member. A mutation run found that
# insufficient, and the gap is worth stating plainly because it is the exact
# shortcut Phase 5 stop condition 1 exists to prevent.
#
# A serializer needs none of that vocabulary to re-derive a status. It needs one
# string:
#
#     if verdict.primary_reason.value == "rcpt_accepted":
#         status = "likely_deliverable"
#
# No import, no `Status` member, no published set — and a second aggregation
# policy, drifting toward whatever an API consumer asked for. So the *values*
# are refused too.


#: The four published status values, as they appear on the wire.
STATUS_VALUES = ("likely_deliverable", "invalid", "temporary_unknown", "unknown")


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_writes_a_status_value_as_a_literal(name: str) -> None:
    """A status is copied from the verdict, never spelled out.

    Every module here reads `verdict.status.value`; none needs to know what a
    status *is*. Writing one as a literal is either a re-derivation or the first
    half of one.
    """
    tree = tree_of(PHASE_6_MODULES[name])
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        assert node.value not in STATUS_VALUES, f"{name} writes the status {node.value!r}"


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_no_phase_6_module_compares_against_a_reason_code_value(name: str) -> None:
    """The other half of the same shortcut.

    A comparison against `"rcpt_accepted"` or `"null_mx"` is a reason being read
    to decide something. Phase 6 reads a reason only to *copy* it into a
    response or to ask the operator sink about `internal_error` — which uses the
    enum member, not its text.
    """
    from emailcheck.domain.reasons import ReasonCode

    published = {member.value for member in ReasonCode}
    tree = tree_of(PHASE_6_MODULES[name])
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        assert node.value not in published, f"{name} writes the reason {node.value!r}"


def test_the_public_status_and_confidence_are_copied_without_a_conditional() -> None:
    """Structural: the projection is an assignment, not a decision.

    An `IfExp` or a `Compare` in the `status=` argument is a status being chosen
    at serialization time, however it is spelled.
    """
    tree = tree_of(PHASE_6_MODULES["public_result"])
    builder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "public_result"
    )
    call = next(
        node
        for node in ast.walk(builder)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "PublicResult"
    )
    for keyword in call.keywords:
        if keyword.arg not in {"status", "confidence"}:
            continue
        assert isinstance(keyword.value, ast.Attribute), (
            f"{keyword.arg} is computed rather than copied: {ast.dump(keyword.value)}"
        )


def test_no_entry_point_rewrites_the_public_body_after_building_it() -> None:
    """A handler that edits the projected body is re-deriving one field at a time.

    `handle` returns what `public_result` built. It never subscript-assigns into
    it, which is what `body["status"] = ...` would need.
    """
    for name in ("api", "cli"):
        tree = tree_of(PHASE_6_MODULES[name])
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    assert not isinstance(target, ast.Subscript), (
                        f"{name} assigns into a mapping: {ast.dump(node)}"
                    )


def _names_bound_to(path: Path, symbol: str) -> set[str]:
    """Every local name bound to `symbol`, including aliases.

    A name-based check is only as good as the name. `from ... import Principal
    as _P` followed by `_P(account_id=...)` is the same construction wearing a
    different label, so the alias is resolved before the calls are examined.
    """
    bound: set[str] = set()
    for node in ast.walk(tree_of(path)):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == symbol:
                    bound.add(alias.asname or alias.name)
    return bound


@pytest.mark.parametrize("name", sorted(PHASE_6_MODULES))
def test_a_principal_is_not_constructed_under_an_alias_either(name: str) -> None:
    """Phase 4 stop condition 2, resolved through the import rather than by name.

    The earlier test refused `Principal(...)`. This refuses the same call
    reached through `import Principal as _P`, which is what a name-based check
    misses and what a mutation run found.
    """
    if name in {"principal", "api_keys"}:
        return
    path = PHASE_6_MODULES[name]
    aliases = _names_bound_to(path, "Principal")
    for node in ast.walk(tree_of(path)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in aliases, f"{name} constructs a Principal as {node.func.id}"


# --- the job subsystem, and the doors it opens ------------------------------
#
# `prompts/06-api-cli.md` makes the active endpoint asynchronous, which adds an
# entry point that did not exist when the scans above were written: a worker.
# The rules that applied to `apps/` apply to it, and two more do as well.


def test_the_worker_goes_through_the_high_level_service() -> None:
    """Phase 4 stop condition 1, on the newest door.

    A worker calling `SMTPProbeService` would probe without the one-`RCPT TO`
    bound, the attempt cap, and the candidate ordering — all three of which live
    in `SMTPVerificationService`, one layer above it. The `ENTRY_POINTS` scan
    already refuses the low-level names here; this asserts the positive half.
    """
    source = code_without_docstrings(PHASE_6_MODULES["jobs"])
    assert "AddressVerificationService" in source
    assert "self.verification.verify" in source


def test_the_active_endpoint_hands_off_rather_than_awaiting_a_verification() -> None:
    """`prompts/06-api-cli.md`: no synchronous waiting for active SMTP.

    Structural rather than behavioural: `_active` reaches the job service and
    never the verification service, so a build that quietly went back to
    awaiting a probe is a visible edit rather than a slow response.
    """
    tree = tree_of(PHASE_6_MODULES["api"])
    active = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_active"
    )
    for node in ast.walk(active):
        if isinstance(node, ast.Attribute) and node.attr == "verification":
            raise AssertionError("the active endpoint reaches the verification service directly")
    assert "self.jobs.submit" in ast.unparse(active)


def test_a_job_identifier_is_not_derived_from_anything_it_could_leak() -> None:
    """ADR 0014: not an incrementing integer, a timestamp, or a hash of the
    target. The generator is asked for a token and nothing else."""
    source = code_without_docstrings(PHASE_6_MODULES["jobs"])
    assert "self.random.token" in source
    for forbidden in ("uuid", "hashlib", "md5", "sha1", "monotonic", "counter", "+ 1)"):
        assert forbidden not in source.lower(), forbidden


def test_only_the_random_adapter_reaches_a_generator() -> None:
    """`random` is not used anywhere: a Mersenne Twister's state is recoverable
    from its output, which for a job identifier means one caller can predict
    another's."""
    for name, path in PHASE_6_MODULES.items():
        imports = imported_names(path)
        assert "random" not in imports, name
        if name != "random_source":
            assert "secrets" not in imports or name == "cli", name
    assert "secrets" in imported_names(PHASE_6_MODULES["random_source"])


def test_the_job_projection_publishes_a_result_only_for_a_completed_job() -> None:
    """A status invented before a verdict exists would be Phase 5 stop
    condition 1 in the most misleading possible place."""
    source = code_without_docstrings(PHASE_6_MODULES["public_job"])
    assert "JobState.COMPLETED" in source
    assert "only a completed job publishes a result" in source


def test_no_job_module_serializes_a_verdict_or_an_evidence_object() -> None:
    """The job envelope must add no surface the result did not already have."""
    for name in ("jobs", "public_job", "api"):
        source = code_without_docstrings(PHASE_6_MODULES[name])
        for forbidden in ("verdict.evidence", "attempts", "transcript", "stopped_because"):
            assert forbidden not in source, (name, forbidden)


def test_the_cache_key_carries_every_component_section_13_requires() -> None:
    """`docs/requirements.md` section 13: ruleset, sender identity, and the
    normalized target HMAC. ADR 0015 keeps the account as well."""
    source = code_without_docstrings(PHASE_6_MODULES["verdict_cache"])
    for component in (
        "account_digest",
        "target_digest",
        "sender_identity_digest",
        "aggregation_ruleset",
    ):
        assert component in source, component
    assert "correlation_digest" in source
    # The raw values are hashed, never stored.
    assert "hmac_material" in source


def test_the_cache_supplies_no_default_lifetime() -> None:
    """ADR 0015: an unpriced verdict is not stored, rather than stored under a
    duration this project chose. A `or 3600` here would be that duration."""
    tree = tree_of(PHASE_6_MODULES["verdict_cache"])
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp | ast.IfExp):
            rendered = ast.unparse(node)
            assert "lifetime" not in rendered, rendered


def test_the_retry_policy_names_no_provider_and_reads_no_reply_text() -> None:
    """`docs/requirements.md` section 14 lists conditions, not vendors."""
    source = code_without_docstrings(PHASE_6_MODULES["retry"])
    for forbidden in ("diagnostic", "reply", "text", "message", "banner"):
        assert forbidden not in source.lower(), forbidden


def test_the_remote_client_refuses_a_scheme_by_allowlist() -> None:
    """A deny list of dangerous schemes is one scheme behind, always."""
    source = code_without_docstrings(PHASE_6_MODULES["remote_url"])
    assert "PERMITTED_SCHEMES" in source
    assert "urljoin" not in source


def test_the_remote_client_never_interpolates_the_key_into_a_message() -> None:
    """A secret in an error string is a secret in a terminal and a log."""
    tree = tree_of(PHASE_6_MODULES["urllib_client"])
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        rendered = ast.unparse(node)
        if "api_key" in rendered:
            assert "Bearer" in rendered, rendered


# --- the follow-up to the final review -------------------------------------
#
# Each of these pins a statement that was measured to be false, or a control
# that was measured to be missing. They are grouped here because they share one
# property: the code was wrong in a way no behavioural test noticed, and the
# thing that has to stay true is as much a sentence as a branch.


OVERCLAIMS = (
    "costs no enqueue and no probe",
    "a hit at any step returns before the steps below it run",
    "a hit at any of them returns before the ones below it run",
)


@pytest.mark.parametrize("document", ["docs/architecture.md", "src/emailcheck/application/jobs.py"])
def test_no_document_claims_a_cache_hit_is_free(document: str) -> None:
    """A cache hit costs the passive DNS lookup, because both lookups below it
    are keyed by a target that does not exist until the address is parsed.

    A final independent review measured three DNS lookups on a hit while both
    of these documents said there were none.
    """
    text = (ROOT / document).read_text(encoding="utf-8")
    for claim in OVERCLAIMS:
        assert claim not in text, f"{document} repeats the overclaim: {claim!r}"


#: The submission steps, in the order `application/jobs.py` runs them.
STEP_ORDER = ("passive check", "idempotency", "cache", "enqueue")

#: The two documents that draw that order as a diagram.
ORDER_DOCUMENTS = ("docs/architecture.md", "src/emailcheck/application/jobs.py")


def fenced_blocks(text: str) -> list[str]:
    """Every fenced block in a document, as its own string.

    Both places that draw the submission order draw it inside a fence — in
    `jobs.py` the fence is inside the module docstring, which is why one
    extractor serves both.
    """
    blocks: list[str] = []
    current: list[str] = []
    inside = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            if inside:
                blocks.append("\n".join(current))
                current = []
            inside = not inside
            continue
        if inside:
            current.append(line)
    return blocks


def submission_order_block(document: str) -> str:
    """The one fenced block that names all four submission steps.

    Requiring exactly one is part of the assertion: a second diagram claiming a
    different order would be as wrong as one reversed diagram, and searching the
    whole document would find whichever came first.
    """
    text = (ROOT / document).read_text(encoding="utf-8")
    matching = [block for block in fenced_blocks(text) if all(s in block for s in STEP_ORDER)]
    assert len(matching) == 1, f"{document} has {len(matching)} blocks naming all four steps"
    return matching[0]


@pytest.mark.parametrize("document", ORDER_DOCUMENTS)
def test_the_submission_order_block_lists_the_steps_in_the_order_the_code_runs(
    document: str,
) -> None:
    """The positive half of F4, anchored to the block that makes the claim.

    The previous version of this test took the first `"passive check"` in the
    whole document and the next `"cache"` after it. Reversing the diagram left
    it passing, because the prose eight lines below the block also says
    "cache" — a test satisfied by the paragraph explaining the order rather than
    by the order. A final independent review measured that escape.

    So the block is extracted first and every position is read inside it.
    """
    block = submission_order_block(document)
    for step in STEP_ORDER:
        assert block.count(step) == 1, f"{document}: {step!r} appears {block.count(step)} times"

    positions = [block.index(step) for step in STEP_ORDER]
    assert positions == sorted(positions), (
        f"{document} draws the steps as "
        f"{[s for _, s in sorted(zip(positions, STEP_ORDER, strict=True))]}"
    )


def test_the_order_block_is_not_satisfied_by_surrounding_prose() -> None:
    """The extractor is the point, so it is checked on its own.

    A document whose block is reversed must fail even when the words appear in
    the right order somewhere else in the file — which is exactly the shape that
    escaped before.
    """
    reversed_block = "```text\n  cache\n  passive check\n  idempotency\n  enqueue\n```"
    prose = "\n\npassive check, then idempotency, then cache, then enqueue.\n"
    blocks = fenced_blocks(reversed_block + prose)
    assert len(blocks) == 1
    positions = [blocks[0].index(step) for step in STEP_ORDER]
    assert positions != sorted(positions)


def test_the_remote_client_installs_its_own_opener() -> None:
    """`urllib.request.urlopen` uses the default global opener, which follows a
    redirect and carries `Authorization` to wherever it points."""
    source = code_without_docstrings(SOURCE / "adapters" / "http" / "urllib_client.py")
    assert "_OPENER.open" in source
    assert "urlopen" not in source


def test_the_idempotency_identity_includes_the_target() -> None:
    """`docs/architecture.md` section 6: a key *and* a derived target HMAC."""
    source = code_without_docstrings(PHASE_6_MODULES["jobs"])
    assert "correlation_digest" in source
    assert "hmac_material" in source
    assert "target_digest" in source


def test_the_job_service_rolls_back_when_the_executor_refuses() -> None:
    """A `pending` job the executor never accepted can never run, and eviction
    removes only terminal jobs."""
    tree = tree_of(PHASE_6_MODULES["jobs"])
    submit = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "submit"
    )
    guarded = [node for node in ast.walk(submit) if isinstance(node, ast.Try)]
    assert guarded, "the enqueue is not guarded at all"
    rendered = ast.unparse(guarded[0])
    assert "executor.submit" in rendered
    assert "_release" in rendered
    assert "BaseException" in rendered


def test_the_retry_table_is_read_by_reason_and_never_by_reply_code() -> None:
    """`552 5.2.2` is a 5xx that is retried; `550 5.7.1` is a 5xx that is not."""
    source = code_without_docstrings(PHASE_6_MODULES["retry"])
    for forbidden in ("basic_code", "//", "startswith", "4xx", "5xx"):
        assert forbidden not in source, forbidden
