"""What behaviour cannot show about Phase 7.

Every scan reads the **syntax tree with docstrings excluded**. These modules
explain at length what they do not do — which providers they do not name, which
headers they do not trust — and a raw text scan fails on its own prose. This
repository has made that mistake in five separate gates, including once in this
Phase, so the helper is shared rather than rewritten per test.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

pytestmark = pytest.mark.inspection

ROOT = pathlib.Path(__file__).resolve().parent.parent

PHASE_7_MODULES = {
    "abuse_domain": "src/emailcheck/domain/abuse.py",
    "admin_domain": "src/emailcheck/domain/admin.py",
    "indicators": "src/emailcheck/domain/indicators.py",
    "source": "src/emailcheck/domain/source.py",
    "abuse": "src/emailcheck/application/abuse.py",
    "admin": "src/emailcheck/application/admin.py",
    "retention": "src/emailcheck/application/retention.py",
    "quota_port": "src/emailcheck/ports/quota.py",
    "metrics_port": "src/emailcheck/ports/metrics.py",
    "quota_adapter": "src/emailcheck/adapters/system/quota.py",
    "metrics_adapter": "src/emailcheck/adapters/observability/metrics.py",
    "redaction": "src/emailcheck/security/redaction.py",
}


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


# --- provider neutrality -----------------------------------------------------

PROVIDERS = (
    "gmail",
    "google",
    "outlook",
    "hotmail",
    "microsoft",
    "yahoo",
    "proton",
    "icloud",
    "zoho",
    "aol",
    "fastmail",
    "yandex",
    "qq.com",
    "163.com",
)


@pytest.mark.parametrize("name", sorted(PHASE_7_MODULES))
def test_no_phase_7_module_names_a_provider(name: str) -> None:
    """No abuse threshold, budget, indicator, or administrative default is keyed
    to a provider's identity. `docs/threat-model.md` applies this control to
    reply parsing; an abuse threshold that differed by provider would be the
    same failure with higher stakes, and a behavioural test cannot enumerate the
    providers nobody thought of."""
    code = code_without_docstrings(PHASE_7_MODULES[name]).lower()
    offenders = [provider for provider in PROVIDERS if provider in code]
    assert offenders == [], (name, offenders)


# --- the layers are all accounted for ----------------------------------------


def test_every_layer_the_prompt_names_is_enforced_or_accounted_for() -> None:
    """`docs/threat-model.md` lists nine. Eight are `BudgetLayer` members and
    the ninth — global concurrency — is `application/admission.py`'s, since
    Phase 6. A second implementation of a reviewed bound is two bounds that will
    disagree, so this asserts the mapping is total rather than that all nine are
    here."""
    from emailcheck.application.admission import AdmissionSettings
    from emailcheck.domain.abuse import BudgetLayer

    prompt_layers = {
        "API key",
        "account",
        "source IP",
        "target address HMAC",
        "target domain",
        "target MX",
        "sender identity",
        "global concurrency",
        "daily total",
    }
    here = {
        "API key": BudgetLayer.API_KEY,
        "account": BudgetLayer.ACCOUNT,
        "source IP": BudgetLayer.SOURCE_IP,
        "target address HMAC": BudgetLayer.TARGET,
        "target domain": BudgetLayer.TARGET_DOMAIN,
        "target MX": BudgetLayer.TARGET_MX,
        "sender identity": BudgetLayer.SENDER_IDENTITY,
        "daily total": BudgetLayer.DAILY_TOTAL,
    }
    assert set(here) | {"global concurrency"} == prompt_layers
    # The ninth, where it actually lives.
    assert AdmissionSettings().max_in_flight > 0

    # Every layer this enum holds is either one `docs/threat-model.md` names
    # or one a later Phase added deliberately. Phase 9's accept-all domain
    # budget is the second kind: ADR 0017 requires a
    # **separate** domain budget, so it is not `target_domain` and is not one of
    # the eight above. Listing it here rather than widening the comparison keeps
    # a layer added by accident failing.
    added_by_later_phases = {BudgetLayer.ACCEPT_ALL_DOMAIN}
    assert set(here.values()) | added_by_later_phases == set(BudgetLayer)
    assert not set(here.values()) & added_by_later_phases


@pytest.mark.docs_contract
def test_the_public_documentation_lists_the_layers_this_project_claims() -> None:
    """Read from the published threat model, so the two cannot drift apart.

    The list used to be read from an internal implementation prompt, which is
    not part of the published repository. The durable claim — which quota layers
    exist — belongs in `docs/threat-model.md`, where an operator reading about
    enumeration control can find it.
    """
    published = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    for layer in ("API key", "account", "source IP", "target domain", "daily total"):
        assert layer in published, layer


# --- purity ------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["abuse_domain", "admin_domain", "indicators", "source", "redaction"]
)
def test_the_pure_modules_reach_nothing(name: str) -> None:
    """`docs/architecture.md` section 1: domain code depends on no framework, no
    database, no socket, and no clock."""
    code = code_without_docstrings(PHASE_7_MODULES[name])
    tree = ast.parse(code)
    forbidden = {
        "socket",
        "ssl",
        "sqlite3",
        "asyncio",
        "requests",
        "urllib",
        "os",
        "random",
        "time",
        "logging",
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported & forbidden == set(), (name, imported & forbidden)


@pytest.mark.parametrize("name", ["abuse_domain", "admin_domain", "indicators", "redaction"])
def test_the_pure_modules_are_synchronous(name: str) -> None:
    tree = tree_of(PHASE_7_MODULES[name])
    for node in ast.walk(tree):
        assert not isinstance(node, ast.AsyncFunctionDef), name
        assert not isinstance(node, ast.Await), name


def test_no_phase_7_module_reads_the_environment() -> None:
    """The shape the Phase 4 `TLSTrust` inspection already refuses: a control
    configured by whoever can set a variable in the worker's environment."""
    for name, relative in PHASE_7_MODULES.items():
        code = code_without_docstrings(relative)
        assert "environ" not in code, name
        assert "getenv" not in code, name


# --- telemetry is not deliverability -----------------------------------------


def test_no_indicator_or_control_decision_is_a_published_reason_or_status() -> None:
    """`docs/architecture.md` keeps operational telemetry and mailbox semantics
    apart. `rate limited`, `executor full`, and `service health` are not
    `ReasonCode` members and must not become ones."""
    from emailcheck.domain.admin import ControlDecision
    from emailcheck.domain.indicators import Indicator
    from emailcheck.domain.reasons import ReasonCode
    from emailcheck.domain.verdict import Status

    published = {member.value for member in ReasonCode} | {member.value for member in Status}
    operational = {member.value for member in Indicator} | {
        member.value for member in ControlDecision
    }
    assert published.isdisjoint(operational)


def test_no_phase_7_module_builds_a_verdict_or_a_status() -> None:
    """A control that could produce a verdict is one that could answer about a
    mailbox because a budget was exhausted."""
    for name, relative in PHASE_7_MODULES.items():
        tree = ast.parse(code_without_docstrings(relative))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {
                    "Verdict",
                    "Evidence",
                    "Confidence",
                    "aggregate_evidence",
                }, (name, node.func.id)


def test_the_abuse_guard_names_no_status_member() -> None:
    from emailcheck.domain.verdict import Status

    code = code_without_docstrings(PHASE_7_MODULES["abuse"])
    for member in Status:
        assert member.name not in code


# --- every new bound is validated --------------------------------------------


def test_every_phase_7_setting_refuses_a_boolean_and_a_non_positive_value() -> None:
    """The validation style Phases 4 and 6 established: a bound must be a whole
    number, not a boolean, positive, and under a ceiling — because a bound
    nobody would reach is not a bound."""
    from emailcheck.adapters.system.quota import InProcessQuotaStore, QuotaSettingsError
    from emailcheck.application.retention import RetentionError, RetentionSettings
    from emailcheck.domain.abuse import AbuseSettingsError, QuotaSettings

    for bad in (True, 0, -1):
        with pytest.raises(AbuseSettingsError):
            QuotaSettings(window_seconds=bad)  # type: ignore[arg-type]
        with pytest.raises(AbuseSettingsError):
            QuotaSettings(per_account=bad)  # type: ignore[arg-type]
        with pytest.raises(QuotaSettingsError):
            InProcessQuotaStore(max_counters=bad)  # type: ignore[arg-type]
        with pytest.raises(RetentionError):
            RetentionSettings(batch_limit=bad)  # type: ignore[arg-type]


def test_an_absurd_setting_is_refused_the_way_the_others_are() -> None:
    from emailcheck.domain.abuse import MAX_BUDGET, AbuseSettingsError, QuotaSettings

    with pytest.raises(AbuseSettingsError):
        QuotaSettings(per_account=MAX_BUDGET + 1)
    with pytest.raises(AbuseSettingsError):
        QuotaSettings(window_seconds=24 * 60 * 60 + 1)


def test_an_unenforced_layer_is_expressed_as_none_rather_than_a_huge_number() -> None:
    """Explicit, so "not enforced here" and "enforced with a limit nobody
    reaches" are different configurations rather than the same one."""
    from emailcheck.domain.abuse import BudgetLayer, QuotaSettings

    settings = QuotaSettings(per_target=None)
    assert settings.limit_for(BudgetLayer.TARGET) is None


# --- keys carry no material --------------------------------------------------


def test_no_budget_key_can_be_a_mailbox() -> None:
    """The shape check `rate_limit_key`, `Principal`, and `OperatorEvent` already
    make, for the same reason."""
    from emailcheck.domain.abuse import BudgetKey, BudgetKeyError, BudgetLayer

    for value in ("alice@example.test", "with space", "with\nnewline", "", "x" * 300):
        with pytest.raises(BudgetKeyError):
            BudgetKey(layer=BudgetLayer.TARGET, value=value)


def test_the_guard_digests_a_target_rather_than_keying_on_it() -> None:
    """Read from the tree: the target layer's value must come from a digest
    call, not from the address."""
    code = code_without_docstrings(PHASE_7_MODULES["abuse"])
    assert "self._digest(target.hmac_material)" in code
    assert "target.local_part" not in code.replace("local_part_shape(target.local_part.value)", "")


# --- authentication timing ---------------------------------------------------


def test_the_authenticator_compares_every_credential_before_answering() -> None:
    """`ports/authentication.py` requires a constant-time comparison, and an
    early `return` inside the loop makes the *work* depend on where in the
    mapping a key sits — a timing signal about the configuration rather than
    about the credential.

    Asserted by inspection rather than by measurement: a timing test would be
    flaky, and `docs/test-strategy.md` forbids weakening assertions to make timing
    pass. So this reads the loop and requires that nothing leaves it early. A
    mutation restoring the early return escaped the whole suite until this
    existed.
    """
    tree = tree_of("src/emailcheck/adapters/auth/api_keys.py")
    authenticate = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "authenticate"
    )
    loops = [node for node in ast.walk(authenticate) if isinstance(node, ast.For)]
    assert len(loops) == 1

    for node in ast.walk(loops[0]):
        assert not isinstance(node, ast.Return), "the comparison loop returns early"
        assert not isinstance(node, ast.Break), "the comparison loop breaks early"


def test_the_authenticator_still_answers_the_same_thing_for_every_wrong_credential() -> None:
    """The behavioural half, which the inspection above cannot cover: an unknown
    key and a malformed one are indistinguishable to the caller."""
    from emailcheck.adapters.auth.api_keys import build_authenticator

    authenticator = build_authenticator({"acct-1": "k" * 40, "acct-2": "j" * 40})
    for credential in (None, "", "short", "z" * 40, "k" * 39):
        assert authenticator.authenticate(credential) is None
    assert authenticator.authenticate("k" * 40) is not None
    assert authenticator.authenticate("j" * 40) is not None


# --- F6: the ASGI stop conditions are pinned, one row each --------------------
#
# `docs/architecture.md` records seven conditions on the binding nobody has
# written yet. They are what makes the deferred source-IP layer safe: the source
# budget is unenforced today because no transport supplies a `SourceIdentity`,
# and these are the conditions that stop that remaining optional once one does.
#
# Phases 4, 5, and 6 each pin their stop conditions with a docs test. Phase 7's
# were prose only until an independent review said so. Each condition is one
# parametrized row, so deleting one names *which* one — a single substring test
# over the whole section would fail without saying what went missing.

ASGI_STOP_CONDITIONS: dict[str, tuple[str, ...]] = {
    "trusted client IP provenance": (
        "trusted client ip provenance",
        "only thing that may construct a `sourceidentity`",
    ),
    "proxy header policy": (
        "proxy header policy",
        "x-forwarded-for",
        "operator-configured list of proxies",
    ),
    "request body size": (
        "request body size",
        "needs a bound before it is parsed",
    ),
    "request logging redaction": (
        "request logging redaction",
        "`security/redaction.py` rather than a second implementation",
    ),
    "one Deployment per process": (
        "one `deployment` per process, built at startup",
        "not per request",
    ),
    "no request-local control state": ("no request-local limiter, quota store, or admin state",),
    "admin interface not mounted publicly": (
        "the administrative interface is not mounted on the public application",
    ),
}


def flattened_architecture() -> str:
    """The architecture document as one lower-cased line.

    Flattened so a condition may be re-wrapped without failing, which is the
    same treatment `test_every_phase_6_stop_condition_is_recorded` gives its
    plan: the substance is pinned, the prose is not.
    """
    text = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    return " ".join(text.split()).lower()


@pytest.mark.docs_contract
@pytest.mark.parametrize(
    ("condition", "markers"), sorted(ASGI_STOP_CONDITIONS.items()), ids=lambda value: value
)
def test_every_asgi_stop_condition_is_recorded(condition: str, markers: tuple[str, ...]) -> None:
    document = flattened_architecture()
    missing = [marker for marker in markers if marker not in document]
    assert missing == [], f"the ASGI stop condition for {condition} is not recorded: {missing}"


@pytest.mark.docs_contract
def test_the_stop_conditions_live_under_their_own_heading() -> None:
    """So the list is findable, and so a condition cannot be satisfied by a
    coincidental phrase elsewhere in a long document."""
    text = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    assert "#### Stop conditions on the ASGI binding" in text


@pytest.mark.docs_contract
def test_there_are_exactly_seven_and_the_count_is_asserted() -> None:
    """A condition added later must be added to this table too, and one quietly
    dropped from the document fails its own row above.

    **Seven, and Phase 10 did not change that.** An earlier Phase 10 revision
    made it eight by promoting the CSV upload's body limit to a condition of its
    own — but request body size was already the third of the approved seven, so
    that was a duplicate wearing a new name, and it silently rewrote a Phase 7
    invariant to accommodate a later Phase. The upload-specific wording lives
    inside condition three and is pinned by its own Phase 10 test.
    """
    text = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    section = text.split("#### Stop conditions on the ASGI binding", 1)[1].split("###", 1)[0]
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert len(bullets) == len(ASGI_STOP_CONDITIONS) == 7


def test_no_asgi_binding_exists_yet() -> None:
    """The conditions are stop conditions, not a specification of shipped code.

    Phase 7 stays framework-independent: `docs/architecture.md` section 1 puts
    frameworks in `apps/`, and there is still no framework anywhere.
    """
    import ast

    for path in (ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            else:
                continue
            assert not ({"fastapi", "starlette", "uvicorn"} & set(names)), path.name


def test_the_source_layer_is_still_uncounted_because_nothing_supplies_one() -> None:
    """The state the stop conditions exist to end.

    No production code constructs a `SourceIdentity`, so the source budget is
    unenforced today. That is compliant only while there is no transport — which
    is exactly what the first two conditions above are for.
    """
    import ast

    offenders: list[str] = []
    for path in (ROOT / "src").rglob("*.py"):
        if path.name == "source.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "SourceIdentity"
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []
