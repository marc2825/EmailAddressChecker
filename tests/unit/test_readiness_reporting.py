"""The deployment validation and version reports, and what they must not do.

`docs/beta-report-template.md`. Both commands are *reporting
only*, and both of the things they must not do are easy to add by accident:

- **they must perform no I/O.** Checking a PTR, an SPF record, or an open port
  25 from a validation command would be this project's first unauthorized packet,
  from the most surprising possible place. The check is by inspection of the
  syntax tree, not by attempting a call and seeing what happens.
- **they must authorize nothing.** A clean report is not permission to start a
  beta; a human is, and `BetaAuthorization.external_probing_authorized` is where
  that decision lives. The check is that these modules do not name it at all.

Scans read the syntax tree **with docstrings excluded**. These modules explain
at length what they do not do, and a raw text scan fails on their own prose —
a mistake this repository has now made in six separate gates.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
from typing import Final

import pytest
from tests.dataset_fixtures import (
    domain_dataset_text,
    override_dataset_text,
    provider_dataset_text,
    role_dataset_text,
)

from emailcheck.application.readiness import (
    DATASET_UNAVAILABLE,
    UNAVAILABLE_DATASETS,
    VersionReport,
    report_versions,
    validate_deployment,
)
from emailcheck.classification.repository import (
    DISPOSABLE_FILE,
    FREE_MAIL_FILE,
    OVERRIDE_FILE,
    PROVIDER_FILE,
    ROLE_FILE,
    PassiveDatasets,
    load_passive_datasets,
    load_shipped_datasets,
)
from emailcheck.composition import Deployment
from emailcheck.domain.readiness import DEPLOYMENT_GATES, GATE_KEYS, GateStatus, gate_for
from emailcheck.security.identifiers import CANONICAL_INPUT_VERSION

ROOT: Final = pathlib.Path(__file__).resolve().parents[2]

READINESS_MODULES: Final = {
    "domain": "src/emailcheck/domain/readiness.py",
    "application": "src/emailcheck/application/readiness.py",
}

#: Anything that could reach outside this process. A validation command that
#: imported one of these would be one nobody could tell from a prober.
IO_MODULES: Final = (
    "socket",
    "asyncio",
    "ssl",
    "http",
    "urllib",
    "subprocess",
    "os",
    "pathlib",
    "shutil",
    "dns",
)

IO_CALLS: Final = ("open", "getaddrinfo", "gethostbyname", "connect", "system", "run")


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
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def local_deployment() -> Deployment:
    """The profile the CLI reports on. Passive, and holding no secret."""
    from emailcheck.apps.cli import _local_deployment

    return _local_deployment()


# --- neither report performs I/O --------------------------------------------


@pytest.mark.parametrize("name", sorted(READINESS_MODULES))
def test_the_readiness_modules_import_nothing_that_reaches_outside(name: str) -> None:
    offenders = sorted(imported_names(READINESS_MODULES[name]) & set(IO_MODULES))

    assert offenders == [], (name, offenders)


@pytest.mark.parametrize("name", sorted(READINESS_MODULES))
def test_the_readiness_modules_call_nothing_that_reaches_outside(name: str) -> None:
    """Read from the tree, so a call hidden in prose is not a false positive."""
    code = code_without_docstrings(READINESS_MODULES[name])

    for call in IO_CALLS:
        assert f"{call}(" not in code, (name, call)


def test_validating_a_deployment_reaches_no_network() -> None:
    """The suite-wide guard fails any test that opens a socket.

    So this passing is the behavioural half of the inspection above: the report
    was produced and nothing was resolved or connected to.
    """
    report = validate_deployment(local_deployment())

    assert len(report.gates) == 13


# --- neither report authorizes anything -------------------------------------


@pytest.mark.parametrize("name", sorted(READINESS_MODULES))
def test_the_readiness_modules_never_name_the_authorization_flag(name: str) -> None:
    """The one flag that starts a beta is set by a person, in one place.

    A validation command that could write it — or that a caller could read it
    from — would make "all thirteen reported clean" into an authorization, which
    is exactly what `docs/beta-report-template.md`'s exit criteria give to a human.
    """
    code = code_without_docstrings(READINESS_MODULES[name])

    assert "external_probing_authorized" not in code
    assert "BetaAuthorization" not in code


def test_the_readiness_public_surface_is_exactly_the_reviewed_reports() -> None:
    """The barrier F4 needed, stated as a closed surface rather than a banned name.

    Forbidding the identifier `external_probing_authorized` was too narrow: a
    review added

        def beta_may_start(report: DeploymentReport) -> bool:
            return not report.requires_human_verification

    which names no beta type, imports nothing, and passed the whole suite —
    while being exactly the "all thirteen clean, so go" predicate
    `docs/beta-report-template.md` gives to a human. So the contract is the other
    way round: the module's public callables are compared against its `__all__`,
    and **any** new public function fails until somebody adds it deliberately.
    """
    module = importlib.import_module("emailcheck.application.readiness")

    exported = set(module.__all__)
    assert exported == {
        "DATASET_UNAVAILABLE",
        "UNAVAILABLE_DATASETS",
        "DeploymentReport",
        "GateReport",
        "VersionReport",
        "report_versions",
        "validate_deployment",
    }

    public_functions = {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and inspect.isfunction(value)
        and value.__module__ == module.__name__
    }
    assert public_functions == {"report_versions", "validate_deployment"}
    assert public_functions <= exported


def test_no_public_readiness_callable_answers_a_start_no_start_question() -> None:
    """A `DeploymentReport -> bool` predicate is the shape being prevented.

    Narrow on purpose: private helpers may return whatever they like, and
    `_in_process_evidence` does return a `bool`. What may not exist is a
    **public** function that turns the report into a go/no-go answer, because
    that is one call site away from being an authorization.
    """
    tree = tree_of(READINESS_MODULES["application"])

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name.startswith("_"):
            continue
        returns = ast.unparse(node.returns) if node.returns else ""
        arguments = " ".join(
            ast.unparse(argument.annotation) for argument in node.args.args if argument.annotation
        )
        assert not (returns == "bool" and "DeploymentReport" in arguments), (
            f"{node.name} converts a deployment report into a go/no-go answer"
        )


def test_the_readiness_layer_names_no_beta_type() -> None:
    """The dependency direction, pinned. Necessary, and on its own insufficient —
    the escaping mutation imported nothing, which is why the surface test above
    exists beside this one."""
    for relative in READINESS_MODULES.values():
        code = code_without_docstrings(relative)
        for name in ("BetaAuthorization", "BetaHarness", "BetaCorpus", "external_probing"):
            assert name not in code, (relative, name)


def test_the_cli_never_sets_the_authorization_flag_either() -> None:
    code = code_without_docstrings("src/emailcheck/apps/cli.py")

    assert "external_probing_authorized" not in code


def test_there_is_no_passed_status_to_report() -> None:
    """Three values, and the absence of a fourth is the design."""
    assert {status.value for status in GateStatus} == {
        "configured_in_process",
        "not_configured_in_process",
        "requires_human_verification",
    }


# --- the report itself ------------------------------------------------------


def test_every_gate_is_reported_in_the_document_order() -> None:
    report = validate_deployment(local_deployment())

    assert tuple(gate.key for gate in report.gates) == GATE_KEYS


def test_ten_of_the_thirteen_can_only_be_verified_by_a_human() -> None:
    """The three with in-process evidence are the three whose *configuration*
    lives here. The other ten are external facts or human commitments."""
    report = validate_deployment(local_deployment())

    assert len(report.requires_human_verification) == 10
    assert {
        gate.key
        for gate in report.gates
        if gate.status is not GateStatus.REQUIRES_HUMAN_VERIFICATION
    } == {
        "kill_switch_tested",
        "rate_limits_tested",
        "retention_deletion_tested",
    }


def test_a_configured_gate_still_asks_for_the_human_step() -> None:
    """ "Configured" is not "tested", and the operator action says which it is."""
    report = validate_deployment(local_deployment())
    configured = [gate for gate in report.gates if gate.status is GateStatus.CONFIGURED_IN_PROCESS]

    assert configured
    for gate in configured:
        assert "Still required" in gate.operator_action


def test_every_gate_reports_an_action_and_a_reason() -> None:
    """A checklist row that says "confirm SPF" and stops is one that gets ticked."""
    report = validate_deployment(local_deployment())

    for gate in report.gates:
        assert gate.operator_action.strip()
        assert gate.why.strip()
        assert gate.title == gate_for(gate.key).title


def test_the_disclaimer_travels_in_the_json_as_well_as_the_printed_output() -> None:
    """A caller reading the JSON is the caller most likely to treat it as approval."""
    payload = validate_deployment(local_deployment()).as_json_object()

    assert "advisory" in str(payload["disclaimer"])
    assert "human" in str(payload["disclaimer"])
    assert payload["requires_human_verification"] == 10


def test_the_report_carries_no_secret() -> None:
    """It is printed and pasted into tickets, so it holds strings and counts."""
    rendered = repr(validate_deployment(local_deployment()).as_json_object())

    for secret in ("key", "secret", "token", "password"):
        assert f"{secret}=" not in rendered.lower()


# --- version reporting ------------------------------------------------------
#
# Every test here builds a real `PassiveDatasets` through the **production
# loader**, from real dataset files. A test that handed the reporter a mapping
# of names to version strings could not tell a populated dataset from an empty
# one — which is exactly the gap an independent review found, reporting
# `role = empty` beside a shipped role list at `2026-08-07.1`.


def dataset_directory(
    tmp_path: pathlib.Path, *, disposable: tuple[str, ...] = (), role_version: str = "role-9"
) -> pathlib.Path:
    """A complete dataset snapshot on disk, loadable by the production loader."""
    (tmp_path / DISPOSABLE_FILE).write_text(
        domain_dataset_text("disposable_domains", *disposable, version="disposable-7")
    )
    (tmp_path / FREE_MAIL_FILE).write_text(
        domain_dataset_text("free_mail_domains", version="empty-fixture")
    )
    (tmp_path / ROLE_FILE).write_text(role_dataset_text("support", version=role_version))
    (tmp_path / PROVIDER_FILE).write_text(provider_dataset_text(version="empty-fixture"))
    (tmp_path / OVERRIDE_FILE).write_text(override_dataset_text())
    return tmp_path


def versions_of(datasets: PassiveDatasets) -> VersionReport:
    return report_versions(
        package_version="0.0.0", aggregation_ruleset="aggregation-2026-08-09", datasets=datasets
    )


def test_the_shipped_role_version_is_reported_exactly() -> None:
    """The regression the review named, pinned against the file on disk.

    Not `role != unavailable`, which `"empty"` satisfies: the **actual loaded
    version** and the **reported version** must be the same string.
    """
    shipped = load_shipped_datasets()
    loaded = shipped.versions["role"]

    reported = versions_of(shipped).dataset_versions["role"]

    assert reported == loaded
    assert shipped.entry_counts["role"] > 0, "the shipped role dataset is not empty"


def test_the_command_reports_the_deployments_own_datasets() -> None:
    """The CLI profile and the report must describe one snapshot, not two."""
    deployment = local_deployment()

    report = versions_of(deployment.passive_datasets)

    assert report.dataset_versions["role"] == deployment.passive_datasets.versions["role"]
    assert report.dataset_entry_counts == deployment.passive_datasets.entry_counts


def test_a_declared_dataset_that_is_actually_empty_reports_the_declaration(
    tmp_path: pathlib.Path,
) -> None:
    datasets = load_passive_datasets(dataset_directory(tmp_path))

    report = versions_of(datasets)

    assert report.dataset_versions["disposable"] == DATASET_UNAVAILABLE
    assert report.dataset_versions["free_mail"] == DATASET_UNAVAILABLE
    assert report.dataset_versions["provider"] == DATASET_UNAVAILABLE
    assert report.unavailable_datasets == ("disposable", "free_mail", "provider")


def test_populating_a_declared_dataset_is_an_ordinary_data_change(
    tmp_path: pathlib.Path,
) -> None:
    """`src/emailcheck/data/passive/README.md`'s published promise, pinned.

    The disposable list is declared unavailable **and** populated here, with no
    change to any production module. The report must describe the data rather
    than the declaration — otherwise lifting the declaration would need a code
    change, and the README says it does not.
    """
    datasets = load_passive_datasets(dataset_directory(tmp_path, disposable=("throwaway.test",)))

    report = versions_of(datasets)

    assert report.dataset_versions["disposable"] == "disposable-7"
    assert report.dataset_versions["disposable"] != DATASET_UNAVAILABLE
    assert "disposable" not in report.unavailable_datasets
    # The other two are untouched by the change.
    assert report.dataset_versions["free_mail"] == DATASET_UNAVAILABLE
    assert report.dataset_versions["provider"] == DATASET_UNAVAILABLE


def test_a_dataset_nobody_declared_reports_its_own_empty_state(
    tmp_path: pathlib.Path,
) -> None:
    """`disposable_overrides` is empty and undeclared: it reports its version."""
    report = versions_of(load_passive_datasets(dataset_directory(tmp_path)))

    assert report.dataset_versions["disposable_overrides"] == "test-1"
    assert report.dataset_versions["role"] == "role-9"


def test_the_entry_counts_let_an_operator_check_the_derivation(
    tmp_path: pathlib.Path,
) -> None:
    """The category is derived from the counts, so the counts are published."""
    report = versions_of(load_passive_datasets(dataset_directory(tmp_path, disposable=("a.test",))))

    assert report.dataset_entry_counts["disposable"] == 1
    assert report.dataset_entry_counts["free_mail"] == 0
    for name, version in report.dataset_versions.items():
        if version == DATASET_UNAVAILABLE:
            assert report.dataset_entry_counts[name] == 0


def test_the_canonical_input_version_is_read_rather_than_re_declared() -> None:
    """A second copy of a version is a second thing to forget to bump."""
    assert versions_of(PassiveDatasets()).canonical_input_version == CANONICAL_INPUT_VERSION


def test_the_unavailable_set_matches_the_published_declaration() -> None:
    assert frozenset({"disposable", "free_mail", "provider"}) == UNAVAILABLE_DATASETS


def test_the_version_report_carries_no_secret() -> None:
    report = versions_of(load_shipped_datasets())

    assert set(report.as_json_object()) == {
        "package_version",
        "aggregation_ruleset",
        "canonical_input_version",
        "dataset_versions",
        "unavailable_datasets",
        "dataset_entry_counts",
    }


# --- the gate vocabulary ----------------------------------------------------


def test_the_gates_have_distinct_keys_and_a_lookup_that_names_a_miss() -> None:
    assert len(set(GATE_KEYS)) == len(DEPLOYMENT_GATES) == 13

    with pytest.raises(KeyError):
        gate_for("no-such-gate")
