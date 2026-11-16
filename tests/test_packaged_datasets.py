"""The shipped datasets travel with the package, not with the checkout.

An independent review found `data/passive/` sitting outside the wheel while
`_local_deployment()` had come to require it: the loader worked from a
repository checkout and would have failed from an installed package. The
snapshot now lives at `emailcheck/data/passive/` and is reached through
`importlib.resources`.

**These tests must not be able to pass by accident.** A test run from the
repository root can find `data/passive` by luck — through the working
directory, through `sys.path[0]`, through a relative walk up from `__file__` —
and would go on passing after the resource stopped being packaged. So each one
here runs a subprocess:

- from a temporary working directory, so the repository is not the cwd;
- with `PYTHONPATH` naming only a **copied** package tree, so the checkout is
  not importable;
- and one of them asserts that the copy is genuinely isolated by showing that
  the same lookup fails when the data is removed from it.

That copy is the closest thing to an installed wheel this environment can build:
`[tool.hatch.build.targets.wheel] packages = ["src/emailcheck"]` maps the
package directory into the distribution, so copying the package directory is
copying what the wheel would contain. No dependency is installed and no network
is used — the whole exercise is a directory copy and a subprocess.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import tomllib
from fnmatch import fnmatch
from pathlib import Path
from typing import Final

import pytest

from emailcheck.classification.repository import load_shipped_datasets

REPO: Final = Path(__file__).resolve().parents[1]
PACKAGE: Final = REPO / "src" / "emailcheck"
DATASETS: Final = PACKAGE / "data" / "passive"

#: The five files the loader reads. `.example` files are format documentation
#: for a maintainer and are excluded from the distribution by `pyproject.toml`.
SHIPPED_FILES: Final = (
    "disposable_domains.toml",
    "free_mail_domains.toml",
    "role_local_parts.toml",
    "provider_mx_patterns.toml",
    "overrides.toml",
)


def code_without_docstrings(path: Path) -> str:
    """Source with every docstring removed.

    These modules explain at length which lookup they no longer use, and a raw
    text scan fails on their own prose — a mistake this repository has made in
    seven separate gates, so the helper is used rather than rewritten.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
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


def wheel_exclusions() -> tuple[str, ...]:
    """The build configuration's own exclusions, read rather than assumed.

    The simulation below has to honour whatever `pyproject.toml` says, or it is
    a simulation of a different distribution: a mutation adding
    `data/passive/*` here has to make the load tests fail, and it only can if
    this is where the patterns come from.
    """
    configuration = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    wheel = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]
    return tuple(wheel.get("exclude", ()))


def packaged_files() -> tuple[Path, ...]:
    """Every file the wheel would carry, as paths under the package.

    `packages = ["src/emailcheck"]` maps the package directory into the
    distribution, minus the configured exclusions. Patterns are matched against
    the path relative to the package and against the file name, which covers
    both forms this project uses.
    """
    excluded = wheel_exclusions()
    carried: list[Path] = []
    for path in sorted(PACKAGE.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        relative = path.relative_to(PACKAGE)
        if any(
            fnmatch(relative.as_posix(), pattern) or fnmatch(relative.name, pattern)
            for pattern in excluded
        ):
            continue
        carried.append(relative)
    return tuple(carried)


def fake_site_packages(tmp_path: Path, *, with_datasets: bool = True) -> Path:
    """The package as an installed distribution would hold it.

    Built from `packaged_files()` rather than from a blanket copy, so the
    configured exclusions are part of what is being tested.
    """
    site = tmp_path / "site-packages"
    for relative in packaged_files():
        destination = site / "emailcheck" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PACKAGE / relative, destination)
    if not with_datasets:
        shutil.rmtree(site / "emailcheck" / "data" / "passive")
    return site


def run_isolated(script: str, site: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run `script` with only `site` importable, from a directory that is not the repo."""
    # S603: the argument vector is this interpreter and a literal written in
    # this file. Nothing here is untrusted input, and the subprocess is the
    # point — it is what makes the import path and the working directory
    # something the test controls rather than inherits.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=cwd,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(site), "PATH": "/usr/bin:/bin", "HOME": str(cwd)},
        check=False,
    )


# --- the isolation is real --------------------------------------------------


def test_the_isolated_environment_cannot_see_the_repository(tmp_path: Path) -> None:
    """Without this, every test below could be a false pass.

    The subprocess must not be able to reach `src/emailcheck/data/passive`
    through the working directory or through the repository being importable.
    """
    site = fake_site_packages(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    probe = run_isolated(
        "import pathlib, emailcheck, json;"
        "print(json.dumps({"
        "'cwd': str(pathlib.Path.cwd()),"
        "'repo_data_reachable': pathlib.Path('src/emailcheck/data/passive').is_dir(),"
        "'legacy_data_reachable': pathlib.Path('data/passive').is_dir(),"
        "'package': emailcheck.__file__}))",
        site,
        elsewhere,
    )

    assert probe.returncode == 0, probe.stderr
    answer = json.loads(probe.stdout)
    assert answer["cwd"] == str(elsewhere)
    assert answer["repo_data_reachable"] is False
    assert answer["legacy_data_reachable"] is False
    assert str(REPO) not in answer["package"], "the subprocess imported the checkout"


# --- the shipped snapshot loads from the package ----------------------------


def test_the_packaged_datasets_load_from_an_installed_layout(tmp_path: Path) -> None:
    """The property R3 is about: same files, same versions, no checkout."""
    site = fake_site_packages(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    probe = run_isolated(
        "import json;"
        "from emailcheck.classification.repository import load_shipped_datasets;"
        "d = load_shipped_datasets();"
        "print(json.dumps({'versions': d.versions, 'counts': d.entry_counts}))",
        site,
        elsewhere,
    )

    assert probe.returncode == 0, probe.stderr
    answer = json.loads(probe.stdout)
    expected = load_shipped_datasets()
    assert answer["versions"] == expected.versions
    assert answer["counts"] == expected.entry_counts
    assert answer["counts"]["role"] > 0


def test_the_version_report_from_an_installed_layout_names_the_same_role_version(
    tmp_path: Path,
) -> None:
    """Work item 6's reproducibility metadata, from a package rather than a tree."""
    site = fake_site_packages(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    probe = run_isolated(
        "import json;"
        "from emailcheck.classification.repository import load_shipped_datasets;"
        "from emailcheck.application.readiness import report_versions;"
        "r = report_versions(package_version='0.0.0', aggregation_ruleset='rs',"
        " datasets=load_shipped_datasets());"
        "print(json.dumps(r.as_json_object()))",
        site,
        elsewhere,
    )

    assert probe.returncode == 0, probe.stderr
    reported = json.loads(probe.stdout)
    shipped = load_shipped_datasets()
    assert reported["dataset_versions"]["role"] == shipped.versions["role"]
    assert reported["dataset_entry_counts"] == shipped.entry_counts
    # The declaration still holds for the three that ship empty.
    assert set(reported["unavailable_datasets"]) == {"disposable", "free_mail", "provider"}


def test_a_distribution_without_the_datasets_fails_loudly(tmp_path: Path) -> None:
    """**No silent fallback to an empty `PassiveDatasets`.**

    Three of these datasets are legitimately empty, so falling back would be
    indistinguishable from the intended state — and would reinstate exactly the
    defect the review found: the role list gone while the version report went on
    describing it. A missing packaged resource is a packaging error and must
    read as one.
    """
    site = fake_site_packages(tmp_path, with_datasets=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    probe = run_isolated(
        "from emailcheck.classification.repository import load_shipped_datasets;"
        "load_shipped_datasets()",
        site,
        elsewhere,
    )

    assert probe.returncode != 0
    assert "dataset" in probe.stderr.lower()
    assert "empty" not in probe.stdout


# --- what the distribution carries ------------------------------------------


def test_every_dataset_the_loader_reads_is_inside_the_package() -> None:
    """The snapshot and the code ship together, or neither ships."""
    for name in SHIPPED_FILES:
        assert (DATASETS / name).is_file(), f"{name} is not in the package"
    assert (DATASETS / "README.md").is_file(), "the provenance record left the snapshot"
    assert not (REPO / "data").exists(), "the pre-packaging location is still present"


def test_the_distribution_carries_no_test_corpus_or_secret(tmp_path: Path) -> None:
    """What a wheel would contain, inspected as a file list.

    `pyproject.toml` puts the package directory in the wheel, so this is that
    directory minus the exclusions. Nothing here may be a test, a beta corpus, a
    key, or a generated report.
    """
    site = fake_site_packages(tmp_path)
    shipped = sorted(
        path.relative_to(site).as_posix()
        for path in (site / "emailcheck").rglob("*")
        if path.is_file()
    )

    forbidden = (
        "test_",
        "conftest",
        "corpus",
        "authorization",
        ".key",
        ".pem",
        "secret",
        "report-",
    )
    offenders = [name for name in shipped if any(word in name.lower() for word in forbidden)]
    assert offenders == [], offenders

    data_files = [name for name in shipped if "/data/" in name]
    assert sorted(Path(name).name for name in data_files) == sorted([*SHIPPED_FILES, "README.md"])
    assert not [name for name in shipped if name.endswith(".example")], (
        "format examples are maintainer documentation and stay out of the distribution"
    )


def test_the_build_configuration_carries_the_datasets(tmp_path: Path) -> None:
    """The exclusions must not reach the data the loader needs.

    `packaged_files()` reads `pyproject.toml`, so excluding the dataset
    directory there removes it from the simulated install — and every load test
    above fails. This one names the property directly, so the reason is legible
    rather than a distant import error.
    """
    carried = {path.as_posix() for path in packaged_files()}

    for name in SHIPPED_FILES:
        assert f"data/passive/{name}" in carried, f"the wheel would not carry {name}"
    assert "data/passive/README.md" in carried

    site = fake_site_packages(tmp_path)
    assert (site / "emailcheck" / "data" / "passive" / "role_local_parts.toml").is_file()


@pytest.mark.inspection
def test_updating_a_dataset_needs_no_python_change() -> None:
    """The repository's published promise, checked against the packaging config.

    `pyproject.toml` must not name an individual dataset file, and no version
    string may be hard-coded in Python: populating or updating one of these is a
    data change, and a build configuration that listed them one by one would
    make it a code change as well.
    """
    configuration = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    for name in SHIPPED_FILES:
        assert name not in configuration, f"pyproject.toml names {name}"

    shipped_versions = set(load_shipped_datasets().versions.values())
    for source in (REPO / "src").rglob("*.py"):
        code = code_without_docstrings(source)
        for version in shipped_versions:
            assert version not in code, f"{source.name} hard-codes the dataset version {version}"


@pytest.mark.inspection
@pytest.mark.parametrize("name", SHIPPED_FILES)
def test_the_loader_reaches_each_file_through_the_resource_api(name: str) -> None:
    """No path is built from `__file__`, a parent walk, or the working directory."""
    code = code_without_docstrings(REPO / "src/emailcheck/classification/repository.py")

    assert "parents[" not in code, "the loader walks up from its own file again"
    assert "resources.files" in code
    assert (DATASETS / name).is_file()
