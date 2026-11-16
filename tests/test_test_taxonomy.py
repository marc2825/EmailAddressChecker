"""The suite keeps specification tests apart from structural ones.

Issue #2 observed that tests reading source code or documents pin structure,
so a harmless refactor or rewording can fail them, and asked for them to be
separated from tests of behavior. They are separated by marker rather than
deleted, because most guard a safety property no example can show (no code
path sends `DATA`, no module outside the composition root names a low-level
SMTP component, the reason-code table matches the enum):

- `inspection` — the test reads project source, or its syntax tree;
- `docs_contract` — the test reads published documentation.

`python -m pytest -m "not inspection and not docs_contract"` runs the
specification tests alone; CI runs both groups as separate steps, so which kind
failed is visible at a glance. `docs/test-strategy.md` states the policy.

This module keeps the split honest. It finds, statically, every test that can
reach a source- or document-reading operation through its own body, the
module's helper functions and constants, or a module-local fixture, and fails
when such a test lacks its marker. It also fails when a marker is put on a
single test that reads neither, because a misplaced marker would move a
specification test out of the specification run.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.inspection

TESTS: Final = Path(__file__).resolve().parent

INSPECTION: Final = "inspection"
DOCS_CONTRACT: Final = "docs_contract"

#: Calls that read Python source or turn it into a syntax tree.
_SOURCE_CALLS: Final = frozenset(
    {
        ("ast", "parse"),
        ("inspect", "getsource"),
        ("inspect", "getsourcelines"),
        ("inspect", "getsourcefile"),
    }
)


@dataclass(frozen=True, slots=True)
class Reads:
    source: bool = False
    docs: bool = False

    def __or__(self, other: Reads) -> Reads:
        return Reads(self.source or other.source, self.docs or other.docs)


def _direct(node: ast.AST) -> Reads:
    """What one definition reads by itself, ignoring what it refers to."""
    source = docs = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            owner = child.func.value
            if isinstance(owner, ast.Name) and (owner.id, child.func.attr) in _SOURCE_CALLS:
                source = True
        elif isinstance(child, ast.Attribute) and child.attr == "__file__":
            # `some_module.__file__` locates a module's source to read it. The
            # bare name `__file__` (this test's own path) is an ast.Name.
            source = True
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            text = child.value
            if text.endswith(".py") and "\n" not in text:
                source = True
            if text == "docs" or text.startswith("docs/") or text.endswith(".md"):
                docs = True
    return Reads(source, docs)


def _referenced(node: ast.AST) -> set[str]:
    names = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        # Fixture parameters are references to module-level fixture functions.
        names |= {arg.arg for arg in node.args.args + node.args.kwonlyargs}
    return names


def _definitions(tree: ast.Module) -> dict[str, ast.AST]:
    found: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            found[node.target.id] = node
    return found


def _marks(decorators: list[ast.expr]) -> set[str]:
    """Names of `pytest.mark.<name>` used in a decorator list or `pytestmark`."""
    found: set[str] = set()
    for expr in decorators:
        for child in ast.walk(expr):
            if (
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Attribute)
                and child.value.attr == "mark"
            ):
                found.add(child.attr)
    return found


@dataclass(frozen=True, slots=True)
class SuiteEntry:
    module: Path
    name: str
    reads: Reads
    module_marks: frozenset[str]
    own_marks: frozenset[str]

    @property
    def marks(self) -> frozenset[str]:
        return self.module_marks | self.own_marks

    @property
    def label(self) -> str:
        return f"{self.module.relative_to(TESTS.parent)}::{self.name}"


def _module_marks(tree: ast.Module) -> frozenset[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets
        ):
            return frozenset(_marks([node.value]))
    return frozenset()


def _analyse(path: Path) -> Iterator[SuiteEntry]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    definitions = _definitions(tree)
    module_marks = _module_marks(tree)
    memo: dict[str, Reads] = {}

    def reach(name: str, visiting: frozenset[str]) -> Reads:
        if name in memo:
            return memo[name]
        node = definitions[name]
        reads = _direct(node)
        for other in _referenced(node) & definitions.keys():
            if other not in visiting and other != name:
                reads = reads | reach(other, visiting | {name})
        memo[name] = reads
        return reads

    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "test"
        ):
            yield SuiteEntry(
                module=path,
                name=node.name,
                reads=reach(node.name, frozenset()),
                module_marks=module_marks,
                own_marks=frozenset(_marks(node.decorator_list)),
            )


#: Tests the scan flags although they pin neither source structure nor document
#: wording, each with the reason. Keys are a module path (the whole module) or
#: `path::test`. The scan is deliberately broad — any `.py` or `.md` name counts
#: — so that a new structural test cannot slip through by spelling a path
#: differently; this list is the price, and it is checked for staleness below.
NOT_STRUCTURAL: Final[dict[str, str]] = {
    "tests/test_test_taxonomy.py": (
        "this scanner: its own string constants name the signals it looks for"
    ),
    "tests/unit/scripts/test_forbidden_smtp_scanner.py": (
        "the specification of the SMTP-command scanner, whose input is source "
        "text; the fixtures are synthetic files written to tmp_path"
    ),
    "tests/test_package.py::test_package_imports": (
        "compares a configured version path string; reads only pyproject.toml"
    ),
    "tests/unit/test_remediation_c.py::test_a_crashed_writer_does_not_hold_the_fence_forever": (
        "writes a helper script for a subprocess it then kills"
    ),
    "tests/test_packaged_datasets.py::test_every_dataset_the_loader_reads_is_inside_the_package": (
        "names README.md as a packaged file, not as text to match"
    ),
    "tests/test_packaged_datasets.py::test_the_distribution_carries_no_test_corpus_or_secret": (
        "names README.md as a packaged file, not as text to match"
    ),
    "tests/test_packaged_datasets.py::test_the_build_configuration_carries_the_datasets": (
        "names README.md as a packaged file, not as text to match"
    ),
}


def _exempt(test: SuiteEntry) -> bool:
    module = str(test.module.relative_to(TESTS.parent))
    return module in NOT_STRUCTURAL or test.label in NOT_STRUCTURAL


@cache
def suite() -> tuple[SuiteEntry, ...]:
    return tuple(test for path in sorted(TESTS.rglob("test_*.py")) for test in _analyse(path))


def checked() -> tuple[SuiteEntry, ...]:
    return tuple(test for test in suite() if not _exempt(test))


def test_the_markers_are_registered() -> None:
    """`--strict-markers` refuses an unregistered marker; this names the two."""
    config = (TESTS.parent / "pyproject.toml").read_text(encoding="utf-8")
    for marker in (INSPECTION, DOCS_CONTRACT):
        assert f'"{marker}:' in config


def test_the_analysis_sees_the_whole_suite() -> None:
    """A scan that found nothing would pass every rule below vacuously."""
    tests = suite()
    assert len(tests) > 1000
    assert sum(test.reads.source for test in tests) > 100
    assert sum(test.reads.docs for test in tests) > 50


def test_every_exemption_is_still_needed() -> None:
    """An exemption whose test no longer trips the scan is a hole for a new one."""
    flagged = {t.label for t in suite() if t.reads.source or t.reads.docs}
    modules = {label.split("::")[0] for label in flagged}
    stale = [
        key for key in NOT_STRUCTURAL if (key not in flagged if "::" in key else key not in modules)
    ]
    assert stale == []


def test_every_test_that_reads_source_is_marked_inspection() -> None:
    missing = [t.label for t in checked() if t.reads.source and INSPECTION not in t.marks]
    assert missing == [], "mark these @pytest.mark.inspection"


def test_every_test_that_reads_documentation_is_marked_docs_contract() -> None:
    missing = [t.label for t in checked() if t.reads.docs and DOCS_CONTRACT not in t.marks]
    assert missing == [], "mark these @pytest.mark.docs_contract"


def test_a_marker_on_one_test_is_never_on_a_specification_test() -> None:
    """A per-test marker moves that test out of the specification run.

    Module-level `pytestmark` is exempt: a dedicated module (`*_inspection.py`,
    `test_docs_*.py`) is structural as a whole, even where one of its tests
    builds a real value to compare with the source or the document.
    """
    misplaced = [
        t.label
        for t in suite()
        if (INSPECTION in t.own_marks and not t.reads.source)
        or (DOCS_CONTRACT in t.own_marks and not t.reads.docs)
    ]
    assert misplaced == []


@pytest.mark.parametrize(
    ("pattern", "marker"),
    [("*_inspection.py", INSPECTION), ("test_docs_*.py", DOCS_CONTRACT)],
)
def test_dedicated_modules_are_marked_as_a_whole(pattern: str, marker: str) -> None:
    modules = sorted(TESTS.rglob(pattern))
    assert modules, pattern
    unmarked = [
        str(path.relative_to(TESTS.parent))
        for path in modules
        if marker not in _module_marks(ast.parse(path.read_text(encoding="utf-8")))
    ]
    assert unmarked == []
