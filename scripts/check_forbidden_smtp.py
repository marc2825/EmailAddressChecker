"""Refuse any production SMTP path that could emit a forbidden command.

This is a structural scan, not a text search. Both naive approaches fail in the
direction that matters:

- a substring search for the `AUTH` token flags `authentication`, `author`, and
  `authorized`, so it gets disabled or ignored;
- an exact-literal comparison, which is what this script did before Phase 4A,
  misses every command that carries an argument. `"DATA\\r\\n"` happens to strip
  to exactly `DATA`, but `"AUTH PLAIN {credentials}"`, `"BDAT 42"`, `"VRFY x"`,
  and `"SEND FROM:<a>"` do not, and each of those is a real command line.

So a string is read the way a receiving server reads it: take the first SMTP
token, the verb, and compare that. Identifiers are compared only on an exact
match, so `send_timeout` and `metadata` are ordinary names while `SEND` and
`DATA` are not.

Only production SMTP paths are scanned. Tests and documentation must be able to
name a forbidden command in order to prove it is refused.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]

#: Every production path that could serialize an SMTP command. These are globs
#: rather than fixed paths so a new module lands inside the fence by default.
SCAN_PATTERNS: Final[tuple[str, ...]] = (
    "src/emailcheck/domain/smtp*.py",
    "src/emailcheck/application/*smtp*.py",
    "src/emailcheck/adapters/smtp/**/*.py",
    "src/emailcheck/ports/*smtp*.py",
)

#: Paths that must be covered. A glob that stops matching is a gate that stops
#: working, and it would fail silently: nothing scanned means nothing found.
REQUIRED_COVERAGE: Final[tuple[str, ...]] = (
    "src/emailcheck/domain/smtp_contract.py",
    "src/emailcheck/domain/smtp_command.py",
    "src/emailcheck/domain/smtp_session.py",
    "src/emailcheck/ports/smtp.py",
)

#: Directories whose every Python file must be scanned.
REQUIRED_COVERAGE_TREES: Final[tuple[str, ...]] = ("src/emailcheck/adapters/smtp",)

# The tokens below are split so this file does not itself contain a forbidden
# command as a single literal. The scanner never scans `scripts/`, but a future
# reviewer grepping the tree should not find one here either.
_MESSAGE_CONTENT: Final = "message content submission"
_ENUMERATION: Final = "recipient enumeration"
_RELAY: Final = "relay or queue control"
_TRUST: Final = "trusted-peer impersonation"

#: Command verbs this project must never emit, and why each is refused.
FORBIDDEN_COMMANDS: Final[dict[str, str]] = {
    "DA" + "TA": _MESSAGE_CONTENT,
    "BD" + "AT": _MESSAGE_CONTENT,
    "SE" + "ND": _MESSAGE_CONTENT,
    "SO" + "ML": _MESSAGE_CONTENT,
    "SA" + "ML": _MESSAGE_CONTENT,
    "VR" + "FY": _ENUMERATION,
    "EX" + "PN": _ENUMERATION,
    "AU" + "TH": "authentication; this project probes from a managed identity",
    "TU" + "RN": _RELAY,
    "AT" + "RN": _RELAY,
    "ET" + "RN": _RELAY,
    "BU" + "RL": _MESSAGE_CONTENT,
    "XCLI" + "ENT": _TRUST,
    "XFOR" + "WARD": _TRUST,
}

#: An SMTP verb is separated from its argument by a space or, for the two
#: address commands, by a colon. Nothing else splits a verb.
_VERB_SEPARATOR: Final = re.compile(r"[\s:]")

_WIRE_TERMINATOR: Final = "\r\n"


class Finding:
    """One reason a file was refused."""

    __slots__ = ("line", "message", "path")

    def __init__(self, path: Path, line: int, message: str) -> None:
        self.path = path
        self.line = line
        self.message = message

    def __str__(self) -> str:
        try:
            shown = self.path.relative_to(ROOT)
        except ValueError:
            shown = self.path
        return f"{shown}:{self.line}: {self.message}"


def first_smtp_verb(text: str) -> str | None:
    """Return the command verb a receiving server would read from `text`.

    `"AUTH PLAIN abc"` is the `AUTH` command. `"authentication"` is one word and
    is not a command. That difference is the whole point of this function.
    """
    stripped = text.strip()
    if not stripped:
        return None
    verb = _VERB_SEPARATOR.split(stripped, maxsplit=1)[0]
    return verb.upper() if verb else None


def command_verbs(text: str) -> list[str]:
    """Return the verb of every wire line in `text`.

    A literal holding more than one command is one CRLF-separated line per
    command, exactly as a server reads them, so each line is read rather than
    only the first. Without this, `"EHLO {host}\\r\\nDATA\\r\\n"` would be
    reported as an `EHLO`.

    The split is on CRLF alone. Ordinary prose wraps with a bare newline, so
    `"connection lost\\ndata was discarded"` stays one line and is not a command.
    """
    verbs: list[str] = []
    for segment in text.split(_WIRE_TERMINATOR):
        verb = first_smtp_verb(segment)
        if verb is not None:
            verbs.append(verb)
    return verbs


def _string_value(node: ast.expr) -> str | None:
    """Return the literal text of a string or bytes constant."""
    if not isinstance(node, ast.Constant):
        return None
    if isinstance(node.value, str):
        return node.value
    if isinstance(node.value, bytes):
        return node.value.decode("utf-8", errors="replace")
    return None


def _leading_literal(node: ast.expr) -> str | None:
    """Return the text a wire line starts with, folding the forms that build one.

    An f-string and a `+` concatenation both produce a command line, so both are
    read for the literal text that precedes any interpolation.
    """
    direct = _string_value(node)
    if direct is not None:
        return direct
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            text = _string_value(value)
            if text is None:
                break
            parts.append(text)
        return "".join(parts) if parts else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _leading_literal(node.left)
        if left is None:
            return None
        right = _leading_literal(node.right)
        return left if right is None else left + right
    return None


def _docstring_nodes(tree: ast.Module) -> set[int]:
    """Identify docstrings, which describe a command rather than sending one."""
    holders: list[ast.AST] = [tree]
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            holders.append(node)
    for holder in holders:
        body = getattr(holder, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            found.add(id(first.value))
    return found


def _identifier_names(node: ast.AST) -> Iterable[str]:
    """Every name this node introduces or reads, for exact comparison."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, ast.Attribute):
        yield node.attr
    elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        yield node.name
    elif isinstance(node, ast.arg) or (isinstance(node, ast.keyword) and node.arg is not None):
        yield node.arg


def scan_source(source: str, path: Path) -> list[Finding]:
    """Return every reason this source may not be part of an SMTP path."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        return [Finding(path, error.lineno or 0, f"file does not parse: {error.msg}")]

    findings: list[Finding] = []
    docstrings = _docstring_nodes(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant | ast.JoinedStr | ast.BinOp):
            text = _leading_literal(node)
            if text is None:
                continue
            is_docstring = id(node) in docstrings
            # A docstring may name a command in order to forbid it, but not in
            # wire form: a CRLF-terminated line is a command line wherever it
            # sits, and prose does not contain one.
            if is_docstring and _WIRE_TERMINATOR not in text:
                continue
            for verb in command_verbs(text):
                if verb in FORBIDDEN_COMMANDS:
                    findings.append(
                        Finding(
                            path,
                            node.lineno,
                            f"forbidden SMTP command {verb!r} in a command literal "
                            f"({FORBIDDEN_COMMANDS[verb]})",
                        )
                    )
            continue

        for name in _identifier_names(node):
            if name.upper() in FORBIDDEN_COMMANDS:
                findings.append(
                    Finding(
                        path,
                        node.lineno,
                        f"forbidden SMTP command {name.upper()!r} named by the identifier "
                        f"{name!r} ({FORBIDDEN_COMMANDS[name.upper()]})",
                    )
                )

    findings.extend(_scan_dynamic_command_lines(tree, path))
    return sorted(findings, key=lambda finding: (finding.line, finding.message))


_DYNAMIC_HEAD_MESSAGE: Final = (
    "SMTP command line begins with a run-time value; the verb must come from "
    "the closed command enum, not from a variable"
)


def _joined_literal(node: ast.JoinedStr) -> str:
    return "".join(text for value in node.values if (text := _string_value(value)) is not None)


def _leftmost_operand(node: ast.expr) -> ast.expr:
    """Descend the left spine of a `+` chain to whatever starts the line."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.left
    return node


def _concatenated_literal(node: ast.BinOp) -> str:
    """Every literal fragment in a `+` chain, in order, ignoring the rest."""
    parts: list[str] = []

    def walk(current: ast.expr) -> None:
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            walk(current.left)
            walk(current.right)
            return
        text = _string_value(current)
        if text is not None:
            parts.append(text)

    walk(node)
    return "".join(parts)


def _scan_dynamic_command_lines(tree: ast.Module, path: Path) -> list[Finding]:
    """Refuse a wire line whose verb comes from a run-time value.

    A command name assembled at run time is a raw-command API by another route:
    the closed enum stops meaning anything if the verb is a variable. Four
    ordinary Python constructions do this, and all four are refused:

    ```text
    f"{verb} {arg}\\r\\n"            an f-string starting with a placeholder
    "%s %s\\r\\n" % (verb, arg)      percent formatting starting with a spec
    "{} {}\\r\\n".format(verb, arg)  str.format starting with a field
    verb + " " + arg + "\\r\\n"      concatenation starting with a name
    ```

    A literal that merely *contains* a placeholder later in the line is fine:
    `f"EHLO {host}\\r\\n"` names its verb. Only the head matters.

    Deliberate obfuscation — `"".join(["DA", "TA"])`, `bytes([68, 65, 84, 65])`,
    `base64.b64decode(...)` — is out of scope. No static scan catches a computed
    string, and chasing it would trade real coverage for the appearance of it.
    ADR 0008 records that threat model: this defends against accidental
    introduction and ordinary drift, not against a committer who means it.
    """
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if _has_dynamic_verb(node):
            findings.append(Finding(path, node.lineno, _DYNAMIC_HEAD_MESSAGE))
    return findings


def _has_dynamic_verb(node: ast.AST) -> bool:
    """Whether `node` builds a wire line whose first token is not a literal."""
    # f"{verb} ...\r\n"
    if isinstance(node, ast.JoinedStr) and node.values:
        return _WIRE_TERMINATOR in _joined_literal(node) and isinstance(
            node.values[0], ast.FormattedValue
        )

    if isinstance(node, ast.BinOp):
        # "%s ...\r\n" % (verb, arg), including the bytes form.
        if isinstance(node.op, ast.Mod):
            template = _string_value(node.left)
            return (
                template is not None
                and _WIRE_TERMINATOR in template
                and template.lstrip().startswith("%")
            )
        # verb + " " + arg + "\r\n"
        if isinstance(node.op, ast.Add):
            literal = _concatenated_literal(node)
            if _WIRE_TERMINATOR not in literal:
                return False
            return _string_value(_leftmost_operand(node)) is None

    # "{} ...\r\n".format(verb, arg)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        template = _string_value(node.func.value)
        return (
            template is not None
            and _WIRE_TERMINATOR in template
            and template.lstrip().startswith("{")
        )

    return False


def scan_file(path: Path) -> list[Finding]:
    return scan_source(path.read_text(encoding="utf-8"), path)


def iter_python_files(root: Path = ROOT, patterns: Sequence[str] = SCAN_PATTERNS) -> list[Path]:
    """Every production file the fence covers, deduplicated and ordered."""
    found: dict[Path, None] = {}
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                found[path.resolve()] = None
    return list(found)


def check_coverage(scanned: Sequence[Path], root: Path = ROOT) -> list[str]:
    """Report production paths the globs failed to reach.

    Without this, deleting a pattern or misspelling one would make the scan
    pass by scanning nothing at all.
    """
    covered = {path.resolve() for path in scanned}
    problems: list[str] = []
    for relative in REQUIRED_COVERAGE:
        target = (root / relative).resolve()
        if not target.is_file():
            problems.append(f"required file is missing: {relative}")
        elif target not in covered:
            problems.append(f"required file is not scanned: {relative}")
    for relative in REQUIRED_COVERAGE_TREES:
        tree = (root / relative).resolve()
        if not tree.is_dir():
            problems.append(f"required directory is missing: {relative}")
            continue
        for path in sorted(tree.rglob("*.py")):
            if path.resolve() not in covered:
                problems.append(f"required file is not scanned: {path.relative_to(root)}")
    return problems


def scan_paths(paths: Sequence[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_file(path))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to scan; the default is this repository",
    )
    parser.add_argument(
        "--skip-coverage-check",
        action="store_true",
        help="scan without requiring the known production paths to exist",
    )
    arguments = parser.parse_args(argv)
    root: Path = arguments.root.resolve()

    scanned = iter_python_files(root)
    problems: list[str] = []
    if not arguments.skip_coverage_check:
        problems = check_coverage(scanned, root)

    findings = scan_paths(scanned)

    if problems or findings:
        for problem in problems:
            print(f"coverage: {problem}", file=sys.stderr)
        for finding in findings:
            print(str(finding), file=sys.stderr)
        return 1

    print(f"SMTP invariant scan passed ({len(scanned)} files, {len(FORBIDDEN_COMMANDS)} commands).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
