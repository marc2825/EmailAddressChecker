"""The gate itself is tested, because an unexercised gate is a comment.

Every forbidden command is written into a fixture that looks like production
SMTP code, and the scanner must refuse it. Every ordinary identifier that
contains a command as a substring is written into the same kind of fixture, and
the scanner must not.

This file names forbidden commands freely. That is the point of scanning only
production paths: a test has to be able to say the word in order to prove it is
refused.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from check_forbidden_smtp import (
    FORBIDDEN_COMMANDS,
    Finding,
    check_coverage,
    first_smtp_verb,
    iter_python_files,
    scan_source,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCANNER = REPOSITORY_ROOT / "scripts" / "check_forbidden_smtp.py"


def findings(source: str) -> list[Finding]:
    return scan_source(source, Path("fixture.py"))


def messages(source: str) -> str:
    return " | ".join(str(finding) for finding in findings(source))


# --- every forbidden command in a wire literal is refused -------------------


@pytest.mark.parametrize(
    ("literal", "verb"),
    [
        (r'"DATA\r\n"', "DATA"),
        (r'"AUTH PLAIN {credentials}"', "AUTH"),
        (r'"BDAT 123"', "BDAT"),
        (r'"VRFY user"', "VRFY"),
        (r'"EXPN list"', "EXPN"),
        (r'"SEND FROM:<probe@example.net>"', "SEND"),
        (r'"SOML FROM:<probe@example.net>"', "SOML"),
        (r'"SAML FROM:<probe@example.net>"', "SAML"),
    ],
)
def test_a_forbidden_command_literal_is_refused(literal: str, verb: str) -> None:
    """These are the eight the work order named. Each must fail the gate."""
    source = f"def write_line(stream):\n    return {literal}\n"
    reported = messages(source)
    assert reported, f"{verb} was not detected"
    assert verb in reported


@pytest.mark.parametrize("verb", sorted(FORBIDDEN_COMMANDS))
def test_every_published_forbidden_command_is_detected(verb: str) -> None:
    """The set is not decoration: each member is enforced."""
    source = f'def write_line(stream):\n    return "{verb} argument\\r\\n".encode()\n'
    assert verb in messages(source)


@pytest.mark.parametrize(
    "form",
    [
        'return "{verb}\\r\\n"',
        'return b"{verb}\\r\\n"',
        'return f"{verb} {{argument}}\\r\\n"',
        'return "{verb}" + " argument\\r\\n"',
        'return "{verb} argument".encode("ascii")',
        'return "  {verb}   argument  "',
        'return "{verb}:<probe@example.net>"',
    ],
)
def test_a_command_is_detected_however_the_line_is_built(form: str) -> None:
    """Concatenation and interpolation build a command line just as well."""
    source = "def write_line(stream):\n    " + form.format(verb="DATA") + "\n"
    assert "DATA" in messages(source)


def test_a_lowercase_command_is_still_a_command() -> None:
    """SMTP verbs are case insensitive on the wire."""
    assert "DATA" in messages('def f():\n    return "data\\r\\n"\n')


# --- ordinary identifiers are not commands ---------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "authentication = False\n",
        "def author():\n    return 1\n",
        "send_timeout = 3.0\n",
        "database = None\n",
        "metadata = {}\n",
        'CONFIG = {"authentication": False, "metadata": None}\n',
        "def read_metadata(database, send_timeout):\n    return database\n",
        "class Authenticator:\n    authorized = True\n",
        "x = obj.metadata\n",
        "y = call(send_timeout=1.0, authentication=None)\n",
        'DIAGNOSTIC = "mailbox unavailable"\n',
        'NOTE = "no authentication is performed"\n',
        "turnaround_seconds = 5\n",
        "data_directory = None\n",
        "expansion = 2\n",
    ],
)
def test_an_ordinary_identifier_is_not_a_command(source: str) -> None:
    """A gate that flags `authentication` is a gate somebody switches off."""
    assert findings(source) == [], messages(source)


def test_the_exact_five_names_the_work_order_listed_are_clean() -> None:
    source = "authentication = 1\nauthor = 2\nsend_timeout = 3\ndatabase = 4\nmetadata = 5\n"
    assert findings(source) == []


def test_a_docstring_may_forbid_a_command_by_name() -> None:
    """Production code has to be able to say what it must never do."""
    source = '"""This module never issues DATA, VRFY, EXPN, or AUTH."""\n\nvalue = 1\n'
    assert findings(source) == []


def test_a_docstring_may_not_hold_a_wire_line() -> None:
    """Naming a command is documentation; a CRLF-terminated line is not."""
    source = '"""Wire form:\\r\\nDATA\\r\\n"""\n\nvalue = 1\n'
    assert "DATA" in messages(source)


def test_a_command_hidden_after_the_first_wire_line_is_refused() -> None:
    """Reading only the first verb would report this as an EHLO."""
    source = 'BLOCK = "EHLO probe.example.net\\r\\nDATA\\r\\n"\n'
    assert "DATA" in messages(source)


def test_prose_wrapped_with_a_bare_newline_is_not_a_command() -> None:
    """A CRLF makes a wire line; a lone newline makes a paragraph."""
    source = 'NOTE = "connection lost\\ndata was never transmitted"\n'
    assert findings(source) == [], messages(source)


def test_a_comment_naming_a_command_is_not_a_finding() -> None:
    source = "# Never send DATA or AUTH here.\nvalue = 1\n"
    assert findings(source) == []


# --- identifiers that do name a command ------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "class SMTPCommand:\n    DATA = 'x'\n",
        "command = SMTPCommand.DATA\n",
        "def data(self):\n    return None\n",
        "def auth(self, mechanism):\n    return None\n",
        "stream.send(payload)\n",
        "value = module.VRFY\n",
        "def expn(self, alias):\n    return None\n",
    ],
)
def test_an_identifier_naming_a_command_is_refused(source: str) -> None:
    assert findings(source), source


@pytest.mark.parametrize(
    ("form", "label"),
    [
        ('return f"{verb} {argument}\\r\\n"', "f-string"),
        ('return "%s %s\\r\\n" % (verb, argument)', "percent formatting"),
        ('return "{} {}\\r\\n".format(verb, argument)', "str.format"),
        ('return verb + " " + argument + "\\r\\n"', "concatenation"),
        ('return b"%b\\r\\n" % verb.encode()', "bytes percent formatting"),
    ],
)
def test_a_dynamic_verb_is_refused(form: str, label: str) -> None:
    """A verb from a variable makes the closed enum meaningless.

    All four ordinary Python constructions are covered, not only the f-string:
    a review found the other three passed.
    """
    source = f"def write_line(verb, argument):\n    {form}\n"
    assert "run-time value" in messages(source), label


@pytest.mark.parametrize(
    "form",
    [
        'return f"EHLO {host}\\r\\n"',
        'return "EHLO %s\\r\\n" % host',
        'return "EHLO {}\\r\\n".format(host)',
        'return "EHLO " + host + "\\r\\n"',
    ],
)
def test_a_literal_verb_with_an_interpolated_argument_is_fine(form: str) -> None:
    """Only the head matters. The encoder itself is this shape."""
    source = f"def write_line(host):\n    {form}\n"
    assert findings(source) == [], messages(source)


def test_a_diagnostic_string_with_no_crlf_may_be_interpolated() -> None:
    source = 'def describe(stage):\n    return f"{stage} failed"\n'
    assert findings(source) == []


# --- the verb reader -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("DATA\r\n", "DATA"),
        ("data", "DATA"),
        ("AUTH PLAIN abc", "AUTH"),
        ("MAIL FROM:<a@b.example>", "MAIL"),
        ("RCPT TO:<a@b.example>", "RCPT"),
        ("BDAT 123 LAST", "BDAT"),
        ("  QUIT  ", "QUIT"),
        ("authentication", "AUTHENTICATION"),
        ("send_timeout", "SEND_TIMEOUT"),
        ("metadata", "METADATA"),
        ("", None),
        ("   ", None),
    ],
)
def test_the_first_verb_is_read_the_way_a_server_reads_it(text: str, expected: str | None) -> None:
    assert first_smtp_verb(text) == expected


# --- coverage of the production tree ---------------------------------------


def test_every_smtp_production_file_is_scanned() -> None:
    assert check_coverage(iter_python_files(REPOSITORY_ROOT), REPOSITORY_ROOT) == []


def test_the_scanner_covers_each_required_directory() -> None:
    scanned = {path.resolve() for path in iter_python_files(REPOSITORY_ROOT)}
    adapter_tree = REPOSITORY_ROOT / "src" / "emailcheck" / "adapters" / "smtp"
    for path in adapter_tree.rglob("*.py"):
        assert path.resolve() in scanned, path


def test_a_broken_glob_fails_rather_than_scanning_nothing(tmp_path: Path) -> None:
    """The dangerous failure is a gate that passes because it found no files."""
    assert iter_python_files(tmp_path) == []
    problems = check_coverage([], tmp_path)
    assert problems, "an empty tree must be reported, not accepted"


def test_the_scanner_does_not_scan_tests_or_documentation() -> None:
    scanned = {path.resolve() for path in iter_python_files(REPOSITORY_ROOT)}
    assert Path(__file__).resolve() not in scanned
    for path in scanned:
        assert "tests" not in path.relative_to(REPOSITORY_ROOT).parts


# --- the scanner as a command ----------------------------------------------


def test_the_repository_passes_the_gate() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCANNER)],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "passed" in result.stdout


def test_the_gate_fails_on_a_planted_command(tmp_path: Path) -> None:
    """End to end: a dangerous file in a scanned path exits non-zero."""
    planted = tmp_path / "src" / "emailcheck" / "domain"
    planted.mkdir(parents=True)
    (planted / "smtp_planted.py").write_text(
        'def write_line():\n    return "DATA\\r\\n".encode()\n', encoding="utf-8"
    )

    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCANNER), "--root", str(tmp_path), "--skip-coverage-check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "DATA" in result.stderr
