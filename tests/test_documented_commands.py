"""Every `emailcheck` command shown in the user documentation parses.

The commands are taken from the fenced code blocks of the README files, the
PyPI page, and the CLI reference, and handed to the real argument parsers.
Nothing is executed, so no command here reaches DNS or SMTP.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Final

import pytest

from emailcheck.apps import cli, commands

pytestmark = pytest.mark.docs_contract

ROOT: Final = Path(__file__).resolve().parent.parent
DOCUMENTS: Final = ("README.md", "README.en.md", "docs/pypi.md", "docs/usage-ja.md")
_FENCE: Final = re.compile(r"^(```|~~~)")


def documented_commands() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for name in DOCUMENTS:
        inside = False
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
            if _FENCE.match(line.strip()):
                inside = not inside
                continue
            text = line.strip().removeprefix("$ ")
            # A command, not a line of output such as "emailcheck batch: ...".
            if not inside or text.split(" ", 1)[0] != "emailcheck" or ": " in text:
                continue
            # Drop shell comments, redirections, and the `--help` overview.
            text = re.split(r"\s#\s|\s>\s|\s&&\s", text)[0].strip()
            if "<" in text or "..." in text:
                continue
            found.append((name, text))
    return found


COMMANDS_FOUND: Final = documented_commands()


def test_the_documents_show_commands() -> None:
    assert len(COMMANDS_FOUND) > 20
    assert any("--mode active" in command for _, command in COMMANDS_FOUND)


@pytest.mark.parametrize(("document", "command"), COMMANDS_FOUND, ids=lambda value: value)
def test_a_documented_command_parses(
    document: str, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = shlex.split(command)[1:]
    parser = commands.parser() if argv and argv[0] in commands.COMMANDS else cli.build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as stopped:
        assert stopped.code == 0, (document, command, capsys.readouterr().err)
