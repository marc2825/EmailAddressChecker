"""The PyPI page (`docs/pypi.md`) works where PyPI shows it.

PyPI cannot resolve repository-relative links or images, so every link must be
absolute, and every link into this repository must point at the tag of the
version being published, not at `main`, so the page describes the release it
belongs to.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Final

import pytest

from emailcheck import __version__

pytestmark = pytest.mark.docs_contract

ROOT: Final = Path(__file__).resolve().parent.parent
PAGE: Final = ROOT / "docs" / "pypi.md"
REPOSITORY: Final = "https://github.com/marc2825/EmailAddressChecker/"
_LINK: Final = re.compile(r"\]\(([^)\s]+)\)")


def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_the_package_uses_the_pypi_page() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["readme"] == "docs/pypi.md"


def test_every_link_is_absolute_and_pinned_to_this_version() -> None:
    links = _LINK.findall(page())
    assert links
    for link in links:
        assert link.startswith("https://"), link
        if link.startswith(REPOSITORY):
            tag = f"/v{__version__}"
            assert f"{tag}/" in link or link.endswith(tag), link


def test_the_page_has_no_image_or_html() -> None:
    text = page()
    assert "![" not in text
    assert "<img" not in text
    assert "<picture" not in text


def test_the_page_states_the_limits() -> None:
    text = page()
    assert "Passive Mode checks syntax and DNS/MX and never connects to a mail server" in text
    assert "never sends a message" in text
    assert "Neither can show that a mailbox exists" in text
    assert "acknowledged = true" in text
    assert "`unknown`, which is not the same as invalid" in text
    assert "メールボックスの実在やメールの到達は証明しません" in text
