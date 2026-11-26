"""The release workflow keeps its safety gates (issue #7).

Read as text, because the project has no YAML dependency. Each assertion is one
gate `docs/releasing.md` relies on: a tag push reaches only TestPyPI, PyPI needs
a manual run with the tag typed again, publishing stays behind the owner's
switch and a protected Environment, OIDC is granted only to the publish job,
and every action is pinned by commit SHA.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.inspection

WORKFLOW: Final = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"


def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_a_tag_push_publishes_only_to_testpypi() -> None:
    text = workflow()
    assert (
        "name: ${{ github.event_name == 'workflow_dispatch' && inputs.target || 'testpypi' }}"
        in text
    )
    assert "if: github.event_name == 'workflow_dispatch' && inputs.target == 'pypi'" in text
    assert "inputs.target || 'pypi'" not in text


def test_pypi_needs_the_tag_typed_as_confirmation() -> None:
    text = workflow()
    assert 'test "$CONFIRM" = "$TAG"' in text
    assert "CONFIRM: ${{ inputs.confirm }}" in text


def test_publishing_stays_behind_the_switch_the_version_check_and_the_build() -> None:
    text = workflow()
    assert "if: vars.PUBLISH_ENABLED == 'true'" in text
    assert '"refs/tags/v" + __version__' in text
    assert "needs: build" in text
    assert "needs: validate" in text
    for gate in ("python -m twine check dist/*", "python scripts/check_artifacts.py"):
        assert gate in text


def test_only_the_publish_job_can_request_an_oidc_token() -> None:
    text = workflow()
    assert text.count("id-token: write") == 1
    assert text.index("id-token: write") > text.index("  publish:")


def test_every_action_is_pinned_by_commit_sha() -> None:
    uses = re.findall(r"uses: (\S+)", workflow())
    actions = [use for use in uses if not use.startswith("./")]
    assert actions
    for action in actions:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action), action
