"""Reject release publication sequences that violate draft-creation order."""

from __future__ import annotations

import runpy
from pathlib import Path

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_immutable_release_publication.py"))
)
_run = _HELPERS["_run"]
_script = _HELPERS["_script"]


def test_release_edit_must_follow_matching_draft_creation(tmp_path: Path) -> None:
    """Publishing before the matching draft exists must fail closed."""
    script = _script()
    edit = 'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
    create = 'gh release create "$RELEASE_TAG"'
    assert script.count(edit) == 1
    assert script.count(create) == 1
    without_edit = script.replace(edit, "", 1)
    mutated = without_edit.replace(create, f"{edit}\n{create}", 1)
    result, state = _run(tmp_path, script=mutated)
    assert result.returncode != 0
    assert not state["published"]
