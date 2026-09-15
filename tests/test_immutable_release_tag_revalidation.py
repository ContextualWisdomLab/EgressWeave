"""Reject a release if its tag moves after the pre-publication check."""

from __future__ import annotations

import runpy
from pathlib import Path

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_immutable_release_publication.py"))
)
_run = _HELPERS["_run"]

_MOVED_TAG_SHA = "1" * 40


def test_published_release_revalidates_exact_tag_commit(tmp_path: Path) -> None:
    """Publication must not lock a tag that moved after the earlier preflight."""
    result, state = _run(tmp_path, tag_sha=_MOVED_TAG_SHA)
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert not state["verified_assets"]
