"""Reject release-attestation verification before publication."""

from __future__ import annotations

import runpy
from pathlib import Path

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_immutable_release_publication.py"))
)
_run = _HELPERS["_run"]
_script = _HELPERS["_script"]


def test_release_attestation_verification_must_follow_publication(tmp_path: Path) -> None:
    """A draft has no immutable-release attestation to accept as publication evidence."""
    script = _script()
    publish = 'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
    verify = 'gh release verify "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY"'
    assert script.count(publish) == 1
    assert script.count(verify) == 1
    without_verify = script.replace(verify, "", 1)
    mutated = without_verify.replace(publish, f"{verify}\n{publish}", 1)
    result, state = _run(tmp_path, script=mutated)
    assert result.returncode != 0
    assert state["published"] is False
    assert not state["verified_assets"]
