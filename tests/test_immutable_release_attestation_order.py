"""Reject release-attestation verification before publication."""

from __future__ import annotations

import runpy
from pathlib import Path

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_immutable_release_publication.py"))
)
_run = _HELPERS["_run"]
_script = _HELPERS["_script"]

_PUBLISH = 'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
_RELEASE_VERIFY = 'gh release verify "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY"'
_ASSET_LOOP_START = "for asset in release-evidence/*; do"


def test_release_attestation_verification_must_follow_publication(tmp_path: Path) -> None:
    """A draft has no immutable-release attestation to accept as publication evidence."""
    script = _script()
    assert script.count(_PUBLISH) == 1
    assert script.count(_RELEASE_VERIFY) == 1
    without_verify = script.replace(_RELEASE_VERIFY, "", 1)
    mutated = without_verify.replace(_PUBLISH, f"{_RELEASE_VERIFY}\n{_PUBLISH}", 1)
    result, state = _run(tmp_path, script=mutated)
    assert result.returncode != 0
    assert state["published"] is False
    assert not state["verified_assets"]


def test_asset_attestation_verification_must_follow_publication(tmp_path: Path) -> None:
    """Remote asset attestations cannot be accepted before release publication."""
    script = _script()
    assert script.count(_PUBLISH) == 1
    assert script.count(_ASSET_LOOP_START) >= 2
    loop_start = script.rindex(_ASSET_LOOP_START)
    loop_end = script.index("\ndone", loop_start) + len("\ndone")
    asset_loop = script[loop_start:loop_end]
    without_loop = script[:loop_start] + script[loop_end:]
    mutated = without_loop.replace(_PUBLISH, f"{asset_loop}\n{_PUBLISH}", 1)
    result, state = _run(tmp_path, script=mutated)
    assert result.returncode != 0
    assert state["published"] is False
    assert not state["verified_assets"]
