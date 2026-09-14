"""Guard the draft-to-public transition in the immutable release harness."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = Path(__file__).with_name("test_immutable_release_publication.py")
_SPEC = importlib.util.spec_from_file_location(
    "test_immutable_release_publication_contract", _MODULE_PATH
)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - import machinery invariant
    raise RuntimeError("release publication test harness could not be loaded")
_HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HARNESS)


def test_release_edit_must_clear_draft_before_metadata_can_be_public(
    tmp_path: Path,
) -> None:
    """Omitting ``--draft=false`` must not produce publishable release metadata."""
    script = _HARNESS._script()
    expected = (
        'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
    )
    assert expected in script
    mutated = script.replace(
        expected,
        'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY"',
        1,
    )
    result, state = _HARNESS._run(tmp_path, script=mutated)
    assert result.returncode != 0
    assert state["published"] is False
