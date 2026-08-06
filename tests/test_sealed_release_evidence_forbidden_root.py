"""Regression tests for the public manifest writer's forbidden-root boundary."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_sealed_release_evidence_output_boundary import MANIFEST

from egressweave import release_evidence


def test_public_writer_rejects_symlinked_forbidden_root(tmp_path: Path) -> None:
    """Reject a symlink alias before writing inside its canonical target."""
    real_evidence_root = tmp_path / "real-evidence"
    real_evidence_root.mkdir()
    forbidden_root_alias = tmp_path / "evidence-alias"
    try:
        forbidden_root_alias.symlink_to(real_evidence_root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable on this platform")
    output_path = real_evidence_root / "manifest.json"

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=forbidden_root_alias,
        )

    assert not output_path.exists()
