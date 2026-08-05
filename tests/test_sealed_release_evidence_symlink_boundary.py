"""Regression tests for the public evidence-directory symlink boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from egressweave.release_evidence import build_evidence_manifest


def test_public_verifier_rejects_a_symlinked_evidence_directory(tmp_path: Path) -> None:
    """Do not erase the caller-visible symlink boundary through path resolution."""
    real_directory = tmp_path / "real-evidence"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked-evidence"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        build_evidence_manifest(
            linked_directory,
            repository="ContextualWisdomLab/EgressWeave",
            source_sha="0123456789abcdef0123456789abcdef01234567",
        )
