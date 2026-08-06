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


def test_public_writer_rejects_missing_forbidden_root_before_parent_creation(
    tmp_path: Path,
) -> None:
    """Reject a missing exclusion root before creating the output directory."""
    output_path = tmp_path / "new-parent" / "manifest.json"

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=tmp_path / "missing-evidence",
        )

    assert not output_path.parent.exists()


def test_public_writer_rejects_file_forbidden_root_before_parent_creation(
    tmp_path: Path,
) -> None:
    """Reject a non-directory exclusion root before creating output storage."""
    forbidden_root = tmp_path / "not-a-directory"
    forbidden_root.write_text("not an evidence directory", encoding="utf-8")
    output_path = tmp_path / "new-parent" / "manifest.json"

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=forbidden_root,
        )

    assert not output_path.parent.exists()


def test_public_writer_normalizes_forbidden_root_resolution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize a canonicalization failure before creating output storage."""
    forbidden_root = tmp_path / "evidence"
    forbidden_root.mkdir()
    output_path = tmp_path / "new-parent" / "manifest.json"
    original_resolve = Path.resolve

    def fail_forbidden_root(path: Path, *args, **kwargs):
        if path == forbidden_root:
            raise OSError("blocked")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_forbidden_root)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=forbidden_root,
        )

    assert not output_path.parent.exists()
