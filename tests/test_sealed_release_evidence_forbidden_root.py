"""Regression tests for the public manifest writer's forbidden-root boundary."""

from __future__ import annotations

import json
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


def test_public_writer_rejects_relative_symlinked_forbidden_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inspect the first named relative component and reject a symlink alias."""
    monkeypatch.chdir(tmp_path)
    real_evidence_root = Path("real-evidence")
    real_evidence_root.mkdir()
    alias = Path("alias")
    try:
        alias.symlink_to(real_evidence_root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable on this platform")
    output_path = Path("new-parent") / "manifest.json"

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=alias,
        )

    assert not output_path.parent.exists()


def test_public_writer_rejects_intermediate_symlink_erased_by_parent_traversal(
    tmp_path: Path,
) -> None:
    """Reject a lexical symlink component even when a later ``..`` hides it."""
    real_evidence_root = tmp_path / "real-evidence"
    child = real_evidence_root / "child"
    child.mkdir(parents=True)
    alias = real_evidence_root / "alias"
    try:
        alias.symlink_to(child, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable on this platform")
    forbidden_root = alias / ".."
    output_path = tmp_path / "new-parent" / "manifest.json"

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=forbidden_root,
        )

    assert not output_path.parent.exists()


def test_public_writer_accepts_real_forbidden_root_outside_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the documented safe-root success path and all three checks working."""
    forbidden_root = tmp_path / "real-evidence"
    forbidden_root.mkdir()
    output_path = tmp_path / "manifest-parent" / "manifest.json"
    original_check = release_evidence._require_output_outside_verified_set
    observed_roots: list[Path] = []

    def record_containment_check(path: Path, verified_root: Path) -> None:
        observed_roots.append(verified_root)
        original_check(path, verified_root)

    monkeypatch.setattr(
        release_evidence,
        "_require_output_outside_verified_set",
        record_containment_check,
    )

    release_evidence.write_evidence_manifest(
        MANIFEST,
        output_path,
        forbidden_root=forbidden_root,
    )

    assert json.loads(output_path.read_text(encoding="utf-8")) == MANIFEST
    assert observed_roots == [forbidden_root.resolve()] * 3


def test_public_writer_accepts_real_parent_traversal_without_symlinks(
    tmp_path: Path,
) -> None:
    """Permit lexical parent traversal when every named component is a real path."""
    forbidden_root = tmp_path / "real-evidence"
    child = forbidden_root / "child"
    child.mkdir(parents=True)
    output_path = tmp_path / "manifest-parent" / "manifest.json"

    release_evidence.write_evidence_manifest(
        MANIFEST,
        output_path,
        forbidden_root=child / "..",
    )

    assert json.loads(output_path.read_text(encoding="utf-8")) == MANIFEST


def test_public_writer_accepts_relative_real_parent_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve relative real-component parent traversal outside the output path."""
    monkeypatch.chdir(tmp_path)
    child = Path("real-evidence") / "child"
    child.mkdir(parents=True)
    output_path = Path("manifest-parent") / "manifest.json"

    release_evidence.write_evidence_manifest(
        MANIFEST,
        output_path,
        forbidden_root=child / "..",
    )

    assert json.loads(output_path.read_text(encoding="utf-8")) == MANIFEST


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


@pytest.mark.parametrize("failure_type", [OSError, RuntimeError])
def test_public_writer_normalizes_forbidden_root_inspection_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[Exception],
) -> None:
    """Normalize filesystem inspection failures before creating output storage."""
    forbidden_root = tmp_path / "evidence"
    forbidden_root.mkdir()
    output_path = tmp_path / "new-parent" / "manifest.json"
    original_is_symlink = Path.is_symlink

    def fail_forbidden_root(path: Path) -> bool:
        if path == forbidden_root:
            raise failure_type("private filesystem inspection detail")
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", fail_forbidden_root)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        release_evidence.write_evidence_manifest(
            MANIFEST,
            output_path,
            forbidden_root=forbidden_root,
        )

    assert not output_path.parent.exists()
