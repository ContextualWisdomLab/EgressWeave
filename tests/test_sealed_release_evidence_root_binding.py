"""Reject verified evidence paths that traverse a symlinked ancestor."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from test_sealed_release_evidence_source_identity import (
    REPOSITORY,
    SOURCE_SHA,
    _build,
    _evidence,
)

from egressweave import release_evidence


def _aliased_evidence(tmp_path: Path) -> Path:
    """Return a valid evidence directory reached through one parent symlink."""
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    evidence_dir = real_parent / "evidence"
    _evidence(evidence_dir)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    return alias_parent / evidence_dir.name


def test_public_verifier_rejects_symlinked_evidence_parent(tmp_path: Path) -> None:
    """Do not verify a valid set through a mutable ancestor link."""
    evidence_dir = _aliased_evidence(tmp_path)

    with pytest.raises(SystemExit, match="must not traverse symlinks"):
        _build(evidence_dir)


def test_cli_rejects_symlinked_evidence_parent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Do not issue a handoff manifest for an ancestor-aliased evidence root."""
    evidence_dir = _aliased_evidence(tmp_path)
    output = tmp_path / "manifest.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(release_evidence.__file__).resolve()),
            "--evidence-dir",
            str(evidence_dir),
            "--repository",
            REPOSITORY,
            "--source-sha",
            SOURCE_SHA,
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit, match="must not traverse symlinks"):
        release_evidence.main()

    assert not output.exists()


def test_public_verifier_normalizes_root_resolution_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Return one stable failure when the evidence root cannot canonicalize."""
    evidence_dir = tmp_path / "evidence"
    _evidence(evidence_dir)
    original_resolve = Path.resolve

    def fail_evidence_root(path: Path, *args, **kwargs):
        if path == evidence_dir:
            raise OSError("blocked")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_evidence_root)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        _build(evidence_dir)


def test_operator_references_preserve_primary_source_metadata() -> None:
    """Keep the cited modification year and joint POSIX authors exact."""
    repository_root = Path(__file__).resolve().parents[1]
    operator_guide = (repository_root / "docs/sealed-release-evidence.md").read_text(
        encoding="utf-8"
    )

    assert "CWE Content Team. (2025)." in operator_guide
    assert "CWE Content Team. (2026)." not in operator_guide
    assert "IEEE Computer Society, & The Open Group. (2018)." in operator_guide
    assert "IEEE Computer Society. (2018)." not in operator_guide
