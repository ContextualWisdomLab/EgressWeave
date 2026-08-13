"""Regressions for sealed release-evidence root membership stability."""

from __future__ import annotations

from pathlib import Path

import pytest

from egressweave import release_evidence

VERSION = "0.3.0"


def _minimal_evidence(root: Path) -> None:
    """Create the exact six direct-child names needed by the snapshot boundary."""
    root.mkdir()
    names = (
        f"egressweave-{VERSION}-py3-none-any.whl",
        f"egressweave-{VERSION}.tar.gz",
        f"egressweave-{VERSION}-py3-none-any.whl.cdx.json",
        f"egressweave-{VERSION}.tar.gz.cdx.json",
        "SOURCE_IDENTITY.json",
        "SHA256SUMS",
    )
    for name in names:
        (root / name).write_bytes(b"bounded fixture")


def test_snapshot_rejects_membership_change_after_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an extra direct child added after the admitted member set is selected."""
    root = tmp_path / "evidence"
    snapshot_root = tmp_path / "snapshot"
    _minimal_evidence(root)
    snapshot_root.mkdir()
    original_select = release_evidence._select_evidence_paths
    root_identity = release_evidence._evidence_root_identity(root)
    source_selections = 0

    def select_then_add_unexpected_member(
        candidate: Path,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        """Add one unreviewed direct child immediately after source selection."""
        nonlocal source_selections
        selected = original_select(candidate)
        if release_evidence._evidence_root_identity(candidate) == root_identity:
            source_selections += 1
            if source_selections == 1:
                (root / "unexpected.txt").write_bytes(b"unreviewed evidence")
        return selected

    monkeypatch.setattr(
        release_evidence,
        "_select_evidence_paths",
        select_then_add_unexpected_member,
    )

    with pytest.raises(SystemExit, match="cardinality mismatch"):
        release_evidence._snapshot_selected_evidence(root, snapshot_root)


def test_snapshot_accepts_private_root_through_symlinked_parent(tmp_path: Path) -> None:
    """Accept a private snapshot whose lexical parent aliases its real location."""
    root = tmp_path / "evidence"
    _minimal_evidence(root)
    real_parent = tmp_path / "private"
    real_parent.mkdir()
    alias_parent = tmp_path / "var"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    snapshot_root = alias_parent / "snapshot"
    snapshot_root.mkdir()

    snapshot_paths, _, _, _ = release_evidence._snapshot_selected_evidence(
        root,
        snapshot_root,
    )

    canonical_snapshot_root = snapshot_root.resolve(strict=True)
    assert {path.parent for path in snapshot_paths} == {canonical_snapshot_root}


def test_snapshot_rejects_unavailable_private_root(tmp_path: Path) -> None:
    """Fail closed when the private snapshot root cannot be resolved strictly."""
    root = tmp_path / "evidence"
    _minimal_evidence(root)
    missing_snapshot_root = tmp_path / "missing-snapshot"

    with pytest.raises(
        SystemExit,
        match="release evidence snapshot directory is unavailable",
    ):
        release_evidence._snapshot_selected_evidence(root, missing_snapshot_root)
