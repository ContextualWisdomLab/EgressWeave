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
    source_selections = 0

    def select_then_add_unexpected_member(
        candidate: Path,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        """Add one unreviewed direct child immediately after source selection."""
        nonlocal source_selections
        selected = original_select(candidate)
        if candidate == root:
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
