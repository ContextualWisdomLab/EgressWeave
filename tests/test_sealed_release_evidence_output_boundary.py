"""Tests for fail-closed sealed-evidence manifest output."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from egressweave import release_evidence

MANIFEST: dict[str, Any] = {
    "artifacts": [],
    "cycloneDxSpecVersion": "1.7",
    "format": "egressweave.release-evidence",
    "formatVersion": 1,
    "predicateType": "https://cyclonedx.org/bom",
    "repository": "ContextualWisdomLab/EgressWeave",
    "sourceSha": "0123456789abcdef0123456789abcdef01234567",
}


def test_manifest_output_refuses_overwrite_and_preserves_existing_bytes(
    tmp_path: Path,
) -> None:
    """Never replace a prior handoff manifest with newer unreviewed evidence."""
    output = tmp_path / "manifest.json"
    output.write_bytes(b"existing evidence\n")

    with pytest.raises(SystemExit, match="already exists"):
        release_evidence.write_evidence_manifest(MANIFEST, output)

    assert output.read_bytes() == b"existing evidence\n"


def test_manifest_output_refuses_symlink_without_changing_target(tmp_path: Path) -> None:
    """Do not follow an attacker-controlled final-path symbolic link."""
    target = tmp_path / "target.json"
    target.write_bytes(b"trusted target\n")
    output = tmp_path / "manifest.json"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(SystemExit, match="already exists"):
        release_evidence.write_evidence_manifest(MANIFEST, output)

    assert output.is_symlink()
    assert target.read_bytes() == b"trusted target\n"


@pytest.mark.parametrize(
    "manifest",
    [[], {"bad": float("nan")}, {"bad": object()}, {"bad": (1,)}],
)
def test_manifest_output_rejects_non_strict_json_before_file_creation(
    tmp_path: Path,
    manifest: object,
) -> None:
    """Reject ambiguous or Python-only values before touching the output path."""
    output = tmp_path / "manifest.json"

    with pytest.raises(SystemExit, match="strict JSON object"):
        release_evidence.write_evidence_manifest(manifest, output)

    assert not output.exists()


def test_manifest_output_creates_private_regular_file(tmp_path: Path) -> None:
    """Create a new regular output with owner-only permissions where supported."""
    output = tmp_path / "new" / "manifest.json"

    release_evidence.write_evidence_manifest(MANIFEST, output)

    assert output.is_file()
    assert output.read_text(encoding="utf-8").endswith("\n")
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_manifest_output_normalizes_unusable_parent(tmp_path: Path) -> None:
    """Return one stable failure when the requested parent is not a directory."""
    parent = tmp_path / "not-a-directory"
    parent.write_text("x", encoding="utf-8")

    with pytest.raises(SystemExit, match="parent directory"):
        release_evidence.write_evidence_manifest(MANIFEST, parent / "manifest.json")


def test_manifest_output_detects_final_path_replacement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Refuse a manifest path replaced after its descriptor was written."""
    output = tmp_path / "manifest.json"
    original_fsync = release_evidence.os.fsync

    def replace_after_sync(descriptor: int) -> None:
        original_fsync(descriptor)
        output.unlink()
        output.write_bytes(b"replacement\n")

    monkeypatch.setattr(release_evidence.os, "fsync", replace_after_sync)

    with pytest.raises(SystemExit, match="unreadable or unsafe"):
        release_evidence.write_evidence_manifest(MANIFEST, output)

    assert output.read_bytes() == b"replacement\n"


def test_manifest_output_normalizes_creation_failure(tmp_path: Path, monkeypatch) -> None:
    """Return one stable error when exclusive descriptor creation fails."""
    output = tmp_path / "manifest.json"

    def fail_open(*args, **kwargs):
        raise OSError("blocked")

    monkeypatch.setattr(release_evidence.os, "open", fail_open)

    with pytest.raises(SystemExit, match="cannot be created safely"):
        release_evidence.write_evidence_manifest(MANIFEST, output)

    assert not output.exists()


def test_manifest_output_normalizes_write_failure(tmp_path: Path, monkeypatch) -> None:
    """Return one stable error when durable output synchronization fails."""
    output = tmp_path / "manifest.json"

    def fail_sync(descriptor: int) -> None:
        raise OSError("blocked")

    monkeypatch.setattr(release_evidence.os, "fsync", fail_sync)

    with pytest.raises(SystemExit, match="cannot be created safely"):
        release_evidence.write_evidence_manifest(MANIFEST, output)

    assert output.is_file()
