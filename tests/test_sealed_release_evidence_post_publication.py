"""Fail closed when release evidence or its manifest changes after publication."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from test_sealed_release_evidence_source_identity import (
    REPOSITORY,
    SOURCE_SHA,
    _evidence,
)

from egressweave import release_evidence


def _run_cli(
    evidence_dir: Path,
    output_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> int:
    """Run the release-evidence CLI against one exact test fixture."""
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
            str(output_path),
        ],
    )
    return release_evidence.main()


def test_cli_revalidates_evidence_after_manifest_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a set that changes immediately after the manifest is written."""
    evidence_dir = tmp_path / "evidence"
    _evidence(evidence_dir)
    output_path = tmp_path / "manifest.json"
    original_writer = release_evidence.write_evidence_manifest

    def mutate_after_write(*args, **kwargs) -> None:
        original_writer(*args, **kwargs)
        (evidence_dir / "late-addition").write_bytes(b"unsealed")

    monkeypatch.setattr(release_evidence, "write_evidence_manifest", mutate_after_write)

    with pytest.raises(SystemExit, match="changed after manifest publication"):
        _run_cli(evidence_dir, output_path, monkeypatch)


def test_cli_rejects_a_different_post_publication_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject semantically different evidence returned by the final verifier pass."""
    evidence_dir = tmp_path / "evidence"
    _evidence(evidence_dir)
    output_path = tmp_path / "manifest.json"
    original_builder = release_evidence.build_evidence_manifest
    calls = 0

    def change_second_manifest(*args, **kwargs):
        nonlocal calls
        calls += 1
        manifest = original_builder(*args, **kwargs)
        if calls == 2:
            manifest = dict(manifest)
            manifest["sourceSha"] = "f" * 40
        return manifest

    monkeypatch.setattr(
        release_evidence,
        "build_evidence_manifest",
        change_second_manifest,
    )

    with pytest.raises(SystemExit, match="changed after manifest publication"):
        _run_cli(evidence_dir, output_path, monkeypatch)

    assert calls == 2


def test_cli_rechecks_manifest_bytes_after_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject replacement of the owner-only output after its descriptor closes."""
    evidence_dir = tmp_path / "evidence"
    _evidence(evidence_dir)
    output_path = tmp_path / "manifest.json"
    original_writer = release_evidence.write_evidence_manifest

    def replace_after_write(*args, **kwargs) -> None:
        original_writer(*args, **kwargs)
        output_path.write_bytes(b"{}\n")

    monkeypatch.setattr(release_evidence, "write_evidence_manifest", replace_after_write)

    with pytest.raises(SystemExit, match="output changed after publication"):
        _run_cli(evidence_dir, output_path, monkeypatch)
