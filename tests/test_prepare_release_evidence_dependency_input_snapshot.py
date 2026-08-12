"""Test immutable snapshots for reviewed dependency evidence inputs."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from test_prepare_release_evidence import (
    LOCK_PATH,
    MANIFEST_PATH,
    REPOSITORY,
    SOURCE_SHA,
    _load_preparer,
    _write_distributions,
)


def test_reviewed_dependency_inputs_are_snapshotted_before_generator_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep one accepted manifest/lock byte snapshot across both SBOM builds."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    dependency_manifest = tmp_path / "reviewed-runtime-dependencies.json"
    runtime_lock = tmp_path / "reviewed-runtime-lock.txt"
    shutil.copyfile(MANIFEST_PATH, dependency_manifest)
    shutil.copyfile(LOCK_PATH, runtime_lock)
    accepted_manifest = dependency_manifest.read_bytes()
    accepted_lock = runtime_lock.read_bytes()

    class SnapshotObserved(RuntimeError):
        """Stop after proving parser inputs are detached from mutable caller paths."""

    class RecordingGenerator:
        """Require generator inputs to remain the bytes accepted before mutation."""

        def build_attestable_sbom(
            self,
            artifact_path: Path,
            manifest_path: Path,
            lock_path: Path,
        ) -> dict[str, object]:
            del artifact_path
            assert manifest_path != dependency_manifest
            assert lock_path != runtime_lock
            assert manifest_path.read_bytes() == accepted_manifest
            assert lock_path.read_bytes() == accepted_lock
            raise SnapshotObserved

    def mutate_inputs_then_load_generator() -> RecordingGenerator:
        dependency_manifest.write_bytes(b"{}\n")
        runtime_lock.write_text("# replaced after acceptance\n", encoding="utf-8")
        return RecordingGenerator()

    monkeypatch.setattr(
        preparer,
        "_load_attestable_generator",
        mutate_inputs_then_load_generator,
    )

    with pytest.raises(SnapshotObserved):
        preparer.prepare_release_evidence(
            evidence_dir,
            tmp_path / "handoff.json",
            repository=REPOSITORY,
            source_sha=SOURCE_SHA,
            dependency_manifest_path=dependency_manifest,
            runtime_lock_path=runtime_lock,
        )
