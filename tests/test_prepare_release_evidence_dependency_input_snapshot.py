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


def _prepare_with_reviewed_inputs(
    preparer,
    tmp_path: Path,
    dependency_manifest: Path,
    runtime_lock: Path,
) -> dict[str, object]:
    """Run release preparation with caller-selected reviewed dependency inputs."""
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    return preparer.prepare_release_evidence(
        evidence_dir,
        tmp_path / "handoff.json",
        repository=REPOSITORY,
        source_sha=SOURCE_SHA,
        dependency_manifest_path=dependency_manifest,
        runtime_lock_path=runtime_lock,
    )


def test_reviewed_dependency_inputs_are_snapshotted_before_generator_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep one accepted manifest/lock byte snapshot across both SBOM builds."""
    preparer = _load_preparer()
    dependency_manifest = tmp_path / "reviewed-runtime-dependencies.json"
    runtime_lock = tmp_path / "reviewed-runtime-lock.txt"
    shutil.copyfile(MANIFEST_PATH, dependency_manifest)
    shutil.copyfile(LOCK_PATH, runtime_lock)
    accepted_manifest = dependency_manifest.read_bytes()
    accepted_lock = runtime_lock.read_bytes()
    real_generator = preparer._load_attestable_generator()
    observed_snapshots: tuple[Path, Path] | None = None
    call_count = 0

    class SnapshotObserved(RuntimeError):
        """Stop after proving both parsers consumed the same detached snapshots."""

    class RecordingGenerator:
        """Require both generator calls to reuse the accepted immutable inputs."""

        def build_attestable_sbom(
            self,
            artifact_path: Path,
            manifest_path: Path,
            lock_path: Path,
        ) -> dict[str, object]:
            nonlocal call_count, observed_snapshots
            call_count += 1
            assert manifest_path != dependency_manifest
            assert lock_path != runtime_lock
            assert manifest_path.read_bytes() == accepted_manifest
            assert lock_path.read_bytes() == accepted_lock
            current_snapshots = (manifest_path, lock_path)
            if observed_snapshots is None:
                observed_snapshots = current_snapshots
            else:
                assert current_snapshots == observed_snapshots
                raise SnapshotObserved
            return real_generator.build_attestable_sbom(
                artifact_path,
                manifest_path,
                lock_path,
            )

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
        _prepare_with_reviewed_inputs(
            preparer,
            tmp_path,
            dependency_manifest,
            runtime_lock,
        )

    assert call_count == 2


def test_reviewed_inputs_with_same_basename_use_distinct_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reach generator loading when manifest and lock share one basename."""
    preparer = _load_preparer()
    manifest_dir = tmp_path / "manifest"
    lock_dir = tmp_path / "lock"
    manifest_dir.mkdir()
    lock_dir.mkdir()
    dependency_manifest = manifest_dir / "requirements.txt"
    runtime_lock = lock_dir / "requirements.txt"
    shutil.copyfile(MANIFEST_PATH, dependency_manifest)
    shutil.copyfile(LOCK_PATH, runtime_lock)

    class GeneratorReached(RuntimeError):
        """Prove both reviewed snapshots were created without basename collision."""

    def stop_at_generator() -> None:
        raise GeneratorReached

    monkeypatch.setattr(preparer, "_load_attestable_generator", stop_at_generator)

    with pytest.raises(GeneratorReached):
        _prepare_with_reviewed_inputs(
            preparer,
            tmp_path,
            dependency_manifest,
            runtime_lock,
        )


def test_reviewed_input_exact_size_limit_reaches_generator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept exactly one MiB of reviewed input before parser delegation."""
    preparer = _load_preparer()
    dependency_manifest = tmp_path / "reviewed-runtime-dependencies.json"
    runtime_lock = tmp_path / "reviewed-runtime-lock.txt"
    dependency_manifest.write_bytes(b"x" * preparer.MAX_REVIEWED_INPUT_BYTES)
    shutil.copyfile(LOCK_PATH, runtime_lock)

    class GeneratorReached(RuntimeError):
        """Prove the exact finite boundary reaches generator loading."""

    def stop_at_generator() -> None:
        raise GeneratorReached

    monkeypatch.setattr(preparer, "_load_attestable_generator", stop_at_generator)

    with pytest.raises(GeneratorReached):
        _prepare_with_reviewed_inputs(
            preparer,
            tmp_path,
            dependency_manifest,
            runtime_lock,
        )


def test_reviewed_input_over_size_limit_is_generically_rejected_before_generator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject oversized reviewed bytes without exposing the rejection rule."""
    preparer = _load_preparer()
    dependency_manifest = tmp_path / "reviewed-runtime-dependencies.json"
    runtime_lock = tmp_path / "reviewed-runtime-lock.txt"
    dependency_manifest.write_bytes(b"x" * (preparer.MAX_REVIEWED_INPUT_BYTES + 1))
    shutil.copyfile(LOCK_PATH, runtime_lock)
    generator_loaded = False

    def fail_if_loaded() -> None:
        nonlocal generator_loaded
        generator_loaded = True
        raise AssertionError("generator loaded after reviewed-input rejection")

    monkeypatch.setattr(preparer, "_load_attestable_generator", fail_if_loaded)

    with pytest.raises(SystemExit) as rejected:
        _prepare_with_reviewed_inputs(
            preparer,
            tmp_path,
            dependency_manifest,
            runtime_lock,
        )

    assert str(rejected.value) == "reviewed input is unreadable or unsafe"
    assert not generator_loaded


def test_reviewed_input_growth_after_preflight_is_generically_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hide the rule when accepted input grows beyond the bound before snapshotting."""
    preparer = _load_preparer()
    dependency_manifest = tmp_path / "reviewed-runtime-dependencies.json"
    runtime_lock = tmp_path / "reviewed-runtime-lock.txt"
    shutil.copyfile(MANIFEST_PATH, dependency_manifest)
    shutil.copyfile(LOCK_PATH, runtime_lock)
    original_preflight = preparer._require_reviewed_input_preflight
    mutated = False

    def grow_after_preflight(path: Path, *, label: str):
        nonlocal mutated
        accepted_identity = original_preflight(path, label=label)
        if path == dependency_manifest and not mutated:
            with path.open("ab") as stream:
                stream.truncate(preparer.MAX_REVIEWED_INPUT_BYTES + 1)
            mutated = True
        return accepted_identity

    def fail_if_loaded() -> None:
        raise AssertionError("generator loaded after reviewed-input identity changed")

    monkeypatch.setattr(
        preparer,
        "_require_reviewed_input_preflight",
        grow_after_preflight,
    )
    monkeypatch.setattr(preparer, "_load_attestable_generator", fail_if_loaded)

    with pytest.raises(SystemExit) as rejected:
        _prepare_with_reviewed_inputs(
            preparer,
            tmp_path,
            dependency_manifest,
            runtime_lock,
        )

    assert mutated
    assert str(rejected.value) == "reviewed input is unreadable or unsafe"
