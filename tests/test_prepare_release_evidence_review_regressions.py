"""Review-driven regressions for the sealed release-evidence preparer."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_prepare_release_evidence import (
    LOCK_PATH,
    MANIFEST_PATH,
    REPOSITORY,
    SDIST_NAME,
    SOURCE_SHA,
    WHEEL_NAME,
    _load_preparer,
    _write_distributions,
)

from egressweave import release_evidence

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PREPARATION_GUIDE = REPOSITORY_ROOT / "docs" / "release-evidence-preparation.md"
PREPARER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "prepare_release_evidence.py"


def _prepare_with_inputs(
    preparer,
    evidence_dir: Path,
    handoff_path: Path,
    *,
    dependency_manifest_path: Path = MANIFEST_PATH,
    runtime_lock_path: Path = LOCK_PATH,
):
    """Run the preparer through its public entry point with explicit input paths."""
    return preparer.prepare_release_evidence(
        evidence_dir,
        handoff_path,
        repository=REPOSITORY,
        source_sha=SOURCE_SHA,
        dependency_manifest_path=dependency_manifest_path,
        runtime_lock_path=runtime_lock_path,
    )


def test_operator_guide_names_existing_reviewed_dependency_inputs() -> None:
    """Keep the copy-paste preparation command bound to repository-owned inputs."""
    guide = PREPARATION_GUIDE.read_text(encoding="utf-8")

    assert "scripts/ci/release_runtime_dependencies.json" in guide
    assert "requirements-ci.txt" in guide
    assert "scripts/ci/runtime-dependency-manifest.json" not in guide
    assert "requirements-runtime.txt" not in guide


def test_preparer_uses_public_post_publication_reverification_api() -> None:
    """Keep the standalone preparer off private package implementation symbols."""
    source = PREPARER_PATH.read_text(encoding="utf-8")

    assert hasattr(release_evidence, "reverify_published_evidence_manifest")
    assert "release_evidence._require_post_publication_state" not in source
    assert "release_evidence.reverify_published_evidence_manifest" in source


def test_handoff_path_without_filename_fails_before_evidence_mutation(
    tmp_path: Path,
) -> None:
    """Reject a directory-like handoff target before generating sealed evidence."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)

    with pytest.raises(SystemExit, match="handoff manifest path must name one regular file"):
        _prepare_with_inputs(preparer, evidence_dir, Path("."))

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}


def test_distribution_versions_must_match_before_generated_outputs(
    tmp_path: Path,
) -> None:
    """Reject wheel/sdist filename version drift before generating evidence."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _, sdist_path = _write_distributions(evidence_dir)
    mismatched_sdist = evidence_dir / "egressweave-0.4.0.tar.gz"
    sdist_path.rename(mismatched_sdist)

    with pytest.raises(SystemExit, match="versions do not match"):
        _prepare_with_inputs(preparer, evidence_dir, tmp_path / "handoff.json")

    assert {path.name for path in evidence_dir.iterdir()} == {
        WHEEL_NAME,
        mismatched_sdist.name,
    }
    assert not (tmp_path / "handoff.json").exists()


def test_private_writer_refuses_preexisting_generated_file_without_overwrite(
    tmp_path: Path,
) -> None:
    """Preserve a pre-existing generated path rather than replacing it."""
    preparer = _load_preparer()
    generated = tmp_path / "generated.json"
    generated.write_bytes(b"sentinel")

    with pytest.raises(SystemExit, match="already exists"):
        preparer._write_private_file(generated, b"replacement", label="generated evidence")

    assert generated.read_bytes() == b"sentinel"


@pytest.mark.parametrize("input_kind", ["dependency manifest", "runtime lock"])
def test_reviewed_dependency_inputs_reject_symlinks(
    tmp_path: Path,
    input_kind: str,
) -> None:
    """Reject symlinked reviewed dependency inputs through the generic boundary."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    linked_input = tmp_path / ("dependency.json" if input_kind == "dependency manifest" else "runtime.txt")
    target = MANIFEST_PATH if input_kind == "dependency manifest" else LOCK_PATH
    try:
        linked_input.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    dependency_manifest = linked_input if input_kind == "dependency manifest" else MANIFEST_PATH
    runtime_lock = linked_input if input_kind == "runtime lock" else LOCK_PATH
    with pytest.raises(SystemExit, match="reviewed input is unreadable or unsafe"):
        _prepare_with_inputs(
            preparer,
            evidence_dir,
            tmp_path / "handoff.json",
            dependency_manifest_path=dependency_manifest,
            runtime_lock_path=runtime_lock,
        )

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not (tmp_path / "handoff.json").exists()


def test_missing_handoff_parent_fails_before_generated_outputs(
    tmp_path: Path,
) -> None:
    """Require an existing canonical handoff parent before evidence mutation."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    handoff_path = tmp_path / "missing-parent" / "handoff.json"

    with pytest.raises(SystemExit, match="handoff manifest parent is missing or unsafe"):
        _prepare_with_inputs(preparer, evidence_dir, handoff_path)

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not handoff_path.exists()
