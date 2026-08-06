"""Tests for credential-free preparation of the sealed release evidence set."""

from __future__ import annotations

import importlib.util
import json
import shutil
import stat
from pathlib import Path

import pytest
from test_release_sbom import LOCK_PATH, MANIFEST_PATH, _write_sdist, _write_wheel

from egressweave import release_evidence

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PREPARER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "prepare_release_evidence.py"
REPOSITORY = "ContextualWisdomLab/EgressWeave"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
WHEEL_NAME = "egressweave-0.3.0-py3-none-any.whl"
SDIST_NAME = "egressweave-0.3.0.tar.gz"


def _load_preparer():
    """Load the repository-only preparation script from its exact path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_prepare_release_evidence",
        PREPARER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_distributions(directory: Path) -> tuple[Path, Path]:
    """Create one canonical wheel and source distribution fixture."""
    directory.mkdir()
    wheel_path = directory / WHEEL_NAME
    sdist_path = directory / SDIST_NAME
    _write_wheel(wheel_path)
    _write_sdist(sdist_path)
    return wheel_path, sdist_path


def _prepare(preparer, evidence_dir: Path, handoff_path: Path):
    """Run the public preparation function with reviewed repository inputs."""
    return preparer.prepare_release_evidence(
        evidence_dir,
        handoff_path,
        repository=REPOSITORY,
        source_sha=SOURCE_SHA,
        dependency_manifest_path=MANIFEST_PATH,
        runtime_lock_path=LOCK_PATH,
    )


def test_prepare_release_evidence_emits_one_verified_six_file_set(
    tmp_path: Path,
) -> None:
    """Generate the exact sealed payloads and one separately stored handoff."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    handoff_path = tmp_path / "handoff.json"

    prepared_manifest = _prepare(preparer, evidence_dir, handoff_path)

    expected_names = {
        WHEEL_NAME,
        f"{WHEEL_NAME}.cdx.json",
        SDIST_NAME,
        f"{SDIST_NAME}.cdx.json",
        "SOURCE_IDENTITY.json",
        "SHA256SUMS",
    }
    assert {path.name for path in evidence_dir.iterdir()} == expected_names
    checksum_lines = (evidence_dir / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    checksum_names = [line.split("  ", 1)[1] for line in checksum_lines]
    assert checksum_names == sorted(checksum_names)
    assert len(checksum_lines) == 5
    assert set(checksum_names) == expected_names - {"SHA256SUMS"}
    assert (evidence_dir / "SOURCE_IDENTITY.json").read_bytes() == (
        b'{"format":"egressweave.release-source-identity","formatVersion":1,'
        b'"repository":"ContextualWisdomLab/EgressWeave",'
        b'"sourceSha":"0123456789abcdef0123456789abcdef01234567"}\n'
    )

    independently_verified = release_evidence.build_evidence_manifest(
        evidence_dir,
        repository=REPOSITORY,
        source_sha=SOURCE_SHA,
    )
    assert prepared_manifest == independently_verified
    assert json.loads(handoff_path.read_text(encoding="utf-8")) == independently_verified
    for generated_path in [
        evidence_dir / f"{WHEEL_NAME}.cdx.json",
        evidence_dir / f"{SDIST_NAME}.cdx.json",
        evidence_dir / "SOURCE_IDENTITY.json",
        evidence_dir / "SHA256SUMS",
        handoff_path,
    ]:
        assert stat.S_IMODE(generated_path.stat().st_mode) == 0o600


def test_prepare_release_evidence_is_repeatable_for_identical_archives(
    tmp_path: Path,
) -> None:
    """Produce byte-identical evidence when every exact input byte is reused."""
    preparer = _load_preparer()
    first_dir = tmp_path / "first"
    first_wheel, first_sdist = _write_distributions(first_dir)
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    shutil.copyfile(first_wheel, second_dir / first_wheel.name)
    shutil.copyfile(first_sdist, second_dir / first_sdist.name)

    _prepare(preparer, first_dir, tmp_path / "first-handoff.json")
    _prepare(preparer, second_dir, tmp_path / "second-handoff.json")

    for filename in (
        f"{WHEEL_NAME}.cdx.json",
        f"{SDIST_NAME}.cdx.json",
        "SOURCE_IDENTITY.json",
        "SHA256SUMS",
    ):
        assert (first_dir / filename).read_bytes() == (second_dir / filename).read_bytes()
    assert (tmp_path / "first-handoff.json").read_bytes() == (
        tmp_path / "second-handoff.json"
    ).read_bytes()


def test_prepare_release_evidence_rejects_unexpected_input_before_writing(
    tmp_path: Path,
) -> None:
    """Refuse stale or unrelated files before any evidence output is created."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    (evidence_dir / "stale.txt").write_text("stale", encoding="utf-8")
    handoff_path = tmp_path / "handoff.json"

    with pytest.raises(SystemExit, match="exactly one wheel and source distribution"):
        _prepare(preparer, evidence_dir, handoff_path)

    assert {path.name for path in evidence_dir.iterdir()} == {
        WHEEL_NAME,
        SDIST_NAME,
        "stale.txt",
    }
    assert not handoff_path.exists()


def test_prepare_release_evidence_rejects_oversized_archive_before_generator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject compressed input bytes before loading any archive parser."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    wheel_path, _ = _write_distributions(evidence_dir)
    wheel_path.write_bytes(b"")
    with wheel_path.open("r+b") as stream:
        stream.truncate(preparer.MAX_DISTRIBUTION_BYTES + 1)
    handoff_path = tmp_path / "handoff.json"

    def fail_if_loaded():
        raise AssertionError("the generator ran before the distribution size preflight")

    monkeypatch.setattr(preparer, "_load_attestable_generator", fail_if_loaded)

    with pytest.raises(SystemExit, match="release distribution .* exceeds the safety bound"):
        _prepare(preparer, evidence_dir, handoff_path)

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not handoff_path.exists()


def test_prepare_release_evidence_rejects_symlinked_distribution_before_writing(
    tmp_path: Path,
) -> None:
    """Reject a linked archive instead of following it into the sealed set."""
    preparer = _load_preparer()
    source_dir = tmp_path / "source"
    wheel_path, sdist_path = _write_distributions(source_dir)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    try:
        (evidence_dir / wheel_path.name).symlink_to(wheel_path)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")
    shutil.copyfile(sdist_path, evidence_dir / sdist_path.name)
    handoff_path = tmp_path / "handoff.json"

    with pytest.raises(SystemExit, match="regular direct-child files"):
        _prepare(preparer, evidence_dir, handoff_path)

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not handoff_path.exists()


def test_prepare_release_evidence_rejects_handoff_inside_the_sealed_set(
    tmp_path: Path,
) -> None:
    """Keep the generated handoff from mutating the evidence it summarizes."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    handoff_path = evidence_dir / "handoff.json"

    with pytest.raises(SystemExit, match="handoff manifest must remain outside"):
        _prepare(preparer, evidence_dir, handoff_path)

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not handoff_path.exists()


def test_prepare_release_evidence_rejects_invalid_source_identity_before_writing(
    tmp_path: Path,
) -> None:
    """Validate exact repository and source authority before creating evidence."""
    preparer = _load_preparer()
    evidence_dir = tmp_path / "evidence"
    _write_distributions(evidence_dir)
    handoff_path = tmp_path / "handoff.json"

    with pytest.raises(SystemExit, match="repository or source identity is invalid"):
        preparer.prepare_release_evidence(
            evidence_dir,
            handoff_path,
            repository="other/repository",
            source_sha="main",
            dependency_manifest_path=MANIFEST_PATH,
            runtime_lock_path=LOCK_PATH,
        )

    assert {path.name for path in evidence_dir.iterdir()} == {WHEEL_NAME, SDIST_NAME}
    assert not handoff_path.exists()
