"""Regression tests for the direct release-SBOM archive-size boundary."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
EXPECTED_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def _load_generator() -> ModuleType:
    """Load the standalone generator without importing the package under test."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_archive_bound",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_sparse_oversized_file(path: Path) -> None:
    """Create one cheap sparse fixture just above the accepted compressed bound."""
    with path.open("wb") as stream:
        stream.truncate(EXPECTED_MAX_ARTIFACT_BYTES + 1)


def test_oversized_wheel_fails_before_zip_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an oversized wheel before ZIP parser CPU or memory can be spent."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_sparse_oversized_file(wheel_path)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser ran before the compressed-byte bound")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="compressed-byte safety bound"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_oversized_sdist_fails_before_tar_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an oversized source archive before gzip/tar parsing begins."""
    generator = _load_generator()
    sdist_path = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_sparse_oversized_file(sdist_path)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("tar parser ran before the compressed-byte bound")

    monkeypatch.setattr(generator.tarfile, "open", unexpected_parser)

    with pytest.raises(SystemExit, match="compressed-byte safety bound"):
        generator.build_sbom(sdist_path, MANIFEST_PATH)


def test_symlinked_archive_fails_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a direct archive symlink instead of following it into a parser."""
    generator = _load_generator()
    target = tmp_path / "target.whl"
    with zipfile.ZipFile(target, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"invalid")
    alias = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser followed an unsafe archive link")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(alias, MANIFEST_PATH)


def test_archive_lstat_failure_is_normalized_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize filesystem inspection failure without exposing local details."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"invalid")
    original_lstat = Path.lstat

    def fail_artifact_lstat(path: Path, *args, **kwargs):
        if path == wheel_path:
            raise OSError("sensitive local filesystem detail")
        return original_lstat(path, *args, **kwargs)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser ran after archive inspection failed")

    monkeypatch.setattr(Path, "lstat", fail_artifact_lstat)
    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_directory_archive_is_rejected_as_unsafe(tmp_path: Path) -> None:
    """Reject a non-regular artifact with the same stable public failure."""
    generator = _load_generator()
    directory = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    directory.mkdir()

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(directory, MANIFEST_PATH)
