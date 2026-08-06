"""Regression tests for bounded archive-member enumeration."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
EXPECTED_MAX_ARCHIVE_MEMBERS = 10_000


def _load_generator() -> ModuleType:
    """Load the standalone generator without importing the package under test."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_member_bound",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_overmember_wheel(path: Path) -> None:
    """Create a compact wheel-shaped ZIP with one member beyond the policy."""
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(EXPECTED_MAX_ARCHIVE_MEMBERS + 1):
            archive.writestr(f"payload/member-{index:05d}", b"")


def _write_overmember_sdist(path: Path) -> None:
    """Create a compact gzip tar with one member beyond the policy."""
    with tarfile.open(path, mode="w:gz") as archive:
        for index in range(EXPECTED_MAX_ARCHIVE_MEMBERS + 1):
            member = tarfile.TarInfo(f"payload/member-{index:05d}")
            member.size = 0
            archive.addfile(member, io.BytesIO())


def test_wheel_member_bound_precedes_zipfile_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an overmember wheel before ZipFile builds its complete table."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_overmember_wheel(wheel_path)

    def unexpected_zip_parser(*args: object, **kwargs: object) -> object:
        pytest.fail("ZipFile materialized members before the repository bound")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_zip_parser)

    with pytest.raises(SystemExit, match="archive-member safety bound"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_sdist_member_bound_does_not_materialize_getmembers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop streaming tar enumeration without calling getmembers()."""
    generator = _load_generator()
    sdist_path = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_overmember_sdist(sdist_path)

    def unexpected_getmembers(*args: object, **kwargs: object) -> object:
        pytest.fail("TarFile.getmembers materialized members before the bound")

    monkeypatch.setattr(generator.tarfile.TarFile, "getmembers", unexpected_getmembers)

    with pytest.raises(SystemExit, match="archive-member safety bound"):
        generator.build_sbom(sdist_path, MANIFEST_PATH)
