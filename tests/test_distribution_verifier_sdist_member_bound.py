"""Regression coverage for bounded source-distribution member verification."""

from __future__ import annotations

import importlib.util
import io
import tarfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "verify_distribution.py"
VERSION = "0.3.0"
PREFIX = f"egressweave-{VERSION}"
REQUIRED_SDIST_PATHS = (
    f"{PREFIX}/pyproject.toml",
    f"{PREFIX}/README.md",
    f"{PREFIX}/CHANGELOG.md",
    f"{PREFIX}/LICENSE",
    f"{PREFIX}/src/egressweave/__init__.py",
    f"{PREFIX}/src/egressweave/py.typed",
    f"{PREFIX}/src/egressweave/schemas/decision-evidence-v1.schema.json",
    f"{PREFIX}/tests/test_quality_contracts.py",
    f"{PREFIX}/docs/release.md",
)


def _load_verifier():
    """Load the non-packaged distribution verifier from the repository tree."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_verify_distribution_member_bound",
        VERIFIER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_sdist(path: Path, extra_paths: tuple[str, ...] = ()) -> None:
    """Write one deterministic zero-payload gzip tar with the requested paths."""
    with tarfile.open(path, mode="w:gz") as archive:
        for name in (*REQUIRED_SDIST_PATHS, *extra_paths):
            member = tarfile.TarInfo(name)
            member.size = 0
            archive.addfile(member, io.BytesIO())


def test_sdist_verifier_never_materializes_the_complete_member_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require streaming semantic admission instead of ``TarFile.getmembers()``."""
    verifier = _load_verifier()
    sdist_path = tmp_path / f"egressweave-{VERSION}.tar.gz"
    _write_sdist(sdist_path)

    def reject_getmembers(self: tarfile.TarFile):
        del self
        raise AssertionError("distribution verifier materialized every sdist member")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", reject_getmembers)

    digest = verifier._verify_sdist(sdist_path, {"version": VERSION})

    assert len(digest) == 64


def test_sdist_verifier_does_not_accumulate_tarinfo_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep tarfile's internal metadata cache bounded during streaming admission."""
    verifier = _load_verifier()
    sdist_path = tmp_path / f"egressweave-{VERSION}.tar.gz"
    extra_paths = tuple(f"{PREFIX}/cache-probe-{index:02d}.txt" for index in range(32))
    _write_sdist(sdist_path, extra_paths)
    original_next = tarfile.TarFile.next
    max_cached_members = 0

    def recording_next(self: tarfile.TarFile):
        nonlocal max_cached_members
        max_cached_members = max(max_cached_members, len(self.members))
        member = original_next(self)
        max_cached_members = max(max_cached_members, len(self.members))
        return member

    monkeypatch.setattr(tarfile.TarFile, "next", recording_next)

    verifier._verify_sdist(sdist_path, {"version": VERSION})

    assert max_cached_members <= 1


def test_sdist_verifier_rejects_the_first_member_beyond_the_finite_budget(
    tmp_path: Path,
) -> None:
    """Stop semantic enumeration at the reviewed ceiling before retaining more names."""
    verifier = _load_verifier()
    assert verifier.MAX_SDIST_MEMBERS == 4096
    sdist_path = tmp_path / f"egressweave-{VERSION}.tar.gz"
    extra_count = verifier.MAX_SDIST_MEMBERS - len(REQUIRED_SDIST_PATHS) + 1
    extra_paths = tuple(
        f"{PREFIX}/bounded-member-{index:04d}.txt" for index in range(extra_count)
    )
    _write_sdist(sdist_path, extra_paths)

    with pytest.raises(SystemExit, match="source distribution member limit"):
        verifier._verify_sdist(sdist_path, {"version": VERSION})
