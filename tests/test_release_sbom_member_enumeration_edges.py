"""Edge-case regressions for release archive preflight and semantic fallbacks."""

from __future__ import annotations

import importlib.util
import io
import struct
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Iterator

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"


def _load_generator() -> ModuleType:
    """Load the standalone SBOM generator without importing EgressWeave."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_member_edges",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_two_member_wheel(path: Path) -> None:
    """Write a compact canonical ZIP with two central-directory records."""
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("one", b"")
        archive.writestr("two", b"")


def _rewrite_zip_counts(path: Path, count: int) -> None:
    """Rewrite both EOCD entry-count fields while preserving directory bytes."""
    payload = bytearray(path.read_bytes())
    eocd = payload.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<H", payload, eocd + 8, count)
    struct.pack_into("<H", payload, eocd + 10, count)
    path.write_bytes(payload)


def test_low_level_archive_helpers_fail_closed_on_malformed_inputs() -> None:
    """Exercise malformed helper branches before archive object materialization."""
    generator = _load_generator()

    ordinary_extra = struct.pack("<HH", 0xCAFE, 1) + b"x"
    assert generator._zip_extra_uses_zip64(ordinary_extra) is False
    with pytest.raises(SystemExit, match="valid ZIP"):
        generator._zip_extra_uses_zip64(struct.pack("<HH", 0xCAFE, 2) + b"x")

    with pytest.raises(SystemExit, match="valid gzip tar"):
        generator._tar_number(b"\x80" + b"\x00" * 11)
    with pytest.raises(SystemExit, match="valid gzip tar"):
        generator._tar_number(b"8\x00")

    bad_checksum = bytearray(512)
    bad_checksum[0] = 1
    bad_checksum[148:156] = b"0000000\x00"
    with pytest.raises(SystemExit, match="valid gzip tar"):
        generator._require_tar_checksum(bytes(bad_checksum))

    with pytest.raises(SystemExit, match="truncated"):
        generator._read_exact(io.BytesIO(b"a"), 2, "truncated archive")
    with pytest.raises(SystemExit, match="valid gzip tar"):
        generator._read_expanded(io.BytesIO(b"a"), 2, 0)
    assert generator._read_expanded(io.BytesIO(b"ab"), 2, 0, retain=False) == (
        b"",
        2,
    )


def test_wheel_declared_count_and_final_count_mismatch_are_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover declared over-budget and post-scan count-consistency rejection."""
    generator = _load_generator()
    wheel = tmp_path / "two.whl"
    _write_two_member_wheel(wheel)

    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 1)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="archive-member"):
        generator._preflight_wheel_members(stream)

    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 10_000)
    _rewrite_zip_counts(wheel, 1)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)


class _SemanticMember:
    """Minimal tar member double for secondary semantic-defense tests."""

    def __init__(
        self,
        name: str,
        *,
        size: int = 0,
        special: bool = False,
        sparse: bool = False,
        regular: bool = False,
        directory: bool = True,
    ) -> None:
        self.name = name
        self.size = size
        self._special = special
        self._sparse = sparse
        self._regular = regular
        self._directory = directory

    def issym(self) -> bool:
        """Return whether this double represents a symbolic link."""
        return self._special

    def islnk(self) -> bool:
        """Return whether this double represents a hard link."""
        return False

    def isdev(self) -> bool:
        """Return whether this double represents a device."""
        return False

    def isfifo(self) -> bool:
        """Return whether this double represents a FIFO."""
        return False

    def issparse(self) -> bool:
        """Return whether this double represents a sparse tar member."""
        return self._sparse

    def isfile(self) -> bool:
        """Return whether this double represents a regular file."""
        return self._regular

    def isdir(self) -> bool:
        """Return whether this double represents a directory."""
        return self._directory


class _SemanticArchive:
    """Context-managed streaming tar double with controlled extraction."""

    def __init__(self, members: list[_SemanticMember], extracted: object = b"") -> None:
        self._members = members
        self._extracted = extracted

    def __enter__(self) -> _SemanticArchive:
        """Return this archive double from the context manager."""
        return self

    def __exit__(self, *args: object) -> None:
        """Leave the archive double without suppressing exceptions."""
        return None

    def __iter__(self) -> Iterator[_SemanticMember]:
        """Yield the configured semantic members in order."""
        return iter(self._members)

    def extractfile(self, member: _SemanticMember) -> object:
        """Return the configured extraction result for one regular member."""
        del member
        return self._extracted


def _disable_preflight_and_install_archive(
    generator: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    archive: _SemanticArchive,
) -> None:
    """Expose secondary semantic defenses independently of physical preflight."""
    monkeypatch.setattr(generator, "_preflight_sdist_members", lambda stream: None)
    monkeypatch.setattr(generator.tarfile, "open", lambda *args, **kwargs: archive)


def test_secondary_sdist_semantic_defenses_remain_reachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep semantic fallback checks measured even though preflight rejects first."""
    cases = [
        (
            [_SemanticMember("root/link", special=True)],
            "link or special file",
        ),
        (
            [_SemanticMember("root/sparse", sparse=True, regular=True, directory=False)],
            "sparse archive form",
        ),
        (
            [_SemanticMember("root/unknown", directory=False)],
            "unsupported tar form",
        ),
    ]

    for members, message in cases:
        generator = _load_generator()
        _disable_preflight_and_install_archive(
            generator,
            monkeypatch,
            _SemanticArchive(members),
        )
        with pytest.raises(SystemExit, match=message):
            generator._sdist_metadata(io.BytesIO())
        monkeypatch.undo()


def test_secondary_sdist_member_count_and_missing_extraction_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measure redundant member-count defense and unreadable metadata handling."""
    generator = _load_generator()
    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 1)
    _disable_preflight_and_install_archive(
        generator,
        monkeypatch,
        _SemanticArchive(
            [_SemanticMember("one"), _SemanticMember("two")],
        ),
    )
    with pytest.raises(SystemExit, match="archive-member safety bound"):
        generator._sdist_metadata(io.BytesIO())

    monkeypatch.undo()
    generator = _load_generator()
    metadata = _SemanticMember(
        "root/PKG-INFO",
        size=1,
        regular=True,
        directory=False,
    )
    _disable_preflight_and_install_archive(
        generator,
        monkeypatch,
        _SemanticArchive([metadata], extracted=None),
    )
    with pytest.raises(SystemExit, match="metadata could not be read"):
        generator._sdist_metadata(io.BytesIO())
