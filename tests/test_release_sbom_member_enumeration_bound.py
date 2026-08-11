"""Regression tests for bounded archive-member enumeration."""

from __future__ import annotations

import gzip
import importlib.util
import io
import struct
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
EXPECTED_MAX_ARCHIVE_MEMBERS = 10_000
GENERIC_REJECTION = "release artifact failed verification"


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

    with pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator.build_sbom(sdist_path, MANIFEST_PATH)


def _metadata() -> bytes:
    """Return minimal metadata matching the reviewed release manifest."""
    return (
        b"Metadata-Version: 2.4\n"
        b"Name: egressweave\n"
        b"Version: 0.3.0\n"
        b"License-Expression: Apache-2.0\n"
        b"Requires-Dist: httpcore<2.0,>=1.0\n"
        b"Requires-Dist: httpx<0.29,>=0.28\n"
        b"Requires-Dist: idna<4,>=3.18\n\n"
    )


def _write_valid_wheel(path: Path) -> None:
    """Write one canonical wheel accepted by both preflight and ZipFile."""
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", _metadata())


def _write_valid_sdist(path: Path) -> None:
    """Write one canonical gzip tar accepted by both parser stages."""
    payload = _metadata()
    member = tarfile.TarInfo("egressweave-0.3.0/PKG-INFO")
    member.size = len(payload)
    with tarfile.open(path, mode="w:gz") as archive:
        archive.addfile(member, io.BytesIO(payload))


def _rewrite_eocd(path: Path, **changes: int) -> None:
    """Replace selected EOCD integer fields in one small ZIP fixture."""
    payload = bytearray(path.read_bytes())
    offset = payload.rfind(b"PK\x05\x06")
    assert offset >= 0
    fields = list(struct.unpack_from("<4s4H2LH", payload, offset))
    indexes = {
        "disk_number": 1,
        "directory_disk": 2,
        "disk_entries": 3,
        "total_entries": 4,
        "directory_size": 5,
        "directory_offset": 6,
    }
    for name, value in changes.items():
        fields[indexes[name]] = value
    struct.pack_into("<4s4H2LH", payload, offset, *fields)
    path.write_bytes(payload)


def _central_offset(payload: bytes) -> int:
    """Return the first central-directory offset from a small ZIP EOCD."""
    eocd = payload.rfind(b"PK\x05\x06")
    assert eocd >= 0
    return struct.unpack_from("<4s4H2LH", payload, eocd)[6]


def _write_raw_sdist(
    path: Path,
    records: list[tuple[tarfile.TarInfo, bytes]],
    trailing: bytes = b"",
) -> None:
    """Write explicit physical tar records inside one gzip member."""
    raw = bytearray()
    for member, payload in records:
        member.size = len(payload)
        raw.extend(member.tobuf(format=tarfile.PAX_FORMAT))
        raw.extend(payload)
        raw.extend(b"\x00" * ((-len(payload)) % 512))
    raw.extend(b"\x00" * 1024)
    raw.extend(trailing)
    path.write_bytes(gzip.compress(bytes(raw), mtime=0))


def test_new_archive_bounds_are_exact() -> None:
    """Lock every pre-materialization resource constant to its reviewed value."""
    generator = _load_generator()

    assert generator.MAX_ARCHIVE_MEMBERS == EXPECTED_MAX_ARCHIVE_MEMBERS
    assert generator.MAX_EXPANDED_TAR_BYTES == 512 * 1024 * 1024
    assert generator.MAX_TAR_EXTENSION_BYTES == 1 * 1024 * 1024
    assert generator.ZIP64_EOCD_LOCATOR_SIZE == 20


def test_canonical_wheel_and_sdist_remain_compatible(tmp_path: Path) -> None:
    """Accept canonical release archives after bounded preflight."""
    generator = _load_generator()
    wheel = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    sdist = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_valid_wheel(wheel)
    _write_valid_sdist(sdist)

    assert generator.build_sbom(wheel, MANIFEST_PATH)["bomFormat"] == "CycloneDX"
    assert generator.build_sbom(sdist, MANIFEST_PATH)["bomFormat"] == "CycloneDX"


def test_sdist_preflight_spools_one_validated_expanded_stream(tmp_path: Path) -> None:
    """Validate regular and directory records while retaining one parseable snapshot."""
    generator = _load_generator()
    sdist = tmp_path / "regular-and-directory.tar.gz"
    regular = tarfile.TarInfo("egressweave-0.3.0/data.txt")
    directory = tarfile.TarInfo("egressweave-0.3.0/data/")
    directory.type = tarfile.DIRTYPE
    _write_raw_sdist(sdist, [(regular, b"payload"), (directory, b"")])

    with sdist.open("rb") as stream:
        expanded = generator._preflight_sdist_members(stream)
        try:
            header = expanded.read(512)
            assert header[: len(regular.name)] == regular.name.encode()
            assert int(header[124:136].strip(b" \x00") or b"0", 8) == len(b"payload")
        finally:
            expanded.close()


@pytest.mark.parametrize(
    ("member_type", "payload"),
    [
        (tarfile.SYMTYPE, b""),
        (b"X", b""),
        (tarfile.XHDTYPE, b"GNU.sparse.map=0,1\n"),
    ],
)
def test_sdist_preflight_rejects_physical_member_forms(
    tmp_path: Path,
    member_type: bytes,
    payload: bytes,
) -> None:
    """Reject links, unknown records, and sparse extension metadata in preflight."""
    generator = _load_generator()
    sdist = tmp_path / "invalid-member-form.tar.gz"
    member = tarfile.TarInfo("egressweave-0.3.0/member")
    member.type = member_type
    _write_raw_sdist(sdist, [(member, payload)])

    with sdist.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)


def test_sdist_preflight_rejects_oversized_extension_header(tmp_path: Path) -> None:
    """Reject a PAX extension before reading its oversized expanded payload."""
    generator = _load_generator()
    sdist = tmp_path / "oversized-extension.tar.gz"
    member = tarfile.TarInfo("pax-header")
    member.type = tarfile.XHDTYPE
    payload = b"x" * (generator.MAX_TAR_EXTENSION_BYTES + 1)
    _write_raw_sdist(sdist, [(member, payload)])

    with sdist.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)


def test_sdist_preflight_rejects_nonzero_trailing_expanded_bytes(tmp_path: Path) -> None:
    """Reject bytes after the canonical two tar end blocks."""
    generator = _load_generator()
    sdist = tmp_path / "trailing-bytes.tar.gz"
    _write_raw_sdist(sdist, [], trailing=b"unexpected")

    with sdist.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)


def test_sdist_metadata_parses_the_spooled_snapshot_without_gzip_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the validated uncompressed snapshot for semantic metadata parsing."""
    generator = _load_generator()
    sdist = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_valid_sdist(sdist)
    original_open = generator.tarfile.open
    modes: list[str | None] = []

    def recording_open(*args: object, **kwargs: object) -> object:
        modes.append(kwargs.get("mode"))
        return original_open(*args, **kwargs)

    monkeypatch.setattr(generator.tarfile, "open", recording_open)
    with sdist.open("rb") as stream:
        metadata = generator._sdist_metadata(stream)

    assert metadata["Name"] == "egressweave"
    assert modes == ["r:"]


def test_zip_comment_signature_does_not_hide_the_real_eocd(tmp_path: Path) -> None:
    """Ignore EOCD-like bytes inside the bounded ZIP comment."""
    generator = _load_generator()
    wheel = tmp_path / "comment.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", _metadata())
        archive.comment = b"comment-PK\x05\x06-not-an-end-record"
    with wheel.open("rb") as stream:
        generator._preflight_wheel_members(stream)


@pytest.mark.parametrize(
    "changes",
    [
        {"disk_number": 1},
        {"directory_disk": 1},
        {"disk_entries": 0},
        {"total_entries": 0xFFFF},
        {"directory_size": 0xFFFFFFFF},
        {"directory_offset": 0xFFFFFFFF},
        {"directory_offset": 1},
    ],
)
def test_zip_eocd_inconsistencies_fail_closed(
    tmp_path: Path,
    changes: dict[str, int],
) -> None:
    """Reject multi-disk, ZIP64-sentinel, count, and offset drift."""
    generator = _load_generator()
    wheel = tmp_path / "bad.whl"
    _write_valid_wheel(wheel)
    _rewrite_eocd(wheel, **changes)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)


def test_zip_central_structure_and_zip64_forms_fail_closed(tmp_path: Path) -> None:
    """Reject malformed central records and unnecessary ZIP64 structures."""
    generator = _load_generator()

    wheel = tmp_path / "signature.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    central = _central_offset(payload)
    payload[central : central + 4] = b"NOPE"
    wheel.write_bytes(payload)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)

    wheel = tmp_path / "length.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    central = _central_offset(payload)
    struct.pack_into("<H", payload, central + 28, 0xFFFF)
    wheel.write_bytes(payload)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)

    wheel = tmp_path / "locator.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    eocd = payload.rfind(b"PK\x05\x06")
    payload[eocd:eocd] = b"PK\x06\x07" + b"\x00" * 16
    directory_size = struct.unpack_from("<L", payload, eocd + 20 + 12)[0]
    struct.pack_into("<L", payload, eocd + 20 + 16, directory_size + 20)
    wheel.write_bytes(payload)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)

    assert generator._zip_extra_uses_zip64(b"") is False
    assert generator._zip_extra_uses_zip64(struct.pack("<HH", 1, 0)) is True
    with pytest.raises(SystemExit, match="valid ZIP"):
        generator._zip_extra_uses_zip64(b"x")


def test_actual_zip_records_cannot_exceed_bound_despite_declared_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop on the first physical record over the configured bound."""
    generator = _load_generator()
    wheel = tmp_path / "two.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("one", b"")
        archive.writestr("two", b"")
    _rewrite_eocd(wheel, total_entries=1, disk_entries=1)
    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 1)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="archive-member"):
        generator._preflight_wheel_members(stream)


def test_tar_preflight_bounds_and_special_forms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject over-budget expansion, extensions, and unsafe tar forms."""
    generator = _load_generator()

    extension = tmp_path / "extension.tar.gz"
    member = tarfile.TarInfo("pax")
    member.type = b"x"
    _write_raw_sdist(extension, [(member, b"x")])
    monkeypatch.setattr(generator, "MAX_TAR_EXTENSION_BYTES", 0)
    with extension.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)

    ordinary = tmp_path / "ordinary.tar.gz"
    _write_valid_sdist(ordinary)
    monkeypatch.setattr(generator, "MAX_TAR_EXTENSION_BYTES", 1_048_576)
    monkeypatch.setattr(generator, "MAX_EXPANDED_TAR_BYTES", 511)
    with ordinary.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)

    monkeypatch.setattr(generator, "MAX_EXPANDED_TAR_BYTES", 512 * 1024 * 1024)
    for index, (type_flag, payload) in enumerate(
        [
            (b"2", b""),
            (b"Z", b""),
            (b"x", b"20 GNU.sparse.name=x\n"),
        ]
    ):
        path = tmp_path / f"special-{index}.tar.gz"
        member = tarfile.TarInfo("entry")
        member.type = type_flag
        _write_raw_sdist(path, [(member, payload)])
        with path.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
            generator._preflight_sdist_members(stream)


def test_tar_preflight_normalizes_corruption_and_rewinds(tmp_path: Path) -> None:
    """Normalize gzip and deflate corruption and rewind the descriptor."""
    generator = _load_generator()

    corrupt = tmp_path / "corrupt.tar.gz"
    corrupt.write_bytes(b"not gzip")
    with corrupt.open("rb") as stream:
        with pytest.raises(SystemExit, match=GENERIC_REJECTION):
            generator._preflight_sdist_members(stream)
        assert stream.tell() == 0

    damaged = tmp_path / "damaged-deflate.tar.gz"
    damaged_payload = bytearray(gzip.compress(b"\x00" * 4096, mtime=0))
    damaged_payload[15:60] = b"\xff" * 45
    damaged.write_bytes(damaged_payload)
    with damaged.open("rb") as stream:
        with pytest.raises(SystemExit, match=GENERIC_REJECTION):
            generator._preflight_sdist_members(stream)
        assert stream.tell() == 0

    trailing = tmp_path / "trailing.tar.gz"
    _write_raw_sdist(trailing, [], trailing=b"X")
    with trailing.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._preflight_sdist_members(stream)


def test_streaming_sdist_preserves_semantic_archive_checks(tmp_path: Path) -> None:
    """Reject duplicate, unsafe, missing, and oversized package metadata generically."""
    generator = _load_generator()

    duplicate = tmp_path / "duplicate.tar.gz"
    one = tarfile.TarInfo("root/file")
    two = tarfile.TarInfo("root/file")
    _write_raw_sdist(duplicate, [(one, b""), (two, b"")])
    with duplicate.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._sdist_metadata(stream)

    unsafe = tmp_path / "unsafe.tar.gz"
    member = tarfile.TarInfo("../outside")
    _write_raw_sdist(unsafe, [(member, b"")])
    with unsafe.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._sdist_metadata(stream)

    missing = tmp_path / "missing.tar.gz"
    member = tarfile.TarInfo("root/file")
    _write_raw_sdist(missing, [(member, b"")])
    with missing.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._sdist_metadata(stream)

    oversized = tmp_path / "oversized.tar.gz"
    member = tarfile.TarInfo("root/PKG-INFO")
    _write_raw_sdist(
        oversized,
        [(member, b"x" * (generator.MAX_METADATA_BYTES + 1))],
    )
    with oversized.open("rb") as stream, pytest.raises(SystemExit, match=GENERIC_REJECTION):
        generator._sdist_metadata(stream)
