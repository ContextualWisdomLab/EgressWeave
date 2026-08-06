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
        "comment_size": 7,
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
    """Lock the pre-materialization tar resource constants to reviewed values."""
    generator = _load_generator()

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


def test_zip_comment_signature_does_not_hide_the_real_eocd(tmp_path: Path) -> None:
    """Ignore EOCD-like bytes inside the bounded ZIP comment."""
    generator = _load_generator()
    wheel = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", _metadata())
        archive.comment = b"comment-PK\x05\x06-not-an-end-record"

    with wheel.open("rb") as stream:
        generator._preflight_wheel_members(stream)


def test_zip_eocd_and_multidisk_inconsistencies_fail_closed(tmp_path: Path) -> None:
    """Reject missing, multi-disk, ZIP64-sentinel, and offset-drift EOCD forms."""
    generator = _load_generator()
    invalid = "not a valid ZIP archive"
    tiny = tmp_path / "tiny.whl"
    tiny.write_bytes(b"PK\x05\x06")
    with tiny.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_wheel_members(stream)

    for index, changes in enumerate(
        (
            {"disk_number": 1},
            {"directory_disk": 1},
            {"disk_entries": 0},
            {"total_entries": 0xFFFF},
            {"directory_size": 0xFFFFFFFF},
            {"directory_offset": 0xFFFFFFFF},
            {"directory_offset": 1},
        )
    ):
        wheel = tmp_path / f"bad-{index}.whl"
        _write_valid_wheel(wheel)
        _rewrite_eocd(wheel, **changes)
        with wheel.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
            generator._preflight_wheel_members(stream)


def test_zip64_locator_is_rejected_before_zipfile(tmp_path: Path) -> None:
    """Reject a ZIP64 locator even when the classic EOCD looks plausible."""
    generator = _load_generator()
    wheel = tmp_path / "zip64-locator.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    eocd = payload.rfind(b"PK\x05\x06")
    payload[eocd:eocd] = b"PK\x06\x07" + b"\x00" * 16
    directory_size = struct.unpack_from("<L", payload, eocd + 20 + 12)[0]
    struct.pack_into("<L", payload, eocd + 20 + 16, directory_size + 20)
    wheel.write_bytes(payload)

    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="valid ZIP"):
        generator._preflight_wheel_members(stream)


def test_zip_central_directory_structure_is_finite_and_consistent(
    tmp_path: Path,
) -> None:
    """Reject malformed records, impossible variable lengths, and count lies."""
    generator = _load_generator()
    invalid = "not a valid ZIP archive"

    wheel = tmp_path / "bad-signature.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    central = _central_offset(payload)
    payload[central : central + 4] = b"NOPE"
    wheel.write_bytes(payload)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_wheel_members(stream)

    wheel = tmp_path / "bad-length.whl"
    _write_valid_wheel(wheel)
    payload = bytearray(wheel.read_bytes())
    central = _central_offset(payload)
    struct.pack_into("<H", payload, central + 28, 0xFFFF)
    wheel.write_bytes(payload)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_wheel_members(stream)

    wheel = tmp_path / "count-lie.whl"
    _write_valid_wheel(wheel)
    _rewrite_eocd(wheel, total_entries=2, disk_entries=2)
    with wheel.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_wheel_members(stream)


def test_zip_central_zip64_fields_and_extra_are_rejected(tmp_path: Path) -> None:
    """Reject ZIP64 sentinels and ZIP64 extra fields before object allocation."""
    generator = _load_generator()
    invalid = "not a valid ZIP archive"
    for index, field_offset in enumerate((20, 24, 42)):
        wheel = tmp_path / f"central-zip64-{index}.whl"
        _write_valid_wheel(wheel)
        payload = bytearray(wheel.read_bytes())
        central = _central_offset(payload)
        struct.pack_into("<L", payload, central + field_offset, 0xFFFFFFFF)
        wheel.write_bytes(payload)
        with wheel.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
            generator._preflight_wheel_members(stream)

    assert generator._zip_extra_uses_zip64(b"") is False
    assert generator._zip_extra_uses_zip64(struct.pack("<HH", 2, 0)) is False
    assert generator._zip_extra_uses_zip64(struct.pack("<HH", 1, 0)) is True
    for extra in (b"x", struct.pack("<HH", 2, 2) + b"x"):
        with pytest.raises(SystemExit, match=invalid):
            generator._zip_extra_uses_zip64(extra)


def test_actual_zip_records_cannot_exceed_bound_despite_declared_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop on the first physical record over the bound despite a lying EOCD."""
    generator = _load_generator()
    wheel = tmp_path / "two.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("one", b"")
        archive.writestr("two", b"")
    _rewrite_eocd(wheel, total_entries=1, disk_entries=1)
    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 1)

    with wheel.open("rb") as stream, pytest.raises(SystemExit, match="archive-member"):
        generator._preflight_wheel_members(stream)


def test_tar_numeric_checksum_and_expanded_read_helpers() -> None:
    """Normalize malformed tar numbers, checksums, truncation, and budgets."""
    generator = _load_generator()
    invalid = "not a valid gzip tar"

    assert generator._tar_number(b"\x00" * 12) == 0
    assert generator._tar_number(b"00000000010\x00") == 8
    for field in (b"\x80" + b"\x00" * 11, b"0000000008\x00"):
        with pytest.raises(SystemExit, match=invalid):
            generator._tar_number(field)

    header = bytearray(512)
    header[148:156] = b"0000000\x00"
    with pytest.raises(SystemExit, match=invalid):
        generator._require_tar_checksum(bytes(header))

    payload, consumed = generator._read_expanded(io.BytesIO(b"abcd"), 4, 0)
    assert payload == b"abcd" and consumed == 4
    payload, consumed = generator._read_expanded(
        io.BytesIO(b"abcd"), 4, 0, retain=False
    )
    assert payload == b"" and consumed == 4
    with pytest.raises(SystemExit, match="expanded-tar"):
        generator._read_expanded(io.BytesIO(), -1, 0)
    with pytest.raises(SystemExit, match=invalid):
        generator._read_expanded(io.BytesIO(b"a"), 2, 0)


def test_tar_preflight_rejects_special_unsupported_and_sparse_forms(
    tmp_path: Path,
) -> None:
    """Fail closed on links, unknown types, and PAX sparse declarations."""
    generator = _load_generator()
    cases = (
        (b"2", b"", "link or special"),
        (b"Z", b"", "unsupported tar form"),
        (b"x", b"20 GNU.sparse.name=x\n", "sparse archive form"),
    )
    for index, (type_flag, payload, message) in enumerate(cases):
        path = tmp_path / f"case-{index}.tar.gz"
        member = tarfile.TarInfo("entry")
        member.type = type_flag
        _write_raw_sdist(path, [(member, payload)])
        with path.open("rb") as stream, pytest.raises(SystemExit, match=message):
            generator._preflight_sdist_members(stream)


def test_tar_extension_and_expansion_limits_precede_semantic_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject extension and aggregate expansion overages before tarfile.open."""
    generator = _load_generator()
    path = tmp_path / "extension.tar.gz"
    member = tarfile.TarInfo("pax")
    member.type = b"x"
    _write_raw_sdist(path, [(member, b"x")])
    monkeypatch.setattr(generator, "MAX_TAR_EXTENSION_BYTES", 0)
    with path.open("rb") as stream, pytest.raises(SystemExit, match="extension header"):
        generator._preflight_sdist_members(stream)

    _write_valid_sdist(path)
    monkeypatch.setattr(generator, "MAX_TAR_EXTENSION_BYTES", 1_048_576)
    monkeypatch.setattr(generator, "MAX_EXPANDED_TAR_BYTES", 511)
    with path.open("rb") as stream, pytest.raises(SystemExit, match="expanded-tar"):
        generator._preflight_sdist_members(stream)


def test_tar_preflight_rejects_truncation_bad_checksum_and_trailing_data(
    tmp_path: Path,
) -> None:
    """Reject malformed gzip/tar framing through one stable public error."""
    generator = _load_generator()
    invalid = "not a valid gzip tar"

    truncated = tmp_path / "truncated.tar.gz"
    truncated.write_bytes(gzip.compress(b"short", mtime=0))
    with truncated.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_sdist_members(stream)

    bad_checksum = tmp_path / "checksum.tar.gz"
    member = tarfile.TarInfo("entry")
    _write_raw_sdist(bad_checksum, [(member, b"")])
    raw = bytearray(gzip.decompress(bad_checksum.read_bytes()))
    raw[0] ^= 1
    bad_checksum.write_bytes(gzip.compress(bytes(raw), mtime=0))
    with bad_checksum.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_sdist_members(stream)

    trailing = tmp_path / "trailing.tar.gz"
    _write_raw_sdist(trailing, [], trailing=b"X")
    with trailing.open("rb") as stream, pytest.raises(SystemExit, match=invalid):
        generator._preflight_sdist_members(stream)


def test_tar_preflight_normalizes_gzip_errors_and_rewinds(
    tmp_path: Path,
) -> None:
    """Normalize corrupt gzip input and restore the accepted descriptor position."""
    generator = _load_generator()
    corrupt = tmp_path / "corrupt.tar.gz"
    corrupt.write_bytes(b"not gzip")
    with corrupt.open("rb") as stream:
        with pytest.raises(SystemExit, match="not a valid gzip tar"):
            generator._preflight_sdist_members(stream)
        assert stream.tell() == 0


def test_streaming_sdist_rejects_duplicate_unsafe_and_missing_metadata(
    tmp_path: Path,
) -> None:
    """Retain only bounded names while preserving semantic archive checks."""
    generator = _load_generator()

    duplicate = tmp_path / "duplicate.tar.gz"
    one = tarfile.TarInfo("root/file")
    two = tarfile.TarInfo("root/file")
    _write_raw_sdist(duplicate, [(one, b""), (two, b"")])
    with duplicate.open("rb") as stream, pytest.raises(SystemExit, match="duplicate"):
        generator._sdist_metadata(stream)

    unsafe = tmp_path / "unsafe.tar.gz"
    member = tarfile.TarInfo("../outside")
    _write_raw_sdist(unsafe, [(member, b"")])
    with unsafe.open("rb") as stream, pytest.raises(
        SystemExit,
        match="unsafe archive path",
    ):
        generator._sdist_metadata(stream)

    missing = tmp_path / "missing.tar.gz"
    member = tarfile.TarInfo("root/file")
    _write_raw_sdist(missing, [(member, b"")])
    with missing.open("rb") as stream, pytest.raises(
        SystemExit,
        match="one root PKG-INFO",
    ):
        generator._sdist_metadata(stream)


def test_streaming_sdist_metadata_cardinality_and_size(tmp_path: Path) -> None:
    """Reject duplicate or oversized root metadata before unbounded extraction."""
    generator = _load_generator()

    duplicate = tmp_path / "two-metadata.tar.gz"
    first = tarfile.TarInfo("root/PKG-INFO")
    second = tarfile.TarInfo("other/PKG-INFO")
    _write_raw_sdist(duplicate, [(first, _metadata()), (second, _metadata())])
    with duplicate.open("rb") as stream, pytest.raises(
        SystemExit,
        match="one root PKG-INFO",
    ):
        generator._sdist_metadata(stream)

    oversized = tmp_path / "oversized-metadata.tar.gz"
    member = tarfile.TarInfo("root/PKG-INFO")
    _write_raw_sdist(oversized, [(member, b"x" * (generator.MAX_METADATA_BYTES + 1))])
    with oversized.open("rb") as stream, pytest.raises(
        SystemExit,
        match="metadata exceeds",
    ):
        generator._sdist_metadata(stream)


def test_streaming_sdist_semantic_special_branches_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep semantic fallback checks even after physical preflight."""
    generator = _load_generator()
    monkeypatch.setattr(
        generator,
        "_preflight_sdist_members",
        lambda stream: stream.seek(0),
    )

    class FakeMember:
        name = "root/file"
        size = 0

        def __init__(self, kind: str) -> None:
            self.kind = kind

        def issym(self) -> bool:
            return self.kind == "link"

        def islnk(self) -> bool:
            return False

        def isdev(self) -> bool:
            return False

        def isfifo(self) -> bool:
            return self.kind == "fifo"

        def issparse(self) -> bool:
            return self.kind == "sparse"

        def isfile(self) -> bool:
            return self.kind == "file"

        def isdir(self) -> bool:
            return self.kind == "dir"

    class FakeArchive:
        def __init__(self, members: list[FakeMember]) -> None:
            self.members = members

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def __iter__(self):
            return iter(self.members)

        def extractfile(self, member: FakeMember):
            return None

    for kind, message in (
        ("link", "link or special"),
        ("fifo", "link or special"),
        ("sparse", "sparse archive form"),
        ("other", "unsupported tar form"),
    ):
        monkeypatch.setattr(
            generator.tarfile,
            "open",
            lambda *args, kind=kind, **kwargs: FakeArchive([FakeMember(kind)]),
        )
        with pytest.raises(SystemExit, match=message):
            generator._sdist_metadata(io.BytesIO(b""))

    metadata_member = FakeMember("file")
    metadata_member.name = "root/PKG-INFO"
    monkeypatch.setattr(
        generator.tarfile,
        "open",
        lambda *args, **kwargs: FakeArchive([metadata_member]),
    )
    with pytest.raises(SystemExit, match="could not be read"):
        generator._sdist_metadata(io.BytesIO(b""))


def test_exact_zip_reads_and_trailing_tar_budget_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject truncated ZIP reads and over-budget zero padding after tar EOF."""
    generator = _load_generator()
    with pytest.raises(SystemExit, match="truncated"):
        generator._read_exact(io.BytesIO(b"a"), 2, "truncated")

    path = tmp_path / "padded.tar.gz"
    _write_raw_sdist(path, [], trailing=b"\x00" * 1024)
    monkeypatch.setattr(generator, "MAX_EXPANDED_TAR_BYTES", 1024)
    with path.open("rb") as stream, pytest.raises(SystemExit, match="expanded-tar"):
        generator._preflight_sdist_members(stream)


def test_streaming_sdist_semantic_member_limit_and_tar_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain a semantic member cap and normalize tarfile parser failures."""
    generator = _load_generator()
    monkeypatch.setattr(
        generator,
        "_preflight_sdist_members",
        lambda stream: stream.seek(0),
    )
    monkeypatch.setattr(generator, "MAX_ARCHIVE_MEMBERS", 1)

    class Member:
        name = "root/file"
        size = 0

        def issym(self) -> bool:
            return False

        def islnk(self) -> bool:
            return False

        def isdev(self) -> bool:
            return False

        def isfifo(self) -> bool:
            return False

        def issparse(self) -> bool:
            return False

        def isfile(self) -> bool:
            return True

        def isdir(self) -> bool:
            return False

    class Archive:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def __iter__(self):
            return iter([Member(), Member()])

    monkeypatch.setattr(generator.tarfile, "open", lambda *args, **kwargs: Archive())
    with pytest.raises(SystemExit, match="archive-member"):
        generator._sdist_metadata(io.BytesIO())

    def fail_tar(*args: object, **kwargs: object) -> object:
        raise tarfile.ReadError("invalid")

    monkeypatch.setattr(generator.tarfile, "open", fail_tar)
    with pytest.raises(SystemExit, match="not a valid gzip tar"):
        generator._sdist_metadata(io.BytesIO())
