"""Generate deterministic CycloneDX 1.7 SBOMs from release archives.

The archive is parsed as untrusted data and never imported. Output binds the
artifact SHA-256 to reviewed metadata and a hash-pinned runtime graph, without
clock-derived fields, so identical inputs produce byte-identical JSON.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement

MANIFEST_SCHEMA_VERSION = 1
SBOM_GENERATOR_VERSION = "1"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_SPEC_VERSION = "1.7"
MAX_METADATA_BYTES = MAX_MANIFEST_BYTES = 1_048_576
MAX_ARCHIVE_MEMBERS = 10_000
MAX_RELEASE_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_TAR_BYTES = 512 * 1024 * 1024
MAX_TAR_EXTENSION_BYTES = 1 * 1024 * 1024
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_EOCD_LOCATOR_SIZE = 20
ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
ZIP_EOCD = struct.Struct("<4s4H2LH")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
NAME_SEPARATORS = re.compile(r"[-_.]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
REVIEWED_SPDX_LICENSE_IDS = frozenset(
    {
        "Apache-2.0",
        "BSD-3-Clause",
        "MIT",
        "MPL-2.0",
        "PSF-2.0",
    }
)


def _parse_arguments() -> argparse.Namespace:
    """Parse artifact, manifest, and output paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("artifact", "manifest", "lock", "output"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    return parser.parse_args()


def _unsafe_artifact_error(error: BaseException | None = None) -> SystemExit:
    """Return one stable non-leaking failure for unsafe parser-visible state."""
    failure = SystemExit("release artifact is missing or unsafe")
    if error is not None:
        failure.__cause__ = error
    return failure


def _require_live_artifact_descriptor(stream: BinaryIO) -> int:
    """Return the live regular-file size or fail through a stable public error."""
    try:
        descriptor = stream.fileno()
        metadata = os.fstat(descriptor)
    except (OSError, TypeError, ValueError) as error:
        raise _unsafe_artifact_error(error)
    if (
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 0
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise _unsafe_artifact_error()
    if metadata.st_size > MAX_RELEASE_ARTIFACT_BYTES:
        raise SystemExit("release artifact exceeds the compressed-byte safety bound")
    return metadata.st_size


def _require_artifact_position(stream: BinaryIO) -> int:
    """Return one finite nonnegative parser position inside the byte ceiling."""
    try:
        position = stream.tell()
    except (OSError, TypeError, ValueError) as error:
        raise _unsafe_artifact_error(error)
    if (
        isinstance(position, bool)
        or not isinstance(position, int)
        or position < 0
        or position > MAX_RELEASE_ARTIFACT_BYTES
    ):
        raise _unsafe_artifact_error()
    return position


class _LiveBoundedArtifactReader(io.BufferedIOBase):
    """Expose parser reads and seeks while rechecking one finite live descriptor."""

    def __init__(self, stream: BinaryIO) -> None:
        super().__init__()
        self._stream = stream

    def readable(self) -> bool:
        """Report that the accepted artifact descriptor supports reads."""
        return True

    def seekable(self) -> bool:
        """Report that archive parsers may seek within the accepted descriptor."""
        return True

    def fileno(self) -> int:
        """Return the validated underlying descriptor without leaking failures."""
        try:
            descriptor = self._stream.fileno()
        except (OSError, TypeError, ValueError) as error:
            raise _unsafe_artifact_error(error)
        if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
            raise _unsafe_artifact_error()
        return descriptor

    def tell(self) -> int:
        """Return one validated finite parser position."""
        return _require_artifact_position(self._stream)

    def read(self, size: int = -1) -> bytes:
        """Read no more than the finite ceiling and reject concurrent growth."""
        _require_live_artifact_descriptor(self._stream)
        position_before = _require_artifact_position(self._stream)
        if isinstance(size, bool) or not isinstance(size, int):
            raise _unsafe_artifact_error()
        remaining_with_tripwire = MAX_RELEASE_ARTIFACT_BYTES - position_before + 1
        bounded_size = (
            remaining_with_tripwire
            if size < 0 or size > remaining_with_tripwire
            else size
        )
        try:
            payload = self._stream.read(bounded_size)
        except (OSError, TypeError, ValueError) as error:
            raise _unsafe_artifact_error(error)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise _unsafe_artifact_error()
        payload_bytes = bytes(payload)
        if len(payload_bytes) > bounded_size:
            raise _unsafe_artifact_error()
        _require_live_artifact_descriptor(self._stream)
        position_after = _require_artifact_position(self._stream)
        if position_after != position_before + len(payload_bytes):
            raise _unsafe_artifact_error()
        if len(payload_bytes) > MAX_RELEASE_ARTIFACT_BYTES:
            raise SystemExit(
                "release artifact exceeds the compressed-byte safety bound"
            )
        return payload_bytes

    def readinto(self, buffer: bytearray | memoryview) -> int:
        """Fill a parser buffer through the same bounded read contract."""
        try:
            payload = self.read(len(buffer))
            buffer[: len(payload)] = payload
        except (OSError, TypeError, ValueError) as error:
            raise _unsafe_artifact_error(error)
        return len(payload)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Seek only while descriptor state and parser position remain safe."""
        _require_live_artifact_descriptor(self._stream)
        try:
            position = self._stream.seek(offset, whence)
        except (OSError, TypeError, ValueError) as error:
            raise _unsafe_artifact_error(error)
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or position < 0
            or position > MAX_RELEASE_ARTIFACT_BYTES
        ):
            raise _unsafe_artifact_error()
        _require_live_artifact_descriptor(self._stream)
        if _require_artifact_position(self._stream) != position:
            raise _unsafe_artifact_error()
        return position


def _open_release_artifact(path: Path) -> BinaryIO:
    """Open one preflighted regular archive and bind it to the accepted identity."""
    try:
        path_metadata = path.lstat()
    except OSError as error:
        raise SystemExit("release artifact is missing or unsafe") from error
    if not stat.S_ISREG(path_metadata.st_mode):
        raise SystemExit("release artifact is missing or unsafe")
    if path_metadata.st_size > MAX_RELEASE_ARTIFACT_BYTES:
        raise SystemExit("release artifact exceeds the compressed-byte safety bound")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit("release artifact is missing or unsafe") from error
    try:
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_metadata.st_dev != path_metadata.st_dev
            or opened_metadata.st_ino != path_metadata.st_ino
        ):
            raise SystemExit("release artifact is missing or unsafe")
        if opened_metadata.st_size > MAX_RELEASE_ARTIFACT_BYTES:
            raise SystemExit(
                "release artifact exceeds the compressed-byte safety bound"
            )
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _name(value: str) -> str:
    """Return a canonical Python distribution name."""
    return NAME_SEPARATORS.sub("-", value).lower()


def _requirement(value: str) -> str:
    """Canonicalize an index requirement and reject URLs or extras."""
    try:
        parsed = Requirement(value)
    except InvalidRequirement as error:
        raise SystemExit(f"invalid runtime requirement: {value!r}") from error
    if parsed.url is not None or parsed.extras:
        raise SystemExit("runtime requirements must not use URLs or extras")
    return str(parsed)


def _requirement_name(value: str) -> str:
    """Return the canonical package name in a requirement."""
    try:
        return _name(Requirement(value).name)
    except InvalidRequirement as error:
        raise SystemExit(f"invalid runtime requirement: {value!r}") from error


def _safe_archive_name(value: str) -> bool:
    """Return whether an archive path is relative and traversal-free."""
    path = PurePosixPath(value)
    return bool(
        value
        and "\\" not in value
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _check_archive_names(names: list[str], source: str) -> None:
    """Reject excessive, duplicate, or unsafe member paths."""
    if len(names) > MAX_ARCHIVE_MEMBERS:
        raise SystemExit(f"{source} exceeds the archive-member safety bound")
    if len(names) != len(set(names)):
        raise SystemExit(f"{source} contains duplicate archive paths")
    if not all(_safe_archive_name(name) for name in names):
        raise SystemExit(f"{source} contains an unsafe archive path")


def _parse_metadata(payload: bytes, source: str) -> Message:
    """Parse bounded core metadata."""
    if len(payload) > MAX_METADATA_BYTES:
        raise SystemExit(f"{source} metadata exceeds the safety bound")
    return BytesParser(policy=default).parsebytes(payload)


def _read_exact(stream: BinaryIO, size: int, error_message: str) -> bytes:
    """Read exactly ``size`` bytes or reject a truncated untrusted archive."""
    payload = stream.read(size)
    if len(payload) != size:
        raise SystemExit(error_message)
    return payload


def _find_zip_eocd(stream: BinaryIO) -> tuple[int, tuple[int, ...]]:
    """Locate one canonical single-disk ZIP end record with a bounded tail read."""
    invalid = "release wheel is not a valid ZIP archive"
    archive_size = _require_live_artifact_descriptor(stream)
    tail_size = min(archive_size, ZIP_EOCD.size + 65_535)
    stream.seek(archive_size - tail_size)
    tail = _read_exact(stream, tail_size, invalid)
    candidate = tail.rfind(ZIP_EOCD_SIGNATURE)
    while candidate >= 0:
        if candidate + ZIP_EOCD.size <= len(tail):
            record = ZIP_EOCD.unpack_from(tail, candidate)
            if candidate + ZIP_EOCD.size + record[-1] == len(tail):
                return archive_size - tail_size + candidate, record[1:]
        candidate = tail.rfind(ZIP_EOCD_SIGNATURE, 0, candidate)
    raise SystemExit(invalid)


def _zip_extra_uses_zip64(extra: bytes) -> bool:
    """Return whether a central-directory extra field declares ZIP64 data."""
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise SystemExit("release wheel is not a valid ZIP archive")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if cursor + field_size > len(extra):
            raise SystemExit("release wheel is not a valid ZIP archive")
        if field_id == 0x0001:
            return True
        cursor += field_size
    return False


def _preflight_wheel_members(stream: BinaryIO) -> None:
    """Count canonical ZIP members before ``ZipFile`` allocates ``ZipInfo`` objects."""
    invalid = "release wheel is not a valid ZIP archive"
    eocd_offset, fields = _find_zip_eocd(stream)
    disk_number, directory_disk, disk_entries, total_entries, size, offset, _ = fields
    if (
        disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or ZIP64_EOCD_LOCATOR_SIGNATURE
        in _zip_tail_before(stream, eocd_offset, ZIP64_EOCD_LOCATOR_SIZE)
    ):
        raise SystemExit(invalid)
    if (
        total_entries == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or offset + size != eocd_offset
    ):
        raise SystemExit(invalid)
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise SystemExit("wheel exceeds the archive-member safety bound")

    stream.seek(offset)
    consumed = 0
    actual_entries = 0
    while consumed < size:
        fixed = _read_exact(stream, ZIP_CENTRAL_HEADER.size, invalid)
        consumed += len(fixed)
        values = ZIP_CENTRAL_HEADER.unpack(fixed)
        if values[0] != ZIP_CENTRAL_SIGNATURE:
            raise SystemExit(invalid)
        compressed_size, uncompressed_size = values[8], values[9]
        name_size, extra_size, comment_size = values[10], values[11], values[12]
        start_disk, local_offset = values[13], values[16]
        variable_size = name_size + extra_size + comment_size
        if consumed + variable_size > size:
            raise SystemExit(invalid)
        variable = _read_exact(stream, variable_size, invalid)
        consumed += variable_size
        extra = variable[name_size : name_size + extra_size]
        if (
            start_disk != 0
            or compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
            or _zip_extra_uses_zip64(extra)
        ):
            raise SystemExit(invalid)
        actual_entries += 1
        if actual_entries > MAX_ARCHIVE_MEMBERS:
            raise SystemExit("wheel exceeds the archive-member safety bound")
    if consumed != size or actual_entries != total_entries:
        raise SystemExit(invalid)
    stream.seek(0)


def _zip_tail_before(stream: BinaryIO, offset: int, size: int) -> bytes:
    """Read at most ``size`` bytes immediately before one ZIP structure."""
    start = max(0, offset - size)
    stream.seek(start)
    return _read_exact(
        stream,
        offset - start,
        "release wheel is not a valid ZIP archive",
    )


def _tar_number(field: bytes) -> int:
    """Parse a canonical non-negative POSIX tar octal number."""
    if field and field[0] & 0x80:
        raise SystemExit("release source distribution is not a valid gzip tar")
    stripped = field.rstrip(b"\x00 ").lstrip(b" ")
    if not stripped:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in stripped):
        raise SystemExit("release source distribution is not a valid gzip tar")
    return int(stripped, 8)


def _require_tar_checksum(header: bytes) -> None:
    """Require the stored POSIX tar checksum to match one physical header."""
    expected = _tar_number(header[148:156])
    observed = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if observed != expected:
        raise SystemExit("release source distribution is not a valid gzip tar")


def _read_expanded(
    stream: BinaryIO,
    size: int,
    consumed: int,
    *,
    retain: bool = True,
    sink: BinaryIO | None = None,
) -> tuple[bytes, int]:
    """Read bounded expanded tar bytes, optionally retaining or spooling them."""
    invalid = "release source distribution is not a valid gzip tar"
    if size < 0 or consumed + size > MAX_EXPANDED_TAR_BYTES:
        raise SystemExit("source distribution exceeds the expanded-tar safety bound")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 1_048_576))
        if not chunk:
            raise SystemExit(invalid)
        if sink is not None:
            sink.write(chunk)
        if retain:
            chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), consumed + size


def _preflight_sdist_members(stream: BinaryIO) -> BinaryIO:
    """Validate and spool one bounded expanded tar stream for semantic parsing."""
    invalid = "release source distribution is not a valid gzip tar"
    stream.seek(0)
    consumed = 0
    members = 0
    zero_headers = 0
    expanded_archive = tempfile.TemporaryFile(mode="w+b")
    try:
        with gzip.GzipFile(fileobj=stream, mode="rb") as expanded:
            while zero_headers < 2:
                header, consumed = _read_expanded(
                    expanded,
                    512,
                    consumed,
                    sink=expanded_archive,
                )
                if header == b"\x00" * 512:
                    zero_headers += 1
                    continue
                zero_headers = 0
                _require_tar_checksum(header)
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    raise SystemExit(
                        "source distribution exceeds the archive-member safety bound"
                    )
                size = _tar_number(header[124:136])
                type_flag = header[156:157]
                if type_flag in {b"1", b"2", b"3", b"4", b"6", b"7", b"S"}:
                    raise SystemExit(
                        "source distribution contains a link or special file"
                    )
                if type_flag not in {b"\x00", b"0", b"5", b"x", b"g", b"L"}:
                    raise SystemExit(
                        "source distribution contains an unsupported tar form"
                    )
                if type_flag in {b"x", b"g", b"L"} and size > MAX_TAR_EXTENSION_BYTES:
                    raise SystemExit(
                        "source distribution extension header exceeds the safety bound"
                    )
                padded_size = (size + 511) // 512 * 512
                payload, consumed = _read_expanded(
                    expanded,
                    padded_size,
                    consumed,
                    retain=type_flag in {b"x", b"g"},
                    sink=expanded_archive,
                )
                if type_flag in {b"x", b"g"} and b"GNU.sparse." in payload[:size]:
                    raise SystemExit(
                        "source distribution contains a sparse archive form"
                    )
            while True:
                trailing = expanded.read(1_048_576)
                if not trailing:
                    break
                if consumed + len(trailing) > MAX_EXPANDED_TAR_BYTES:
                    raise SystemExit(
                        "source distribution exceeds the expanded-tar safety bound"
                    )
                if trailing.strip(b"\x00"):
                    raise SystemExit(invalid)
                expanded_archive.write(trailing)
                consumed += len(trailing)
        expanded_archive.seek(0)
        return expanded_archive
    except SystemExit:
        expanded_archive.close()
        raise
    except (OSError, EOFError, zlib.error) as error:
        expanded_archive.close()
        raise SystemExit(invalid) from error
    except BaseException:
        expanded_archive.close()
        raise
    finally:
        stream.seek(0)


def _wheel_metadata(stream: BinaryIO) -> Message:
    """Read the sole bounded wheel METADATA member from the bound archive."""
    _preflight_wheel_members(stream)
    try:
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            _check_archive_names([item.filename for item in members], "wheel")
            selected = [
                item for item in members if item.filename.endswith(".dist-info/METADATA")
            ]
            if len(selected) != 1:
                raise SystemExit("wheel must contain exactly one core METADATA member")
            if selected[0].file_size > MAX_METADATA_BYTES:
                raise SystemExit("wheel metadata exceeds the safety bound")
            return _parse_metadata(archive.read(selected[0]), "wheel")
    except zipfile.BadZipFile as error:
        raise SystemExit("release wheel is not a valid ZIP archive") from error


def _sdist_metadata(stream: BinaryIO) -> Message:
    """Read one root PKG-INFO while retaining only bounded streaming state."""
    expanded_archive = _preflight_sdist_members(stream)
    selected_payload: bytes | None = None
    seen_names: set[str] = set()
    member_count = 0
    try:
        with tarfile.open(fileobj=expanded_archive, mode="r:") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise SystemExit(
                        "source distribution exceeds the archive-member safety bound"
                    )
                if member.name in seen_names:
                    raise SystemExit(
                        "source distribution contains duplicate archive paths"
                    )
                seen_names.add(member.name)
                if not _safe_archive_name(member.name):
                    raise SystemExit(
                        "source distribution contains an unsafe archive path"
                    )
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                ):
                    raise SystemExit(
                        "source distribution contains a link or special file"
                    )
                if member.issparse():
                    raise SystemExit(
                        "source distribution contains a sparse archive form"
                    )
                if not (member.isfile() or member.isdir()):
                    raise SystemExit(
                        "source distribution contains an unsupported tar form"
                    )
                path = PurePosixPath(member.name)
                if (
                    member.isfile()
                    and len(path.parts) == 2
                    and path.name == "PKG-INFO"
                ):
                    if selected_payload is not None:
                        raise SystemExit(
                            "source distribution must contain one root PKG-INFO"
                        )
                    if member.size > MAX_METADATA_BYTES:
                        raise SystemExit(
                            "source distribution metadata exceeds the safety bound"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise SystemExit(
                            "source distribution metadata could not be read"
                        )
                    selected_payload = extracted.read(MAX_METADATA_BYTES + 1)
        if selected_payload is None:
            raise SystemExit("source distribution must contain one root PKG-INFO")
        return _parse_metadata(selected_payload, "source distribution")
    except tarfile.TarError as error:
        raise SystemExit(
            "release source distribution is not a valid gzip tar"
        ) from error
    finally:
        expanded_archive.close()


def _artifact_metadata(stream: BinaryIO, filename: str) -> Message:
    """Read metadata through a live-bounded wheel or source-archive descriptor."""
    bounded_stream = _LiveBoundedArtifactReader(stream)
    if filename.endswith(".whl"):
        return _wheel_metadata(bounded_stream)
    if filename.endswith(".tar.gz"):
        return _sdist_metadata(bounded_stream)
    raise SystemExit("release artifact must be a .whl or .tar.gz distribution")


def _text(data: dict[str, Any], key: str, context: str) -> str:
    """Return one required safe non-empty string."""
    value = data.get(key)
    if not isinstance(value, str) or not value or any(c in value for c in "\r\n\x00"):
        raise SystemExit(f"{context} requires safe string field {key!r}")
    return value


def _reviewed_spdx_license_id(data: dict[str, Any], key: str, context: str) -> str:
    """Return one reviewed SPDX identifier accepted by CycloneDX 1.7."""
    value = _text(data, key, context)
    if value not in REVIEWED_SPDX_LICENSE_IDS:
        raise SystemExit(f"{context} requires a reviewed SPDX license identifier")
    return value


def _list(data: dict[str, Any], key: str, context: str) -> list[str]:
    """Return one required unique list of safe strings."""
    value = data.get(key)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or any(c in item for c in "\r\n\x00")
        for item in value
    ):
        raise SystemExit(f"{context} requires safe string-list field {key!r}")
    if len(value) != len(set(value)):
        raise SystemExit(f"{context} field {key!r} contains duplicates")
    return value


def _names(data: dict[str, Any], key: str, context: str) -> list[str]:
    """Return one unique list of canonical package names."""
    values = [_name(item) for item in _list(data, key, context)]
    if len(values) != len(set(values)):
        raise SystemExit(f"{context} field {key!r} contains duplicate names")
    return values


def _component(raw: object) -> dict[str, Any]:
    """Validate one reviewed dependency component."""
    if not isinstance(raw, dict):
        raise SystemExit("manifest components must be objects")
    name = _name(_text(raw, "name", "component"))
    item = {
        "name": name,
        "version": _text(raw, "version", name),
        "license": _reviewed_spdx_license_id(raw, "license", name),
        "sha256": _text(raw, "sha256", name),
        "artifact_filename": _text(raw, "artifact_filename", name),
        "purl": _text(raw, "purl", name),
        "depends_on": _names(raw, "depends_on", name),
        "marker": raw.get("marker"),
    }
    if SHA256.fullmatch(item["sha256"]) is None:
        raise SystemExit(f"component {name} requires a lowercase SHA-256 digest")
    if "/" in item["artifact_filename"] or "\\" in item["artifact_filename"]:
        raise SystemExit(f"component {name} artifact filename must not contain a path")
    expected = f"pkg:pypi/{name}@{item['version']}"
    if item["purl"] != expected:
        raise SystemExit(f"component {name} purl must equal {expected!r}")
    marker = item["marker"]
    if marker is not None and (
        not isinstance(marker, str)
        or not marker
        or len(marker) > 200
        or any(c in marker for c in "\r\n\x00")
    ):
        raise SystemExit(f"component {name} has an invalid runtime marker")
    return item


def _reachable(roots: list[str], components: dict[str, dict[str, Any]]) -> set[str]:
    """Return reachable package names while rejecting unknowns and cycles."""
    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in active:
            raise SystemExit(f"runtime dependency manifest contains a cycle at {name!r}")
        if name in visited:
            return
        if name not in components:
            raise SystemExit(f"runtime dependency manifest references unknown {name!r}")
        active.add(name)
        for dependency in components[name]["depends_on"]:
            visit(dependency)
        active.remove(name)
        visited.add(name)

    for root in roots:
        visit(root)
    return visited


def _load_manifest(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load and validate the reviewed runtime dependency closure."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise SystemExit("runtime dependency manifest exceeds the safety bound")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit("runtime dependency manifest is unreadable or invalid JSON") from error
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise SystemExit("runtime dependency manifest schema_version must equal 1")
    raw_root = raw.get("root")
    if not isinstance(raw_root, dict):
        raise SystemExit("runtime dependency manifest requires a root object")
    root = {
        "name": _name(_text(raw_root, "name", "root")),
        "license": _reviewed_spdx_license_id(raw_root, "license", "root"),
        "depends_on": _names(raw_root, "depends_on", "root"),
        "requires_dist": sorted(
            _requirement(item) for item in _list(raw_root, "requires_dist", "root")
        ),
    }
    required_names = sorted(_requirement_name(item) for item in root["requires_dist"])
    if required_names != sorted(root["depends_on"]):
        raise SystemExit("root requirement names must exactly match root dependencies")
    raw_components = raw.get("components")
    if not isinstance(raw_components, list) or not raw_components:
        raise SystemExit("runtime dependency manifest requires components")
    components: dict[str, dict[str, Any]] = {}
    for raw_component in raw_components:
        item = _component(raw_component)
        if item["name"] in components:
            raise SystemExit(f"runtime dependency manifest duplicates component {item['name']!r}")
        if item["name"] == root["name"]:
            raise SystemExit("root package cannot also be a dependency")
        components[item["name"]] = item
    unreachable = set(components) - _reachable(root["depends_on"], components)
    if unreachable:
        raise SystemExit(
            "runtime dependency manifest contains unreachable components: "
            f"{sorted(unreachable)}"
        )
    return root, components


def _canonical_marker(value: str | None, context: str) -> str | None:
    """Return a normalized environment marker or reject invalid syntax."""
    if value is None:
        return None
    try:
        return str(Marker(value))
    except InvalidMarker as error:
        raise SystemExit(f"{context} contains an invalid environment marker") from error


def _load_runtime_lock(path: Path) -> dict[str, dict[str, str | None]]:
    """Load exact package versions, markers, and hashes from the CI lock."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise SystemExit("runtime lock exceeds the safety bound")
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SystemExit("runtime lock is unreadable") from error
    entries: dict[str, dict[str, str | None]] = {}
    for raw_line in content.replace("\\\n", " ").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("--hash=sha256:") != 1:
            raise SystemExit("runtime lock entries require exactly one SHA-256 hash")
        requirement_text, digest = line.split("--hash=sha256:", 1)
        digest = digest.strip()
        if SHA256.fullmatch(digest) is None:
            raise SystemExit("runtime lock contains a noncanonical SHA-256 hash")
        try:
            requirement = Requirement(requirement_text.strip())
        except InvalidRequirement as error:
            raise SystemExit("runtime lock contains an invalid requirement") from error
        if requirement.extras:
            raise SystemExit("runtime lock requirements must not use extras")
        name = _name(requirement.name)
        if name in entries:
            raise SystemExit(f"runtime lock duplicates package {name!r}")
        specifiers = list(requirement.specifier)
        version = (
            specifiers[0].version
            if requirement.url is None
            and len(specifiers) == 1
            and specifiers[0].operator == "=="
            else None
        )
        entries[name] = {
            "version": version,
            "sha256": digest,
            "marker": str(requirement.marker) if requirement.marker is not None else None,
        }
    return entries


def validate_runtime_lock(manifest_path: Path, lock_path: Path) -> None:
    """Require every SBOM dependency to equal its executable lock evidence."""
    _, components = _load_manifest(manifest_path)
    lock_entries = _load_runtime_lock(lock_path)
    for name, component in components.items():
        locked = lock_entries.get(name)
        expected = {
            "version": component["version"],
            "sha256": component["sha256"],
            "marker": _canonical_marker(component["marker"], f"component {name}"),
        }
        if locked != expected:
            raise SystemExit(
                f"component {name!r} does not match the hash-locked runtime subset"
            )


def _identity(metadata: Message) -> tuple[str, str, str, list[str]]:
    """Return package identity and canonical direct requirements."""
    name = metadata.get("Name")
    version = metadata.get("Version")
    license_id = metadata.get("License-Expression")
    if not name or not version or not license_id:
        raise SystemExit("artifact metadata lacks identity or license fields")
    requirements = sorted(
        _requirement(item) for item in metadata.get_all("Requires-Dist", [])
    )
    if len(requirements) != len(set(requirements)):
        raise SystemExit("artifact metadata contains duplicate runtime requirements")
    return _name(name), version, license_id, requirements


def _sha256_file(stream: BinaryIO) -> str:
    """Hash the bound artifact while enforcing its live finite byte ceiling."""
    digest = hashlib.sha256()
    stream.seek(0)
    consumed = 0
    while block := stream.read(1_048_576):
        consumed += len(block)
        if consumed > MAX_RELEASE_ARTIFACT_BYTES:
            raise SystemExit(
                "release artifact exceeds the compressed-byte safety bound"
            )
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def _component_json(item: dict[str, Any]) -> dict[str, Any]:
    """Convert one component to deterministic CycloneDX JSON."""
    properties = [
        {
            "name": "egressweave:release:dependency-artifact",
            "value": item["artifact_filename"],
        }
    ]
    if item["marker"] is not None:
        properties.append(
            {"name": "egressweave:release:runtime-marker", "value": item["marker"]}
        )
    return {
        "type": "library",
        "bom-ref": item["purl"],
        "name": item["name"],
        "version": item["version"],
        "purl": item["purl"],
        "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
        "licenses": [{"license": {"id": item["license"]}}],
        "properties": properties,
    }


def build_sbom(artifact_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Build deterministic CycloneDX evidence for one exact distribution."""
    with _open_release_artifact(artifact_path) as artifact_stream:
        digest_before = _sha256_file(artifact_stream)
        package, version, license_id, requirements = _identity(
            _artifact_metadata(artifact_stream, artifact_path.name)
        )
        digest = _sha256_file(artifact_stream)
    if digest != digest_before:
        raise SystemExit("release artifact changed during verification")

    root, components = _load_manifest(manifest_path)
    if package != root["name"] or license_id != root["license"]:
        raise SystemExit("artifact identity or license does not match the manifest")
    names = sorted(_requirement_name(item) for item in requirements)
    if names != sorted(root["depends_on"]):
        raise SystemExit("artifact direct runtime dependencies do not match the manifest")
    if requirements != root["requires_dist"]:
        raise SystemExit("artifact runtime requirement declarations do not match the manifest")
    root_ref = f"urn:egressweave:artifact:sha256:{digest}"
    ordered = sorted(components.values(), key=lambda item: item["purl"])
    dependencies = [
        {
            "ref": root_ref,
            "dependsOn": sorted(components[name]["purl"] for name in root["depends_on"]),
        },
        *(
            {
                "ref": item["purl"],
                "dependsOn": sorted(
                    components[name]["purl"] for name in item["depends_on"]
                ),
            }
            for item in ordered
        ),
    ]
    return {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": package,
                "version": version,
                "purl": f"pkg:pypi/{package}@{version}",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "licenses": [{"license": {"id": license_id}}],
                "properties": [
                    {
                        "name": "egressweave:release:artifact-filename",
                        "value": artifact_path.name,
                    },
                    {
                        "name": "egressweave:release:dependency-scope",
                        "value": "supported-python-runtime-union",
                    },
                    {
                        "name": "egressweave:release:generator-version",
                        "value": SBOM_GENERATOR_VERSION,
                    },
                ],
            }
        },
        "components": [_component_json(item) for item in ordered],
        "dependencies": dependencies,
    }


def write_sbom(sbom: dict[str, Any], output_path: Path) -> None:
    """Write stable sorted UTF-8 JSON with one trailing newline."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Generate one release SBOM and return zero on success."""
    arguments = _parse_arguments()
    validate_runtime_lock(arguments.manifest.resolve(), arguments.lock.resolve())
    write_sbom(
        build_sbom(arguments.artifact, arguments.manifest.resolve()),
        arguments.output.resolve(),
    )
    print(f"wrote CycloneDX {CYCLONEDX_SPEC_VERSION} SBOM: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
