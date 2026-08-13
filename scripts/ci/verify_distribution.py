"""Verify EgressWeave release distributions without executing package code.

The verifier treats wheel and source-distribution archives as data. It confirms
that filenames, metadata, license evidence, typed-package markers, versioned
machine-readable schema resources, and source contents match ``pyproject.toml``;
optionally binds a published GitHub release tag to the package version and dated
changelog section; and writes deterministic SHA-256 checksums for the
credential-separated publishing job.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import BinaryIO

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

DISTRIBUTION_NAME = "egressweave"
HASH_CHUNK_SIZE = 1024 * 1024
MAX_DISTRIBUTION_BYTES = 256 * 1024 * 1024
MAX_SDIST_MEMBERS = 4096
MAX_WHEEL_MEMBERS = 4096
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_EOCD_LOCATOR_SIZE = 20
ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
ZIP_EOCD = struct.Struct("<4s4H2LH")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
CHANGELOG_RELEASE_PATTERN = re.compile(
    r"^## \[(?P<version>\d+\.\d+\.\d+)\] - (?P<date>\d{4}-\d{2}-\d{2})$",
    flags=re.MULTILINE,
)
CHANGELOG_UNRELEASED_PATTERN = re.compile(
    r"^## \[Unreleased\]\s*\n(?P<body>.*?)(?=^## \[)",
    flags=re.MULTILINE | re.DOTALL,
)


def _parse_arguments() -> argparse.Namespace:
    """Parse the distribution directory and optional release-tag binding."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=Path("dist"),
        help="directory containing exactly one EgressWeave wheel and sdist",
    )
    parser.add_argument(
        "--release-ref",
        help="published release tag, required to equal v<project.version>",
    )
    return parser.parse_args()


def _load_project(repository_root: Path) -> dict[str, object]:
    """Return the PEP 621 project table from the repository configuration."""
    with (repository_root / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)
    return pyproject["project"]


def _normalized_distribution_stem(name: str) -> str:
    """Return the normalized wheel/sdist filename stem for a project name."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _require_regular_distribution_state(archive_path: Path) -> os.stat_result:
    """Return bounded lexical state for one canonical distribution archive."""
    try:
        archive_state = archive_path.lstat()
    except OSError:
        raise SystemExit("distribution archive is missing or unsafe") from None
    if not stat.S_ISREG(archive_state.st_mode):
        raise SystemExit("distribution archive is missing or unsafe")
    if archive_state.st_size > MAX_DISTRIBUTION_BYTES:
        raise SystemExit(
            "distribution archive exceeds the 256 MiB verification limit: "
            f"{archive_path.name}"
        )
    return archive_state


def _same_distribution_state(expected: os.stat_result, observed: os.stat_result) -> bool:
    """Return whether two snapshots identify the same unchanged regular file."""
    return (
        stat.S_ISREG(observed.st_mode)
        and expected.st_dev == observed.st_dev
        and expected.st_ino == observed.st_ino
        and expected.st_size == observed.st_size
    )


def _sha256_exact_size(archive_file: BinaryIO, expected_size: int) -> str | None:
    """Digest exactly one accepted file size, returning None on byte-count drift."""
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = archive_file.read(min(HASH_CHUNK_SIZE, remaining))
        if not chunk:
            return None
        digest.update(chunk)
        remaining -= len(chunk)
    if archive_file.read(1):
        return None
    return digest.hexdigest()


@contextmanager
def _open_stable_distribution(archive_path: Path) -> Iterator[BinaryIO]:
    """Yield a bounded immutable parser snapshot while retaining source identity."""
    expected_state = _require_regular_distribution_state(archive_path)
    try:
        archive_file = archive_path.open("rb")
    except OSError:
        raise SystemExit("distribution archive is missing or unsafe") from None

    try:
        opened_state = os.fstat(archive_file.fileno())
        if not _same_distribution_state(expected_state, opened_state):
            raise SystemExit("distribution archive is missing or unsafe")

        with tempfile.TemporaryFile(mode="w+b") as snapshot_file:
            snapshot_digest = hashlib.sha256()
            remaining = expected_state.st_size
            while remaining:
                chunk = archive_file.read(min(HASH_CHUNK_SIZE, remaining))
                if not chunk:
                    raise SystemExit("distribution archive is missing or unsafe")
                snapshot_file.write(chunk)
                snapshot_digest.update(chunk)
                remaining -= len(chunk)
            if archive_file.read(1):
                raise SystemExit(
                    "distribution archive exceeds the 256 MiB verification limit: "
                    f"{archive_path.name}"
                )

            snapshot_open_state = os.fstat(archive_file.fileno())
            snapshot_path_state = _require_regular_distribution_state(archive_path)
            if not _same_distribution_state(
                expected_state,
                snapshot_open_state,
            ) or not _same_distribution_state(expected_state, snapshot_path_state):
                raise SystemExit("distribution archive is missing or unsafe")

            accepted_digest = snapshot_digest.hexdigest()
            snapshot_file.seek(0)
            yield snapshot_file
            final_open_state = os.fstat(archive_file.fileno())
            final_source_digest = None
            if _same_distribution_state(expected_state, final_open_state):
                archive_file.seek(0)
                final_source_digest = _sha256_exact_size(
                    archive_file,
                    expected_state.st_size,
                )
    except SystemExit:
        raise
    except OSError:
        raise SystemExit("distribution archive is missing or unsafe") from None
    finally:
        archive_file.close()

    final_path_state = _require_regular_distribution_state(archive_path)
    if not _same_distribution_state(
        expected_state,
        final_open_state,
    ) or not _same_distribution_state(expected_state, final_path_state):
        raise SystemExit("distribution archive is missing or unsafe")
    if final_source_digest != accepted_digest:
        raise SystemExit("distribution archive is missing or unsafe")


def _select_archives(dist_dir: Path, name: str, version: str) -> tuple[Path, Path]:
    """Select only finite canonical wheel and source distributions for publication."""
    normalized_name = _normalized_distribution_stem(name)
    wheel_path = dist_dir / f"{normalized_name}-{version}-py3-none-any.whl"
    sdist_path = dist_dir / f"{name}-{version}.tar.gz"
    publishable_archives = sorted(
        [*dist_dir.glob("*.whl"), *dist_dir.glob("*.tar.gz")],
        key=lambda path: path.name,
    )
    expected_archives = {wheel_path, sdist_path}
    if len(publishable_archives) != 2 or set(publishable_archives) != expected_archives:
        raise SystemExit(
            "unexpected distribution archives; expected exactly "
            f"{sorted(path.name for path in expected_archives)}, observed "
            f"{[path.name for path in publishable_archives]}"
        )
    for archive_path in publishable_archives:
        _require_regular_distribution_state(archive_path)
    return wheel_path, sdist_path


def _admit_archive_name(name: str, seen: set[str]) -> None:
    """Validate and retain one archive path without building an unbounded name list."""
    pure_path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure_path.is_absolute()
        or any(part in {"", ".", ".."} for part in pure_path.parts)
        or name in seen
    ):
        raise SystemExit(f"distribution contains an unsafe archive path: {name!r}")
    seen.add(name)


def _safe_archive_names(names: list[str]) -> set[str]:
    """Reject absolute, parent-traversing, duplicate, or backslash archive paths."""
    seen: set[str] = set()
    for name in names:
        _admit_archive_name(name, seen)
    return seen


def _read_exact(stream: BinaryIO, size: int, error_message: str) -> bytes:
    """Read exactly ``size`` stable-snapshot bytes or fail closed on truncation."""
    payload = stream.read(size)
    if len(payload) != size:
        raise SystemExit(error_message)
    return payload


def _wheel_snapshot_size(stream: BinaryIO) -> int:
    """Return one finite stable wheel snapshot size without reopening its path."""
    try:
        size = stream.seek(0, os.SEEK_END)
    except OSError:
        raise SystemExit("wheel is not a valid ZIP archive") from None
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > MAX_DISTRIBUTION_BYTES
    ):
        raise SystemExit("wheel is not a valid ZIP archive")
    return size


def _find_wheel_eocd(stream: BinaryIO) -> tuple[int, tuple[int, ...]]:
    """Locate one canonical single-disk ZIP end record with a bounded tail read."""
    invalid = "wheel is not a valid ZIP archive"
    archive_size = _wheel_snapshot_size(stream)
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


def _wheel_extra_uses_zip64(extra: bytes) -> bool:
    """Return whether a central-directory extra field declares ZIP64 data."""
    invalid = "wheel is not a valid ZIP archive"
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise SystemExit(invalid)
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if cursor + field_size > len(extra):
            raise SystemExit(invalid)
        if field_id == 0x0001:
            return True
        cursor += field_size
    return False


def _wheel_tail_before(stream: BinaryIO, offset: int, size: int) -> bytes:
    """Read at most ``size`` bytes immediately before one ZIP structure."""
    start = max(0, offset - size)
    stream.seek(start)
    return _read_exact(
        stream,
        offset - start,
        "wheel is not a valid ZIP archive",
    )


def _preflight_wheel_members(stream: BinaryIO) -> None:
    """Bound canonical ZIP entries before ``ZipFile`` allocates ``ZipInfo`` objects."""
    invalid = "wheel is not a valid ZIP archive"
    eocd_offset, fields = _find_wheel_eocd(stream)
    disk_number, directory_disk, disk_entries, total_entries, size, offset, _ = fields
    if (
        disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or _wheel_tail_before(
            stream,
            eocd_offset,
            ZIP64_EOCD_LOCATOR_SIZE,
        ).startswith(ZIP64_EOCD_LOCATOR_SIGNATURE)
    ):
        raise SystemExit(invalid)
    if (
        total_entries == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or offset + size != eocd_offset
    ):
        raise SystemExit(invalid)
    if total_entries > MAX_WHEEL_MEMBERS:
        raise SystemExit("wheel member limit exceeded")

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
            or _wheel_extra_uses_zip64(extra)
        ):
            raise SystemExit(invalid)
        actual_entries += 1
        if actual_entries > MAX_WHEEL_MEMBERS:
            raise SystemExit("wheel member limit exceeded")
    if consumed != size or actual_entries != total_entries:
        raise SystemExit(invalid)
    stream.seek(0)


def _verify_wheel(wheel_path: Path, project: dict[str, object]) -> str:
    """Verify wheel contents after bounded central-directory member admission."""
    version = str(project["version"])
    dist_info = f"{DISTRIBUTION_NAME}-{version}.dist-info"
    required_paths = {
        f"{DISTRIBUTION_NAME}/__init__.py",
        f"{DISTRIBUTION_NAME}/py.typed",
        f"{DISTRIBUTION_NAME}/schemas/decision-evidence-v1.schema.json",
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/RECORD",
        f"{dist_info}/licenses/LICENSE",
    }

    with _open_stable_distribution(wheel_path) as wheel_file:
        wheel_digest = _sha256_stream(wheel_file)
        wheel_file.seek(0)
        _preflight_wheel_members(wheel_file)
        with zipfile.ZipFile(wheel_file) as wheel_archive:
            names = _safe_archive_names(wheel_archive.namelist())
            missing = required_paths - names
            if missing:
                raise SystemExit(f"wheel is missing required files: {sorted(missing)}")
            metadata = BytesParser(policy=default).parsebytes(
                wheel_archive.read(f"{dist_info}/METADATA")
            )

    expected_metadata = {
        "Name": str(project["name"]),
        "Version": version,
        "Requires-Python": str(project["requires-python"]),
        "License-Expression": str(project["license"]),
    }
    for field_name, expected_value in expected_metadata.items():
        if metadata.get(field_name) != expected_value:
            raise SystemExit(
                f"wheel metadata {field_name!r} did not match: "
                f"expected {expected_value!r}, observed {metadata.get(field_name)!r}"
            )
    if "LICENSE" not in metadata.get_all("License-File", []):
        raise SystemExit("wheel metadata does not declare LICENSE as a license file")
    return wheel_digest


def _verify_sdist(sdist_path: Path, project: dict[str, object]) -> str:
    """Verify source-distribution paths with bounded streaming member admission."""
    version = str(project["version"])
    prefix = f"{DISTRIBUTION_NAME}-{version}"
    required_paths = {
        f"{prefix}/pyproject.toml",
        f"{prefix}/README.md",
        f"{prefix}/CHANGELOG.md",
        f"{prefix}/LICENSE",
        f"{prefix}/src/{DISTRIBUTION_NAME}/__init__.py",
        f"{prefix}/src/{DISTRIBUTION_NAME}/py.typed",
        (
            f"{prefix}/src/{DISTRIBUTION_NAME}/schemas/"
            "decision-evidence-v1.schema.json"
        ),
        f"{prefix}/tests/test_quality_contracts.py",
        f"{prefix}/docs/release.md",
    }

    with _open_stable_distribution(sdist_path) as sdist_file:
        sdist_digest = _sha256_stream(sdist_file)
        sdist_file.seek(0)
        names: set[str] = set()
        with tarfile.open(fileobj=sdist_file, mode="r|gz") as sdist_archive:
            for member_count, member in enumerate(sdist_archive, start=1):
                if member_count > MAX_SDIST_MEMBERS:
                    raise SystemExit("source distribution member limit exceeded")
                _admit_archive_name(member.name, names)
                if member.issym() or member.islnk() or member.isdev():
                    raise SystemExit("source distribution contains a link or device entry")
                # Python 3.10-3.14 retain yielded TarInfo objects in this public list.
                # Links are rejected above, so no later member may need that cache.
                sdist_archive.members.clear()

    missing = required_paths - names
    if missing:
        raise SystemExit(
            f"source distribution is missing required files: {sorted(missing)}"
        )
    if any(not name.startswith(f"{prefix}/") for name in names):
        raise SystemExit("source distribution contains a path outside its versioned root")
    return sdist_digest


def _verify_release_ref(
    release_ref: str | None,
    version: str,
    changelog_path: Path,
) -> None:
    """Bind an optional published release tag to the version and changelog."""
    if release_ref is None:
        return
    expected_ref = f"v{version}"
    if release_ref != expected_ref:
        raise SystemExit(
            f"release tag must equal {expected_ref!r}; observed {release_ref!r}"
        )
    changelog = changelog_path.read_text(encoding="utf-8")
    released_versions = {
        match.group("version") for match in CHANGELOG_RELEASE_PATTERN.finditer(changelog)
    }
    if version not in released_versions:
        raise SystemExit(
            f"CHANGELOG.md lacks a dated release section for version {version}"
        )
    unreleased_match = CHANGELOG_UNRELEASED_PATTERN.search(changelog)
    if unreleased_match is None:
        raise SystemExit("CHANGELOG.md lacks the required Unreleased section")
    if unreleased_match.group("body").strip():
        raise SystemExit(
            "CHANGELOG.md Unreleased section is not empty; move every entry into "
            "the dated release section before publishing"
        )


def _sha256_stream(archive_file: BinaryIO) -> str:
    """Return a digest while keeping each binary read bounded to 1 MiB."""
    digest = hashlib.sha256()
    while chunk := archive_file.read(HASH_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_file(archive_path: Path) -> str:
    """Hash one stable bounded regular distribution without following retargets."""
    with _open_stable_distribution(archive_path) as archive_file:
        return _sha256_stream(archive_file)


def _write_sha256sums(
    dist_dir: Path,
    archives: tuple[Path, Path],
    *,
    expected_digests: dict[Path, str] | None = None,
) -> Path:
    """Create checksums only for bytes matching any parsed snapshot digests."""
    checksum_path = dist_dir / "SHA256SUMS"
    lines: list[str] = []
    for archive_path in sorted(archives, key=lambda path: path.name):
        digest = _sha256_file(archive_path)
        if expected_digests is not None and digest != expected_digests.get(archive_path):
            raise SystemExit("distribution archive is missing or unsafe")
        lines.append(f"{digest}  {archive_path.name}\n")
    try:
        with checksum_path.open("x", encoding="ascii", newline="\n") as checksum_file:
            checksum_file.write("".join(lines))
    except OSError:
        raise SystemExit("checksum output path already exists or is unsafe") from None
    return checksum_path


def main() -> int:
    """Verify distributions and write checksums, returning zero on success."""
    arguments = _parse_arguments()
    repository_root = Path(__file__).resolve().parents[2]
    project = _load_project(repository_root)
    if project["name"] != DISTRIBUTION_NAME:
        raise SystemExit(
            f"unexpected project name: expected {DISTRIBUTION_NAME!r}, "
            f"observed {project['name']!r}"
        )

    dist_dir = arguments.dist_dir.resolve()
    wheel_path, sdist_path = _select_archives(
        dist_dir,
        str(project["name"]),
        str(project["version"]),
    )
    wheel_digest = _verify_wheel(wheel_path, project)
    sdist_digest = _verify_sdist(sdist_path, project)
    _verify_release_ref(
        arguments.release_ref,
        str(project["version"]),
        repository_root / "CHANGELOG.md",
    )
    checksum_path = _write_sha256sums(
        dist_dir,
        (wheel_path, sdist_path),
        expected_digests={wheel_path: wheel_digest, sdist_path: sdist_digest},
    )
    print(f"verified {wheel_path.name}, {sdist_path.name}, and {checksum_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
