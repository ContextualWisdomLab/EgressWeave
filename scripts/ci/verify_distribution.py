#!/usr/bin/env python3
"""Verify EgressWeave release distributions without executing package code.

The verifier treats wheel and source-distribution archives as data. It confirms
that filenames, metadata, license evidence, typed-package markers, and source
contents match ``pyproject.toml``; optionally binds a published GitHub release
tag to the package version and dated changelog section; and writes deterministic
SHA-256 checksums for the credential-separated publishing job.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import tarfile
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

DISTRIBUTION_NAME = "egressweave"
CHANGELOG_RELEASE_PATTERN = re.compile(
    r"^## \[(?P<version>\d+\.\d+\.\d+)\] - (?P<date>\d{4}-\d{2}-\d{2})$",
    flags=re.MULTILINE,
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


def _select_archives(dist_dir: Path, name: str, version: str) -> tuple[Path, Path]:
    """Select exactly one correctly named wheel and source distribution."""
    normalized_name = _normalized_distribution_stem(name)
    wheel_candidates = sorted(
        dist_dir.glob(f"{normalized_name}-{version}-py3-none-any.whl")
    )
    sdist_candidates = sorted(dist_dir.glob(f"{name}-{version}.tar.gz"))
    if len(wheel_candidates) != 1 or len(sdist_candidates) != 1:
        raise SystemExit(
            "expected exactly one canonical wheel and source distribution; "
            f"found wheels={wheel_candidates}, sdists={sdist_candidates}"
        )
    return wheel_candidates[0], sdist_candidates[0]


def _safe_archive_names(names: list[str]) -> set[str]:
    """Reject absolute, parent-traversing, duplicate, or backslash archive paths."""
    seen: set[str] = set()
    for name in names:
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
    return seen


def _verify_wheel(wheel_path: Path, project: dict[str, object]) -> None:
    """Verify wheel contents and core metadata without importing the package."""
    version = str(project["version"])
    dist_info = f"{DISTRIBUTION_NAME}-{version}.dist-info"
    required_paths = {
        f"{DISTRIBUTION_NAME}/__init__.py",
        f"{DISTRIBUTION_NAME}/py.typed",
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/RECORD",
        f"{dist_info}/licenses/LICENSE",
    }

    with zipfile.ZipFile(wheel_path) as wheel_archive:
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


def _verify_sdist(sdist_path: Path, project: dict[str, object]) -> None:
    """Verify source-distribution paths and required release evidence."""
    version = str(project["version"])
    prefix = f"{DISTRIBUTION_NAME}-{version}"
    required_paths = {
        f"{prefix}/pyproject.toml",
        f"{prefix}/README.md",
        f"{prefix}/CHANGELOG.md",
        f"{prefix}/LICENSE",
        f"{prefix}/src/{DISTRIBUTION_NAME}/__init__.py",
        f"{prefix}/src/{DISTRIBUTION_NAME}/py.typed",
        f"{prefix}/tests/test_quality_contracts.py",
        f"{prefix}/docs/release.md",
    }

    with tarfile.open(sdist_path, mode="r:gz") as sdist_archive:
        members = sdist_archive.getmembers()
        names = _safe_archive_names([member.name for member in members])
        if any(member.issym() or member.islnk() or member.isdev() for member in members):
            raise SystemExit("source distribution contains a link or device entry")

    missing = required_paths - names
    if missing:
        raise SystemExit(
            f"source distribution is missing required files: {sorted(missing)}"
        )
    if any(not name.startswith(f"{prefix}/") for name in names):
        raise SystemExit("source distribution contains a path outside its versioned root")


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


def _write_sha256sums(dist_dir: Path, archives: tuple[Path, Path]) -> Path:
    """Write deterministic SHA-256 checksums for the reviewed distributions."""
    checksum_path = dist_dir / "SHA256SUMS"
    lines: list[str] = []
    for archive_path in sorted(archives, key=lambda path: path.name):
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {archive_path.name}\n")
    checksum_path.write_text("".join(lines), encoding="ascii")
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
    _verify_wheel(wheel_path, project)
    _verify_sdist(sdist_path, project)
    _verify_release_ref(
        arguments.release_ref,
        str(project["version"]),
        repository_root / "CHANGELOG.md",
    )
    checksum_path = _write_sha256sums(dist_dir, (wheel_path, sdist_path))
    print(f"verified {wheel_path.name}, {sdist_path.name}, and {checksum_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
