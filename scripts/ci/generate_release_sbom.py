"""Generate deterministic CycloneDX 1.7 SBOMs from release archives.

The archive is parsed as untrusted data and never imported. Output binds the
artifact SHA-256 to reviewed metadata and a hash-pinned runtime graph, without
clock-derived fields, so identical inputs produce byte-identical JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tarfile
import zipfile
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement

MANIFEST_SCHEMA_VERSION = 1
SBOM_GENERATOR_VERSION = "1"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_SPEC_VERSION = "1.7"
MAX_METADATA_BYTES = MAX_MANIFEST_BYTES = 1_048_576
MAX_ARCHIVE_MEMBERS = 10_000
MAX_RELEASE_ARTIFACT_BYTES = 256 * 1024 * 1024
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


def _preflight_release_artifact(path: Path) -> None:
    """Reject an unsafe or oversized release archive before parser execution."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit("release artifact is missing or unsafe") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("release artifact is missing or unsafe")
    if metadata.st_size > MAX_RELEASE_ARTIFACT_BYTES:
        raise SystemExit("release artifact exceeds the compressed-byte safety bound")


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


def _wheel_metadata(path: Path) -> Message:
    """Read the sole bounded wheel METADATA member."""
    try:
        with zipfile.ZipFile(path) as archive:
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


def _sdist_metadata(path: Path) -> Message:
    """Read the sole bounded root PKG-INFO member."""
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            _check_archive_names([item.name for item in members], "source distribution")
            if any(item.issym() or item.islnk() or item.isdev() for item in members):
                raise SystemExit("source distribution contains a link or device")
            selected = [
                item
                for item in members
                if item.isfile()
                and len(PurePosixPath(item.name).parts) == 2
                and PurePosixPath(item.name).name == "PKG-INFO"
            ]
            if len(selected) != 1:
                raise SystemExit("source distribution must contain one root PKG-INFO")
            if selected[0].size > MAX_METADATA_BYTES:
                raise SystemExit("source distribution metadata exceeds the safety bound")
            stream = archive.extractfile(selected[0])
            if stream is None:
                raise SystemExit("source distribution metadata could not be read")
            return _parse_metadata(stream.read(), "source distribution")
    except tarfile.TarError as error:
        raise SystemExit("release source distribution is not a valid gzip tar") from error


def _artifact_metadata(path: Path) -> Message:
    """Read metadata from a wheel or gzip source distribution."""
    if path.name.endswith(".whl"):
        return _wheel_metadata(path)
    if path.name.endswith(".tar.gz"):
        return _sdist_metadata(path)
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


def _sha256_file(path: Path) -> str:
    """Return an artifact SHA-256 without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1_048_576), b""):
            digest.update(block)
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
    _preflight_release_artifact(artifact_path)
    package, version, license_id, requirements = _identity(
        _artifact_metadata(artifact_path)
    )
    root, components = _load_manifest(manifest_path)
    if package != root["name"] or license_id != root["license"]:
        raise SystemExit("artifact identity or license does not match the manifest")
    names = sorted(_requirement_name(item) for item in requirements)
    if names != sorted(root["depends_on"]):
        raise SystemExit("artifact direct runtime dependencies do not match the manifest")
    if requirements != root["requires_dist"]:
        raise SystemExit("artifact runtime requirement declarations do not match the manifest")
    digest = _sha256_file(artifact_path)
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
        build_sbom(arguments.artifact.resolve(), arguments.manifest.resolve()),
        arguments.output.resolve(),
    )
    print(f"wrote CycloneDX {CYCLONEDX_SPEC_VERSION} SBOM: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
