"""Generate deterministic CycloneDX 1.7 SBOMs for release distributions.

The generator treats wheel and source-distribution archives as untrusted data.
It binds one exact artifact digest to the package metadata inside that archive,
then combines the verified root dependency declarations with a reviewed,
hash-pinned runtime dependency manifest. The resulting JSON intentionally omits
creation timestamps and random serial numbers so repeated generation from the
same artifact and manifest produces byte-identical evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_SCHEMA_VERSION = 1
SBOM_GENERATOR_VERSION = "1"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_SPEC_VERSION = "1.7"
MAX_METADATA_BYTES = 1_048_576
NORMALIZED_NAME_PATTERN = re.compile(r"[-_.]+")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SPDX_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
REQUIREMENT_NAME_PATTERN = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_arguments() -> argparse.Namespace:
    """Parse paths for one release artifact, its manifest, and output SBOM."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _normalized_name(name: str) -> str:
    """Return the canonical comparison form for a Python distribution name."""
    return NORMALIZED_NAME_PATTERN.sub("-", name).lower()


def _requirement_name(requirement: str) -> str:
    """Extract and normalize a distribution name from one ``Requires-Dist`` row."""
    match = REQUIREMENT_NAME_PATTERN.match(requirement)
    if match is None:
        raise SystemExit(f"artifact contains an invalid Requires-Dist value: {requirement!r}")
    return _normalized_name(match.group(1))


def _safe_archive_name(name: str) -> bool:
    """Return whether an archive path is relative, normalized, and traversal-free."""
    pure_path = PurePosixPath(name)
    return bool(
        name
        and "\\" not in name
        and not pure_path.is_absolute()
        and all(part not in {"", ".", ".."} for part in pure_path.parts)
    )


def _read_limited_metadata(raw_metadata: bytes, source: str) -> Message:
    """Parse bounded core metadata from an archive member."""
    if len(raw_metadata) > MAX_METADATA_BYTES:
        raise SystemExit(f"{source} metadata exceeds the one-megabyte safety bound")
    return BytesParser(policy=default).parsebytes(raw_metadata)


def _read_wheel_metadata(artifact_path: Path) -> Message:
    """Read the sole safe ``.dist-info/METADATA`` member from a wheel."""
    try:
        with zipfile.ZipFile(artifact_path) as wheel_archive:
            names = wheel_archive.namelist()
            if any(not _safe_archive_name(name) for name in names):
                raise SystemExit("wheel contains an unsafe archive path")
            metadata_names = [
                name for name in names if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise SystemExit("wheel must contain exactly one core METADATA member")
            return _read_limited_metadata(
                wheel_archive.read(metadata_names[0]),
                "wheel",
            )
    except zipfile.BadZipFile as error:
        raise SystemExit("release wheel is not a valid ZIP archive") from error


def _read_sdist_metadata(artifact_path: Path) -> Message:
    """Read the sole safe root ``PKG-INFO`` member from a gzip source archive."""
    try:
        with tarfile.open(artifact_path, mode="r:gz") as sdist_archive:
            members = sdist_archive.getmembers()
            if any(not _safe_archive_name(member.name) for member in members):
                raise SystemExit("source distribution contains an unsafe archive path")
            if any(member.issym() or member.islnk() or member.isdev() for member in members):
                raise SystemExit("source distribution contains a link or device member")
            metadata_members = [
                member
                for member in members
                if member.isfile()
                and len(PurePosixPath(member.name).parts) == 2
                and PurePosixPath(member.name).name == "PKG-INFO"
            ]
            if len(metadata_members) != 1:
                raise SystemExit("source distribution must contain one root PKG-INFO member")
            metadata_member = metadata_members[0]
            if metadata_member.size > MAX_METADATA_BYTES:
                raise SystemExit("source distribution metadata exceeds the safety bound")
            extracted = sdist_archive.extractfile(metadata_member)
            if extracted is None:
                raise SystemExit("source distribution metadata could not be read")
            return _read_limited_metadata(extracted.read(), "source distribution")
    except tarfile.TarError as error:
        raise SystemExit("release source distribution is not a valid gzip tar archive") from error


def _read_artifact_metadata(artifact_path: Path) -> Message:
    """Read core metadata from a supported wheel or source distribution."""
    if artifact_path.name.endswith(".whl"):
        return _read_wheel_metadata(artifact_path)
    if artifact_path.name.endswith(".tar.gz"):
        return _read_sdist_metadata(artifact_path)
    raise SystemExit("release artifact must be a .whl or .tar.gz distribution")


def _required_text(mapping: dict[str, Any], key: str, context: str) -> str:
    """Return one required non-empty string from a decoded manifest mapping."""
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{context} requires a non-empty string field {key!r}")
    if any(character in value for character in "\r\n\x00"):
        raise SystemExit(f"{context} field {key!r} contains a control separator")
    return value


def _required_string_list(mapping: dict[str, Any], key: str, context: str) -> list[str]:
    """Return one required list containing only non-empty unique strings."""
    value = mapping.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SystemExit(f"{context} requires a string list field {key!r}")
    normalized = [_normalized_name(item) for item in value]
    if len(set(normalized)) != len(normalized):
        raise SystemExit(f"{context} field {key!r} contains duplicate names")
    return normalized


def _validate_component(raw_component: object) -> dict[str, Any]:
    """Validate and normalize one dependency component from the reviewed manifest."""
    if not isinstance(raw_component, dict):
        raise SystemExit("runtime dependency manifest components must be objects")
    name = _normalized_name(_required_text(raw_component, "name", "component"))
    version = _required_text(raw_component, "version", f"component {name}")
    license_identifier = _required_text(raw_component, "license", f"component {name}")
    sha256 = _required_text(raw_component, "sha256", f"component {name}")
    artifact_filename = _required_text(
        raw_component,
        "artifact_filename",
        f"component {name}",
    )
    purl = _required_text(raw_component, "purl", f"component {name}")
    depends_on = _required_string_list(raw_component, "depends_on", f"component {name}")
    marker = raw_component.get("marker")

    if SHA256_PATTERN.fullmatch(sha256) is None:
        raise SystemExit(f"component {name} requires a lowercase SHA-256 digest")
    if SPDX_IDENTIFIER_PATTERN.fullmatch(license_identifier) is None:
        raise SystemExit(f"component {name} requires one SPDX license identifier")
    if "/" in artifact_filename or "\\" in artifact_filename:
        raise SystemExit(f"component {name} artifact filename must not contain a path")
    expected_purl = f"pkg:pypi/{name}@{version}"
    if purl != expected_purl:
        raise SystemExit(
            f"component {name} purl must equal {expected_purl!r}; observed {purl!r}"
        )
    if marker is not None and (
        not isinstance(marker, str)
        or not marker
        or len(marker) > 200
        or any(character in marker for character in "\r\n\x00")
    ):
        raise SystemExit(f"component {name} has an invalid runtime marker")

    return {
        "name": name,
        "version": version,
        "license": license_identifier,
        "sha256": sha256,
        "artifact_filename": artifact_filename,
        "purl": purl,
        "depends_on": depends_on,
        "marker": marker,
    }


def _reachable_components(
    root_dependencies: list[str],
    components: dict[str, dict[str, Any]],
) -> set[str]:
    """Return every dependency reachable from the package root, rejecting cycles."""
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise SystemExit(f"runtime dependency manifest contains a cycle at {name!r}")
        if name in visited:
            return
        if name not in components:
            raise SystemExit(f"runtime dependency manifest references unknown component {name!r}")
        visiting.add(name)
        for dependency_name in components[name]["depends_on"]:
            if dependency_name == name:
                raise SystemExit(f"component {name!r} cannot depend on itself")
            visit(dependency_name)
        visiting.remove(name)
        visited.add(name)

    for dependency_name in root_dependencies:
        visit(dependency_name)
    return visited


def _load_manifest(manifest_path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load and validate the reviewed exact runtime dependency closure."""
    try:
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit("runtime dependency manifest is unreadable or invalid JSON") from error
    if not isinstance(raw_manifest, dict):
        raise SystemExit("runtime dependency manifest must be a JSON object")
    if raw_manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise SystemExit(
            f"runtime dependency manifest schema_version must equal {MANIFEST_SCHEMA_VERSION}"
        )
    raw_root = raw_manifest.get("root")
    if not isinstance(raw_root, dict):
        raise SystemExit("runtime dependency manifest requires a root object")
    root = {
        "name": _normalized_name(_required_text(raw_root, "name", "root")),
        "license": _required_text(raw_root, "license", "root"),
        "depends_on": _required_string_list(raw_root, "depends_on", "root"),
    }
    if SPDX_IDENTIFIER_PATTERN.fullmatch(root["license"]) is None:
        raise SystemExit("root requires one SPDX license identifier")

    raw_components = raw_manifest.get("components")
    if not isinstance(raw_components, list) or not raw_components:
        raise SystemExit("runtime dependency manifest requires a non-empty components list")
    components: dict[str, dict[str, Any]] = {}
    for raw_component in raw_components:
        component = _validate_component(raw_component)
        name = component["name"]
        if name == root["name"]:
            raise SystemExit("root package must not be duplicated as a dependency component")
        if name in components:
            raise SystemExit(f"runtime dependency manifest duplicates component {name!r}")
        components[name] = component

    reachable = _reachable_components(root["depends_on"], components)
    unreachable = set(components) - reachable
    if unreachable:
        raise SystemExit(
            "runtime dependency manifest contains unreachable components: "
            f"{sorted(unreachable)}"
        )
    return root, components


def _metadata_identity(metadata: Message) -> tuple[str, str, str, list[str]]:
    """Return normalized package identity, license, and direct requirements."""
    name = metadata.get("Name")
    version = metadata.get("Version")
    license_identifier = metadata.get("License-Expression")
    if not name or not version or not license_identifier:
        raise SystemExit(
            "artifact metadata requires Name, Version, and License-Expression fields"
        )
    direct_dependencies = sorted(
        {_requirement_name(requirement) for requirement in metadata.get_all("Requires-Dist", [])}
    )
    return _normalized_name(name), version, license_identifier, direct_dependencies


def _sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one release artifact."""
    digest = hashlib.sha256()
    with path.open("rb") as artifact_file:
        for block in iter(lambda: artifact_file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _component_entry(component: dict[str, Any]) -> dict[str, Any]:
    """Convert one validated manifest component to CycloneDX JSON."""
    properties = [
        {
            "name": "egressweave:release:dependency-artifact",
            "value": component["artifact_filename"],
        }
    ]
    if component["marker"] is not None:
        properties.append(
            {
                "name": "egressweave:release:runtime-marker",
                "value": component["marker"],
            }
        )
    return {
        "type": "library",
        "bom-ref": component["purl"],
        "name": component["name"],
        "version": component["version"],
        "purl": component["purl"],
        "hashes": [{"alg": "SHA-256", "content": component["sha256"]}],
        "licenses": [{"license": {"id": component["license"]}}],
        "properties": properties,
    }


def build_sbom(artifact_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Build a deterministic CycloneDX document for one exact distribution."""
    if not artifact_path.is_file():
        raise SystemExit("release artifact does not exist or is not a regular file")
    metadata = _read_artifact_metadata(artifact_path)
    root, components = _load_manifest(manifest_path)
    package_name, version, license_identifier, direct_dependencies = _metadata_identity(metadata)
    if package_name != root["name"]:
        raise SystemExit(
            f"artifact package name {package_name!r} does not match manifest root {root['name']!r}"
        )
    if license_identifier != root["license"]:
        raise SystemExit(
            "artifact license expression does not match the reviewed runtime manifest"
        )
    if direct_dependencies != sorted(root["depends_on"]):
        raise SystemExit(
            "artifact direct runtime dependencies do not match the reviewed manifest: "
            f"artifact={direct_dependencies}, manifest={sorted(root['depends_on'])}"
        )

    artifact_digest = _sha256_file(artifact_path)
    root_purl = f"pkg:pypi/{package_name}@{version}"
    root_reference = f"urn:egressweave:artifact:sha256:{artifact_digest}"
    dependency_entries = [
        {
            "ref": root_reference,
            "dependsOn": sorted(components[name]["purl"] for name in root["depends_on"]),
        }
    ]
    for component in sorted(components.values(), key=lambda item: item["purl"]):
        dependency_entries.append(
            {
                "ref": component["purl"],
                "dependsOn": sorted(
                    components[name]["purl"] for name in component["depends_on"]
                ),
            }
        )

    return {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": root_reference,
                "name": package_name,
                "version": version,
                "purl": root_purl,
                "hashes": [{"alg": "SHA-256", "content": artifact_digest}],
                "licenses": [{"license": {"id": license_identifier}}],
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
        "components": [
            _component_entry(component)
            for component in sorted(components.values(), key=lambda item: item["purl"])
        ],
        "dependencies": dependency_entries,
    }


def write_sbom(sbom: dict[str, Any], output_path: Path) -> None:
    """Write canonical UTF-8 JSON with stable ordering and one trailing newline."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Generate one deterministic release SBOM and return zero on success."""
    arguments = _parse_arguments()
    sbom = build_sbom(arguments.artifact.resolve(), arguments.manifest.resolve())
    write_sbom(sbom, arguments.output.resolve())
    print(f"wrote CycloneDX {CYCLONEDX_SPEC_VERSION} SBOM: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
