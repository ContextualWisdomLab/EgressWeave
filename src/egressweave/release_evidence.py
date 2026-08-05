"""Verify and summarize a credential-free sealed EgressWeave release evidence set.

The verifier treats distributions and CycloneDX documents as inert bytes. It
accepts only the exact canonical wheel, source distribution, one SBOM for each
artifact, and a sorted ``SHA256SUMS`` file. It then emits a deterministic manifest
that a separately reviewed credentialed workflow can bind to repository and
source identity without rebuilding or executing caller-controlled code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

DISTRIBUTION_NAME = "egressweave"
EXPECTED_REPOSITORY = "ContextualWisdomLab/EgressWeave"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_FORMAT = "CycloneDX"
CYCLONEDX_SPEC_VERSION = "1.7"
CYCLONEDX_DOCUMENT_VERSION = 1
ATTESTATION_PREDICATE_TYPE = "https://cyclonedx.org/bom"
EVIDENCE_MANIFEST_FORMAT = "egressweave.release-evidence"
EVIDENCE_MANIFEST_VERSION = 1
DOCUMENT_IDENTITY_URL_PREFIX = (
    "https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/"
)
SOURCE_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
WHEEL_PATTERN = re.compile(
    r"^egressweave-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl$"
)
SDIST_PATTERN = re.compile(
    r"^egressweave-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz$"
)
CHECKSUM_LINE_PATTERN = re.compile(
    r"^(?P<digest>[0-9a-f]{64})  (?P<filename>[A-Za-z0-9][A-Za-z0-9._+-]*)$"
)
MAX_CHECKSUM_BYTES = 65_536
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

__all__ = [
    "build_evidence_manifest",
    "main",
    "write_evidence_manifest",
]


def _parse_arguments() -> argparse.Namespace:
    """Parse the exact evidence directory, identity binding, and manifest output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256_file(path: Path, *, maximum_bytes: int, label: str) -> str:
    """Return a bounded file SHA-256 without loading the file into memory."""
    try:
        file_size = path.stat().st_size
    except OSError as error:
        raise SystemExit(f"{label} is unreadable") from error
    if file_size > maximum_bytes:
        raise SystemExit(f"{label} exceeds the safety bound")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1_048_576), b""):
                digest.update(block)
    except OSError as error:
        raise SystemExit(f"{label} is unreadable") from error
    return digest.hexdigest()


def _select_evidence_paths(evidence_dir: Path) -> tuple[Path, Path, Path, Path, Path]:
    """Return the exact wheel, sdist, SBOMs, and checksum file or fail closed."""
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise SystemExit("release evidence directory is missing or unsafe")
    try:
        entries = sorted(evidence_dir.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise SystemExit("release evidence directory is unreadable") from error
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise SystemExit("release evidence must contain regular direct-child files only")

    wheels = [path for path in entries if WHEEL_PATTERN.fullmatch(path.name)]
    sdists = [path for path in entries if SDIST_PATTERN.fullmatch(path.name)]
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("release evidence requires exactly one canonical wheel and sdist")
    wheel_path = wheels[0]
    sdist_path = sdists[0]
    wheel_version = WHEEL_PATTERN.fullmatch(wheel_path.name).group("version")
    sdist_version = SDIST_PATTERN.fullmatch(sdist_path.name).group("version")
    if wheel_version != sdist_version:
        raise SystemExit("wheel and source distribution versions do not match")

    wheel_sbom = evidence_dir / f"{wheel_path.name}.cdx.json"
    sdist_sbom = evidence_dir / f"{sdist_path.name}.cdx.json"
    checksum_path = evidence_dir / "SHA256SUMS"
    expected = {wheel_path, sdist_path, wheel_sbom, sdist_sbom, checksum_path}
    if set(entries) != expected:
        observed = [path.name for path in entries]
        required = sorted(path.name for path in expected)
        raise SystemExit(
            f"release evidence cardinality mismatch; expected {required}, observed {observed}"
        )
    return wheel_path, sdist_path, wheel_sbom, sdist_sbom, checksum_path


def _load_checksums(checksum_path: Path, expected_names: set[str]) -> dict[str, str]:
    """Return one canonical sorted SHA-256 entry for every evidence payload."""
    _sha256_file(
        checksum_path,
        maximum_bytes=MAX_CHECKSUM_BYTES,
        label="SHA256SUMS",
    )
    try:
        content = checksum_path.read_bytes().decode("ascii")
    except (OSError, UnicodeError) as error:
        raise SystemExit("SHA256SUMS must be readable canonical ASCII") from error
    if not content.endswith("\n") or "\r" in content:
        raise SystemExit("SHA256SUMS must use LF lines with one trailing newline")
    lines = content.splitlines()
    parsed: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise SystemExit("SHA256SUMS contains a noncanonical entry")
        filename = match.group("filename")
        if filename in parsed:
            raise SystemExit("SHA256SUMS contains a duplicate filename")
        parsed[filename] = match.group("digest")
    if list(parsed) != sorted(parsed):
        raise SystemExit("SHA256SUMS entries must be sorted by filename")
    if set(parsed) != expected_names:
        raise SystemExit("SHA256SUMS does not cover the exact evidence payload set")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject non-standard NaN and infinity tokens during JSON parsing."""
    raise ValueError(f"non-standard JSON number {value}")


def _load_strict_json(path: Path) -> dict[str, Any]:
    """Load one bounded RFC 8259 JSON object without duplicate member names."""
    _sha256_file(path, maximum_bytes=MAX_SBOM_BYTES, label=f"SBOM {path.name}")
    try:
        content = path.read_text(encoding="utf-8")
        document = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"SBOM {path.name} is not strict JSON") from error
    if type(document) is not dict:
        raise SystemExit(f"SBOM {path.name} must be a JSON object")
    return document


def _canonical_pre_serial_digest(document: dict[str, Any]) -> str:
    """Return SHA-256 over strict canonical SBOM semantics without ``serialNumber``."""
    without_serial = dict(document)
    without_serial.pop("serialNumber", None)
    try:
        canonical = json.dumps(
            without_serial,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise SystemExit("SBOM contains a value outside strict JSON") from None
    return hashlib.sha256(canonical).hexdigest()


def _expected_serial_number(document: dict[str, Any]) -> str:
    """Return the independently recomputed content-bound UUID version 5 URN."""
    digest = _canonical_pre_serial_digest(document)
    identity_url = f"{DOCUMENT_IDENTITY_URL_PREFIX}{digest}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity_url)}"


def _require_mapping(value: object, *, label: str) -> dict[str, Any]:
    """Return a built-in JSON object or fail with a stable evidence error."""
    if type(value) is not dict:
        raise SystemExit(f"{label} must be a JSON object")
    return value


def _verify_sbom(
    sbom_path: Path,
    *,
    artifact_name: str,
    artifact_digest: str,
    version: str,
) -> str:
    """Verify exact CycloneDX identity and root-artifact binding for one SBOM."""
    document = _load_strict_json(sbom_path)
    required_envelope = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": CYCLONEDX_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": CYCLONEDX_DOCUMENT_VERSION,
    }
    if any(document.get(key) != value for key, value in required_envelope.items()):
        raise SystemExit(f"SBOM {sbom_path.name} is not the exact CycloneDX 1.7 profile")
    if type(document.get("version")) is not int:
        raise SystemExit(f"SBOM {sbom_path.name} has a non-integer document version")

    serial_number = document.get("serialNumber")
    if type(serial_number) is not str:
        raise SystemExit(f"SBOM {sbom_path.name} lacks a serial number")
    try:
        parsed_uuid = uuid.UUID(serial_number.removeprefix("urn:uuid:"))
    except (AttributeError, ValueError):
        raise SystemExit(f"SBOM {sbom_path.name} has an invalid serial number") from None
    if serial_number != f"urn:uuid:{parsed_uuid}":
        raise SystemExit(f"SBOM {sbom_path.name} has a noncanonical UUID URN")
    if parsed_uuid.variant != uuid.RFC_4122:
        raise SystemExit(f"SBOM {sbom_path.name} does not use the RFC UUID variant")
    if parsed_uuid.version != 5:
        raise SystemExit(f"SBOM {sbom_path.name} does not use UUID version 5")
    if serial_number != _expected_serial_number(document):
        raise SystemExit(f"SBOM {sbom_path.name} has the wrong content-bound identity")

    metadata = _require_mapping(document.get("metadata"), label="SBOM metadata")
    component = _require_mapping(metadata.get("component"), label="SBOM root component")
    expected_reference = f"urn:egressweave:artifact:sha256:{artifact_digest}"
    if component.get("bom-ref") != expected_reference:
        raise SystemExit(f"SBOM {sbom_path.name} root reference does not bind the artifact")
    if component.get("name") != DISTRIBUTION_NAME:
        raise SystemExit(f"SBOM {sbom_path.name} package name does not match the artifact")
    if component.get("version") != version:
        raise SystemExit(f"SBOM {sbom_path.name} package version does not match the artifact")
    if component.get("purl") != f"pkg:pypi/{DISTRIBUTION_NAME}@{version}":
        raise SystemExit(f"SBOM {sbom_path.name} package URL does not match the artifact")
    if component.get("hashes") != [{"alg": "SHA-256", "content": artifact_digest}]:
        raise SystemExit(f"SBOM {sbom_path.name} root hash does not bind the artifact")

    properties = component.get("properties")
    if type(properties) is not list:
        raise SystemExit(f"SBOM {sbom_path.name} root properties are malformed")
    filename_values = [
        item.get("value")
        for item in properties
        if type(item) is dict
        and item.get("name") == "egressweave:release:artifact-filename"
    ]
    if filename_values != [artifact_name]:
        raise SystemExit(f"SBOM {sbom_path.name} filename binding is not exact")
    return serial_number


def build_evidence_manifest(
    evidence_dir: Path,
    *,
    repository: str,
    source_sha: str,
) -> dict[str, Any]:
    """Verify one sealed evidence set and return its deterministic handoff manifest."""
    if repository != EXPECTED_REPOSITORY:
        raise SystemExit(f"repository must equal {EXPECTED_REPOSITORY}")
    if SOURCE_SHA_PATTERN.fullmatch(source_sha) is None:
        raise SystemExit("source SHA must be exactly 40 lowercase hexadecimal characters")

    wheel_path, sdist_path, wheel_sbom, sdist_sbom, checksum_path = (
        _select_evidence_paths(evidence_dir.resolve())
    )
    payload_paths = (wheel_path, sdist_path, wheel_sbom, sdist_sbom)
    checksums = _load_checksums(checksum_path, {path.name for path in payload_paths})
    observed_digests = {
        wheel_path.name: _sha256_file(
            wheel_path,
            maximum_bytes=MAX_ARTIFACT_BYTES,
            label="wheel",
        ),
        sdist_path.name: _sha256_file(
            sdist_path,
            maximum_bytes=MAX_ARTIFACT_BYTES,
            label="source distribution",
        ),
        wheel_sbom.name: _sha256_file(
            wheel_sbom,
            maximum_bytes=MAX_SBOM_BYTES,
            label="wheel SBOM",
        ),
        sdist_sbom.name: _sha256_file(
            sdist_sbom,
            maximum_bytes=MAX_SBOM_BYTES,
            label="source-distribution SBOM",
        ),
    }
    if checksums != observed_digests:
        raise SystemExit("release evidence digest mismatch")

    version = WHEEL_PATTERN.fullmatch(wheel_path.name).group("version")
    artifacts: list[dict[str, str]] = []
    for kind, artifact_path, sbom_path in (
        ("sdist", sdist_path, sdist_sbom),
        ("wheel", wheel_path, wheel_sbom),
    ):
        artifact_digest = observed_digests[artifact_path.name]
        serial_number = _verify_sbom(
            sbom_path,
            artifact_name=artifact_path.name,
            artifact_digest=artifact_digest,
            version=version,
        )
        artifacts.append(
            {
                "artifactFilename": artifact_path.name,
                "artifactSha256": artifact_digest,
                "kind": kind,
                "sbomFilename": sbom_path.name,
                "sbomSerialNumber": serial_number,
                "sbomSha256": observed_digests[sbom_path.name],
            }
        )
    artifacts.sort(key=lambda item: item["artifactFilename"])
    return {
        "artifacts": artifacts,
        "format": EVIDENCE_MANIFEST_FORMAT,
        "formatVersion": EVIDENCE_MANIFEST_VERSION,
        "cycloneDxSpecVersion": CYCLONEDX_SPEC_VERSION,
        "predicateType": ATTESTATION_PREDICATE_TYPE,
        "repository": repository,
        "sourceSha": source_sha,
    }


def write_evidence_manifest(manifest: dict[str, Any], output_path: Path) -> None:
    """Write stable UTF-8 JSON outside the verified evidence directory."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Verify sealed evidence and write one deterministic credential handoff manifest."""
    arguments = _parse_arguments()
    evidence_dir = arguments.evidence_dir.resolve()
    output_path = arguments.output.resolve()
    if output_path == evidence_dir or output_path.is_relative_to(evidence_dir):
        raise SystemExit("evidence manifest output must remain outside the verified set")
    manifest = build_evidence_manifest(
        evidence_dir,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
    )
    write_evidence_manifest(manifest, output_path)
    print(f"verified sealed release evidence: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
