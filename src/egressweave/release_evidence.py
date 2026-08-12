"""Verify and summarize a credential-free sealed EgressWeave release evidence set.

The verifier treats distributions, CycloneDX documents, and source identity as
inert bytes. It accepts only the exact canonical wheel, source distribution, one
SBOM for each artifact, one canonical source-identity document, and a sorted
``SHA256SUMS`` file. It then emits a deterministic manifest for a separately
reviewed credentialed workflow without rebuilding or executing caller-controlled
code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

DISTRIBUTION_NAME = "egressweave"
EXPECTED_REPOSITORY = "ContextualWisdomLab/EgressWeave"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_FORMAT = "CycloneDX"
CYCLONEDX_SPEC_VERSION = "1.7"
CYCLONEDX_DOCUMENT_VERSION = 1
ATTESTATION_PREDICATE_TYPE = "https://cyclonedx.org/bom"
EVIDENCE_MANIFEST_FORMAT = "egressweave.release-evidence"
EVIDENCE_MANIFEST_VERSION = 2
SOURCE_IDENTITY_FILENAME = "SOURCE_IDENTITY.json"
SOURCE_IDENTITY_FORMAT = "egressweave.release-source-identity"
SOURCE_IDENTITY_VERSION = 1
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
MAX_EVIDENCE_MANIFEST_BYTES = 65_536
MAX_SOURCE_IDENTITY_BYTES = 4_096
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

__all__ = [
    "build_evidence_manifest",
    "main",
    "reverify_published_evidence_manifest",
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


def _require_open_regular_file(path: Path, stream: Any, *, label: str) -> None:
    """Require the opened descriptor to match one current regular path."""
    try:
        path_state = path.lstat()
        opened_state = os.fstat(stream.fileno())
    except OSError as error:
        raise SystemExit(f"{label} is unreadable or unsafe") from error
    if (
        not stat.S_ISREG(path_state.st_mode)
        or not stat.S_ISREG(opened_state.st_mode)
        or (path_state.st_dev, path_state.st_ino)
        != (opened_state.st_dev, opened_state.st_ino)
    ):
        raise SystemExit(f"{label} is unreadable or unsafe")


def _sha256_file(path: Path, *, maximum_bytes: int, label: str) -> str:
    """Return a bounded SHA-256 from one descriptor-bound regular file."""
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            _require_open_regular_file(path, stream, label=label)
            for block in iter(lambda: stream.read(1_048_576), b""):
                total_bytes += len(block)
                if total_bytes > maximum_bytes:
                    raise SystemExit(f"{label} exceeds the safety bound")
                digest.update(block)
    except OSError as error:
        raise SystemExit(f"{label} is unreadable") from error
    return digest.hexdigest()


def _read_bounded_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    """Read at most one configured payload plus one detection byte.

    The path is opened once, matched to its current regular-file descriptor, and
    read in finite chunks. The final one-byte allowance detects growth beyond the
    configured limit without first materializing an attacker-controlled file.
    """
    chunks: list[bytes] = []
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            _require_open_regular_file(path, stream, label=label)
            while True:
                remaining = maximum_bytes - total_bytes
                block = stream.read(min(1_048_576, remaining + 1))
                if not block:
                    break
                total_bytes += len(block)
                if total_bytes > maximum_bytes:
                    raise SystemExit(f"{label} exceeds the safety bound")
                chunks.append(block)
    except OSError as error:
        raise SystemExit(f"{label} is unreadable") from error
    return b"".join(chunks)


def _require_stable_read(
    content: bytes,
    *,
    digest_before: str,
    digest_after: str,
    label: str,
) -> None:
    """Require one separately read byte snapshot to match both file digests."""
    content_digest = hashlib.sha256(content).hexdigest()
    if content_digest != digest_before or content_digest != digest_after:
        raise SystemExit(f"{label} changed during verification")


def _require_canonical_evidence_root(evidence_dir: Path) -> Path:
    """Return one real evidence directory without symlinked path components.

    The lexical absolute path must equal the strictly resolved path. Once this
    check succeeds, callers use the returned real path so later retargeting of a
    previously supplied ancestor symlink cannot change the verified directory.
    """
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise SystemExit("release evidence directory is missing or unsafe")
    try:
        lexical_root = Path(os.path.abspath(evidence_dir))
        resolved_root = evidence_dir.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SystemExit("release evidence directory is missing or unsafe") from error
    if lexical_root != resolved_root:
        raise SystemExit("release evidence directory path must not traverse symlinks")
    return resolved_root


def _select_evidence_paths(
    evidence_dir: Path,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    """Return the exact artifacts, SBOMs, source identity, and checksum file."""
    evidence_dir = _require_canonical_evidence_root(evidence_dir)
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
    source_identity_path = evidence_dir / SOURCE_IDENTITY_FILENAME
    checksum_path = evidence_dir / "SHA256SUMS"
    legacy_expected = {
        wheel_path,
        sdist_path,
        wheel_sbom,
        sdist_sbom,
        checksum_path,
    }
    if set(entries) == legacy_expected:
        raise SystemExit("release evidence lacks sealed source identity")
    expected = legacy_expected | {source_identity_path}
    if set(entries) != expected:
        observed = [path.name for path in entries]
        required = sorted(path.name for path in expected)
        raise SystemExit(
            f"release evidence cardinality mismatch; expected {required}, observed {observed}"
        )
    return (
        wheel_path,
        sdist_path,
        wheel_sbom,
        sdist_sbom,
        source_identity_path,
        checksum_path,
    )


def _evidence_root_identity(evidence_dir: Path) -> tuple[int, int]:
    """Return the current filesystem identity of one admitted evidence root."""
    try:
        state = evidence_dir.lstat()
    except OSError as error:
        raise SystemExit("release evidence directory changed") from error
    return state.st_dev, state.st_ino


def _snapshot_selected_evidence(
    evidence_dir: Path,
    snapshot_root: Path,
) -> tuple[
    tuple[Path, Path, Path, Path, Path, Path],
    tuple[Path, Path, Path, Path, Path, Path],
    tuple[int, int],
    dict[str, str],
]:
    """Copy one descriptor-bound evidence authority into a private finite snapshot."""
    canonical_root = _require_canonical_evidence_root(evidence_dir)
    root_identity = _evidence_root_identity(canonical_root)
    original_paths = _select_evidence_paths(canonical_root)
    maximums = (
        MAX_ARTIFACT_BYTES,
        MAX_ARTIFACT_BYTES,
        MAX_SBOM_BYTES,
        MAX_SBOM_BYTES,
        MAX_SOURCE_IDENTITY_BYTES,
        MAX_CHECKSUM_BYTES,
    )
    labels = (
        "wheel",
        "source distribution",
        "wheel SBOM",
        "source-distribution SBOM",
        "sealed source identity",
        "SHA256SUMS",
    )
    source_digests: dict[str, str] = {}

    with ExitStack() as stack:
        opened: list[tuple[Path, Any, int, str]] = []
        for path, maximum_bytes, label in zip(
            original_paths,
            maximums,
            labels,
            strict=True,
        ):
            try:
                stream = stack.enter_context(path.open("rb"))
            except OSError as error:
                raise SystemExit(f"{label} is unreadable") from error
            _require_open_regular_file(path, stream, label=label)
            opened.append((path, stream, maximum_bytes, label))

        if _evidence_root_identity(canonical_root) != root_identity:
            raise SystemExit("release evidence directory changed")
        _select_evidence_paths(canonical_root)
        for path, stream, _, label in opened:
            _require_open_regular_file(path, stream, label=label)

        for path, stream, maximum_bytes, label in opened:
            digest = hashlib.sha256()
            total_bytes = 0
            snapshot_path = snapshot_root / path.name
            try:
                with snapshot_path.open("xb") as output:
                    while True:
                        block = stream.read(1_048_576)
                        if not block:
                            break
                        total_bytes += len(block)
                        if total_bytes > maximum_bytes:
                            raise SystemExit(f"{label} exceeds the safety bound")
                        digest.update(block)
                        output.write(block)
            except OSError as error:
                raise SystemExit(f"{label} cannot be snapshotted safely") from error
            source_digests[path.name] = digest.hexdigest()

    snapshot_paths = _select_evidence_paths(snapshot_root)
    return snapshot_paths, original_paths, root_identity, source_digests


def _load_checksums(
    checksum_path: Path,
    expected_names: set[str],
) -> tuple[dict[str, str], str]:
    """Return canonical payload checksums and the accepted file snapshot digest."""
    digest_before = _sha256_file(
        checksum_path,
        maximum_bytes=MAX_CHECKSUM_BYTES,
        label="SHA256SUMS",
    )
    try:
        raw_content = _read_bounded_file(
            checksum_path,
            maximum_bytes=MAX_CHECKSUM_BYTES,
            label="SHA256SUMS",
        )
        content = raw_content.decode("ascii")
    except UnicodeError as error:
        raise SystemExit("SHA256SUMS must be readable canonical ASCII") from error
    digest_after = _sha256_file(
        checksum_path,
        maximum_bytes=MAX_CHECKSUM_BYTES,
        label="SHA256SUMS",
    )
    _require_stable_read(
        raw_content,
        digest_before=digest_before,
        digest_after=digest_after,
        label="SHA256SUMS",
    )
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
    return parsed, digest_after


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


def _load_source_identity(
    path: Path,
    *,
    expected_digest: str,
) -> tuple[str, str]:
    """Return exact repository and source values from one sealed identity file."""
    label = "sealed source identity"
    digest_before = _sha256_file(
        path,
        maximum_bytes=MAX_SOURCE_IDENTITY_BYTES,
        label=label,
    )
    try:
        raw_content = _read_bounded_file(
            path,
            maximum_bytes=MAX_SOURCE_IDENTITY_BYTES,
            label=label,
        )
        document = json.loads(
            raw_content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SystemExit("sealed source identity is not strict JSON") from error
    digest_after = _sha256_file(
        path,
        maximum_bytes=MAX_SOURCE_IDENTITY_BYTES,
        label=label,
    )
    _require_stable_read(
        raw_content,
        digest_before=digest_before,
        digest_after=digest_after,
        label=label,
    )
    if digest_after != expected_digest:
        raise SystemExit("sealed source identity changed during verification")
    if type(document) is not dict:
        raise SystemExit("sealed source identity must be a JSON object")
    required_names = {"format", "formatVersion", "repository", "sourceSha"}
    if (
        set(document) != required_names
        or document.get("format") != SOURCE_IDENTITY_FORMAT
        or type(document.get("formatVersion")) is not int
        or document.get("formatVersion") != SOURCE_IDENTITY_VERSION
        or type(document.get("repository")) is not str
        or document.get("repository") != EXPECTED_REPOSITORY
        or type(document.get("sourceSha")) is not str
        or SOURCE_SHA_PATTERN.fullmatch(document.get("sourceSha")) is None
    ):
        raise SystemExit("sealed source identity has an invalid exact profile")
    canonical = (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if raw_content != canonical:
        raise SystemExit("sealed source identity is not canonical JSON")
    return document["repository"], document["sourceSha"]


def _load_strict_json(
    path: Path,
    *,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Load strict bounded JSON and optionally bind it to a sealed digest."""
    label = f"SBOM {path.name}"
    digest_before = _sha256_file(path, maximum_bytes=MAX_SBOM_BYTES, label=label)
    try:
        raw_content = _read_bounded_file(
            path,
            maximum_bytes=MAX_SBOM_BYTES,
            label=label,
        )
        content = raw_content.decode("utf-8")
        document = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SystemExit(f"{label} is not strict JSON") from error
    digest_after = _sha256_file(path, maximum_bytes=MAX_SBOM_BYTES, label=label)
    _require_stable_read(
        raw_content,
        digest_before=digest_before,
        digest_after=digest_after,
        label=label,
    )
    if expected_digest is not None and digest_after != expected_digest:
        raise SystemExit(f"{label} does not match the sealed digest")
    if type(document) is not dict:
        raise SystemExit(f"{label} must be a JSON object")
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
    except (RecursionError, TypeError, ValueError):
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
    expected_digest: str,
) -> str:
    """Verify exact CycloneDX identity and root-artifact binding for one SBOM."""
    document = _load_strict_json(sbom_path, expected_digest=expected_digest)
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


def _payload_digests(
    payload_specs: tuple[tuple[Path, int, str], ...],
) -> dict[str, str]:
    """Hash every selected payload through its bounded regular-file boundary."""
    return {
        path.name: _sha256_file(path, maximum_bytes=maximum_bytes, label=label)
        for path, maximum_bytes, label in payload_specs
    }


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

    with TemporaryDirectory(prefix="egressweave-release-evidence-") as snapshot_directory:
        snapshot_root = Path(snapshot_directory)
        (
            snapshot_paths,
            original_paths,
            root_identity,
            source_snapshot_digests,
        ) = _snapshot_selected_evidence(evidence_dir, snapshot_root)
        (
            wheel_path,
            sdist_path,
            wheel_sbom,
            sdist_sbom,
            source_identity_path,
            checksum_path,
        ) = snapshot_paths
        payload_specs = (
            (wheel_path, MAX_ARTIFACT_BYTES, "wheel"),
            (sdist_path, MAX_ARTIFACT_BYTES, "source distribution"),
            (wheel_sbom, MAX_SBOM_BYTES, "wheel SBOM"),
            (sdist_sbom, MAX_SBOM_BYTES, "source-distribution SBOM"),
            (
                source_identity_path,
                MAX_SOURCE_IDENTITY_BYTES,
                "sealed source identity",
            ),
        )
        payload_paths = tuple(path for path, _, _ in payload_specs)
        checksums, checksum_digest = _load_checksums(
            checksum_path,
            {path.name for path in payload_paths},
        )
        observed_digests = _payload_digests(payload_specs)
        if checksums != observed_digests:
            raise SystemExit("release evidence digest mismatch")

        sealed_repository, sealed_source_sha = _load_source_identity(
            source_identity_path,
            expected_digest=observed_digests[source_identity_path.name],
        )
        if sealed_repository != repository or sealed_source_sha != source_sha:
            raise SystemExit("sealed source identity does not match caller expectations")

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
                expected_digest=observed_digests[sbom_path.name],
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
        if _payload_digests(payload_specs) != observed_digests:
            raise SystemExit("release evidence changed during verification")
        if (
            _sha256_file(
                checksum_path,
                maximum_bytes=MAX_CHECKSUM_BYTES,
                label="SHA256SUMS",
            )
            != checksum_digest
        ):
            raise SystemExit("SHA256SUMS changed during verification")

        canonical_original_root = _require_canonical_evidence_root(evidence_dir)
        if _evidence_root_identity(canonical_original_root) != root_identity:
            raise SystemExit("release evidence directory changed")
        _select_evidence_paths(canonical_original_root)
        original_maximums = (
            MAX_ARTIFACT_BYTES,
            MAX_ARTIFACT_BYTES,
            MAX_SBOM_BYTES,
            MAX_SBOM_BYTES,
            MAX_SOURCE_IDENTITY_BYTES,
            MAX_CHECKSUM_BYTES,
        )
        original_labels = (
            "wheel",
            "source distribution",
            "wheel SBOM",
            "source-distribution SBOM",
            "sealed source identity",
            "SHA256SUMS",
        )
        original_specs = tuple(
            (path, maximum_bytes, label)
            for path, maximum_bytes, label in zip(
                original_paths,
                original_maximums,
                original_labels,
                strict=True,
            )
        )
        if _payload_digests(original_specs) != source_snapshot_digests:
            raise SystemExit("release evidence changed during verification")

        artifacts.sort(key=lambda item: item["artifactFilename"])
        return {
            "artifacts": artifacts,
            "checksumFilename": checksum_path.name,
            "checksumSha256": checksum_digest,
            "format": EVIDENCE_MANIFEST_FORMAT,
            "formatVersion": EVIDENCE_MANIFEST_VERSION,
            "cycloneDxSpecVersion": CYCLONEDX_SPEC_VERSION,
            "predicateType": ATTESTATION_PREDICATE_TYPE,
            "repository": sealed_repository,
            "sourceIdentityFilename": source_identity_path.name,
            "sourceIdentitySha256": observed_digests[source_identity_path.name],
            "sourceSha": sealed_source_sha,
        }


def _encode_evidence_manifest(manifest: dict[str, Any]) -> bytes:
    """Return one detached deterministic payload containing strict JSON data."""
    if type(manifest) is not dict:
        raise SystemExit("evidence manifest must be a strict JSON object")
    try:
        text = json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        snapshot = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (RecursionError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        raise SystemExit("evidence manifest must be a strict JSON object") from None
    if snapshot != manifest:
        raise SystemExit("evidence manifest must be a strict JSON object")
    return (text + "\n").encode("utf-8")


def _open_exclusive_manifest(path: str, flags: int) -> int:
    """Create a private descriptor without following or replacing the final path."""
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)


def _require_output_outside_verified_set(
    output_path: Path,
    verified_root: Path,
) -> None:
    """Require the current output location to remain outside verified evidence."""
    try:
        resolved_parent = output_path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SystemExit("evidence manifest parent directory is unavailable") from error
    resolved_output = resolved_parent / output_path.name
    if resolved_output == verified_root or resolved_output.is_relative_to(verified_root):
        raise SystemExit("evidence manifest output must remain outside the verified set")


def _require_canonical_forbidden_root(forbidden_root: Path) -> Path:
    """Return one canonical excluded directory or raise one stable public error.

    Every named lexical component is inspected before any ``..`` normalization,
    so a symbolic link cannot be hidden by later parent traversal. Public callers
    receive one dedicated non-leaking failure, then the existing canonical-root
    contract supplies the single authority reused by the writer afterward.
    """
    try:
        current = Path(forbidden_root.anchor)
        for component in forbidden_root.parts[len(current.parts) :]:
            current /= component
            if component != ".." and current.is_symlink():
                raise SystemExit(
                    "release evidence directory path must not traverse symlinks"
                )
        return _require_canonical_evidence_root(forbidden_root)
    except (SystemExit, OSError, RuntimeError):
        raise SystemExit(
            "evidence manifest forbidden root is missing or unsafe"
        ) from None


def write_evidence_manifest(
    manifest: dict[str, Any],
    output_path: Path,
    *,
    forbidden_root: Path | None = None,
) -> None:
    """Create one private manifest while optionally excluding one real directory.

    When supplied, ``forbidden_root`` must name an existing real directory through
    a lexical path with no symbolic-link component. The writer validates it before
    creating the output parent, stores the canonical result once, and reuses that
    same authority for every pre-write, descriptor-bound, and post-sync check.
    """
    payload = _encode_evidence_manifest(manifest)
    canonical_forbidden_root = (
        _require_canonical_forbidden_root(forbidden_root)
        if forbidden_root is not None
        else None
    )
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SystemExit("evidence manifest parent directory is unavailable") from error
    if canonical_forbidden_root is not None:
        _require_output_outside_verified_set(output_path, canonical_forbidden_root)

    try:
        with open(output_path, "xb", opener=_open_exclusive_manifest) as stream:
            _require_open_regular_file(
                output_path,
                stream,
                label="evidence manifest output",
            )
            if canonical_forbidden_root is not None:
                _require_output_outside_verified_set(
                    output_path,
                    canonical_forbidden_root,
                )
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            _require_open_regular_file(
                output_path,
                stream,
                label="evidence manifest output",
            )
            if canonical_forbidden_root is not None:
                _require_output_outside_verified_set(
                    output_path,
                    canonical_forbidden_root,
                )
    except FileExistsError:
        raise SystemExit("evidence manifest output already exists") from None
    except OSError as error:
        raise SystemExit("evidence manifest output cannot be created safely") from error


def _require_post_publication_state(
    evidence_dir: Path,
    output_path: Path,
    *,
    repository: str,
    source_sha: str,
    expected_payload: bytes,
) -> None:
    """Reverify sealed input and emitted bytes after manifest publication."""
    try:
        observed_manifest = build_evidence_manifest(
            evidence_dir,
            repository=repository,
            source_sha=source_sha,
        )
        observed_payload = _encode_evidence_manifest(observed_manifest)
    except SystemExit:
        raise SystemExit(
            "release evidence changed after manifest publication"
        ) from None
    if observed_payload != expected_payload:
        raise SystemExit("release evidence changed after manifest publication")

    try:
        _require_output_outside_verified_set(output_path, evidence_dir)
        published_payload = _read_bounded_file(
            output_path,
            maximum_bytes=MAX_EVIDENCE_MANIFEST_BYTES,
            label="evidence manifest output",
        )
        _require_output_outside_verified_set(output_path, evidence_dir)
    except SystemExit:
        raise SystemExit(
            "evidence manifest output changed after publication"
        ) from None
    if published_payload != expected_payload:
        raise SystemExit("evidence manifest output changed after publication")


def reverify_published_evidence_manifest(
    evidence_dir: Path,
    output_path: Path,
    *,
    repository: str,
    source_sha: str,
    expected_manifest: dict[str, Any],
) -> None:
    """Reverify one sealed evidence set and its exact published manifest bytes.

    ``expected_manifest`` is encoded through the same strict deterministic public
    evidence contract used by the writer. The verifier then rebuilds the sealed
    set and rereads the closed output through bounded descriptor/path checks.
    """
    expected_payload = _encode_evidence_manifest(expected_manifest)
    _require_post_publication_state(
        evidence_dir,
        output_path,
        repository=repository,
        source_sha=source_sha,
        expected_payload=expected_payload,
    )


def main() -> int:
    """Verify sealed evidence and write one deterministic credential handoff manifest."""
    arguments = _parse_arguments()
    evidence_dir = _require_canonical_evidence_root(arguments.evidence_dir)
    resolved_evidence_dir = evidence_dir
    output_path = arguments.output.parent.resolve() / arguments.output.name
    if output_path == resolved_evidence_dir or output_path.is_relative_to(
        resolved_evidence_dir
    ):
        raise SystemExit("evidence manifest output must remain outside the verified set")
    manifest = build_evidence_manifest(
        evidence_dir,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
    )
    write_evidence_manifest(
        manifest,
        output_path,
        forbidden_root=resolved_evidence_dir,
    )
    reverify_published_evidence_manifest(
        evidence_dir,
        output_path,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
        expected_manifest=manifest,
    )
    print(f"verified sealed release evidence: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
