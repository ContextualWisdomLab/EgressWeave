"""Prepare one credential-free six-file release evidence set.

The script treats built distributions as untrusted inert archives. It generates
paired deterministic CycloneDX 1.7 documents, seals exact repository and source
identity, writes sorted checksums, and asks the shipped verifier to create and
independently recheck a handoff manifest outside the evidence directory. It has
no network, signing, publication, release, tag, ref, model, or credential logic.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from egressweave import release_evidence

ATTESTABLE_GENERATOR_PATH = Path(__file__).with_name(
    "generate_attestable_release_sbom.py"
)
MAX_DISTRIBUTION_BYTES = release_evidence.MAX_ARTIFACT_BYTES
MAX_REVIEWED_INPUT_BYTES = 1_048_576
COPY_BLOCK_BYTES = 1_048_576
DistributionIdentity = tuple[int, int, int]

__all__ = ["main", "prepare_release_evidence"]


def _parse_arguments() -> argparse.Namespace:
    """Parse exact evidence, reviewed dependency, identity, and handoff inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--handoff-manifest", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dependency-manifest", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    return parser.parse_args()


def _require_source_identity(repository: str, source_sha: str) -> None:
    """Require the exact repository and one lowercase Git object identifier."""
    if (
        repository != release_evidence.EXPECTED_REPOSITORY
        or release_evidence.SOURCE_SHA_PATTERN.fullmatch(source_sha) is None
    ):
        raise SystemExit("release repository or source identity is invalid")


def _require_canonical_directory(path: Path, *, label: str) -> Path:
    """Return one existing real directory reached without symbolic links."""
    if not path.is_dir() or path.is_symlink():
        raise SystemExit(f"{label} is missing or unsafe")
    try:
        lexical_path = Path(os.path.abspath(path))
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    if lexical_path != resolved_path:
        raise SystemExit(f"{label} must not traverse symbolic links")
    return resolved_path


def _require_canonical_file(path: Path, *, label: str) -> Path:
    """Return one existing regular repository input reached without links."""
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} is missing or unsafe")
    try:
        lexical_path = Path(os.path.abspath(path))
        resolved_path = path.resolve(strict=True)
        path_state = path.lstat()
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    if lexical_path != resolved_path or not stat.S_ISREG(path_state.st_mode):
        raise SystemExit(f"{label} is missing or unsafe")
    return resolved_path


def _require_handoff_outside_evidence(
    handoff_path: Path,
    evidence_root: Path,
) -> Path:
    """Return one named output file whose real parent remains outside evidence."""
    if handoff_path.name in {"", ".", ".."}:
        raise SystemExit("handoff manifest path must name one regular file")
    parent = _require_canonical_directory(
        handoff_path.parent,
        label="handoff manifest parent",
    )
    resolved_output = parent / handoff_path.name
    if resolved_output == evidence_root or resolved_output.is_relative_to(evidence_root):
        raise SystemExit("handoff manifest must remain outside the sealed evidence set")
    return resolved_output


def _select_distributions(evidence_root: Path) -> tuple[Path, Path]:
    """Select exactly one canonical wheel and one matching source distribution."""
    try:
        entries = sorted(evidence_root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise SystemExit("release evidence input directory is unreadable") from error
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise SystemExit("release evidence inputs must be regular direct-child files")

    wheels = [path for path in entries if release_evidence.WHEEL_PATTERN.fullmatch(path.name)]
    sdists = [path for path in entries if release_evidence.SDIST_PATTERN.fullmatch(path.name)]
    if len(entries) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(
            "release evidence inputs require exactly one wheel and source distribution"
        )

    wheel_match = release_evidence.WHEEL_PATTERN.fullmatch(wheels[0].name)
    sdist_match = release_evidence.SDIST_PATTERN.fullmatch(sdists[0].name)
    if wheel_match is None or sdist_match is None:
        raise SystemExit(
            "release evidence inputs require exactly one wheel and source distribution"
        )
    if wheel_match.group("version") != sdist_match.group("version"):
        raise SystemExit("release wheel and source distribution versions do not match")
    return wheels[0], sdists[0]


def _distribution_identity(metadata: os.stat_result) -> DistributionIdentity:
    """Return the device, inode, and finite byte size that identify one archive."""
    return metadata.st_dev, metadata.st_ino, metadata.st_size


def _require_distribution_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    max_bytes: int = MAX_DISTRIBUTION_BYTES,
) -> DistributionIdentity:
    """Return one regular finite input identity or fail through stable errors."""
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} is unreadable or unsafe")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} exceeds the safety bound")
    return _distribution_identity(metadata)


def _require_distribution_preflight(
    path: Path,
    *,
    label: str,
) -> DistributionIdentity:
    """Bind current regular-file identity before loading any archive parser."""
    try:
        path_state = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unreadable or unsafe") from error
    return _require_distribution_metadata(path_state, label=label)


def _require_reviewed_input_preflight(
    path: Path,
    *,
    label: str,
) -> DistributionIdentity:
    """Bind one reviewed dependency input to the generator's one-MiB ceiling."""
    try:
        path_state = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unreadable or unsafe") from error
    return _require_distribution_metadata(
        path_state,
        label=label,
        max_bytes=MAX_REVIEWED_INPUT_BYTES,
    )


def _snapshot_distribution(
    path: Path,
    snapshot_root: Path,
    accepted_identity: DistributionIdentity,
    *,
    label: str,
    max_bytes: int = MAX_DISTRIBUTION_BYTES,
) -> Path:
    """Copy one accepted descriptor into a private parser-only immutable snapshot.

    The accepted path identity is checked against both the no-follow descriptor
    and the current pathname before and after the bounded copy. Downstream parsers
    receive only the private snapshot, never the mutable caller-controlled path.
    """
    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor: int | None = None
    snapshot_descriptor: int | None = None
    snapshot_path = snapshot_root / path.name
    try:
        source_descriptor = os.open(path, read_flags)
        opened_identity = _require_distribution_metadata(
            os.fstat(source_descriptor),
            label=label,
            max_bytes=max_bytes,
        )
        current_identity = _require_distribution_metadata(
            path.lstat(),
            label=label,
            max_bytes=max_bytes,
        )
        if opened_identity != accepted_identity or current_identity != accepted_identity:
            raise SystemExit(f"{label} is unreadable or unsafe")

        snapshot_descriptor = os.open(snapshot_path, write_flags, 0o600)
        os.fchmod(snapshot_descriptor, 0o600)
        copied_bytes = 0
        while True:
            block = os.read(source_descriptor, COPY_BLOCK_BYTES)
            if not block:
                break
            copied_bytes += len(block)
            if copied_bytes > max_bytes:
                raise SystemExit(f"{label} exceeds the safety bound")
            remaining = memoryview(block)
            while remaining:
                written = os.write(snapshot_descriptor, remaining)
                if written <= 0:
                    raise OSError("short snapshot write")
                remaining = remaining[written:]
        os.fsync(snapshot_descriptor)

        final_opened_identity = _require_distribution_metadata(
            os.fstat(source_descriptor),
            label=label,
            max_bytes=max_bytes,
        )
        final_path_identity = _require_distribution_metadata(
            path.lstat(),
            label=label,
            max_bytes=max_bytes,
        )
        snapshot_state = os.fstat(snapshot_descriptor)
        if (
            final_opened_identity != accepted_identity
            or final_path_identity != accepted_identity
            or not stat.S_ISREG(snapshot_state.st_mode)
            or stat.S_IMODE(snapshot_state.st_mode) != 0o600
            or snapshot_state.st_size != copied_bytes
        ):
            raise SystemExit(f"{label} is unreadable or unsafe")
        return snapshot_path
    except FileExistsError:
        raise SystemExit(f"{label} parser snapshot already exists") from None
    except OSError as error:
        raise SystemExit(f"{label} is unreadable or unsafe") from error
    finally:
        if snapshot_descriptor is not None:
            os.close(snapshot_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)


def _load_attestable_generator() -> ModuleType:
    """Load the repository-only deterministic generator without importing archives."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_attestable_release_sbom_for_preparation",
        ATTESTABLE_GENERATOR_PATH,
    )
    if specification is None or specification.loader is None:
        raise SystemExit("attestable release SBOM generator could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _strict_pretty_json_bytes(document: dict[str, Any]) -> bytes:
    """Return deterministic indented strict-JSON bytes with one final newline."""
    try:
        return (
            json.dumps(
                document,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        raise SystemExit("generated release evidence is not strict JSON") from None


def _source_identity_bytes(repository: str, source_sha: str) -> bytes:
    """Return canonical compact source-identity bytes for the sealed set."""
    document = {
        "format": release_evidence.SOURCE_IDENTITY_FORMAT,
        "formatVersion": release_evidence.SOURCE_IDENTITY_VERSION,
        "repository": repository,
        "sourceSha": source_sha,
    }
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path, *, label: str) -> str:
    """Hash one bounded descriptor-bound regular distribution."""
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            path_state = path.lstat()
            opened_state = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(path_state.st_mode)
                or not stat.S_ISREG(opened_state.st_mode)
                or (path_state.st_dev, path_state.st_ino)
                != (opened_state.st_dev, opened_state.st_ino)
            ):
                raise SystemExit(f"{label} is unreadable or unsafe")
            for block in iter(lambda: stream.read(1_048_576), b""):
                total_bytes += len(block)
                if total_bytes > MAX_DISTRIBUTION_BYTES:
                    raise SystemExit(f"{label} exceeds the safety bound")
                digest.update(block)
    except OSError as error:
        raise SystemExit(f"{label} is unreadable") from error
    return digest.hexdigest()


def _write_private_file(path: Path, payload: bytes, *, label: str) -> None:
    """Exclusively create one owner-only regular file and durably write all bytes."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        opened_state = os.fstat(descriptor)
        path_state = path.lstat()
        if (
            not stat.S_ISREG(opened_state.st_mode)
            or not stat.S_ISREG(path_state.st_mode)
            or (opened_state.st_dev, opened_state.st_ino)
            != (path_state.st_dev, path_state.st_ino)
            or stat.S_IMODE(opened_state.st_mode) != 0o600
        ):
            raise OSError("unsafe output identity")
    except FileExistsError:
        raise SystemExit(f"{label} already exists") from None
    except OSError as error:
        raise SystemExit(f"{label} cannot be created safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _checksum_bytes(payloads: dict[str, bytes | Path]) -> bytes:
    """Return sorted canonical SHA-256 lines for five exact payloads."""
    lines: list[str] = []
    for filename in sorted(payloads):
        payload = payloads[filename]
        digest = (
            _sha256_file(payload, label=f"release distribution {filename}")
            if isinstance(payload, Path)
            else hashlib.sha256(payload).hexdigest()
        )
        lines.append(f"{digest}  {filename}\n")
    return "".join(lines).encode("ascii")


def prepare_release_evidence(
    evidence_dir: Path,
    handoff_path: Path,
    *,
    repository: str,
    source_sha: str,
    dependency_manifest_path: Path,
    runtime_lock_path: Path,
) -> dict[str, Any]:
    """Create and independently verify one credential-free release handoff.

    The input directory must initially contain only one canonical wheel and one
    matching source distribution. Each accepted archive and reviewed dependency
    input is copied from its no-follow identity-bound descriptor into one private
    parser-only snapshot before the generator loads. Every generated file is new,
    owner-only, and deterministic. The returned mapping is the exact manifest
    already rebuilt and verified after the separately stored handoff is published.
    """
    _require_source_identity(repository, source_sha)
    evidence_root = _require_canonical_directory(
        evidence_dir,
        label="release evidence input directory",
    )
    resolved_handoff = _require_handoff_outside_evidence(handoff_path, evidence_root)
    dependency_manifest_label = "reviewed runtime dependency manifest"
    runtime_lock_label = "hash-locked runtime requirements"
    dependency_manifest = _require_canonical_file(
        dependency_manifest_path,
        label=dependency_manifest_label,
    )
    runtime_lock = _require_canonical_file(
        runtime_lock_path,
        label=runtime_lock_label,
    )
    dependency_manifest_identity = _require_reviewed_input_preflight(
        dependency_manifest,
        label=dependency_manifest_label,
    )
    runtime_lock_identity = _require_reviewed_input_preflight(
        runtime_lock,
        label=runtime_lock_label,
    )
    wheel_path, sdist_path = _select_distributions(evidence_root)
    wheel_label = f"release distribution {wheel_path.name}"
    sdist_label = f"release distribution {sdist_path.name}"
    wheel_identity = _require_distribution_preflight(wheel_path, label=wheel_label)
    sdist_identity = _require_distribution_preflight(sdist_path, label=sdist_label)

    with tempfile.TemporaryDirectory(prefix="egressweave-release-evidence-") as temporary:
        snapshot_root = Path(temporary)
        wheel_snapshot = _snapshot_distribution(
            wheel_path,
            snapshot_root,
            wheel_identity,
            label=wheel_label,
        )
        sdist_snapshot = _snapshot_distribution(
            sdist_path,
            snapshot_root,
            sdist_identity,
            label=sdist_label,
        )
        dependency_manifest_snapshot = _snapshot_distribution(
            dependency_manifest,
            snapshot_root,
            dependency_manifest_identity,
            label=dependency_manifest_label,
            max_bytes=MAX_REVIEWED_INPUT_BYTES,
        )
        runtime_lock_snapshot = _snapshot_distribution(
            runtime_lock,
            snapshot_root,
            runtime_lock_identity,
            label=runtime_lock_label,
            max_bytes=MAX_REVIEWED_INPUT_BYTES,
        )
        generator = _load_attestable_generator()
        wheel_sbom = _strict_pretty_json_bytes(
            generator.build_attestable_sbom(
                wheel_snapshot,
                dependency_manifest_snapshot,
                runtime_lock_snapshot,
            )
        )
        sdist_sbom = _strict_pretty_json_bytes(
            generator.build_attestable_sbom(
                sdist_snapshot,
                dependency_manifest_snapshot,
                runtime_lock_snapshot,
            )
        )

    source_identity = _source_identity_bytes(repository, source_sha)
    generated_payloads = {
        f"{wheel_path.name}.cdx.json": wheel_sbom,
        f"{sdist_path.name}.cdx.json": sdist_sbom,
        release_evidence.SOURCE_IDENTITY_FILENAME: source_identity,
    }
    checksum_payloads: dict[str, bytes | Path] = {
        wheel_path.name: wheel_path,
        sdist_path.name: sdist_path,
        **generated_payloads,
    }
    checksums = _checksum_bytes(checksum_payloads)

    for filename, payload in generated_payloads.items():
        _write_private_file(
            evidence_root / filename,
            payload,
            label=f"release evidence {filename}",
        )
    _write_private_file(
        evidence_root / "SHA256SUMS",
        checksums,
        label="release evidence SHA256SUMS",
    )

    prepared_manifest = release_evidence.build_evidence_manifest(
        evidence_root,
        repository=repository,
        source_sha=source_sha,
    )
    release_evidence.write_evidence_manifest(
        prepared_manifest,
        resolved_handoff,
        forbidden_root=evidence_root,
    )
    release_evidence.reverify_published_evidence_manifest(
        evidence_root,
        resolved_handoff,
        repository=repository,
        source_sha=source_sha,
        expected_manifest=prepared_manifest,
    )
    return prepared_manifest


def main() -> int:
    """Prepare one exact evidence set and return zero only after re-verification."""
    arguments = _parse_arguments()
    prepare_release_evidence(
        arguments.evidence_dir,
        arguments.handoff_manifest,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
        dependency_manifest_path=arguments.dependency_manifest,
        runtime_lock_path=arguments.runtime_lock,
    )
    print(f"prepared sealed release evidence: {arguments.evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
