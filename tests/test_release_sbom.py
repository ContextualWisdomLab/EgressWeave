"""Tests for deterministic, artifact-bound release SBOM generation."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"


def _load_generator():
    """Load the non-packaged SBOM generator from its repository path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _metadata(
    *,
    requires_dist: tuple[str, ...] = (
        "httpx>=0.28,<0.29",
        "httpcore>=1.0,<2.0",
        "idna>=3.18,<4",
    ),
) -> bytes:
    """Return minimal valid EgressWeave core metadata for archive fixtures."""
    lines = [
        "Metadata-Version: 2.4",
        "Name: egressweave",
        "Version: 0.3.0",
        "License-Expression: Apache-2.0",
    ]
    lines.extend(f"Requires-Dist: {requirement}" for requirement in requires_dist)
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _write_wheel(path: Path, *, metadata: bytes | None = None) -> None:
    """Create a minimal wheel-like ZIP containing one core metadata member."""
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(
            "egressweave-0.3.0.dist-info/METADATA",
            metadata if metadata is not None else _metadata(),
        )


def _write_sdist(path: Path, *, metadata: bytes | None = None) -> None:
    """Create a minimal gzip source archive containing one root PKG-INFO member."""
    payload = metadata if metadata is not None else _metadata()
    member = tarfile.TarInfo("egressweave-0.3.0/PKG-INFO")
    member.size = len(payload)
    member.mtime = 0
    with tarfile.open(path, mode="w:gz") as archive:
        archive.addfile(member, io.BytesIO(payload))


def _manifest_copy(tmp_path: Path) -> Path:
    """Copy the reviewed runtime dependency manifest for mutation tests."""
    destination = tmp_path / "manifest.json"
    destination.write_text(MANIFEST_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def test_sbom_is_deterministic_and_binds_the_exact_wheel(tmp_path: Path) -> None:
    """Emit byte-stable CycloneDX evidence with the wheel's exact digest."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)

    first = generator.build_sbom(wheel_path, MANIFEST_PATH)
    first_path = tmp_path / "first.cdx.json"
    second_path = tmp_path / "second.cdx.json"
    generator.write_sbom(first, first_path)
    generator.write_sbom(generator.build_sbom(wheel_path, MANIFEST_PATH), second_path)

    assert first_path.read_bytes() == second_path.read_bytes()
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.7"
    assert "serialNumber" not in first
    assert "timestamp" not in first["metadata"]
    expected_digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    root = first["metadata"]["component"]
    assert root["hashes"] == [{"alg": "SHA-256", "content": expected_digest}]
    assert root["bom-ref"] == f"urn:egressweave:artifact:sha256:{expected_digest}"
    assert root["purl"] == "pkg:pypi/egressweave@0.3.0"


def test_wheel_and_sdist_share_the_reviewed_runtime_dependency_graph(tmp_path: Path) -> None:
    """Describe the same reviewed runtime closure for both canonical archives."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    sdist_path = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_wheel(wheel_path)
    _write_sdist(sdist_path)

    wheel_sbom = generator.build_sbom(wheel_path, MANIFEST_PATH)
    sdist_sbom = generator.build_sbom(sdist_path, MANIFEST_PATH)

    assert wheel_sbom["components"] == sdist_sbom["components"]
    assert wheel_sbom["dependencies"][1:] == sdist_sbom["dependencies"][1:]
    component_names = {component["name"] for component in wheel_sbom["components"]}
    assert component_names == {
        "anyio",
        "certifi",
        "exceptiongroup",
        "h11",
        "httpcore",
        "httpx",
        "idna",
        "typing-extensions",
    }
    assert all(
        component["hashes"][0]["alg"] == "SHA-256"
        for component in wheel_sbom["components"]
    )


def test_manifest_is_bound_to_hash_locked_runtime_subset(tmp_path: Path) -> None:
    """Reject reviewed dependency evidence that drifts from the executable lock."""
    generator = _load_generator()
    generator.validate_runtime_lock(MANIFEST_PATH, LOCK_PATH)

    manifest_path = _manifest_copy(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["components"][0]["version"] = "99.0.0"
    manifest["components"][0]["purl"] = "pkg:pypi/anyio@99.0.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="does not match the hash-locked runtime subset"):
        generator.validate_runtime_lock(manifest_path, LOCK_PATH)


def test_artifact_dependency_drift_fails_closed(tmp_path: Path) -> None:
    """Reject an archive whose declared direct dependencies differ from review."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path, metadata=_metadata(requires_dist=("httpx>=0.28,<0.29",)))

    with pytest.raises(SystemExit, match="direct runtime dependencies do not match"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_artifact_dependency_specifier_drift_fails_closed(tmp_path: Path) -> None:
    """Reject changed dependency ranges even when distribution names still match."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(
        wheel_path,
        metadata=_metadata(
            requires_dist=(
                "httpx>=0.28,<0.30",
                "httpcore>=1.0,<2.0",
                "idna>=3.18,<4",
            )
        ),
    )

    with pytest.raises(SystemExit, match="runtime requirement declarations do not match"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_compressed_metadata_size_is_checked_before_decompression(tmp_path: Path) -> None:
    """Reject a declared oversized wheel metadata member before allocating it."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(
        wheel_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "egressweave-0.3.0.dist-info/METADATA",
            b"X" * (generator.MAX_METADATA_BYTES + 1),
        )

    with pytest.raises(SystemExit, match="metadata exceeds the safety bound"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_manifest_duplicate_component_fails_closed(tmp_path: Path) -> None:
    """Reject ambiguous dependency identity before generating buyer evidence."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)
    manifest_path = _manifest_copy(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["components"].append(dict(manifest["components"][0]))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="duplicates component"):
        generator.build_sbom(wheel_path, manifest_path)


def test_manifest_unreachable_component_fails_closed(tmp_path: Path) -> None:
    """Exclude development-only or accidentally retained packages from release scope."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)
    manifest_path = _manifest_copy(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["components"].append(
        {
            "name": "unrelated",
            "version": "1.0.0",
            "license": "MIT",
            "sha256": "0" * 64,
            "artifact_filename": "unrelated-1.0.0-py3-none-any.whl",
            "purl": "pkg:pypi/unrelated@1.0.0",
            "depends_on": [],
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="unreachable components"):
        generator.build_sbom(wheel_path, manifest_path)


def test_manifest_digest_and_purl_are_strictly_validated(tmp_path: Path) -> None:
    """Reject noncanonical component identity and non-SHA-256 lock evidence."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)
    manifest_path = _manifest_copy(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["components"][0]["sha256"] = "ABC"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="lowercase SHA-256"):
        generator.build_sbom(wheel_path, manifest_path)

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["components"][0]["purl"] = "pkg:pypi/other@4.14.2"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SystemExit, match="purl must equal"):
        generator.build_sbom(wheel_path, manifest_path)


def test_unsafe_or_ambiguous_archives_fail_closed(tmp_path: Path) -> None:
    """Treat release archives as untrusted data and reject ambiguous metadata."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", _metadata())
        archive.writestr("other-1.0.dist-info/METADATA", _metadata())

    with pytest.raises(SystemExit, match="exactly one core METADATA"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)

    unsupported_path = tmp_path / "egressweave.zip"
    unsupported_path.write_bytes(b"not a distribution")
    with pytest.raises(SystemExit, match="must be a .whl or .tar.gz"):
        generator.build_sbom(unsupported_path, MANIFEST_PATH)


def test_manifest_rejects_unreviewed_spdx_license_identifier(tmp_path: Path) -> None:
    """Reject a syntactically plausible token that CycloneDX cannot use as SPDX ID."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)
    manifest_path = _manifest_copy(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["components"][0]["license"] = "Not-A-Real-License"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="reviewed SPDX license identifier"):
        generator.build_sbom(wheel_path, manifest_path)
