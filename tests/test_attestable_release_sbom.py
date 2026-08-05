"""Tests for deterministic CycloneDX evidence accepted by ``actions/attest``."""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = (
    REPOSITORY_ROOT / "scripts" / "ci" / "generate_attestable_release_sbom.py"
)
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"


def _load_generator():
    """Load the repository-only attestation compatibility generator."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_attestable_release_sbom",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _metadata() -> bytes:
    """Return minimal valid EgressWeave core metadata for wheel fixtures."""
    return (
        b"Metadata-Version: 2.4\n"
        b"Name: egressweave\n"
        b"Version: 0.3.0\n"
        b"License-Expression: Apache-2.0\n"
        b"Requires-Dist: httpx>=0.28,<0.29\n"
        b"Requires-Dist: httpcore>=1.0,<2.0\n"
        b"Requires-Dist: idna>=3.18,<4\n\n"
    )


def _write_wheel(path: Path, *, marker: bytes = b"") -> None:
    """Create a valid wheel-like archive whose exact bytes can be varied."""
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", _metadata())
        archive.writestr("egressweave/_attestation_fixture", marker)


def test_attestable_sbom_has_deterministic_rfc4122_document_identity(
    tmp_path: Path,
) -> None:
    """Give identical SBOM semantics one stable UUID URN and changed bytes another."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)

    first = generator.build_attestable_sbom(wheel_path, MANIFEST_PATH, LOCK_PATH)
    second = generator.build_attestable_sbom(wheel_path, MANIFEST_PATH, LOCK_PATH)

    assert first == second
    assert first["serialNumber"].startswith("urn:uuid:")
    serial = uuid.UUID(first["serialNumber"].removeprefix("urn:uuid:"))
    assert serial.version == 5
    assert serial.variant == uuid.RFC_4122

    changed_path = tmp_path / "egressweave-0.3.0-changed-py3-none-any.whl"
    _write_wheel(changed_path, marker=b"changed exact artifact bytes")
    changed = generator.build_attestable_sbom(changed_path, MANIFEST_PATH, LOCK_PATH)
    assert changed["serialNumber"] != first["serialNumber"]


def test_attestable_sbom_matches_pinned_actions_attest_cyclonedx_contract(
    tmp_path: Path,
) -> None:
    """Expose every field required by the reviewed ``actions/attest`` detector."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_wheel(wheel_path)

    sbom = generator.build_attestable_sbom(wheel_path, MANIFEST_PATH, LOCK_PATH)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.7"
    assert sbom["serialNumber"]
    assert generator.ATTESTATION_PREDICATE_TYPE == "https://cyclonedx.org/bom"


def test_attestable_sbom_api_rejects_manifest_lock_drift(tmp_path: Path) -> None:
    """Prevent direct Python callers from bypassing executable lock parity."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    manifest_path = tmp_path / "runtime-dependencies.json"
    _write_wheel(wheel_path)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["components"][0]["version"] = "99.0.0"
    manifest["components"][0]["purl"] = "pkg:pypi/anyio@99.0.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="does not match the hash-locked runtime subset"):
        generator.build_attestable_sbom(wheel_path, manifest_path, LOCK_PATH)


def test_attestable_sbom_cli_writes_byte_stable_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Validate the lock and emit repeatable evidence through the operator CLI."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    first_path = tmp_path / "first.cdx.json"
    second_path = tmp_path / "second.cdx.json"
    _write_wheel(wheel_path)

    for output_path in (first_path, second_path):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                str(GENERATOR_PATH),
                "--artifact",
                str(wheel_path),
                "--manifest",
                str(MANIFEST_PATH),
                "--lock",
                str(LOCK_PATH),
                "--output",
                str(output_path),
            ],
        )
        assert generator.main() == 0

    assert first_path.read_bytes() == second_path.read_bytes()
    document = json.loads(first_path.read_text(encoding="utf-8"))
    assert document["serialNumber"].startswith("urn:uuid:")
    assert "timestamp" not in document["metadata"]
