"""Regression tests for sealed repository and source identity binding."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from egressweave import release_evidence

REPOSITORY = "ContextualWisdomLab/EgressWeave"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SOURCE_SHA = "89abcdef0123456789abcdef0123456789abcdef"
VERSION = "0.3.0"


def _digest(path: Path) -> str:
    """Return SHA-256 for one test fixture."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _serial(document: dict[str, Any]) -> str:
    """Derive the content-bound UUIDv5 independently of production code."""
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    prefix = "https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, prefix + digest)}"


def _sbom(filename: str, digest: str) -> dict[str, Any]:
    """Return one valid exact-profile CycloneDX document."""
    document: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": f"urn:egressweave:artifact:sha256:{digest}",
                "name": "egressweave",
                "version": VERSION,
                "purl": f"pkg:pypi/egressweave@{VERSION}",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {
                        "name": "egressweave:release:artifact-filename",
                        "value": filename,
                    }
                ],
            }
        },
        "components": [],
        "dependencies": [],
    }
    document["serialNumber"] = _serial(document)
    return document


def _legacy_evidence(root: Path) -> None:
    """Create the previously accepted five-file evidence set without source identity."""
    root.mkdir()
    wheel = root / f"egressweave-{VERSION}-py3-none-any.whl"
    sdist = root / f"egressweave-{VERSION}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    wheel_sbom = root / f"{wheel.name}.cdx.json"
    sdist_sbom = root / f"{sdist.name}.cdx.json"
    wheel_sbom.write_text(
        json.dumps(_sbom(wheel.name, _digest(wheel))),
        encoding="utf-8",
    )
    sdist_sbom.write_text(
        json.dumps(_sbom(sdist.name, _digest(sdist))),
        encoding="utf-8",
    )
    payloads = (wheel, sdist, wheel_sbom, sdist_sbom)
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_digest(path)}  {path.name}\n"
            for path in sorted(payloads, key=lambda item: item.name)
        ),
        encoding="ascii",
    )


def test_legacy_evidence_without_sealed_source_identity_fails(tmp_path: Path) -> None:
    """Reject artifact evidence whose repository and source are only caller assertions."""
    root = tmp_path / "evidence"
    _legacy_evidence(root)

    with pytest.raises(SystemExit, match="sealed source identity"):
        release_evidence.build_evidence_manifest(
            root,
            repository=REPOSITORY,
            source_sha=SOURCE_SHA,
        )


def test_valid_artifacts_cannot_be_relabeled_with_another_source(tmp_path: Path) -> None:
    """Reject a different valid-looking source SHA for the same sealed payload bytes."""
    root = tmp_path / "evidence"
    _legacy_evidence(root)

    with pytest.raises(SystemExit, match="sealed source identity"):
        release_evidence.build_evidence_manifest(
            root,
            repository=REPOSITORY,
            source_sha=OTHER_SOURCE_SHA,
        )
