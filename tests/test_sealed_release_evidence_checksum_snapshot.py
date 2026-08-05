"""Regression test for the sealed checksum snapshot lifetime."""

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
    """Return one minimal valid exact-profile CycloneDX document."""
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


def _source_identity() -> bytes:
    """Return one canonical exact repository/source identity payload."""
    return (
        json.dumps(
            {
                "format": "egressweave.release-source-identity",
                "formatVersion": 1,
                "repository": REPOSITORY,
                "sourceSha": SOURCE_SHA,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _evidence(root: Path) -> dict[str, Path]:
    """Create one complete valid six-file release evidence set."""
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
    source_identity = root / "SOURCE_IDENTITY.json"
    source_identity.write_bytes(_source_identity())
    checksum = root / "SHA256SUMS"
    payloads = (wheel, sdist, wheel_sbom, sdist_sbom, source_identity)
    checksum.write_text(
        "".join(
            f"{_digest(path)}  {path.name}\n"
            for path in sorted(payloads, key=lambda item: item.name)
        ),
        encoding="ascii",
    )
    return {"checksum": checksum}


def test_manifest_rejects_checksum_mutation_after_sbom_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not issue a manifest after the accepted checksum file has changed."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    original_verify = release_evidence._verify_sbom

    def verify_then_mutate(
        sbom_path: Path,
        *,
        artifact_name: str,
        artifact_digest: str,
        version: str,
    ) -> str:
        """Replace SHA256SUMS only after both SBOMs and payloads were accepted."""
        serial = original_verify(
            sbom_path,
            artifact_name=artifact_name,
            artifact_digest=artifact_digest,
            version=version,
        )
        if artifact_name.endswith(".whl"):
            paths["checksum"].write_text("replaced after verification\n", encoding="ascii")
        return serial

    monkeypatch.setattr(release_evidence, "_verify_sbom", verify_then_mutate)

    with pytest.raises(SystemExit, match="SHA256SUMS changed during verification"):
        release_evidence.build_evidence_manifest(
            root,
            repository=REPOSITORY,
            source_sha=SOURCE_SHA,
        )
