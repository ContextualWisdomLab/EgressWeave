"""Regression test for checksum-bound SBOM semantic verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_sealed_release_evidence_source_identity import (
    _build,
    _evidence,
    _serial,
)

from egressweave import release_evidence


def _alternate_sbom_bytes(accepted_bytes: bytes) -> bytes:
    """Return a valid but semantically different CycloneDX fixture."""
    alternate_document = json.loads(accepted_bytes)
    alternate_document["components"] = [
        {
            "name": "unsealed-alternate-semantics",
            "type": "library",
            "version": "1",
        }
    ]
    alternate_document.pop("serialNumber")
    alternate_document["serialNumber"] = _serial(alternate_document)
    return json.dumps(alternate_document).encode("utf-8")


def test_private_snapshot_ignores_transient_source_sbom_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep source-root ABA changes outside the admitted semantic snapshot."""
    root = tmp_path / "evidence"
    _evidence(root)
    wheel = root / "egressweave-0.3.0-py3-none-any.whl"
    source_sbom = root / f"{wheel.name}.cdx.json"
    accepted_bytes = source_sbom.read_bytes()
    alternate_bytes = _alternate_sbom_bytes(accepted_bytes)
    accepted_manifest = _build(root)
    original_verify = release_evidence._verify_sbom

    def verify_while_source_is_alternate(
        sbom_path: Path,
        *,
        artifact_name: str,
        artifact_digest: str,
        version: str,
        expected_digest: str,
    ) -> str:
        """Swap only the caller-owned source while the private snapshot is parsed."""
        if not artifact_name.endswith(".whl"):
            return original_verify(
                sbom_path,
                artifact_name=artifact_name,
                artifact_digest=artifact_digest,
                version=version,
                expected_digest=expected_digest,
            )
        source_sbom.write_bytes(alternate_bytes)
        try:
            return original_verify(
                sbom_path,
                artifact_name=artifact_name,
                artifact_digest=artifact_digest,
                version=version,
                expected_digest=expected_digest,
            )
        finally:
            source_sbom.write_bytes(accepted_bytes)

    monkeypatch.setattr(
        release_evidence,
        "_verify_sbom",
        verify_while_source_is_alternate,
    )

    assert _build(root) == accepted_manifest


def test_strict_json_rejects_semantics_outside_sealed_digest(tmp_path: Path) -> None:
    """Retain direct proof that semantic parsing cannot outrun its sealed digest."""
    path = tmp_path / "payload.cdx.json"
    accepted_document = {
        "bomFormat": "CycloneDX",
        "components": [],
    }
    accepted_bytes = json.dumps(accepted_document).encode("utf-8")
    accepted_digest = hashlib.sha256(accepted_bytes).hexdigest()
    path.write_bytes(accepted_bytes)
    alternate_document = dict(accepted_document)
    alternate_document["components"] = [{"name": "alternate"}]
    path.write_text(json.dumps(alternate_document), encoding="utf-8")

    with pytest.raises(SystemExit, match="sealed digest"):
        release_evidence._load_strict_json(
            path,
            expected_digest=accepted_digest,
        )
