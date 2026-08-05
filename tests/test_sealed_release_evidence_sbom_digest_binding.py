"""Regression test for checksum-bound SBOM semantic verification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_sealed_release_evidence_source_identity import (
    _build,
    _evidence,
    _serial,
)

from egressweave import release_evidence


def test_semantic_sbom_snapshot_must_match_the_accepted_checksum_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a valid alternate SBOM parsed between matching outer snapshots."""
    root = tmp_path / "evidence"
    _evidence(root)
    wheel = root / "egressweave-0.3.0-py3-none-any.whl"
    sbom = root / f"{wheel.name}.cdx.json"
    accepted_bytes = sbom.read_bytes()
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
    alternate_bytes = json.dumps(alternate_document).encode("utf-8")
    original_load = release_evidence._load_strict_json

    def load_alternate_then_restore(
        path: Path,
        *,
        expected_digest: str | None = None,
    ):
        """Expose an ABA swap only during semantic parsing of the wheel SBOM."""
        if path != sbom:
            if expected_digest is None:
                return original_load(path)
            return original_load(path, expected_digest=expected_digest)
        path.write_bytes(alternate_bytes)
        try:
            if expected_digest is None:
                return original_load(path)
            return original_load(path, expected_digest=expected_digest)
        finally:
            path.write_bytes(accepted_bytes)

    monkeypatch.setattr(release_evidence, "_load_strict_json", load_alternate_then_restore)

    with pytest.raises(SystemExit, match="sealed digest"):
        _build(root)
