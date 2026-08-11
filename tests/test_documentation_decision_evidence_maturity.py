"""Contracts separating shipped decision evidence from the packaged-schema PR."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
API_CONTRACT_PATH = REPOSITORY_ROOT / "docs" / "product" / "API_CONTRACT.md"


def test_api_contract_distinguishes_runtime_mapping_from_packaged_json_schema() -> None:
    """Keep the existing v1 mapping shipped while PR #90 remains an artifact addition."""
    api_contract = " ".join(
        API_CONTRACT_PATH.read_text(encoding="utf-8").split()
    )

    assert "Protected main already exports `DECISION_EVIDENCE_SCHEMA_VERSION`, `EgressDecisionEvidence`, and deterministic JSON-compatible `as_dict()` output" in api_contract
    assert "ACTIVE-PR" in api_contract
    assert "packaged JSON Schema Draft 2020-12 resource" in api_contract
    assert "A future **ACTIVE-PR** may add a versioned machine-readable decision-evidence schema" not in api_contract
