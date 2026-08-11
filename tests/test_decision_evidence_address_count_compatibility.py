"""Compatibility regression for the versioned decision-evidence address count."""

from __future__ import annotations

from dataclasses import fields

from egressweave.decision_evidence import (
    EgressDecisionEvidence,
    get_decision_evidence_json_schema,
)


def test_schema_preserves_existing_total_address_count_contract() -> None:
    """Keep the protected-main total count in runtime and schema v1 evidence."""
    runtime_fields = {field.name for field in fields(EgressDecisionEvidence)}
    assert "address_count" in runtime_fields

    schema = get_decision_evidence_json_schema()
    required = schema["required"]
    properties = schema["properties"]

    assert isinstance(required, list)
    assert "address_count" in required
    assert isinstance(properties, dict)
    assert properties["address_count"] == {"type": "integer", "minimum": 1}
