"""Regression tests for the packaged decision-evidence JSON Schema contract."""

from __future__ import annotations

import json
from importlib import resources

import egressweave

from egressweave import (
    DECISION_EVIDENCE_SCHEMA_VERSION,
    EgressPolicy,
    build_egress_decision_evidence,
)
from egressweave.validation import _make_validated_egress_url


def _load_schema() -> dict[str, object]:
    """Load the public schema through the API that this slice introduces."""
    loader = getattr(egressweave, "get_decision_evidence_json_schema")
    schema = loader()
    assert isinstance(schema, dict)
    return schema


def _example_evidence() -> dict[str, object]:
    """Return one runtime evidence record for schema-contract comparison."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
    )
    return build_egress_decision_evidence(
        validated,
        policy=EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods={"GET", "POST"},
        ),
    ).as_dict()


def test_packaged_schema_matches_runtime_decision_evidence_contract() -> None:
    """Keep the machine-readable v1 schema aligned with emitted evidence fields."""
    schema = _load_schema()
    evidence = _example_evidence()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(evidence)

    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert properties["schema_version"] == {"const": DECISION_EVIDENCE_SCHEMA_VERSION}
    assert properties["authority"] == {"type": "string", "minLength": 1}
    assert properties["allowed_methods"] == {
        "type": "array",
        "minItems": 1,
        "uniqueItems": True,
        "items": {"type": "string", "minLength": 1},
    }
    for count_field in (
        "address_count",
        "ipv4_address_count",
        "ipv6_address_count",
    ):
        assert properties[count_field] == {"type": "integer", "minimum": 0}
    for fingerprint_field in ("policy_fingerprint", "decision_fingerprint"):
        assert properties[fingerprint_field] == {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
        }


def test_schema_loader_returns_detached_data_on_every_call() -> None:
    """Prevent caller mutation from changing subsequent schema loads."""
    first = _load_schema()
    first_properties = first["properties"]
    assert isinstance(first_properties, dict)
    first_properties["authority"] = {"type": "null"}

    second = _load_schema()
    second_properties = second["properties"]
    assert isinstance(second_properties, dict)
    assert second_properties["authority"] == {"type": "string", "minLength": 1}


def test_schema_is_a_packaged_utf8_json_resource() -> None:
    """Ship the schema inside the importable package rather than docs only."""
    schema_resource = resources.files("egressweave").joinpath(
        "schemas",
        "decision-evidence-v1.schema.json",
    )
    with schema_resource.open("r", encoding="utf-8") as schema_file:
        packaged_schema = json.load(schema_file)

    assert packaged_schema == _load_schema()
