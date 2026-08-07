"""Regression tests for the packaged decision-evidence JSON Schema contract."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import egressweave
from egressweave.validation import _make_validated_egress_url

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_METHOD_ITEM_SCHEMA = {
    "type": "string",
    "pattern": "^[!#$%&'*+.^_`|~0-9A-Z-]+$",
    "not": {"const": "CONNECT"},
}


def _load_schema() -> dict[str, object]:
    """Load the public schema through the API that this slice introduces."""
    schema = egressweave.get_decision_evidence_json_schema()
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
    return egressweave.build_egress_decision_evidence(
        validated,
        policy=egressweave.EgressPolicy.from_hosts(
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
    assert properties["schema_version"] == {
        "const": egressweave.DECISION_EVIDENCE_SCHEMA_VERSION
    }
    assert properties["authority"] == {"type": "string", "minLength": 1}
    assert properties["allowed_methods"] == {
        "type": "array",
        "uniqueItems": True,
        "items": _METHOD_ITEM_SCHEMA,
    }
    assert properties["address_count"] == {"type": "integer", "minimum": 1}
    for count_field in ("ipv4_address_count", "ipv6_address_count"):
        assert properties[count_field] == {"type": "integer", "minimum": 0}
    for fingerprint_field in ("policy_fingerprint", "decision_fingerprint"):
        assert properties[fingerprint_field] == {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
        }


def test_schema_accepts_runtime_deny_all_method_policy_shape() -> None:
    """Allow the empty method list emitted by a valid deny-all method policy."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )
    evidence = egressweave.build_egress_decision_evidence(
        validated,
        policy=egressweave.EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods=set(),
        ),
    ).as_dict()

    assert evidence["allowed_methods"] == []
    properties = _load_schema()["properties"]
    assert isinstance(properties, dict)
    allowed_methods = properties["allowed_methods"]
    assert isinstance(allowed_methods, dict)
    assert "minItems" not in allowed_methods


def test_schema_method_items_match_runtime_normalization_contract() -> None:
    """Reject method spellings that normalized runtime evidence cannot emit."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )
    evidence = egressweave.build_egress_decision_evidence(
        validated,
        policy=egressweave.EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods={"get", "m-search"},
        ),
    ).as_dict()
    assert evidence["allowed_methods"] == ["GET", "M-SEARCH"]

    properties = _load_schema()["properties"]
    assert isinstance(properties, dict)
    allowed_methods = properties["allowed_methods"]
    assert isinstance(allowed_methods, dict)
    method_items = allowed_methods["items"]
    assert isinstance(method_items, dict)
    assert method_items == _METHOD_ITEM_SCHEMA

    method_pattern = method_items["pattern"]
    assert isinstance(method_pattern, str)
    assert all(re.fullmatch(method_pattern, method) for method in evidence["allowed_methods"])
    assert re.fullmatch(method_pattern, "CONNECT") is not None
    assert method_items["not"] == {"const": "CONNECT"}
    for impossible_method in ("get", "GET POST", "méthod"):
        assert re.fullmatch(method_pattern, impossible_method) is None


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


def test_authoritative_docs_publish_versioned_schema_contract() -> None:
    """Keep architecture and changelog aligned with the public schema contract."""
    architecture = (_REPOSITORY_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    changelog = (_REPOSITORY_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    for required_fragment in (
        "decision-evidence-v1.schema.json",
        "get_decision_evidence_json_schema()",
    ):
        assert required_fragment in architecture
        assert required_fragment in changelog
