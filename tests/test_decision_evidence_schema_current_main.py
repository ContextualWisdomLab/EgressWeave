"""Test-first contract for provider-neutral decision-evidence JSON Schema v1."""

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


def _example_evidence(*, methods: set[str] | None = None) -> dict[str, object]:
    """Build one real runtime evidence mapping for schema parity assertions."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
    )
    policy = egressweave.EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"GET", "POST"} if methods is None else methods,
    )
    return egressweave.build_egress_decision_evidence(
        validated,
        policy=policy,
    ).as_dict()


def _load_schema() -> dict[str, object]:
    """Load the v1 schema through the public detached loader under test."""
    schema = egressweave.get_decision_evidence_json_schema()
    assert isinstance(schema, dict)
    return schema


def test_packaged_schema_matches_protected_main_runtime_shape() -> None:
    """Version the existing runtime record without deleting compatibility fields."""
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
    assert properties["ipv4_address_count"] == {"type": "integer", "minimum": 0}
    assert properties["ipv6_address_count"] == {"type": "integer", "minimum": 0}
    for fingerprint_field in ("policy_fingerprint", "decision_fingerprint"):
        assert properties[fingerprint_field] == {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
        }


def test_schema_preserves_total_and_family_count_consistency_contract() -> None:
    """Keep the shipped total while documenting its runtime derivation from families."""
    evidence = _example_evidence()
    assert evidence["address_count"] == 2
    assert evidence["ipv4_address_count"] == 1
    assert evidence["ipv6_address_count"] == 1
    assert evidence["address_count"] == (
        evidence["ipv4_address_count"] + evidence["ipv6_address_count"]
    )

    schema = _load_schema()
    required = schema["required"]
    assert isinstance(required, list)
    assert "address_count" in required


def test_schema_accepts_runtime_deny_all_method_policy_shape() -> None:
    """Allow the empty method list emitted by a valid deny-all method policy."""
    evidence = _example_evidence(methods=set())
    assert evidence["allowed_methods"] == []

    properties = _load_schema()["properties"]
    assert isinstance(properties, dict)
    allowed_methods = properties["allowed_methods"]
    assert isinstance(allowed_methods, dict)
    assert "minItems" not in allowed_methods


def test_schema_method_items_match_runtime_normalization_contract() -> None:
    """Accept only method spellings that normalized runtime evidence can emit."""
    evidence = _example_evidence(methods={"get", "m-search"})
    assert evidence["allowed_methods"] == ["GET", "M-SEARCH"]

    properties = _load_schema()["properties"]
    assert isinstance(properties, dict)
    allowed_methods = properties["allowed_methods"]
    assert isinstance(allowed_methods, dict)
    method_items = allowed_methods["items"]
    assert method_items == _METHOD_ITEM_SCHEMA
    assert isinstance(method_items, dict)
    method_pattern = method_items["pattern"]
    assert isinstance(method_pattern, str)

    assert all(
        re.fullmatch(method_pattern, method)
        for method in evidence["allowed_methods"]
    )
    assert re.fullmatch(method_pattern, "CONNECT") is not None
    assert method_items["not"] == {"const": "CONNECT"}
    for impossible_method in ("get", "GET POST", "méthod"):
        assert re.fullmatch(method_pattern, impossible_method) is None


def test_schema_loader_returns_detached_data_on_every_call() -> None:
    """Prevent caller mutation from changing later loads or package state."""
    first = _load_schema()
    first_properties = first["properties"]
    assert isinstance(first_properties, dict)
    first_properties["authority"] = {"type": "null"}

    second = _load_schema()
    second_properties = second["properties"]
    assert isinstance(second_properties, dict)
    assert second_properties["authority"] == {"type": "string", "minLength": 1}


def test_schema_is_a_packaged_utf8_json_resource() -> None:
    """Ship the schema inside the importable package rather than documentation only."""
    resource = resources.files("egressweave").joinpath(
        "schemas",
        "decision-evidence-v1.schema.json",
    )
    with resource.open("r", encoding="utf-8") as schema_file:
        packaged_schema = json.load(schema_file)

    assert packaged_schema == _load_schema()


def test_distribution_verifier_requires_schema_in_wheel_and_sdist() -> None:
    """Keep the versioned schema inside both independently verified artifacts."""
    verifier = (_REPOSITORY_ROOT / "scripts/ci/verify_distribution.py").read_text(
        encoding="utf-8"
    )

    assert (
        'f"{DISTRIBUTION_NAME}/schemas/decision-evidence-v1.schema.json"'
        in verifier
    )
    assert "decision-evidence-v1.schema.json" in verifier
    assert "src/{DISTRIBUTION_NAME}/schemas/" in verifier
