"""Tests for deterministic, non-secret egress decision evidence."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressDecisionEvidence,
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_decision_evidence,
)
from egressweave.validation import _make_validated_egress_url


def _validated_result():
    """Return one signed result containing public IPv4 and IPv6 addresses."""
    return _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
    )


def test_decision_evidence_is_deterministic_and_excludes_request_secrets() -> None:
    """Record authority and counts without exposing paths or resolved addresses."""
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"POST", "GET"},
        max_response_bytes=4096,
    )

    evidence = build_egress_decision_evidence(_validated_result(), policy=policy)
    repeated = build_egress_decision_evidence(_validated_result(), policy=policy)

    assert evidence == repeated
    assert evidence.schema_version == "egressweave.decision-evidence.v1"
    assert evidence.authority == "api.example.com:443"
    assert evidence.allowed_methods == ("GET", "POST")
    assert evidence.ipv4_address_count == 1
    assert evidence.ipv6_address_count == 1
    assert len(evidence.policy_fingerprint) == 64
    assert len(evidence.decision_fingerprint) == 64

    serialized = evidence.as_dict()
    assert serialized == {
        "schema_version": "egressweave.decision-evidence.v1",
        "authority": "api.example.com:443",
        "allowed_methods": ["GET", "POST"],
        "ipv4_address_count": 1,
        "ipv6_address_count": 1,
        "policy_fingerprint": evidence.policy_fingerprint,
        "decision_fingerprint": evidence.decision_fingerprint,
    }
    serialized_text = repr(serialized)
    assert "/v1/models" not in serialized_text
    assert "93.184.216.34" not in serialized_text
    assert "2606:2800" not in serialized_text


def test_policy_fingerprint_is_stable_across_input_order() -> None:
    """Canonicalize authority and method order before hashing policy evidence."""
    first = EgressPolicy.from_authorities(
        [("b.example.com", 8443), ("a.example.com", 443)],
        allowed_methods={"POST", "GET"},
    )
    second = EgressPolicy.from_authorities(
        [("a.example.com", 443), ("b.example.com", 8443)],
        allowed_methods={"GET", "POST"},
    )
    validated = _make_validated_egress_url(
        "https://a.example.com/status",
        "a.example.com",
        443,
        ("93.184.216.34",),
    )

    first_evidence = build_egress_decision_evidence(validated, policy=first)
    second_evidence = build_egress_decision_evidence(validated, policy=second)

    assert first_evidence.policy_fingerprint == second_evidence.policy_fingerprint
    assert first_evidence.decision_fingerprint == second_evidence.decision_fingerprint


def test_policy_change_changes_evidence_fingerprints() -> None:
    """Make policy drift visible without recording the original configuration."""
    validated = _validated_result()
    first = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"GET"},
        max_response_bytes=4096,
    )
    second = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"GET", "POST"},
        max_response_bytes=8192,
    )

    first_evidence = build_egress_decision_evidence(validated, policy=first)
    second_evidence = build_egress_decision_evidence(validated, policy=second)

    assert first_evidence.policy_fingerprint != second_evidence.policy_fingerprint
    assert first_evidence.decision_fingerprint != second_evidence.decision_fingerprint


def test_request_budget_change_changes_evidence_fingerprints() -> None:
    """Include the outbound body budget in audit-visible policy correlation."""
    validated = _validated_result()
    smaller_budget = EgressPolicy.from_hosts(
        "api.example.com",
        max_request_bytes=4096,
        max_response_bytes=8192,
    )
    larger_budget = EgressPolicy.from_hosts(
        "api.example.com",
        max_request_bytes=8192,
        max_response_bytes=8192,
    )

    smaller_evidence = build_egress_decision_evidence(
        validated,
        policy=smaller_budget,
    )
    larger_evidence = build_egress_decision_evidence(
        validated,
        policy=larger_budget,
    )

    assert smaller_evidence.policy_fingerprint != larger_evidence.policy_fingerprint
    assert smaller_evidence.decision_fingerprint != larger_evidence.decision_fingerprint


def test_evidence_builder_rejects_tampered_validation_state_generically() -> None:
    """Revalidate signed state and preserve the non-leaking runtime error boundary."""
    validated = _validated_result()
    object.__setattr__(validated, "port", 8443)
    policy = EgressPolicy.from_hosts("api.example.com")

    with pytest.raises(EgressNotAllowedError) as error:
        build_egress_decision_evidence(validated, policy=policy)

    assert str(error.value) == EGRESS_NOT_ALLOWED


def test_decision_evidence_is_immutable_and_serialization_is_detached() -> None:
    """Prevent audit records from changing after construction or serialization."""
    evidence = build_egress_decision_evidence(
        _validated_result(),
        policy=EgressPolicy.from_hosts("api.example.com"),
    )

    with pytest.raises(FrozenInstanceError):
        evidence.ipv4_address_count = 99

    serialized = evidence.as_dict()
    serialized["allowed_methods"].append("CONNECT")

    assert evidence.allowed_methods == (
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
    )
    assert isinstance(evidence, EgressDecisionEvidence)
