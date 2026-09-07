"""Regression tests for builder-issued decision evidence."""

from __future__ import annotations

import pytest

from egressweave import EgressDecisionEvidence

_DIRECT_CONSTRUCTION_ERROR = (
    "EgressDecisionEvidence objects must come from the evidence builder"
)


def test_decision_evidence_rejects_direct_public_construction() -> None:
    """Require decision evidence to come from the validating builder."""
    with pytest.raises(TypeError, match=_DIRECT_CONSTRUCTION_ERROR):
        EgressDecisionEvidence(
            schema_version="egressweave.decision-evidence.v1",
            authority="api.example.com:443",
            allowed_methods=("GET",),
            address_count=1,
            ipv4_address_count=1,
            ipv6_address_count=0,
            policy_fingerprint="0" * 64,
            decision_fingerprint="1" * 64,
        )


def test_decision_evidence_rejects_empty_direct_construction_consistently() -> None:
    """Keep the intentional factory-only error for argument-shape mistakes."""
    with pytest.raises(TypeError, match=_DIRECT_CONSTRUCTION_ERROR):
        EgressDecisionEvidence()
