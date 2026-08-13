"""Regression tests for builder-issued decision evidence."""

from __future__ import annotations

import pytest

from egressweave import EgressDecisionEvidence


def test_decision_evidence_rejects_direct_public_construction() -> None:
    """Require decision evidence to come from the validating builder."""
    with pytest.raises(
        TypeError,
        match="EgressDecisionEvidence objects must come from the evidence builder",
    ):
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
