"""Regression contracts keeping UML class members aligned with runtime APIs."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
UML_PATH = REPOSITORY_ROOT / "docs" / "architecture" / "UML.md"


def _uml_text() -> str:
    """Return the canonical UML documentation as UTF-8 text."""
    return UML_PATH.read_text(encoding="utf-8")


def test_decision_evidence_uml_uses_public_runtime_field_names() -> None:
    """Prevent conceptual aliases from masquerading as protected-main dataclass fields."""
    uml = _uml_text()
    expected_members = (
        "+schema_version",
        "+authority",
        "+allowed_methods",
        "+address_count",
        "+ipv4_address_count",
        "+ipv6_address_count",
        "+policy_fingerprint",
        "+decision_fingerprint",
    )
    stale_aliases = (
        "+canonical_authority",
        "+method_policy",
        "+address_family_counts",
    )

    missing = [member for member in expected_members if member not in uml]
    stale = [member for member in stale_aliases if member in uml]
    assert not missing, f"UML is missing EgressDecisionEvidence runtime fields: {missing}"
    assert not stale, f"UML still presents conceptual aliases as runtime fields: {stale}"
