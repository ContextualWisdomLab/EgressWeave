"""Contracts for bounded canonical automation-prompt governance documentation."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    """Return one repository document as UTF-8 text."""
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def test_adr_records_integrated_bounded_canonical_prompt() -> None:
    """Keep prompt source, size, incident recovery, and shipped maturity aligned."""
    adr = _read("docs/adr/0004-bounded-canonical-automation-prompt.md")

    for required_phrase in (
        ".github/prompts/hourly-product-maintainer.md",
        "12 KiB",
        "inline YAML heredoc",
        "control-plane incident",
        "prompt repair alone",
        "IMPLEMENTED-ON-PROTECTED-MAIN",
    ):
        assert required_phrase in adr
    assert "Status: **Accepted**" in adr
    assert "This decision is **ACTIVE-PR** implementation" not in adr


def test_product_and_technical_requirements_include_prompt_control_plane_contract() -> None:
    """Make scheduler prompt integrity a verifiable product-delivery requirement."""
    prd = _read("docs/product/PRD.md")
    trd = _read("docs/product/TRD.md")

    assert "bounded canonical maintainer prompt" in prd
    assert "control-plane incident" in prd
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in prd
    assert ".github/prompts/hourly-product-maintainer.md" in trd
    assert "12 KiB" in trd
    assert "must not broaden repository-write authority" in trd


def test_architecture_and_uml_show_prompt_loading_and_resumable_failure() -> None:
    """Require a reviewable scheduler-bootstrap and recovery data flow."""
    system_architecture = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
    uml = _read("docs/architecture/UML.md")

    for required_phrase in (
        "Canonical maintainer prompt",
        "12 KiB",
        "OpenCode",
        "Credential-free verifier",
    ):
        assert required_phrase in system_architecture
    for required_phrase in (
        "validate canonical prompt",
        "generic scheduled-task failure",
        "resume repository work",
        "prompt repair is not completion",
    ):
        assert required_phrase in uml


def test_operability_audit_and_traceability_cover_integrated_scheduler_recovery() -> None:
    """Keep generic scheduler recovery current with the integrated prompt loader."""
    operability = _read("docs/product/OPERABILITY.md")
    audit = _read("docs/product/DOCUMENTATION_AUDIT.md")
    traceability = _read("docs/product/TRACEABILITY.md")

    for document in (operability, audit, traceability):
        assert "canonical prompt" in document
        assert "control-plane incident" in document
    assert "12 KiB" in operability
    assert "exact hidden error code is unavailable" in operability
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in audit
    assert "canonical prompt" in audit
    assert "ADR 0004" in traceability


def test_erd_keeps_automation_run_state_outside_the_library_database_boundary() -> None:
    """Prevent scheduler incidents from creating false EgressWeave persistence ownership."""
    erd = _read("docs/architecture/ERD.md")

    assert "automation_run_record" in erd
    assert "control_plane_incident_record" in erd
    assert "platform-owned" in erd
    assert "not EgressWeave database entities" in erd
