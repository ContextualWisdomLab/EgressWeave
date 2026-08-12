"""Contracts for bounded canonical automation-prompt governance documentation."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    """Return one repository document as UTF-8 text."""
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def _markdown_section(document: str, heading: str, *, level: int = 3) -> str:
    """Return one exact Markdown heading section, including nested headings."""
    marker = f"{'#' * level} {heading}"
    start = document.find(marker)
    assert start >= 0, f"missing Markdown section: {marker}"
    next_marker = f"\n{'#' * level} "
    end = document.find(next_marker, start + len(marker))
    return document[start:] if end < 0 else document[start:end]


def _workflow_prompt_budget_bytes(workflow: str) -> int:
    """Extract the exact protected workflow's numeric prompt-byte ceiling."""
    match = re.search(r'\[ "\$prompt_bytes" -gt (?P<limit>[0-9]+) \]', workflow)
    assert match is not None, "workflow prompt byte ceiling is missing"
    return int(match.group("limit"))


def test_adr_records_integrated_bounded_canonical_prompt() -> None:
    """Keep exact ADR status, budget, recovery authority, and maturity aligned."""
    adr = _read("docs/adr/0004-bounded-canonical-automation-prompt.md")
    budget = _markdown_section(adr, "2. Explicit prompt-size budget")
    recovery = _markdown_section(
        adr, "4. Generic failures are resumable control-plane incidents"
    )
    maturity = _markdown_section(adr, "5. Verification and maturity")

    assert adr.startswith("# ADR 0004: Bounded canonical automation prompt\n\nStatus: **Accepted**")
    assert ".github/prompts/hourly-product-maintainer.md" in adr
    assert "12,000 bytes" in budget
    assert "inline YAML heredoc" in adr
    assert "control-plane incident" in recovery
    assert "external maintainer" in recovery
    assert "SHALL NOT modify `.github/**` or the canonical prompt itself" in recovery
    assert "external prompt repair alone earns zero completion credit" in recovery.lower()
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in maturity
    assert "external scheduler is a separate evidence boundary" in maturity
    assert "This decision is **ACTIVE-PR** implementation" not in adr


def test_prompt_budget_matches_protected_workflow_boundary_and_adjacent_values() -> None:
    """Bind documentation to the literal 12,000-byte workflow comparison."""
    workflow = _read(".github/workflows/hourly-product-development.yml")
    limit = _workflow_prompt_budget_bytes(workflow)

    assert limit == 12_000
    assert not 12_000 > limit
    assert 12_001 > limit
    assert "12 KiB control-plane budget" in workflow  # diagnostic text is non-authoritative


def test_product_and_technical_requirements_include_prompt_control_plane_contract() -> None:
    """Scope scheduler maturity and authority checks to the exact requirements."""
    prd = _read("docs/product/PRD.md")
    trd = _read("docs/product/TRD.md")
    prd_goal = _markdown_section(
        prd, "PRD-G-007 — Bounded and resumable automation control plane"
    )
    prd_requirement = _markdown_section(
        prd, "PRD-FR-012 — Canonical automation prompt integrity"
    )
    trd_architecture = _markdown_section(
        trd, "TRD-AR-005 — Bounded canonical automation prompt"
    )

    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in prd_goal
    assert "control-plane incident" in prd_goal
    assert "external maintainer" in prd_goal
    assert ".github/**" in prd_goal
    assert ".github/prompts/hourly-product-maintainer.md" in prd_requirement
    assert "12,000 bytes" in prd_requirement
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in trd_architecture
    assert "12,000 bytes" in trd_architecture
    assert "must not broaden repository-write authority" in trd_architecture
    assert "external maintainer" in trd_architecture
    assert ".github/**" in trd_architecture


def test_architecture_and_uml_show_prompt_loading_and_resumable_failure() -> None:
    """Require a reviewable scheduler-bootstrap and recovery data flow."""
    system_architecture = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
    uml = _read("docs/architecture/UML.md")
    prompt_flow = _markdown_section(
        system_architecture,
        "IMPLEMENTED-ON-PROTECTED-MAIN: bounded canonical prompt data flow",
    )

    for required_phrase in (
        "Canonical maintainer prompt",
        "12,000-byte",
        "OpenCode",
        "Credential-free verifier",
        "external maintainer",
    ):
        assert required_phrase in prompt_flow
    for required_phrase in (
        "validate canonical prompt",
        "generic scheduled-task failure",
        "resume repository work",
        "prompt repair is not completion",
    ):
        assert required_phrase in uml


def test_operability_audit_and_traceability_cover_integrated_scheduler_recovery() -> None:
    """Scope current-truth scheduler assertions to the exact audit section."""
    operability = _read("docs/product/OPERABILITY.md")
    audit = _read("docs/product/DOCUMENTATION_AUDIT.md")
    traceability = _read("docs/product/TRACEABILITY.md")
    current_truth = _markdown_section(audit, "4. Current versus target truth", level=2)
    implemented = _markdown_section(current_truth, "IMPLEMENTED-ON-PROTECTED-MAIN")

    assert "canonical prompt" in operability
    assert "control-plane incident" in operability
    assert "12,000-byte" in operability
    assert "exact hidden error code is unavailable" in operability
    assert "external maintainer" in operability
    assert "canonical prompt" in implemented
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" in implemented
    assert "External scheduler/control-plane recovery" in implemented
    assert "ADR 0004" in traceability
    assert "12,000-byte" in traceability
    assert ".github/**" in traceability
    assert "external maintainer" in traceability


def test_erd_keeps_automation_run_state_outside_the_library_database_boundary() -> None:
    """Prevent scheduler incidents from creating false EgressWeave persistence ownership."""
    erd = _read("docs/architecture/ERD.md")

    assert "automation_run_record" in erd
    assert "control_plane_incident_record" in erd
    assert "platform-owned" in erd
    assert "not EgressWeave database entities" in erd
