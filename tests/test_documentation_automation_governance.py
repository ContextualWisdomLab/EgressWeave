"""Contracts for work-conserving automation and dependency-handoff documentation."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ADR_PATH = "docs/adr/0003-work-conserving-automation-and-dependency-handoff.md"


def _read(relative_path: str) -> str:
    """Return one repository text file as UTF-8."""
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def _line_containing(text: str, needle: str) -> str:
    """Return the unique documentation line that contains ``needle``."""
    matches = [line for line in text.splitlines() if needle in line]
    assert len(matches) == 1, f"expected one line containing {needle!r}, found {matches!r}"
    return matches[0]


def test_automation_governance_adr_is_indexed_and_status_bearing() -> None:
    """Keep the durable autonomous-maintenance decision out of chat-only history."""
    assert (REPOSITORY_ROOT / ADR_PATH).is_file()
    adr = _read(ADR_PATH)
    assert "Status: **Proposed**" in adr

    adr_index = _read("docs/adr/README.md")
    row = _line_containing(
        adr_index,
        "0003-work-conserving-automation-and-dependency-handoff.md",
    )
    assert "| [0003]" in row
    assert "| Proposed |" in row


def test_automation_governance_adr_defines_non_terminal_handoffs() -> None:
    """Prevent one useful action or one waiting dependency from becoming run completion."""
    adr = " ".join(_read(ADR_PATH).split()).lower()
    for required_phrase in (
        "work-conserving",
        "same invocation",
        "double exit sweep",
        "read-only dependency",
        "exact identity",
        "control-plane incident",
        "transient",
        "repository-write authority",
    ):
        assert required_phrase in adr, f"automation ADR is missing {required_phrase!r}"


def test_automation_governance_adr_makes_selection_and_exit_deterministic() -> None:
    """Require machine-checkable lane ordering, freshness, handoff, and exit evidence."""
    adr = " ".join(_read(ADR_PATH).split()).lower()
    for required_phrase in (
        "deterministic lane priority",
        "tie-break",
        "fresh snapshot",
        "safe action",
        "executable action",
        "handoff may be skipped only",
        "termination is permitted only",
        "selected action",
        "termination reason",
    ):
        assert required_phrase in adr, f"automation ADR is missing {required_phrase!r}"


def test_exact_evidence_is_bound_to_head_and_live_base_identity() -> None:
    """Invalidate acceptance evidence when either the candidate head or live base moves."""
    adr = " ".join(_read(ADR_PATH).split()).lower()
    assert "head or independently resolved live base identity changes" in adr
    assert "new head-and-live-base combination" in adr


def test_uml_exposes_dependency_advancement_and_control_plane_recovery() -> None:
    """Make the scheduler handoff semantics reviewable as an architecture diagram."""
    uml = _read("docs/architecture/UML.md")
    assert "Work-conserving automation control loop" in uml
    assert "Maturity: **Proposed governance**" in uml
    assert "does not claim" in uml
    assert "dependency advancement" in uml.lower()
    assert "control-plane error" in uml.lower()
    assert "double exit sweep" in uml.lower()
    assert "sequenceDiagram" in uml
    assert "revalidate dependent head/base, gates and writer lease" in uml
    assert "handoff only when dependent lane still matches" in uml
    assert "freeze affected action and continue" in uml


def test_documentation_audit_tracks_automation_governance_as_a_canonical_gap() -> None:
    """Keep the fitness matrix aware of the conversation-to-repository governance decision."""
    audit = _read("docs/product/DOCUMENTATION_AUDIT.md")
    row = _line_containing(audit, "Automation control-plane governance")
    assert "PARTIAL" in row
    assert "ADR 0003" in row
    assert "Proposed" in row
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" not in row
    assert "selects one bounded change" in row
    assert "does not override protected-main workflow source" in row
    assert "work-conserving" in audit.lower()
    assert "dependency" in audit.lower()
    assert "not shipped" in audit.lower() or "not protected-main" in audit.lower()


def test_traceability_maps_automation_governance_to_decision_and_evidence() -> None:
    """Connect the durable automation decision to machine-testable evidence and maturity."""
    traceability = _read("docs/product/TRACEABILITY.md")
    row = _line_containing(traceability, "Automation governance:")
    assert "ADR 0003" in row
    assert "PROPOSED-GOVERNANCE" in row
    assert "IMPLEMENTED-ON-PROTECTED-MAIN" not in row
    assert "tests/test_documentation_automation_governance.py" in row
    for required_phrase in (
        "work-conserving",
        "dependency handoff",
        "control-plane incident",
        "double exit sweep",
    ):
        assert required_phrase in row.lower()


def test_protected_product_handoff_has_no_repository_local_publisher() -> None:
    """Keep operator docs, accepted ADR, and architecture aligned on publisher-free handoff."""
    operator_docs = _read("docs/hourly-autonomous-maintenance.md")
    accepted_adr = _read("docs/adr/0001-security-boundaries-and-modular-integration.md")
    architecture = _read("ARCHITECTURE.md")

    operator_automation = operator_docs.split(
        "## Zero-PR product-development loop",
        1,
    )[1].split("## Model change boundary", 1)[0]
    adr_automation = accepted_adr.split("### 6. Credential-separated automation", 1)[
        1
    ].split("## Alternatives considered", 1)[0]
    architecture_automation = architecture.split("## Repository automation", 1)[1].split(
        "## References",
        1,
    )[0]

    normalized_operator = " ".join(operator_automation.split()).lower()
    assert "credential-free" in normalized_operator
    assert "no repository-local product-development job promotes" in normalized_operator

    for section in (adr_automation, architecture_automation):
        normalized = " ".join(section.split()).lower()
        assert "credential-free" in normalized
        assert "repository-local" in normalized
        assert "pull request" in normalized

    assert "publishing identity creates a normal pull request" not in adr_automation
    assert "publication use separate runners" not in architecture_automation
