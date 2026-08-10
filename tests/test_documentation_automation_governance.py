"""Contracts for work-conserving automation and dependency-handoff documentation."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ADR_PATH = "docs/adr/0003-work-conserving-automation-and-dependency-handoff.md"


def _read(relative_path: str) -> str:
    """Return one repository text file as UTF-8."""
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def test_automation_governance_adr_is_indexed_and_status_bearing() -> None:
    """Keep the durable autonomous-maintenance decision out of chat-only history."""
    assert (REPOSITORY_ROOT / ADR_PATH).is_file()
    adr_index = _read("docs/adr/README.md")
    assert "0003-work-conserving-automation-and-dependency-handoff.md" in adr_index
    assert "| [0003]" in adr_index
    assert "| Proposed |" in adr_index


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


def test_uml_exposes_dependency_advancement_and_control_plane_recovery() -> None:
    """Make the scheduler handoff semantics reviewable as an architecture diagram."""
    uml = _read("docs/architecture/UML.md")
    assert "Work-conserving automation control loop" in uml
    assert "dependency advancement" in uml.lower()
    assert "control-plane error" in uml.lower()
    assert "double exit sweep" in uml.lower()
    assert "sequenceDiagram" in uml


def test_documentation_audit_tracks_automation_governance_as_a_canonical_gap() -> None:
    """Keep the fitness matrix aware of the conversation-to-repository governance decision."""
    audit = _read("docs/product/DOCUMENTATION_AUDIT.md")
    assert "Automation control-plane governance" in audit
    assert "ADR 0003" in audit
    assert "work-conserving" in audit.lower()
    assert "dependency" in audit.lower()


def test_changelog_records_the_automation_governance_baseline() -> None:
    """Keep the new durable governance contract visible in unreleased history."""
    changelog = " ".join(_read("CHANGELOG.md").split()).lower()
    assert "automation governance" in changelog
    assert "dependency handoff" in changelog
