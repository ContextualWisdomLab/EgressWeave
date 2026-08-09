"""Contracts for root-cause and feasibility handling in the hourly scheduler."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
RCA_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "hourly-rca-feasibility.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def _maintainer_prompt(workflow: str) -> str:
    """Extract the literal OpenCode maintainer prompt from the workflow."""
    start_marker = "cat >\"$prompt_file\" <<'PROMPT'"
    end_marker = "\n          PROMPT"
    return workflow.split(start_marker, 1)[1].split(end_marker, 1)[0]


def test_scheduler_requires_rca_and_operational_feasibility_before_escalation() -> None:
    """Require evidence-led RCA and a realistic remediation choice before stopping."""
    prompt = _maintainer_prompt(_read(PRODUCT_WORKFLOW_PATH))
    required_contract = (
        "Perform a root-cause analysis from exact current evidence",
        "validate each candidate's operational feasibility",
        "available permissions and tools, writer leases, branch protection",
        "Execute the smallest safe remediation that is both technically sound and operationally realistic",
        "continue with the next non-conflicting bounded action instead of stopping at the first blocker",
        "Escalate only after every autonomously actionable path has been exhausted",
    )

    missing = [fragment for fragment in required_contract if fragment not in prompt]
    assert not missing, f"scheduler RCA contract is missing: {missing}"


def test_scheduler_keeps_working_after_each_intermediate_result() -> None:
    """Prevent one blocker, fix, or documentation artifact from ending useful work."""
    prompt = _maintainer_prompt(_read(PRODUCT_WORKFLOW_PATH))
    required_contract = (
        "After every completed or deferred sub-action, reassess the remaining safe work for this same cohesive slice",
        "Do not stop because one candidate is blocked, one fix is complete, or one documentation artifact is updated",
        "documentation completeness",
        "PRD, TRD, ADR, Architecture, UML, and ERD applicability",
        "An ERD may be explicitly not applicable when the core owns no persistence",
        "Only leave the working tree unchanged when no safe material improvement remains inside the allowed edit boundary",
    )

    missing = [fragment for fragment in required_contract if fragment not in prompt]
    assert not missing, f"scheduler continuation contract is missing: {missing}"


def test_operator_docs_explain_the_rca_feasibility_loop() -> None:
    """Keep the scheduler's blocker-handling contract understandable to operators."""
    documentation = " ".join(_read(RCA_DOCUMENTATION_PATH).split())

    assert "root-cause analysis" in documentation
    assert "operational feasibility" in documentation
    assert "every autonomously actionable path has been exhausted" in documentation
    assert "work-conserving" in documentation
    assert "PRD" in documentation
    assert "ERD" in documentation
    assert "no persistence" in documentation


def test_changelog_records_the_scheduler_rca_feasibility_contract() -> None:
    """Keep the governed scheduler behavior visible in release-facing change history."""
    changelog = " ".join(_read(CHANGELOG_PATH).split())

    assert "hourly product-development maintainer" in changelog
    assert "root-cause analysis" in changelog
    assert "operational feasibility" in changelog
