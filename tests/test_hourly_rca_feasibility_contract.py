"""Contracts for root-cause and feasibility handling in the hourly scheduler."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
MAINTAINER_PROMPT_PATH = (
    REPOSITORY_ROOT / ".github" / "prompts" / "hourly-product-maintainer.md"
)
RCA_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "hourly-rca-feasibility.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def _maintainer_prompt() -> str:
    """Return the immutable repository-owned OpenCode maintainer prompt."""
    assert MAINTAINER_PROMPT_PATH.is_file(), (
        "hourly product development must use one canonical prompt file"
    )
    return _read(MAINTAINER_PROMPT_PATH)


def test_scheduler_loads_one_canonical_prompt_instead_of_inline_policy() -> None:
    """Keep policy outside YAML so prompt growth cannot corrupt workflow syntax."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert ".github/prompts/hourly-product-maintainer.md" in workflow
    assert "cat >\"$prompt_file\" <<'PROMPT'" not in workflow
    assert "cp -- \"$prompt_source\" \"$prompt_file\"" in workflow
    assert '[ ! -f "$prompt_source" ] || [ -L "$prompt_source" ]' in workflow
    assert '[[ ! "$prompt_bytes" =~ ^[0-9]+$ ]]' in workflow
    assert '[ "$prompt_bytes" -gt 12000 ]' in workflow
    assert 'chmod 0444 "$prompt_file"' in workflow


def test_canonical_prompt_has_a_bounded_control_plane_budget() -> None:
    """Prevent unbounded scheduler prose from becoming a control-plane failure mode."""
    prompt = _maintainer_prompt()

    assert len(prompt.encode("utf-8")) <= 12_000
    assert prompt.count("ABSOLUTE NO-EARLY-STOP") == 1
    assert prompt.count("MANDATORY DOUBLE EXIT SWEEP") == 1


def test_canonical_prompt_recovers_from_control_plane_errors() -> None:
    """Treat a generic scheduler failure as resumable incident evidence."""
    prompt = _maintainer_prompt().lower()

    for required_phrase in (
        "control-plane incident",
        "generic scheduled-task failure",
        "prompt repair alone earns zero completion credit",
        "continue repository work in the same invocation",
        "do not disable the recurring loop for a transient",
    ):
        assert required_phrase in prompt


def test_canonical_prompt_advances_read_only_dependencies_without_stopping() -> None:
    """Require same-run caller-side work after a material dependency advance."""
    prompt = _maintainer_prompt().lower()

    for required_phrase in (
        "dependency-advancement handoff",
        "bind the new exact protected/default head or pr head",
        "advance the dependent egressweave lane in the same invocation",
        "a dependency wait may never terminate the run",
    ):
        assert required_phrase in prompt


def test_scheduler_requires_rca_and_operational_feasibility_before_escalation() -> None:
    """Require evidence-led RCA and a realistic remediation choice before stopping."""
    prompt = _maintainer_prompt()
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
    prompt = _maintainer_prompt()
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
    assert "canonical prompt" in documentation
    assert "12 KiB" in documentation
    assert "control-plane incident" in documentation
    assert "PRD" in documentation
    assert "ERD" in documentation
    assert "no persistence" in documentation


def test_changelog_records_the_scheduler_rca_feasibility_contract() -> None:
    """Keep the governed scheduler behavior visible in release-facing change history."""
    changelog = " ".join(_read(CHANGELOG_PATH).split())

    assert "hourly product-development maintainer" in changelog
    assert "root-cause analysis" in changelog
    assert "operational feasibility" in changelog
    assert "canonical prompt" in changelog
    assert "control-plane" in changelog
