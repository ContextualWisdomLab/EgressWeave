"""Release-workflow contracts for exact protected-main acceptance evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


def test_release_publication_requires_exact_workflow_evidence_gate() -> None:
    """Block tag and publication jobs until exact required evidence is verified."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "  verify-release-evidence:" in workflow
    assert "name: Verify exact protected-main release evidence" in workflow
    assert "permissions:" in workflow
    assert "actions: read" in workflow
    assert "pull-requests: read" in workflow
    assert "checks: read" in workflow
    assert "Require integrating pull request for exact release commit" in workflow
    assert "Require required workflow evidence for integrating PR head" in workflow
    assert "Require executed Dependency review action" in workflow
    assert "dependency-review" in workflow
    assert "Dependency review" in workflow

    tag_job = workflow.split("  create-release-tag:", maxsplit=1)[1].split(
        "  publish-to-pypi:", maxsplit=1
    )[0]
    assert "- verify-release-evidence" in tag_job

    publish_job = workflow.split("  publish-to-pypi:", maxsplit=1)[1].split(
        "  publish-github-release:", maxsplit=1
    )[0]
    assert "- verify-release-evidence" in publish_job
